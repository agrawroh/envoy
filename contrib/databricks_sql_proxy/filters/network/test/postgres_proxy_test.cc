#include <cstdint>
#include <iostream>

#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/filters/common/ext_authz/ext_authz.h"

#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/factory_context.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/network/source/config.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_postgres_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::HasSubstr;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
using testing::WithArgs;
using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;
using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;

class PostgresProxyTest : public testing::Test {
public:
  PostgresProxyTest() {
    const std::string yaml = R"EOF(
      stat_prefix: "test"
      protocol: POSTGRES
      enable_upstream_tls: true
      destination_cluster_source: SIDECAR_SERVICE
      ext_authz_service:
        envoy_grpc:
          cluster_name: ext_authz_server
      postgres_config:
        read_parameter_status_upstream_ip: true
        store_cancellation_key: true
    )EOF";

    DatabricksSqlProxyProto proto_config;
    TestUtility::loadFromYaml(yaml, proto_config);

    client_ = new Filters::Common::ExtAuthz::MockClient();
    config_ = std::make_shared<Config>(proto_config, context_, stat_prefix_);
    filter_ = std::make_unique<Filter>(config_, ExtAuthzClientPtr{client_});
    ssl_ = std::make_shared<Ssl::MockConnectionInfo>();

    filter_->initializeReadFilterCallbacks(read_callbacks_);
    filter_->initializeWriteFilterCallbacks(write_callbacks_);

    ON_CALL(read_callbacks_.connection_, ssl()).WillByDefault(Return(ssl_));
    ON_CALL(read_callbacks_.connection_, readDisable(_)).WillByDefault(Invoke([this](bool disable) {
      read_callbacks_.connection_.read_enabled_ = !disable;

      if (disable) {
        return Network::Connection::ReadDisableStatus::TransitionedToReadDisabled;
      } else {
        return Network::Connection::ReadDisableStatus::TransitionedToReadEnabled;
      }
    }));
    ON_CALL(read_callbacks_.connection_.stream_info_, setDynamicMetadata(_, _))
        .WillByDefault(Invoke([this](const std::string& name, const ProtobufWkt::Struct& obj) {
          (*read_callbacks_.connection_.stream_info_.metadata_.mutable_filter_metadata())[name]
              .MergeFrom(obj);
        }));

    EXPECT_CALL(*ssl_, sni()).WillRepeatedly(ReturnRef(sni_));
    const std::vector<std::string> uriSan{"someSan"};
    EXPECT_CALL(*ssl_, uriSanPeerCertificate()).WillRepeatedly(Return(uriSan));
    EXPECT_CALL(*ssl_, uriSanLocalCertificate()).WillRepeatedly(Return(uriSan));
  }

  Buffer::OwnedImpl
  createPostgresStartupMessage(int32_t len = PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH,
                               uint32_t protocolVersion = PostgresConstants::PROTOCOL_VERSION) {
    Buffer::OwnedImpl postgres_startup_message;
    postgres_startup_message.writeBEInt<int32_t>(len);
    postgres_startup_message.writeBEInt<uint32_t>(protocolVersion);
    return postgres_startup_message;
  }

  void runExtAuthzFailureTest(Filters::Common::ExtAuthz::CheckStatus ext_auth_response,
                              const std::string& expected_response_code_details,
                              bool expected_system_error, absl::string_view reason_phrase);

  const std::string stat_prefix_{"test."};
  const std::string sni_{"brickstore.database.databricks.com"};

  NiceMock<Server::Configuration::MockFactoryContext> context_;
  std::unique_ptr<Filter> filter_;
  ConfigSharedPtr config_;
  NiceMock<Network::MockReadFilterCallbacks> read_callbacks_;
  NiceMock<Network::MockWriteFilterCallbacks> write_callbacks_;
  std::shared_ptr<Ssl::MockConnectionInfo> ssl_;
  Filters::Common::ExtAuthz::MockClient* client_;
};

// These that onNewConnection should disable read and stop filter iteration.
TEST_F(PostgresProxyTest, NewConnection) {
  EXPECT_CALL(read_callbacks_.connection_, readDisable(false));
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration, filter_->onNewConnection());
}

// Test full end to end flow. The test will simulate TcpProxy by setting connection object
// read_enabled_ state.
TEST_F(PostgresProxyTest, FullEndToEndWithSidecarService) {
  filter_->onNewConnection();

  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(
          Invoke([](Filters::Common::ExtAuthz::RequestCallbacks& /*callback*/,
                    const envoy::service::auth::v3::CheckRequest& request,
                    Tracing::Span& /*parent_span*/, const StreamInfo::StreamInfo& /*stream_info*/) {
            // Verify that we passed dynamic metadata with key
            // "envoy.filters.network.databricks_sql_proxy" to the ext_authz call via CheckRequest.
            EXPECT_EQ(request.attributes().metadata_context().filter_metadata().contains(
                          NetworkFilterNames::get().DatabricksSqlProxy),
                      true);
          }));

  // 1. Client sends a postgres startup message.
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false));

  EXPECT_EQ(1, config_->stats().active_ext_authz_call_.value());

  // Injecting empty buffer to initiate upstream connection after ext_authz call completed.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool end_stream) {
        EXPECT_EQ(data.length(), 0);
        EXPECT_FALSE(end_stream);
      }));

  std::string expected_target_cluster{"some_target_cluster"};
  Filters::Common::ExtAuthz::Response response{};
  response.status = Filters::Common::ExtAuthz::CheckStatus::OK;
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*response.dynamic_metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] =
      target_cluster_value;

  // Simulate the ext_authz server response.
  filter_->onComplete(std::make_unique<Filters::Common::ExtAuthz::Response>(response));

  EXPECT_EQ(0, config_->stats().active_ext_authz_call_.value());

  // Verify that SNI and upstream cluster name are set correctly.
  EXPECT_EQ(sni_,
            read_callbacks_.connection_.stream_info_.filter_state_
                ->getDataReadOnly<Network::UpstreamServerName>(Network::UpstreamServerName::key())
                ->value());
  EXPECT_EQ(expected_target_cluster, read_callbacks_.connection_.stream_info_.filter_state_
                                         ->getDataReadOnly<TcpProxy::PerConnectionCluster>(
                                             TcpProxy::PerConnectionCluster::key())
                                         ->value());

  // Read should be disabled until the upstream connection is established.
  EXPECT_FALSE(read_callbacks_.connection_.read_enabled_);

  // Should have buffered the first message.
  EXPECT_EQ(8, config_->stats().buffered_first_message_.value());

  // 2. Assume that TcpProxy established the upstream connection which will enable read.
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect to inject SSL request to the upstream.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool end_stream) {
        EXPECT_EQ(data.length(), PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);
        EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, data.peekBEInt<uint32_t>(0));
        EXPECT_EQ(PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION, data.peekBEInt<uint32_t>(4));
        EXPECT_FALSE(end_stream);
      }));

  // 3. Assume that TcpProxy established the upstream connection.
  // Timer object for the test is a mock object so we need to call the function directly.
  filter_->pollForUpstreamConnected();

  // Since read is enabled now, onData might be called. Until the upstream connection
  // handshake is fully done, we should not continue the filter chain.
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false));

  // Expect to switch upstream to SSL.
  EXPECT_CALL(read_callbacks_, startUpstreamSecureTransport()).WillOnce(testing::Return(true));

  // Should inject the previously buffered postgres startup message to the upstream.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _))
      .WillOnce(Invoke([len = PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH,
                        protocolVersion = PostgresConstants::PROTOCOL_VERSION](
                           Buffer::Instance& data, bool end_stream) {
        EXPECT_EQ(len, data.length());
        EXPECT_EQ(len, data.peekBEInt<uint32_t>(0));
        EXPECT_EQ(protocolVersion, data.peekBEInt<uint32_t>(4));
        EXPECT_FALSE(end_stream);
      }));

  // 4. Simulate upstream returning SSL response.
  Buffer::OwnedImpl ssl_response;
  ssl_response.writeByte(PostgresConstants::POSTGRES_SUPPORT_SSL);
  // onWrite should inject the previously buffered postgres startup message to the upstream.
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onWrite(ssl_response, false /*end_stream*/));

  // All buffered message should be drained because it sent to the upstream.
  EXPECT_EQ(0, config_->stats().buffered_first_message_.value());

  // Now onData should pass through the buffer as is.
  // For the test, we don't care about the data.
  EXPECT_EQ(Envoy::Network::FilterStatus::Continue,
            filter_->onData(ssl_response, false /*end_stream*/));

  // 5. Filter is waiting for Parameter status message and Backend Key Data message from the
  // upstream. Create those messages and send them to the filter.
  absl::string_view ip = "1.2.3.4";
  size_t parameter_status_message_len =
      sizeof(uint32_t) + CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY.size() +
      1 /* null-terminator */ + ip.size() + 1 /* null-terminator */;
  Buffer::OwnedImpl parameter_status_message;
  parameter_status_message.writeByte(PostgresConstants::PARAMETER_STATUS_MESSAGE_TYPE);
  parameter_status_message.writeBEInt<int32_t>(parameter_status_message_len);
  parameter_status_message.add(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY);
  parameter_status_message.writeByte(0); // null-terminator
  parameter_status_message.add(ip);
  parameter_status_message.writeByte(0); // null-terminator

  // Send the parameter status message to the filter.
  EXPECT_EQ(Envoy::Network::FilterStatus::Continue,
            filter_->onWrite(parameter_status_message, false /*end_stream*/));

  const int32_t process_id = 1111;
  const int32_t secret_key = 9876;
  Buffer::OwnedImpl backend_key_data_message;
  backend_key_data_message.writeByte(PostgresConstants::BACKEND_KEY_DATA_MESSAGE_TYPE);
  backend_key_data_message.writeBEInt<int32_t>(12);         // message length
  backend_key_data_message.writeBEInt<int32_t>(process_id); // process_id
  backend_key_data_message.writeBEInt<int32_t>(secret_key); // secret_key

  Buffer::OwnedImpl combined_data;
  combined_data.add(parameter_status_message);
  combined_data.add(backend_key_data_message);

  // Filter should not forward the parameter status message to the downstream.
  // Only the backend key data message should be forwarded.
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool /* end_stream */) {
        EXPECT_EQ(backend_key_data_message.length(), data.length());
        EXPECT_EQ(backend_key_data_message.toString(), data.toString());
      }));

  // Check should be called to store upstream_ip and cancellation key.
  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([&](Filters::Common::ExtAuthz::RequestCallbacks& /*callback*/,
                           const envoy::service::auth::v3::CheckRequest& request,
                           Tracing::Span& /*parent_span*/,
                           const StreamInfo::StreamInfo& /*stream_info*/) {
        ProtobufWkt::Struct dynamic_metadata =
            request.attributes().metadata_context().filter_metadata().at(
                NetworkFilterNames::get().DatabricksSqlProxy);
        EXPECT_EQ(dynamic_metadata.fields()
                      .at(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY)
                      .string_value(),
                  ip);
        EXPECT_EQ(dynamic_metadata.fields()
                      .at(CommonConstants::CANCELLATION_PROCESS_ID_KEY)
                      .number_value(),
                  process_id);
        EXPECT_EQ(dynamic_metadata.fields()
                      .at(CommonConstants::CANCELLATION_SECRET_KEY_KEY)
                      .number_value(),
                  secret_key);
      }));

  EXPECT_EQ(Envoy::Network::FilterStatus::Continue,
            filter_->onWrite(combined_data, false /*end_stream*/));

  // Now onWrite should pass through the buffer as is.
  // For the test, we don't care about the data.
  EXPECT_EQ(Envoy::Network::FilterStatus::Continue,
            filter_->onWrite(ssl_response, false /*end_stream*/));

  EXPECT_EQ(0, config_->stats().errors_.value());
  EXPECT_EQ(1, config_->stats().successful_login_.value());
}

// Test that when destination_cluster_source is set to SNI, the SNI is used as the upstream cluster
// name. This does not do a full end-to-end test because the rest of the code is the same as the
// FullEndToEndWithSidecarService test.
TEST_F(PostgresProxyTest, SniAsDestinationClusterSource) {
  const std::string yaml = R"EOF(
      stat_prefix: "test"
      protocol: POSTGRES
      enable_upstream_tls: true
      destination_cluster_source: SNI
    )EOF";

  DatabricksSqlProxyProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  ConfigSharedPtr config = std::make_shared<Config>(proto_config, context_, stat_prefix_);
  std::unique_ptr<Filter> filter = std::make_unique<Filter>(config, ExtAuthzClientPtr{nullptr});

  filter->initializeReadFilterCallbacks(read_callbacks_);
  filter->initializeWriteFilterCallbacks(write_callbacks_);

  filter->onNewConnection();

  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  read_callbacks_.connection_.read_enabled_ = true;

  // Injecting empty buffer to initiate upstream connection after getting SNI.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool end_stream) {
        EXPECT_EQ(data.length(), 0);
        EXPECT_FALSE(end_stream);
      }));

  // Client sends a postgres startup message.
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter->onData(postgres_startup_message, false));

  // Verify that SNI and upstream cluster name are set correctly.
  EXPECT_EQ(sni_,
            read_callbacks_.connection_.stream_info_.filter_state_
                ->getDataReadOnly<Network::UpstreamServerName>(Network::UpstreamServerName::key())
                ->value());
  EXPECT_EQ(sni_, read_callbacks_.connection_.stream_info_.filter_state_
                      ->getDataReadOnly<TcpProxy::PerConnectionCluster>(
                          TcpProxy::PerConnectionCluster::key())
                      ->value());

  // Should have buffered the first message.
  EXPECT_EQ(8, config_->stats().buffered_first_message_.value());
  // Should not have any active ext_authz call.
  EXPECT_EQ(0, config->stats().active_ext_authz_call_.value());
  EXPECT_EQ(0, config->stats().errors_.value());
  // We have not finished authentication yet. successful_login should be 0.
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test that if there is not enough data to process the first start-up message,
// the connection should still be open to wait for more data.
TEST_F(PostgresProxyTest, NotEnoughData) {
  Buffer::OwnedImpl postgres_startup_message_short;
  postgres_startup_message_short.writeBEInt<uint8_t>(1);
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect to have at least 8 bytes to start processing the start-up message.
  // Only have 4 bytes so far (message_length).
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message_short, false /*end_stream*/));
  // Connection should still be open.
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Open);
  EXPECT_TRUE(read_callbacks_.connection_.read_enabled_);
  EXPECT_EQ(0, config_->stats().active_ext_authz_call_.value());

  const std::string connection_string_options{"user\0testuser\0database\0testdb\0", 30};
  Buffer::OwnedImpl postgres_startup_message;
  postgres_startup_message.writeBEInt<int32_t>(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH +
                                               connection_string_options.length());
  postgres_startup_message.writeBEInt<uint32_t>(PostgresConstants::PROTOCOL_VERSION);
  // Don't write the full message yet. Only write the message length and protocol version (8 bytes).

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));
  // Connection should still be open.
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Open);
  EXPECT_TRUE(read_callbacks_.connection_.read_enabled_);
  EXPECT_EQ(0, config_->stats().active_ext_authz_call_.value());
  // onData should not drain the buffer because there is not enough data to process the message.
  EXPECT_EQ(8, postgres_startup_message.length());

  // Write the rest of the message.
  postgres_startup_message.add(connection_string_options);

  EXPECT_CALL(*client_, check(_, _, _, _));

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));

  // Code should proceed to a point where we call ext_authz.
  EXPECT_EQ(1, config_->stats().active_ext_authz_call_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
  // onData should drain the buffer because the message is processed.
  EXPECT_EQ(0, postgres_startup_message.length());
}

// Test that if the start-up message length is shorter than expected, the connection should be
// closed. The minimum length of the start-up message is 8 bytes (4 bytes message length and 4 bytes
// protocol version).
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
TEST_F(PostgresProxyTest, ShorterThanExpectedMessage) {
  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage(4);
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_TRUE(read_callbacks_.connection_.read_enabled_);

  EXPECT_EQ(1UL, config_->stats().invalid_message_length_.value());
  EXPECT_EQ(1UL, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test that if the start-up message length is larger than expected, the connection should be
// closed.
TEST_F(PostgresProxyTest, LargerThanExpectedMessage) {
  Buffer::OwnedImpl postgres_startup_message =
      createPostgresStartupMessage(PostgresConstants::MAX_POSTGRES_MESSAGE_LENGTH + 1);
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_TRUE(read_callbacks_.connection_.read_enabled_);

  EXPECT_EQ(1UL, config_->stats().invalid_message_length_.value());
  EXPECT_EQ(1UL, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test that if the protocol version is incorrect, the connection should be closed.
TEST_F(PostgresProxyTest, IncorrectProtocolVersion) {
  Buffer::OwnedImpl postgres_startup_message =
      createPostgresStartupMessage(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH, 5);
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(90, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(89, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(), HasSubstr("Unsupported frontend protocol"));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));

  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);

  EXPECT_EQ(1UL, config_->stats().invalid_protocol_version_.value());
  EXPECT_EQ(1UL, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test that if the upstream return some data before the postgres SSL request is sent, the
// connection should be closed. as it indicates invalid postgres protocol.
TEST_F(PostgresProxyTest, HandleUpstreamDataInitState) {
  std::unique_ptr<PostgresProxy> postgres_proxy =
      std::make_unique<PostgresProxy>(config_, *filter_);
  postgres_proxy->initializeReadFilterCallbacks(read_callbacks_);
  postgres_proxy->initializeWriteFilterCallbacks(write_callbacks_);

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(114, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(113, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(),
                    HasSubstr("Received data from upstream before sending SSL request"));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  Buffer::OwnedImpl upstream_message;
  upstream_message.writeByte('S');

  // Test postgres specific implementation
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            postgres_proxy->handleUpstreamData(upstream_message, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);

  EXPECT_EQ(1, config_->stats().incorrect_upstream_connection_state_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());

  // Test generic filter implementation
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(62, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(61, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(), HasSubstr("Invalid upstream handshake state"));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration, filter_->onWrite(upstream_message, false));
  EXPECT_EQ(1, config_->stats().protocol_violation_.value());
  EXPECT_EQ(2, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test multiple scenarios that the upstream can return invalid data.
TEST_F(PostgresProxyTest, HandleUpstreamDataSentSslRequestUpstreamState) {
  // ==== Test setup: ====
  // Set the filter to the correct state that will wait for upstream SSL response.
  filter_->onNewConnection();

  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();

  EXPECT_CALL(*client_, check(_, _, _, _));

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false));

  std::string expected_target_cluster{"some_target_cluster"};
  Filters::Common::ExtAuthz::Response response{};
  response.status = Filters::Common::ExtAuthz::CheckStatus::OK;
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*response.dynamic_metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] =
      target_cluster_value;

  // Injecting empty buffer to initiate upstream connection after Check call completed.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _));

  // Simulate the ext_authz server response.
  filter_->onComplete(std::make_unique<Filters::Common::ExtAuthz::Response>(response));

  // Assume that TcpProxy established the upstream connection.
  // This will enable read.
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect to inject SSL request to the upstream.
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _));

  // Timer object for the test is a mock object so we need to call the function directly.
  filter_->pollForUpstreamConnected();

  // ==== Test scenarios ====
  // 1. Upstream send empty data.
  Buffer::OwnedImpl empty_buffer;
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onWrite(empty_buffer, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_EQ(read_callbacks_.connection_.stream_info_.connection_termination_details_,
            "Invalid length of SSL response from upstream.");
  EXPECT_EQ(1UL, config_->stats().invalid_upstream_response_.value());
  EXPECT_EQ(1UL, config_->stats().errors_.value());
  // Reset the connection state to open for the next test case.
  read_callbacks_.connection_.state_ = Network::Connection::State::Open;

  // 2. Now try a case where upstream does not support SSL
  Buffer::OwnedImpl ssl_not_supported_response;
  ssl_not_supported_response.writeByte('N');
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onWrite(ssl_not_supported_response, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_EQ(read_callbacks_.connection_.stream_info_.connection_termination_details_,
            "Upstream does not support SSL.");
  EXPECT_EQ(1UL, config_->stats().upstream_not_support_ssl_.value());
  EXPECT_EQ(2UL, config_->stats().errors_.value());
  // Reset the connection state to open for the next test case.
  read_callbacks_.connection_.state_ = Network::Connection::State::Open;

  // 3. Now try a case where switching to upstream SSL failed.
  EXPECT_CALL(read_callbacks_, startUpstreamSecureTransport()).WillOnce(testing::Return(false));
  Buffer::OwnedImpl ssl_response;
  ssl_response.writeByte(PostgresConstants::POSTGRES_SUPPORT_SSL);
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onWrite(ssl_response, false /*end_stream*/));
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_EQ(read_callbacks_.connection_.stream_info_.connection_termination_details_,
            "Failed to start secure transport with upstream.");
  EXPECT_EQ(1UL, config_->stats().failed_upstream_ssl_handshake_.value());
  EXPECT_EQ(3UL, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

void PostgresProxyTest::runExtAuthzFailureTest(
    Filters::Common::ExtAuthz::CheckStatus ext_auth_response,
    const std::string& expected_response_code_details, bool expected_system_error = false,
    const absl::string_view reason_phrase = "ip address is not allowed") {
  // ==== Test setup: ====
  // Set the filter to the correct state before calling ext_authz Check.
  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  EXPECT_CALL(*client_, check(_, _, _, _));
  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false));

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([reason_phrase](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // Skip the first 4 bytes, which is the message length and read severity code of the error
        // message.
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(), HasSubstr("External authorization failed"));
        EXPECT_THAT(data.toString(), HasSubstr(reason_phrase));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  Filters::Common::ExtAuthz::Response response{};
  response.status = ext_auth_response;
  ProtobufWkt::Struct dynamic_metadata;
  (*dynamic_metadata.mutable_fields())[CommonConstants::REASON_PHRASE_KEY].set_string_value(
      reason_phrase);
  response.dynamic_metadata = dynamic_metadata;

  // Ext Authz server response with failure.
  filter_->onComplete(std::make_unique<Filters::Common::ExtAuthz::Response>(response));

  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);
  EXPECT_EQ(read_callbacks_.connection_.stream_info_.connection_termination_details_.value(),
            "Ext Authz failed");
  EXPECT_EQ(read_callbacks_.connection_.stream_info_.response_code_details_.value(),
            expected_response_code_details);
  EXPECT_TRUE(read_callbacks_.connection_.stream_info_.hasResponseFlag(
      StreamInfo::CoreResponseFlag::UnauthorizedExternalService));

  if (expected_system_error) {
    EXPECT_EQ(1, config_->stats().ext_authz_failed_system_error_.value());
  } else {
    EXPECT_EQ(1, config_->stats().ext_authz_failed_.value());
  }
  EXPECT_EQ(1, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

TEST_F(PostgresProxyTest, ExtAuthzPrivateLinkNotSupported) {
  runExtAuthzFailureTest(Filters::Common::ExtAuthz::CheckStatus::Denied,
                         Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzDenied,
                         /*expected_system_error=*/true,
                         CommonConstants::REASON_CODE_PRIVATE_LINK_NOT_SUPPORTED);
}

TEST_F(PostgresProxyTest, ExtAuthzUnsupportedDestinationType) {
  runExtAuthzFailureTest(Filters::Common::ExtAuthz::CheckStatus::Denied,
                         Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzDenied,
                         /*expected_system_error=*/true,
                         CommonConstants::REASON_CODE_UNSUPPORTED_DESTINATION_TYPE);
}

TEST_F(PostgresProxyTest, ExtAuthzError) {
  runExtAuthzFailureTest(Filters::Common::ExtAuthz::CheckStatus::Error,
                         Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzError,
                         /*expected_system_error=*/true);
}

TEST_F(PostgresProxyTest, ExtAuthzDenied) {
  runExtAuthzFailureTest(Filters::Common::ExtAuthz::CheckStatus::Denied,
                         Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzDenied,
                         /*expected_system_error=*/false);
}

// Test that if the downstream connection does not have ssl, we error out.
TEST_F(PostgresProxyTest, DownstreamNotSsl) {
  EXPECT_CALL(read_callbacks_.connection_, ssl()).WillOnce(Return(nullptr));

  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(140, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(139, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(), HasSubstr("Insecure connection"));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));

  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);

  EXPECT_EQ(1, config_->stats().downstream_not_support_ssl_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
  EXPECT_EQ(0, config_->stats().successful_login_.value());
}

// Test that if the downstream connection does not have SNI, we error out.
TEST_F(PostgresProxyTest, DownstreamNoSni) {
  const std::string empty_sni{};
  EXPECT_CALL(*ssl_, sni()).WillOnce(ReturnRef(empty_sni));

  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool /* end_stream */) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(102, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(101, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        EXPECT_THAT(data.toString(), HasSubstr("Connection does not have SNI."));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  EXPECT_EQ(Envoy::Network::FilterStatus::StopIteration,
            filter_->onData(postgres_startup_message, false /*end_stream*/));

  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Closed);

  EXPECT_EQ(1, config_->stats().downstream_no_sni_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

// Test different connection string input handling scenarios.
TEST_F(PostgresProxyTest, OutputConnectionStringToDynamicMetadata) {
  std::unique_ptr<PostgresProxy> postgres_proxy =
      std::make_unique<PostgresProxy>(config_, *filter_);
  postgres_proxy->initializeReadFilterCallbacks(read_callbacks_);
  postgres_proxy->initializeWriteFilterCallbacks(write_callbacks_);

  Buffer::OwnedImpl data;
  // 1. Empty data.
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 0);
  auto& filter_meta =
      read_callbacks_.connection().streamInfo().dynamicMetadata().mutable_filter_metadata()->at(
          NetworkFilterNames::get().DatabricksSqlProxy);
  Protobuf::Map<std::string, ProtobufWkt::Value> fields = filter_meta.fields();
  // Should contain any connection_string_options
  EXPECT_FALSE(fields.contains("connection_string_options"));

  // 2. Add only 1 byte of data without null terminator.
  data.add("abc", 1);
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 1);
  filter_meta =
      read_callbacks_.connection().streamInfo().dynamicMetadata().mutable_filter_metadata()->at(
          NetworkFilterNames::get().DatabricksSqlProxy);
  fields = filter_meta.fields();
  // Should not contain connection_string_options because there is no null terminator.
  EXPECT_FALSE(fields.contains("connection_string_options"));
  read_callbacks_.connection_.stream_info_.metadata_.clear_filter_metadata();
  data.drain(1);

  // 3. Add 7 bytes of data.
  data.add("ab\0cd\0\0", 7);
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 7);
  filter_meta =
      read_callbacks_.connection().streamInfo().dynamicMetadata().mutable_filter_metadata()->at(
          NetworkFilterNames::get().DatabricksSqlProxy);
  fields = filter_meta.fields();
  // Expect to contain "ab" -> "cd"
  EXPECT_TRUE(fields.contains("connection_string_options"));
  EXPECT_TRUE(fields.at("connection_string_options").struct_value().fields().contains("ab"));
  EXPECT_EQ("cd",
            fields.at("connection_string_options").struct_value().fields().at("ab").string_value());
  read_callbacks_.connection_.stream_info_.metadata_.clear_filter_metadata();
  data.drain(7);

  // 4. Add 8 bytes of data with multiple null terminators.
  data.add("ab\0cd\0\0\0", 8);
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 8);
  filter_meta =
      read_callbacks_.connection().streamInfo().dynamicMetadata().mutable_filter_metadata()->at(
          NetworkFilterNames::get().DatabricksSqlProxy);
  fields = filter_meta.fields();
  // Expect to contain "ab" -> "cd"
  EXPECT_TRUE(fields.contains("connection_string_options"));
  EXPECT_TRUE(fields.at("connection_string_options").struct_value().fields().contains("ab"));
  EXPECT_EQ("cd",
            fields.at("connection_string_options").struct_value().fields().at("ab").string_value());
  read_callbacks_.connection_.stream_info_.metadata_.clear_filter_metadata();
  data.drain(8);

  // 5. Add 7 bytes of data that starts with null-terminator.
  data.add("\0ab\0cd\0", 7);
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 7);
  // We should not have anything in the metadata because outputConnectionStringToDynamicMetadata
  // should return early due to the first byte being a null terminator.
  EXPECT_FALSE(
      read_callbacks_.connection_.stream_info_.metadata_.mutable_filter_metadata()->contains(
          NetworkFilterNames::get().DatabricksSqlProxy));
  read_callbacks_.connection_.stream_info_.metadata_.clear_filter_metadata();
  data.drain(7);

  // 6. Add 7 bytes of data with multiple null terminators in between.
  data.add("ab\0\0cd\0\0", 8);
  postgres_proxy->outputConnectionStringToDynamicMetadata(data, 8);
  filter_meta =
      read_callbacks_.connection().streamInfo().dynamicMetadata().mutable_filter_metadata()->at(
          NetworkFilterNames::get().DatabricksSqlProxy);
  fields = filter_meta.fields();
  // Expect to contain "ab" -> "" and "cd" -> ""
  EXPECT_TRUE(fields.contains("connection_string_options"));
  EXPECT_TRUE(fields.at("connection_string_options").struct_value().fields().contains("ab"));
  EXPECT_EQ("",
            fields.at("connection_string_options").struct_value().fields().at("ab").string_value());
  EXPECT_TRUE(fields.at("connection_string_options").struct_value().fields().contains("cd"));
  EXPECT_EQ("",
            fields.at("connection_string_options").struct_value().fields().at("cd").string_value());
  read_callbacks_.connection_.stream_info_.metadata_.clear_filter_metadata();
  data.drain(8);
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
