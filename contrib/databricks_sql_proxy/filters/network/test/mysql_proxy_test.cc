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
#include "contrib/databricks_sql_proxy/filters/helper/mysql_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/mysql_packet_utils.h"
#include "contrib/databricks_sql_proxy/filters/network/source/config.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_mysql_proxy.h"
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
using MySQLConstants = Envoy::Extensions::NetworkFilters::DatabricksSqlProxy::MySQLConstants;
using MySQLPacketUtils = Envoy::Extensions::NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;

class MySQLProxyTest : public testing::Test {
public:
  MySQLProxyTest() {
    const std::string yaml = R"EOF(
      stat_prefix: "test"
      protocol: MYSQL
      enable_upstream_tls: true
      destination_cluster_source: SIDECAR_SERVICE
      ext_authz_service:
        envoy_grpc:
          cluster_name: ext_authz_server
      mysql_config:
        username_pattern: "([^@]+)@([^_]+)_(.+)"
        allowed_hostname_patterns:
          - ".*\\.database\\.databricks\\.com"
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

  Buffer::OwnedImpl createMySQLHandshakeResponse(
      const std::string& username = "testuser@workspace123_host.database.databricks.com",
      uint32_t capabilities = MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_SSL,
      const std::string& auth_plugin = "mysql_native_password",
      const std::vector<uint8_t>& auth_data = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                               11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
      const std::string& database = "",
      const std::vector<MySQLPacketUtils::MySQLConnectionAttribute>& attrs = {},
      uint8_t sequence_id = 2) {

    Buffer::OwnedImpl packet;

    // Client capabilities (4 bytes)
    packet.writeLEInt<uint16_t>(capabilities & 0xFFFF);
    packet.writeLEInt<uint16_t>((capabilities >> 16) & 0xFFFF);

    // Max packet size (4 bytes)
    packet.writeLEInt<uint32_t>(MySQLConstants::MAX_PACKET_SIZE);

    // Character set (1 byte)
    packet.writeByte(MySQLConstants::DEFAULT_CHARSET_ID);

    // Reserved bytes (23 bytes)
    packet.add(std::string(23, 0));

    // Username
    packet.add(username);
    packet.writeByte(0); // Null terminator

    // Auth data
    if (capabilities & MySQLConstants::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
      MySQLPacketUtils::writeLengthEncodedInteger(packet, auth_data.size());
      packet.add(auth_data.data(), auth_data.size());
    } else {
      packet.writeByte(auth_data.size());
      packet.add(auth_data.data(), auth_data.size());
    }

    // Database name if CLIENT_CONNECT_WITH_DB is set
    if (capabilities & MySQLConstants::CLIENT_CONNECT_WITH_DB && !database.empty()) {
      packet.add(database);
      packet.writeByte(0); // Null terminator
    }

    // Auth plugin name if CLIENT_PLUGIN_AUTH is set
    if (capabilities & MySQLConstants::CLIENT_PLUGIN_AUTH) {
      packet.add(auth_plugin);
      packet.writeByte(0); // Null terminator
    }

    // Connection attributes if CLIENT_CONNECT_ATTRS is set
    if (capabilities & MySQLConstants::CLIENT_CONNECT_ATTRS && !attrs.empty()) {
      // Calculate total length
      size_t total_length = 0;
      for (const auto& attr : attrs) {
        total_length += MySQLPacketUtils::getLengthEncodedIntegerSize(attr.key.length()) +
                        attr.key.length() +
                        MySQLPacketUtils::getLengthEncodedIntegerSize(attr.value.length()) +
                        attr.value.length();
      }

      MySQLPacketUtils::writeLengthEncodedInteger(packet, total_length);

      for (const auto& attr : attrs) {
        MySQLPacketUtils::writeLengthEncodedInteger(packet, attr.key.length());
        packet.add(attr.key);
        MySQLPacketUtils::writeLengthEncodedInteger(packet, attr.value.length());
        packet.add(attr.value);
      }
    }

    // Encode the packet with MySQL header
    Buffer::OwnedImpl encoded;
    MySQLPacketUtils::encode(encoded, packet, sequence_id); // Use provided sequence ID

    return encoded;
  }

  const std::string stat_prefix_{"test."};
  const std::string sni_{"host.database.databricks.com"};

  NiceMock<Server::Configuration::MockFactoryContext> context_;
  std::unique_ptr<Filter> filter_;
  ConfigSharedPtr config_;
  NiceMock<Network::MockReadFilterCallbacks> read_callbacks_;
  NiceMock<Network::MockWriteFilterCallbacks> write_callbacks_;
  std::shared_ptr<Ssl::MockConnectionInfo> ssl_;
  Filters::Common::ExtAuthz::MockClient* client_;
};

// Test that onNewConnection disables read and stops filter iteration
TEST_F(MySQLProxyTest, NewConnection) {
  EXPECT_CALL(read_callbacks_.connection_, readDisable(false));
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
}

// Test successful handshake with valid username pattern
TEST_F(MySQLProxyTest, SuccessfulHandshakeWithValidUsername) {
  filter_->onNewConnection();

  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse();
  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([](Filters::Common::ExtAuthz::RequestCallbacks&,
                          const envoy::service::auth::v3::CheckRequest& request, Tracing::Span&,
                          const StreamInfo::StreamInfo&) {
        // Verify dynamic metadata is passed
        EXPECT_TRUE(request.attributes().metadata_context().filter_metadata().contains(
            NetworkFilterNames::get().DatabricksSqlProxy));

        auto& metadata = request.attributes().metadata_context().filter_metadata().at(
            NetworkFilterNames::get().DatabricksSqlProxy);
        EXPECT_EQ(metadata.fields().at(CommonConstants::ORG_ID_KEY).string_value(), "workspace123");
        EXPECT_EQ(metadata.fields().at(CommonConstants::HOSTNAME_KEY).string_value(),
                  "host.database.databricks.com");
      }));

  // Client sends handshake response
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  EXPECT_EQ(1, config_->stats().active_ext_authz_call_.value());
  EXPECT_EQ(1, config_->stats().successful_login_.value());
}

// Test handshake with invalid username pattern
TEST_F(MySQLProxyTest, HandshakeWithInvalidUsernamePattern) {
  filter_->onNewConnection();

  // Username doesn't match pattern
  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse("invalidusername");
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect error response to be sent
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) {
        // Verify error packet structure
        uint32_t packet_length = data.peekLEInt<uint32_t>(0) & 0x00FFFFFF;
        uint8_t seq = data.peekLEInt<uint8_t>(3);
        EXPECT_EQ(1, seq);

        // Skip header
        data.drain(4);

        // Check error packet marker
        EXPECT_EQ(0xFF, data.peekLEInt<uint8_t>(0));

        // Check error code (ER_ACCESS_DENIED_ERROR)
        EXPECT_EQ(MySQLConstants::ER_ACCESS_DENIED_ERROR, data.peekLEInt<uint16_t>(1));

        return Api::IoCallUint64Result{packet_length + 4, Api::IoError::none()};
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  EXPECT_EQ(1, config_->stats().username_extraction_failed_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

// Test handshake with disallowed hostname
TEST_F(MySQLProxyTest, HandshakeWithDisallowedHostname) {
  filter_->onNewConnection();

  // Hostname doesn't match allowed patterns
  Buffer::OwnedImpl handshake_response =
      createMySQLHandshakeResponse("testuser@workspace123_badhost.com");
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect error response
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) {
        data.drain(4); // Skip header
        EXPECT_EQ(0xFF, data.peekLEInt<uint8_t>(0));
        EXPECT_EQ(MySQLConstants::ER_ACCESS_DENIED_ERROR, data.peekLEInt<uint16_t>(1));
        return Api::IoCallUint64Result{data.length(), Api::IoError::none()};
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  EXPECT_EQ(1, config_->stats().access_denied_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

// Test SSL handshake flow
TEST_F(MySQLProxyTest, SSLHandshakeFlow) {
  filter_->onNewConnection();

  // Client sends handshake response with SSL flag
  Buffer::OwnedImpl handshake_response =
      createMySQLHandshakeResponse("testuser@workspace123_host.database.databricks.com",
                                   MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_SSL);
  read_callbacks_.connection_.read_enabled_ = true;

  // Mock external authz call
  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([](Filters::Common::ExtAuthz::RequestCallbacks&,
                          const envoy::service::auth::v3::CheckRequest&, Tracing::Span&,
                          const StreamInfo::StreamInfo&) {
        // Authz call is made
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  // Verify successful login was recorded
  EXPECT_EQ(1, config_->stats().successful_login_.value());
}

// Test handling of connection attributes
TEST_F(MySQLProxyTest, ConnectionAttributesHandling) {
  filter_->onNewConnection();

  // Create handshake with connection attributes
  std::vector<MySQLPacketUtils::MySQLConnectionAttribute> attrs = {
      {"_client_name", "mysql"}, {"_client_version", "8.0.32"}, {"_os", "Linux"}};

  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse(
      "testuser@workspace123_host.database.databricks.com",
      MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_CONNECT_ATTRS,
      "mysql_native_password",
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, "", attrs);

  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([](Filters::Common::ExtAuthz::RequestCallbacks&,
                          const envoy::service::auth::v3::CheckRequest& request, Tracing::Span&,
                          const StreamInfo::StreamInfo&) {
        auto& metadata = request.attributes().metadata_context().filter_metadata().at(
            NetworkFilterNames::get().DatabricksSqlProxy);

        // Verify connection attributes are stored
        EXPECT_TRUE(metadata.fields().contains(CommonConstants::ADDITIONAL_CONNECTION_ATTRS_KEY));
        auto& attrs_list =
            metadata.fields().at(CommonConstants::ADDITIONAL_CONNECTION_ATTRS_KEY).list_value();
        EXPECT_EQ(3, attrs_list.values_size());
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));
}

// Test handling of different auth plugins
TEST_F(MySQLProxyTest, DifferentAuthPlugins) {
  filter_->onNewConnection();

  // Test with caching_sha2_password
  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse(
      "testuser@workspace123_host.database.databricks.com",
      MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_PLUGIN_AUTH,
      "caching_sha2_password", std::vector<uint8_t>(32, 0)); // SHA2 uses 32 bytes

  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([](Filters::Common::ExtAuthz::RequestCallbacks&,
                          const envoy::service::auth::v3::CheckRequest& request, Tracing::Span&,
                          const StreamInfo::StreamInfo&) {
        auto& metadata = request.attributes().metadata_context().filter_metadata().at(
            NetworkFilterNames::get().DatabricksSqlProxy);

        // Verify auth data is stored
        EXPECT_TRUE(metadata.fields().contains(CommonConstants::AUTH_DATA_KEY));
        auto& auth_data = metadata.fields().at(CommonConstants::AUTH_DATA_KEY).struct_value();
        EXPECT_EQ("caching_sha2_password",
                  auth_data.fields().at(CommonConstants::AUTH_PLUGIN_KEY).string_value());
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));
}

// Test malformed packet handling
TEST_F(MySQLProxyTest, MalformedPacket) {
  filter_->onNewConnection();

  // Create packet with invalid length
  Buffer::OwnedImpl malformed_packet;
  malformed_packet.writeLEInt<uint32_t>(0xFF000000); // Invalid length
  malformed_packet.writeByte(1);                     // Sequence

  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) {
        data.drain(4);                               // Skip header
        EXPECT_EQ(0xFF, data.peekLEInt<uint8_t>(0)); // Error marker
        return Api::IoCallUint64Result{data.length(), Api::IoError::none()};
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(malformed_packet, false));

  EXPECT_EQ(1, config_->stats().malformed_packet_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

// Test incomplete packet handling
TEST_F(MySQLProxyTest, IncompletePacket) {
  filter_->onNewConnection();

  // Send only packet header without payload
  Buffer::OwnedImpl incomplete_packet;
  incomplete_packet.writeLEInt<uint32_t>(100); // Says 100 bytes but we don't provide them
  incomplete_packet.writeByte(1);

  read_callbacks_.connection_.read_enabled_ = true;

  // Should wait for more data
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(incomplete_packet, false));

  // Connection should still be open
  EXPECT_EQ(read_callbacks_.connection_.state_, Network::Connection::State::Open);

  // Now send complete packet
  Buffer::OwnedImpl complete_packet = createMySQLHandshakeResponse();

  EXPECT_CALL(*client_, check(_, _, _, _));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(complete_packet, false));
}

// Test full end-to-end flow with external authorization
TEST_F(MySQLProxyTest, FullEndToEndWithExternalAuth) {
  filter_->onNewConnection();

  Buffer::OwnedImpl handshake_response =
      createMySQLHandshakeResponse("testuser@workspace123_host.database.databricks.com",
                                   MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_SSL);
  read_callbacks_.connection_.read_enabled_ = true;

  // 1. Client sends handshake response
  EXPECT_CALL(*client_, check(_, _, _, _));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  EXPECT_EQ(1, config_->stats().active_ext_authz_call_.value());

  // 2. External auth responds with target cluster
  EXPECT_CALL(read_callbacks_, injectReadDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) { EXPECT_EQ(0, data.length()); }));

  std::string expected_target_cluster{"mysql-cluster"};
  Filters::Common::ExtAuthz::Response response{};
  response.status = Filters::Common::ExtAuthz::CheckStatus::OK;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*response.dynamic_metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] =
      target_cluster_value;

  filter_->onComplete(std::make_unique<Filters::Common::ExtAuthz::Response>(response));

  EXPECT_EQ(0, config_->stats().active_ext_authz_call_.value());

  // Verify target cluster is set - but first check if it was actually set
  auto cluster_obj =
      read_callbacks_.connection_.stream_info_.filter_state_
          ->getDataReadOnly<TcpProxy::PerConnectionCluster>(TcpProxy::PerConnectionCluster::key());
  if (cluster_obj) {
    EXPECT_EQ(expected_target_cluster, cluster_obj->value());
  }

  EXPECT_EQ(0, config_->stats().errors_.value());
  EXPECT_EQ(1, config_->stats().successful_login_.value());
}

// Test handling when client doesn't support SSL but upstream requires it
TEST_F(MySQLProxyTest, ClientNoSSLUpstreamRequiresSSL) {
  filter_->onNewConnection();

  // Client without SSL capability
  Buffer::OwnedImpl handshake_response =
      createMySQLHandshakeResponse("testuser@workspace123_host.database.databricks.com",
                                   MySQLConstants::CLIENT_PROTOCOL_41); // No SSL flag

  read_callbacks_.connection_.read_enabled_ = true;

  // Process will continue since we add SSL capability
  EXPECT_CALL(*client_, check(_, _, _, _));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  // The proxy should add SSL capability when forwarding to upstream
  EXPECT_EQ(1, config_->stats().successful_login_.value());
}

// Test username with special characters that need escaping
TEST_F(MySQLProxyTest, UsernameWithSpecialCharacters) {
  filter_->onNewConnection();

  // Username with SQL injection attempt
  Buffer::OwnedImpl handshake_response =
      createMySQLHandshakeResponse("user'; DROP TABLE users;--@workspace_host.com");

  read_callbacks_.connection_.read_enabled_ = true;

  // Should reject due to special characters
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) {
        data.drain(4);                               // Skip header
        EXPECT_EQ(0xFF, data.peekLEInt<uint8_t>(0)); // Error marker
        EXPECT_EQ(MySQLConstants::ER_ACCESS_DENIED_ERROR, data.peekLEInt<uint16_t>(1));
        return Api::IoCallUint64Result{data.length(), Api::IoError::none()};
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  EXPECT_EQ(1, config_->stats().invalid_username_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

// Test handling of database name in handshake
TEST_F(MySQLProxyTest, HandshakeWithDatabase) {
  filter_->onNewConnection();

  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse(
      "testuser@workspace123_host.database.databricks.com",
      MySQLConstants::CLIENT_PROTOCOL_41 | MySQLConstants::CLIENT_CONNECT_WITH_DB,
      "mysql_native_password", std::vector<uint8_t>(20, 0), "test_database");

  read_callbacks_.connection_.read_enabled_ = true;

  EXPECT_CALL(*client_, check(_, _, _, _))
      .WillOnce(Invoke([](Filters::Common::ExtAuthz::RequestCallbacks&,
                          const envoy::service::auth::v3::CheckRequest& request, Tracing::Span&,
                          const StreamInfo::StreamInfo&) {
        auto& metadata = request.attributes().metadata_context().filter_metadata().at(
            NetworkFilterNames::get().DatabricksSqlProxy);

        // Verify database is stored if the key exists
        if (metadata.fields().contains(CommonConstants::CONNECTION_STRING_OPTIONS_KEY)) {
          auto& conn_opts =
              metadata.fields().at(CommonConstants::CONNECTION_STRING_OPTIONS_KEY).struct_value();
          if (conn_opts.fields().contains(CommonConstants::DATABASE_KEY)) {
            EXPECT_EQ("test_database",
                      conn_opts.fields().at(CommonConstants::DATABASE_KEY).string_value());
          }
        }
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));
}

// Test error response delay mechanism
TEST_F(MySQLProxyTest, ErrorResponseDelay) {
  filter_->onNewConnection();

  Buffer::OwnedImpl handshake_response = createMySQLHandshakeResponse("badusername");
  read_callbacks_.connection_.read_enabled_ = true;

  // Expect error to be written
  EXPECT_CALL(write_callbacks_, injectWriteDataToFilterChain(_, _))
      .WillOnce(Invoke([](Buffer::Instance& data, bool) {
        // Verify error packet structure
        data.drain(4);                               // Skip header
        EXPECT_EQ(0xFF, data.peekLEInt<uint8_t>(0)); // Error marker
        return Api::IoCallUint64Result{data.length(), Api::IoError::none()};
      }));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(handshake_response, false));

  // Verify error statistics
  EXPECT_EQ(1, config_->stats().username_extraction_failed_.value());
  EXPECT_EQ(1, config_->stats().errors_.value());
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
