#include <cstdint>

#include "envoy/extensions/access_loggers/file/v3/file.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.h"
#include "envoy/extensions/transport_sockets/raw_buffer/v3/raw_buffer.pb.validate.h"
#include "envoy/service/auth/v3/external_auth.pb.h"

#include "source/common/network/connection_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/tls/client_ssl_socket.h"
#include "source/common/tls/server_context_config_impl.h"
#include "source/common/tls/server_ssl_socket.h"
#include "source/extensions/filters/common/ext_authz/ext_authz.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/integration/integration.h"
#include "test/mocks/secret/mocks.h"
#include "test/test_common/registry.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_postgres_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/test/sync_write_filter.h"
#include "contrib/databricks_sql_proxy/filters/network/test/sync_write_filter.pb.h"
#include "contrib/databricks_sql_proxy/filters/network/test/sync_write_filter.pb.validate.h"
#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.h"
#include "gtest/gtest.h"

using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;
using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;
using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;
using HandshakeState =
    Envoy::Extensions::NetworkFilters::DatabricksSqlProxy::Filter::HandshakeState;
using UpstreamHandshakeState =
    Envoy::Extensions::NetworkFilters::DatabricksSqlProxy::PostgresProxy::UpstreamHandshakeState;
using testing::MatchesRegex;

namespace Envoy {
namespace {

class DatabricksSqlProxyPostgresIntegrationTest : public Grpc::EnvoyGrpcClientIntegrationParamTest,
                                                  public BaseIntegrationTest {
public:
  DatabricksSqlProxyPostgresIntegrationTest(bool enable_upstream_tls = true)
      : BaseIntegrationTest(GetParam(), postgresConfig(enable_upstream_tls)) {}

  std::string postgresConfig(bool enable_upstream_tls) {
    return fmt::format(
        fmt::runtime(TestEnvironment::readFileToStringForTest(
            TestEnvironment::runfilesPath("contrib/databricks_sql_proxy/filters/network/test/"
                                          "postgres_integration_test_config.yaml"))),
        Platform::null_device_path,                          // admin access log path
        Network::Test::getLoopbackAddressString(GetParam()), // admin endpoint address
        Network::Test::getLoopbackAddressString(GetParam()), // upstream cluster address
        enable_upstream_tls ? upstream_tls_config : "",      // upstream tls config
        "{}",                                                // http2_protocol_options
        Network::Test::getLoopbackAddressString(GetParam()), // ext_authz-service address
        Network::Test::getAnyAddressString(GetParam()),      // listener address
        enable_upstream_tls ? "true" : "false"               // enable_upstream_tls
    );
  }

  static constexpr absl::string_view upstream_tls_config = R"EOF(transport_socket:
      name: "envoy.transport_sockets.tls"
      typed_config:
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.starttls.v3.UpstreamStartTlsConfig"
        cleartext_socket_config:
        tls_socket_config:
          common_tls_context: 
)EOF";

  static constexpr absl::string_view accesslog_config =
      "Protocol=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:protocol)% "
      "handshake_state=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:handshake_"
      "state)% "
      "upstream_handshake_state=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:"
      "upstream_handshake_state)% "
      "user=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:connection_string_options:"
      "user)% "
      "database=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:connection_string_"
      "options:database)% "
      "upstream_ip=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:upstream_ip)% "
      "cancellation_secret_key=%DYNAMIC_METADATA(envoy.filters.network.databricks_sql_proxy:"
      "cancellation_secret_key)% "
      "termination_detail=%CONNECTION_TERMINATION_DETAILS% "
      "response_code_details=%RESPONSE_CODE_DETAILS% "
      "response_flags=%RESPONSE_FLAGS% "
      "DOWNSTREAM_WIRE_BYTES_SENT=%DOWNSTREAM_WIRE_BYTES_SENT% "
      "DOWNSTREAM_WIRE_BYTES_RECEIVED=%DOWNSTREAM_WIRE_BYTES_RECEIVED% "
      "UPSTREAM_WIRE_BYTES_SENT=%UPSTREAM_WIRE_BYTES_SENT% "
      "UPSTREAM_WIRE_BYTES_RECEIVED=%UPSTREAM_WIRE_BYTES_RECEIVED%";

  void initialize() override {
    // By default, the integration test will create 1 fake upstream - fake_upstreams_[0].
    // The default upstream is used for the postgres fake upstream.
    // Add fake upstream for ext_authz service. This will be access by fake_upstreams_[1].
    setUpstreamCount(2);
    setUpstreamProtocol(Http::CodecType::HTTP2);
    BaseIntegrationTest::initialize();
  };

  // Method changes IntegrationTcpClient's transport socket to TLS.
  // Sending any traffic to newly attached TLS transport socket will trigger
  // TLS handshake negotiation.
  void enableTLSonTCPClient(const IntegrationTcpClientPtr& tcp_client) {
    // Setup factory and context for tls transport socket.
    // The tls transport socket will be inserted into fake_upstream when
    // Envoy's upstream starttls transport socket is converted to secure mode.
    std::unique_ptr<Ssl::ContextManager> tls_context_manager =
        std::make_unique<Extensions::TransportSockets::Tls::ContextManagerImpl>(
            server_factory_context_);

    envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext upstream_tls_context;
    upstream_tls_context.set_sni("brickstore.database.databricks.com");

    NiceMock<Server::Configuration::MockTransportSocketFactoryContext> mock_factory_ctx;
    ON_CALL(mock_factory_ctx.server_context_, api()).WillByDefault(testing::ReturnRef(*api_));
    auto cfg = *Extensions::TransportSockets::Tls::ClientContextConfigImpl::create(
        upstream_tls_context, mock_factory_ctx);
    static auto* client_stats_store = new Stats::TestIsolatedStoreImpl();
    Network::UpstreamTransportSocketFactoryPtr tls_context =
        Network::UpstreamTransportSocketFactoryPtr{
            *Extensions::TransportSockets::Tls::ClientSslSocketFactory::create(
                std::move(cfg), *tls_context_manager, *(client_stats_store->rootScope()))};

    Network::TransportSocketOptionsConstSharedPtr options;

    auto connection = dynamic_cast<Envoy::Network::ConnectionImpl*>(tcp_client->connection());
    Network::TransportSocketPtr ts = tls_context->createTransportSocket(
        options, connection->streamInfo().upstreamInfo()->upstreamHost());
    connection->transportSocket() = std::move(ts);
    connection->transportSocket()->setTransportSocketCallbacks(*connection);
  }

  // Method prepares TLS context to be injected to fake upstream.
  // Method creates and attaches TLS transport socket to fake upstream.
  void enableTLSOnFakeUpstream(FakeRawConnectionPtr& fake_upstream_connection) {
    // Setup factory and context for tls transport socket.
    // The tls transport socket will be inserted into fake_upstream when
    // Envoy's upstream starttls transport socket is converted to secure mode.
    std::unique_ptr<Ssl::ContextManager> tls_context_manager =
        std::make_unique<Extensions::TransportSockets::Tls::ContextManagerImpl>(
            server_factory_context_);

    envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext downstream_tls_context;

    std::string yaml_plain = R"EOF(
  common_tls_context:
    validation_context:
      trusted_ca:
        filename: "{{ test_rundir }}/test/config/integration/certs/upstreamcacert.pem"
    tls_certificates:
      certificate_chain:
        filename: "{{ test_rundir }}/test/config/integration/certs/upstreamcert.pem"
      private_key:
        filename: "{{ test_rundir }}/test/config/integration/certs/upstreamkey.pem"
)EOF";

    TestUtility::loadFromYaml(TestEnvironment::substitute(yaml_plain), downstream_tls_context);

    NiceMock<Server::Configuration::MockTransportSocketFactoryContext> mock_factory_ctx;
    ON_CALL(mock_factory_ctx.server_context_, api()).WillByDefault(testing::ReturnRef(*api_));
    auto cfg = *Extensions::TransportSockets::Tls::ServerContextConfigImpl::create(
        downstream_tls_context, mock_factory_ctx, false);
    static auto* client_stats_store = new Stats::TestIsolatedStoreImpl();
    Network::DownstreamTransportSocketFactoryPtr tls_context =
        Network::DownstreamTransportSocketFactoryPtr{
            *Extensions::TransportSockets::Tls::ServerSslSocketFactory::create(
                std::move(cfg), *tls_context_manager, *(client_stats_store->rootScope()), {})};

    Network::TransportSocketPtr ts = tls_context->createDownstreamTransportSocket();
    // Synchronization object used to suspend execution
    // until dispatcher completes transport socket conversion.
    absl::Notification notification;

    // Execute transport socket conversion to TLS on the same thread where received data
    // is dispatched. Otherwise, conversion may collide with data processing.
    fake_upstreams_[0]->dispatcher()->post([&]() {
      auto connection =
          dynamic_cast<Envoy::Network::ConnectionImpl*>(&fake_upstream_connection->connection());
      connection->transportSocket() = std::move(ts);
      connection->transportSocket()->setTransportSocketCallbacks(*connection);
      notification.Notify();
    });

    // Wait until the transport socket conversion completes.
    notification.WaitForNotification();
  }

  void setupAccesslog(std::string& access_log_path,
                      envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* tcp_proxy_config_blob = filter_chain->mutable_filters(2)->mutable_typed_config();

    ASSERT_TRUE(
        tcp_proxy_config_blob->Is<envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy>());
    auto tcp_proxy_config =
        MessageUtil::anyConvert<envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy>(
            *tcp_proxy_config_blob);

    auto* access_log = tcp_proxy_config.add_access_log();
    access_log->set_name("accesslog");
    envoy::extensions::access_loggers::file::v3::FileAccessLog access_log_config;
    access_log_config.set_path(access_log_path);
    access_log_config.mutable_log_format()->mutable_text_format_source()->set_inline_string(
        accesslog_config);
    access_log->mutable_typed_config()->PackFrom(access_log_config);
    auto* runtime_filter = access_log->mutable_filter()->mutable_runtime_filter();
    runtime_filter->set_runtime_key("unused-key");
    auto* percent_sampled = runtime_filter->mutable_percent_sampled();
    percent_sampled->set_numerator(100);
    percent_sampled->set_denominator(envoy::type::v3::FractionalPercent::DenominatorType::
                                         FractionalPercent_DenominatorType_HUNDRED);
    tcp_proxy_config_blob->PackFrom(tcp_proxy_config);
  }

  void verifyAccessLog(std::string access_log_path, const std::string& regex_format_string) {
    auto log_result = waitForAccessLog(access_log_path);
    EXPECT_THAT(log_result, MatchesRegex(regex_format_string));
  }

  Buffer::OwnedImpl createPostgresStartupMessage() {
    const std::string connection_string_options{"user\0testuser\0database\0testdb\0\0", 31};
    Buffer::OwnedImpl postgres_startup_message;
    postgres_startup_message.writeBEInt<int32_t>(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH +
                                                 connection_string_options.length());
    postgres_startup_message.writeBEInt<uint32_t>(PostgresConstants::PROTOCOL_VERSION);
    postgres_startup_message.add(connection_string_options);
    return postgres_startup_message;
  }

  void startPostgresConnectionAndSendStartupMessage(const IntegrationTcpClientPtr& client) {
    // Send SSL request message to the Envoy.
    const std::string postgres_ssl_request{PostgresConstants::POSTGRES_SSL_REQUEST_MESSAGE};
    ASSERT_TRUE(client->connected());
    ASSERT_TRUE(client->write(postgres_ssl_request));

    // Wait for envoy response to the SSL request.
    std::string ssl_support_response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);
    client->waitForData(ssl_support_response, true);
    client->clearData();

    // Switch to TLS transport socket on the client side.
    enableTLSonTCPClient(client);

    // Send postgres startup message to envoy.
    Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
    ASSERT_TRUE(client->write(postgres_startup_message.toString()));

    test_server_->waitForGaugeGe("databricks_sql_proxy.postgres_stats.buffered_first_message",
                                 PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH);
  }

  void runEndToEndTest(
      bool enable_upstream_tls,
      DatabricksSqlProxyProto::DestinationClusterSource destination_cluster_source,
      envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
          postgres_config,
      const std::string& access_log_regex_format_string);

  NiceMock<Network::MockConnectionCallbacks> upstream_callbacks_;
  Envoy::Extensions::NetworkFilters::DatabricksSqlProxy::SyncWriteFilterConfigFactory
      config_factory_{"sync", upstream_callbacks_};
  Registry::InjectFactory<Server::Configuration::NamedNetworkFilterConfigFactory>
      registered_config_factory_{config_factory_};
};

// Helper function to run postgres filter end to end
// The function will start postgres connection and send startup message.
// Then it will create ext_authz response and send it to the filter.
// It waits for the filter to establish connection with the upstream.
// If TLS with upstream is needed, it will start TLS handshake with the upstream.
// Then the client sends the next message to the filter and verifies that the upstream received the
// message.
void DatabricksSqlProxyPostgresIntegrationTest::runEndToEndTest(
    bool enable_upstream_tls,
    DatabricksSqlProxyProto::DestinationClusterSource destination_cluster_source,
    envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
        postgres_config,
    const std::string& access_log_regex_format_string) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);

    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* databricks_sql_proxy_config_blob =
        filter_chain->mutable_filters(0)->mutable_typed_config();
    ASSERT_TRUE(databricks_sql_proxy_config_blob->Is<DatabricksSqlProxyProto>());
    auto databricks_sql_proxy_config =
        MessageUtil::anyConvert<DatabricksSqlProxyProto>(*databricks_sql_proxy_config_blob);

    // Set filter handshake timeout to 1 second.
    databricks_sql_proxy_config.mutable_handshake_timeout()->set_seconds(1);
    // Set the destination
    databricks_sql_proxy_config.set_destination_cluster_source(destination_cluster_source);

    databricks_sql_proxy_config.mutable_postgres_config()->CopyFrom(postgres_config);

    databricks_sql_proxy_config_blob->PackFrom(databricks_sql_proxy_config);
  });

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));
  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  std::string ssl_support_response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);

  startPostgresConnectionAndSendStartupMessage(client);

  FakeHttpConnectionPtr fake_ext_authz_upstream_connection = nullptr;
  FakeStreamPtr ext_authz_request = nullptr;

  if (destination_cluster_source == DatabricksSqlProxyProto::SIDECAR_SERVICE) {
    // Wait for ext_authz call to be made.
    ASSERT_TRUE(fake_upstreams_[1]->waitForHttpConnection(*dispatcher_,
                                                          fake_ext_authz_upstream_connection));
    ASSERT_TRUE(
        fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));

    // Create ext_authz response
    envoy::service::auth::v3::CheckResponse check_response;
    check_response.mutable_status()->set_code(Grpc::Status::WellKnownGrpcStatus::Ok);
    std::string expected_target_cluster{"brickstore.database.databricks.com"};
    ProtobufWkt::Struct dynamic_metadata;
    ProtobufWkt::Value target_cluster_value;
    target_cluster_value.set_string_value(expected_target_cluster);
    (*check_response.mutable_dynamic_metadata()
          ->mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] = target_cluster_value;

    // Send ext_authz response.
    ext_authz_request->startGrpcStream();
    ext_authz_request->sendGrpcMessage(check_response);
    ext_authz_request->finishGrpcStream(Grpc::Status::Ok);
  }

  // Wait for postgres upstream connection to be established.
  FakeRawConnectionPtr fake_postgres_upstream_connection;
  std::string postgres_upstream_received;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_postgres_upstream_connection));

  // Move the time to test that the connection will not be closed because of timeout.
  // We set the timeout to be 1 second. So moving by 2 seconds should trigger the timeout if there
  // is a bug with the code.
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2000));

  if (enable_upstream_tls) {
    // Wait for SSL request to be sent to the upstream.
    ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(8, &postgres_upstream_received));
    ASSERT_EQ(PostgresConstants::POSTGRES_SSL_REQUEST_MESSAGE, postgres_upstream_received);
    // Now that wait for data succeeded, we can clear the buffered data that fake upstream received.
    fake_postgres_upstream_connection->clearData();

    // Reply that upstream support SSL.
    ASSERT_TRUE(fake_postgres_upstream_connection->write(ssl_support_response));
    // Wait for the upstream reply to flush from the current transport socket by
    // confirming that envoy received the reply before switching the fake upstream transport socket
    // to TLS.
    config_factory_.recv_sync_.WaitForNotification();

    enableTLSOnFakeUpstream(fake_postgres_upstream_connection);

    // Now we can signal the envoy to proceed with the TLS handshake.
    // This will forward the reply the upstream support SSL to the postgres filter.
    // After which the filter will switch the upstream to TLS and send the TLS handshake message to
    // the upstream.
    config_factory_.proceed_sync_.Notify();
  } else {
    // Explicitly set the notify flag for recv_sync_ because we want to bypass sync write filter.
    // Since we don't need to switch the transport socket to TLS.
    // Sync write filter is mainly needed for TLS handshake.
    config_factory_.recv_sync_.Notify();
  }

  // Upstream connection waits for postgres startup message from the filter.
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(postgres_startup_message.length(),
                                                             &postgres_upstream_received));
  ASSERT_EQ(postgres_startup_message.toString(), postgres_upstream_received);
  fake_postgres_upstream_connection->clearData();

  // Client send the next message.
  std::string next_message("next message");
  ASSERT_TRUE(client->write(next_message));
  // Upstream should receive the next message
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(next_message.size(),
                                                             &postgres_upstream_received));
  ASSERT_EQ(next_message, postgres_upstream_received);
  fake_postgres_upstream_connection->clearData();

  const std::string_view ip = "1.2.3.4";
  Buffer::OwnedImpl upstream_data;
  // If we need to read upstream_ip parameter status message then inject it.
  if (postgres_config.read_parameter_status_upstream_ip()) {
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

    upstream_data.add(parameter_status_message);
  }
  // Upstream always sends the backend key data message.
  Buffer::OwnedImpl backend_key_data_message;
  backend_key_data_message.writeByte(PostgresConstants::BACKEND_KEY_DATA_MESSAGE_TYPE);
  backend_key_data_message.writeBEInt<int32_t>(
      PostgresConstants::BACKEND_KEY_DATA_MESSAGE_LENGTH -
      sizeof(char));                                  // message length excluding message type
  backend_key_data_message.writeBEInt<int32_t>(1111); // process_id
  backend_key_data_message.writeBEInt<int32_t>(9876); // secret_key
  upstream_data.add(backend_key_data_message);

  ASSERT_TRUE(fake_postgres_upstream_connection->write(upstream_data.toString()));

  // At a minimum, the client should receive the backend key data message.
  ASSERT_TRUE(client->waitForData(backend_key_data_message.length()));
  std::string client_recv_data = client->data();
  Buffer::OwnedImpl client_recv_buffer;
  client_recv_buffer.add(client_recv_data);

  // If send_parameter_status_upstream_ip is set, then the client should receive the upstream_ip
  // parameter status
  if (postgres_config.send_parameter_status_upstream_ip()) {
    EXPECT_THAT(client_recv_buffer.toString(),
                testing::HasSubstr(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY));
  }

  if (postgres_config.randomize_cancellation_key()) {
    // Only compare the first 5 bytes because the rest of the data is random.
    EXPECT_THAT(client_recv_buffer.toString(), testing::HasSubstr(std::string("K\0\0\0\f", 5)));
  } else {
    EXPECT_THAT(client_recv_buffer.toString(),
                testing::HasSubstr(backend_key_data_message.toString()));
  }
  // Only copy out the cancellation_id for later use.
  std::string cancellation_id = client_recv_data.substr(client_recv_data.size() - 8);
  client->clearData();

  if (postgres_config.store_cancellation_key()) {
    if (fake_ext_authz_upstream_connection == nullptr) {
      // Wait for ext_authz call to be made.
      ASSERT_TRUE(fake_upstreams_[1]->waitForHttpConnection(*dispatcher_,
                                                            fake_ext_authz_upstream_connection));
    }

    ASSERT_TRUE(
        fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));
    // Create sidecar response
    envoy::service::auth::v3::CheckResponse check_response;
    check_response.mutable_status()->set_code(Grpc::Status::WellKnownGrpcStatus::Ok);

    // Send sidecar response.
    ext_authz_request->startGrpcStream();
    ext_authz_request->sendGrpcMessage(check_response);
    ext_authz_request->finishGrpcStream(Grpc::Status::Ok);
  }

  if (fake_ext_authz_upstream_connection != nullptr) {
    ASSERT_TRUE(fake_ext_authz_upstream_connection->close());
    ASSERT_TRUE(fake_ext_authz_upstream_connection->waitForDisconnect());
  }

  client->close();
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForDisconnect());

  // Verify the stat is incremented.
  EXPECT_EQ(
      1, test_server_->counter("databricks_sql_inspector.pg-listener.handshake_success")->value());
  EXPECT_EQ(
      0,
      test_server_->gauge("databricks_sql_proxy.postgres_stats.buffered_first_message")->value());
  EXPECT_EQ(1,
            test_server_->counter("databricks_sql_proxy.postgres_stats.successful_login")->value());

  verifyAccessLog(access_log_path, access_log_regex_format_string);
}

INSTANTIATE_TEST_SUITE_P(IpVersions, DatabricksSqlProxyPostgresIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         Grpc::EnvoyGrpcClientIntegrationParamTest::protocolTestParamsToString);

// Integration test when both downstream and upstream SSL is enabled.
// In this scenario test client establishes SSL connection to Envoy. Client sends SSL request
// message. Envoy databricks_sql_inspector filter responds with SSL support. Then the client
// switches to TLS. Next, the client sends the initial postgres startup message. The upstream
// server agrees to use SSL. The traffic is encrypted again when sent to upstream server. The test
// follows the following scenario:

// Test client                     Envoy                  Upstream
// ----- Can I use SSL? ------------>
// <------- Yes---------------------
// <------- TLS handshake ---------->
// ------ Initial postgres msg ----->
//                                    ------ Can I use SSL? --->
//                                    <------- Yes--------------
//                                    <------- TLS handshake--->
//                                    --Initial postgres msg--->
// ------ close connection --------->
//                                    ------ close connection--->
//
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, EndToEndTLSSidecarService) {
  envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
      postgres_config;
  postgres_config.set_read_parameter_status_upstream_ip(true);
  postgres_config.set_store_cancellation_key(true);
  postgres_config.set_randomize_cancellation_key(true);
  runEndToEndTest(
      true, DatabricksSqlProxyProto::SIDECAR_SERVICE, postgres_config,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=testuser "
                  "database=testdb "
                  "upstream_ip=1.2.3.4 "
                  "cancellation_secret_key=9876 "
                  "termination_detail=Local close:  "
                  "response_code_details=- "
                  "response_flags=- "
                  "DOWNSTREAM_WIRE_BYTES_SENT=39 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=59 "
                  "UPSTREAM_WIRE_BYTES_SENT=59 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=39"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::UpstreamConnected),
                  static_cast<int>(UpstreamHandshakeState::ProcessedBackendKeyData)));
}

TEST_P(DatabricksSqlProxyPostgresIntegrationTest, EndToEndTLSSni) {
  envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
      postgres_config;
  postgres_config.set_send_parameter_status_upstream_ip(true);
  runEndToEndTest(
      true, DatabricksSqlProxyProto::SNI, postgres_config,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=testuser "
                  "database=testdb "
                  "upstream_ip={} " // Because read_parameter_status_upstream_ip is not set, we are
                                    // reading the upstream ip from the connection itself.
                  "cancellation_secret_key=9876 "
                  "termination_detail=Local close:  "
                  "response_code_details=- "
                  "response_flags=- "
                  "DOWNSTREAM_WIRE_BYTES_SENT=14 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=59 "
                  "UPSTREAM_WIRE_BYTES_SENT=59 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=14"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::UpstreamConnected),
                  static_cast<int>(UpstreamHandshakeState::ProcessedBackendKeyData),
                  Network::Test::getLoopbackAddressString(version_)));
}

// Test that if we cannot finish the protocol handshake and figure upstream target cluster within
// the time limit, it results in connection termination.
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, HandshakeTimeout) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);

    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* databricks_sql_proxy_config_blob =
        filter_chain->mutable_filters(0)->mutable_typed_config();
    ASSERT_TRUE(databricks_sql_proxy_config_blob->Is<DatabricksSqlProxyProto>());
    auto databricks_sql_proxy_config =
        MessageUtil::anyConvert<DatabricksSqlProxyProto>(*databricks_sql_proxy_config_blob);

    // Set filter handshake timeout to 1 second.
    databricks_sql_proxy_config.mutable_handshake_timeout()->set_seconds(1);

    databricks_sql_proxy_config_blob->PackFrom(databricks_sql_proxy_config);
  });

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));

  // Send SSL request message to the Envoy.
  const std::string postgres_ssl_request{PostgresConstants::POSTGRES_SSL_REQUEST_MESSAGE};
  ASSERT_TRUE(client->connected());
  ASSERT_TRUE(client->write(postgres_ssl_request));

  // Wait for envoy response to the SSL request.
  std::string ssl_support_response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);
  client->waitForData(ssl_support_response, true);

  // Switch to TLS transport socket on the client side.
  enableTLSonTCPClient(client);

  Buffer::OwnedImpl postgres_startup_message;
  // Set the startup message length to be greater than actual data by 10 bytes so that the filter
  // will wait for more data.
  postgres_startup_message.writeBEInt<int32_t>(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH + 10);
  postgres_startup_message.writeBEInt<uint32_t>(PostgresConstants::PROTOCOL_VERSION);
  // Write partial startup message to the client to trigger TLS handshake.
  ASSERT_TRUE(client->write(postgres_startup_message.toString()));

  // We will not send a complete startup message to the filter. The filter will wait for more data
  // and eventually terminate the connection due to handshake timeout.
  // The timeout is set as one seconds, advance 2 seconds to trigger the timeout.
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2000));

  client->close(Network::ConnectionCloseType::NoFlush);

  EXPECT_EQ(1, test_server_->counter("databricks_sql_proxy.postgres_stats.errors")->value());
  EXPECT_EQ(
      1, test_server_->counter("databricks_sql_proxy.postgres_stats.handshake_timeout")->value());

  verifyAccessLog(
      access_log_path,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=- "
                  "database=- "
                  "upstream_ip=- "
                  "cancellation_secret_key=- "
                  "termination_detail=Protocol handshake timed out "
                  "response_code_details=- "
                  "response_flags=SI " // Stream Idle Timeout
                  "DOWNSTREAM_WIRE_BYTES_SENT=0 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=0 "
                  "UPSTREAM_WIRE_BYTES_SENT=0 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=0"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::Init),
                  static_cast<int>(UpstreamHandshakeState::Init)));
}

// Test that ext_authz call timeout results in connection termination.
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, ExtAuthzTimeout) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);

    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* databricks_sql_proxy_config_blob =
        filter_chain->mutable_filters(0)->mutable_typed_config();
    ASSERT_TRUE(databricks_sql_proxy_config_blob->Is<DatabricksSqlProxyProto>());
    auto databricks_sql_proxy_config =
        MessageUtil::anyConvert<DatabricksSqlProxyProto>(*databricks_sql_proxy_config_blob);

    // Set ext_authz timeout to 1 second.
    *databricks_sql_proxy_config.mutable_ext_authz_service()->mutable_timeout() =
        Protobuf::util::TimeUtil::MillisecondsToDuration(1000);
    databricks_sql_proxy_config_blob->PackFrom(databricks_sql_proxy_config);
  });

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));

  startPostgresConnectionAndSendStartupMessage(client);

  // Wait for ext_authz call to be made.
  FakeHttpConnectionPtr fake_ext_authz_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_ext_authz_upstream_connection));
  FakeStreamPtr ext_authz_request;
  ASSERT_TRUE(
      fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));

  // Wait to get at least CheckRequest minimum size.
  ASSERT_TRUE(
      ext_authz_request->waitForData(*dispatcher_, sizeof(envoy::service::auth::v3::CheckRequest)));

  // The timeout is set as one seconds, advance 2 seconds to trigger the timeout.
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2000));

  EXPECT_EQ(1, test_server_->counter("databricks_sql_proxy.postgres_stats.errors")->value());
  EXPECT_EQ(1,
            test_server_->counter("databricks_sql_proxy.postgres_stats.ext_authz_failed")->value());

  client->close(Network::ConnectionCloseType::NoFlush);

  verifyAccessLog(
      access_log_path,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=testuser "
                  "database=testdb "
                  "upstream_ip=- "
                  "cancellation_secret_key=- "
                  "termination_detail=Ext Authz failed "
                  "response_code_details=ext_authz_error "
                  "response_flags=UAEX " // Unauthorized external service.
                  "DOWNSTREAM_WIRE_BYTES_SENT=0 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=0 "
                  "UPSTREAM_WIRE_BYTES_SENT=0 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=0"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::ExtAuthzResponseCompleted),
                  static_cast<int>(UpstreamHandshakeState::Init)));
}

// Test that ext_authz when ext_authz return non-existent cluster, TcpProxy terminates the
// connection.
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, ExtAuthzReturnNotExistCluster) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);
  });

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));

  startPostgresConnectionAndSendStartupMessage(client);

  // Wait for ext_authz call to be made.
  FakeHttpConnectionPtr fake_ext_authz_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_ext_authz_upstream_connection));
  FakeStreamPtr ext_authz_request;
  ASSERT_TRUE(
      fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));

  // Create ext_authz response
  envoy::service::auth::v3::CheckResponse check_response;
  check_response.mutable_status()->set_code(Grpc::Status::WellKnownGrpcStatus::Ok);
  std::string expected_target_cluster{"non_existent_cluster"};
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] = target_cluster_value;

  // Send ext_authz response.
  ext_authz_request->startGrpcStream();
  ext_authz_request->sendGrpcMessage(check_response);
  ext_authz_request->finishGrpcStream(Grpc::Status::Ok);

  // No valid cluster found, so the connection should be terminated by TcpProxy.
  client->waitForDisconnect();

  verifyAccessLog(
      access_log_path,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=testuser "
                  "database=testdb "
                  "upstream_ip=- "
                  "cancellation_secret_key=- "
                  "termination_detail=Local close: NoClusterFound "
                  "response_code_details=- "
                  "response_flags=NC " // No cluster found set by TcpProxy.
                  "DOWNSTREAM_WIRE_BYTES_SENT=0 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=0 "
                  "UPSTREAM_WIRE_BYTES_SENT=0 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=0"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::CreatingUpstreamConnection),
                  static_cast<int>(UpstreamHandshakeState::Init)));
}

// Test that the filter can process and sent cancellation request to the upstream.
// The cancellation request will be sent on unencrypted connection.
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, CancellationRequest) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);

    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* databricks_sql_proxy_config_blob =
        filter_chain->mutable_filters(0)->mutable_typed_config();
    ASSERT_TRUE(databricks_sql_proxy_config_blob->Is<DatabricksSqlProxyProto>());
    auto databricks_sql_proxy_config =
        MessageUtil::anyConvert<DatabricksSqlProxyProto>(*databricks_sql_proxy_config_blob);

    // Set filter handshake timeout to 1 second.
    databricks_sql_proxy_config.mutable_handshake_timeout()->set_seconds(1);

    databricks_sql_proxy_config_blob->PackFrom(databricks_sql_proxy_config);

    // For cancellation request, we need to use raw buffer transport socket because
    // the cancel is send over unencrypted connection.
    envoy::extensions::transport_sockets::raw_buffer::v3::RawBuffer raw_buffer;
    filter_chain->mutable_transport_socket()->mutable_typed_config()->PackFrom(raw_buffer);
  });

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));

  // Try sending cancellation message to the filter.
  Buffer::OwnedImpl cancellation_message;
  cancellation_message.writeBEInt<int32_t>(PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);
  cancellation_message.writeBEInt<int32_t>(PostgresConstants::CANCEL_REQUEST_PROTOCOL_VERSION);
  cancellation_message.writeBEInt<int64_t>(0x1234567812345678);

  ASSERT_TRUE(client->connected());
  ASSERT_TRUE(client->write(cancellation_message.toString()));

  FakeHttpConnectionPtr fake_ext_authz_upstream_connection = nullptr;
  FakeStreamPtr ext_authz_request = nullptr;

  // Wait for ext_authz call to be made.
  ASSERT_TRUE(
      fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_ext_authz_upstream_connection));

  ASSERT_TRUE(
      fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));

  // Create ext_authz response
  const uint32_t process_id = 123;
  const uint32_t secret_key = 9876;
  envoy::service::auth::v3::CheckResponse check_response;
  check_response.mutable_status()->set_code(Grpc::Status::WellKnownGrpcStatus::Ok);
  std::string expected_target_cluster{"brickstore.database.databricks.com"};
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] = target_cluster_value;
  ProtobufWkt::Value upstream_ip;
  upstream_ip.set_string_value("10-20-30-40.hadron-compute.pod.cluster.local");
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::OVERRIDE_UPSTREAM_SNI_KEY] = upstream_ip;
  ProtobufWkt::Value cancellation_process_id;
  cancellation_process_id.set_number_value(process_id);
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::CANCELLATION_PROCESS_ID_KEY] = cancellation_process_id;
  ProtobufWkt::Value cancellation_secret_key;
  cancellation_secret_key.set_number_value(secret_key);
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::CANCELLATION_SECRET_KEY_KEY] = cancellation_secret_key;

  // Send ext_authz response.
  ext_authz_request->startGrpcStream();
  ext_authz_request->sendGrpcMessage(check_response);
  ext_authz_request->finishGrpcStream(Grpc::Status::Ok);

  // Wait for postgres upstream connection to be established.
  FakeRawConnectionPtr fake_postgres_upstream_connection;
  std::string postgres_upstream_received;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_postgres_upstream_connection));

  Buffer::OwnedImpl expected_cancellation_message;
  expected_cancellation_message.writeBEInt<int32_t>(
      PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);
  expected_cancellation_message.writeBEInt<int32_t>(
      PostgresConstants::CANCEL_REQUEST_PROTOCOL_VERSION);
  expected_cancellation_message.writeBEInt<int32_t>(process_id);
  expected_cancellation_message.writeBEInt<int32_t>(secret_key);

  // Verify that upstream received the cancellation message.
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(cancellation_message.length(),
                                                             &postgres_upstream_received));
  ASSERT_EQ(expected_cancellation_message.toString(), postgres_upstream_received);
  fake_postgres_upstream_connection->clearData();

  client->close(Network::ConnectionCloseType::NoFlush);

  EXPECT_EQ(
      1, test_server_->counter("databricks_sql_proxy.postgres_stats.sent_cancel_request")->value());

  verifyAccessLog(access_log_path, fmt::format("Protocol={} "
                                               "handshake_state=4 "
                                               "upstream_handshake_state=4 "
                                               "user=- "
                                               "database=- "
                                               "upstream_ip=- "
                                               "cancellation_secret_key=9876 "
                                               "termination_detail=Local close:  "
                                               "response_code_details=- "
                                               "response_flags=- "
                                               "DOWNSTREAM_WIRE_BYTES_SENT=0 "
                                               "DOWNSTREAM_WIRE_BYTES_RECEIVED=16 "
                                               "UPSTREAM_WIRE_BYTES_SENT=16 "
                                               "UPSTREAM_WIRE_BYTES_RECEIVED=0"
                                               "\r?.*",
                                               DatabricksSqlProxyProto::Protocol_Name(
                                                   DatabricksSqlProxyProto::POSTGRES),
                                               static_cast<int>(HandshakeState::Init),
                                               static_cast<int>(UpstreamHandshakeState::Init)));
}

// Test that if the upstream disconnects by sending FIN (end_stream = true) before the filter
// finishes processing backend key data message, the disconnect is propagated to the client. The
// client should be in a half-closed state.
TEST_P(DatabricksSqlProxyPostgresIntegrationTest, UpstreamDisconnectBeforePgAuthComplete) {
  std::string access_log_path = TestEnvironment::temporaryPath(
      fmt::format("access_log{}{}.txt", version_ == Network::Address::IpVersion::v4 ? "v4" : "v6",
                  TestUtility::uniqueFilename()));

  envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
      postgres_config;
  postgres_config.set_read_parameter_status_upstream_ip(true);
  postgres_config.set_store_cancellation_key(true);
  postgres_config.set_randomize_cancellation_key(true);

  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    setupAccesslog(access_log_path, bootstrap);

    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* databricks_sql_proxy_config_blob =
        filter_chain->mutable_filters(0)->mutable_typed_config();
    ASSERT_TRUE(databricks_sql_proxy_config_blob->Is<DatabricksSqlProxyProto>());
    auto databricks_sql_proxy_config =
        MessageUtil::anyConvert<DatabricksSqlProxyProto>(*databricks_sql_proxy_config_blob);

    // Set filter handshake timeout to 1 second.
    databricks_sql_proxy_config.mutable_handshake_timeout()->set_seconds(1);

    databricks_sql_proxy_config.mutable_postgres_config()->CopyFrom(postgres_config);

    databricks_sql_proxy_config_blob->PackFrom(databricks_sql_proxy_config);
  });

  // Enable half close on the fake upstream connection to test that the connection
  enableHalfClose(true);

  initialize();

  IntegrationTcpClientPtr client = makeTcpConnection(lookupPort("listener_0"));
  Buffer::OwnedImpl postgres_startup_message = createPostgresStartupMessage();
  std::string ssl_support_response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);

  startPostgresConnectionAndSendStartupMessage(client);

  FakeHttpConnectionPtr fake_ext_authz_upstream_connection = nullptr;
  FakeStreamPtr ext_authz_request = nullptr;

  // Wait for ext_authz call to be made.
  ASSERT_TRUE(
      fake_upstreams_[1]->waitForHttpConnection(*dispatcher_, fake_ext_authz_upstream_connection));
  ASSERT_TRUE(
      fake_ext_authz_upstream_connection->waitForNewStream(*dispatcher_, ext_authz_request));

  // Create ext_authz response
  envoy::service::auth::v3::CheckResponse check_response;
  check_response.mutable_status()->set_code(Grpc::Status::WellKnownGrpcStatus::Ok);
  std::string expected_target_cluster{"brickstore.database.databricks.com"};
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*check_response.mutable_dynamic_metadata()
        ->mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] = target_cluster_value;

  // Send ext_authz response.
  ext_authz_request->startGrpcStream();
  ext_authz_request->sendGrpcMessage(check_response);
  ext_authz_request->finishGrpcStream(Grpc::Status::Ok);

  // Wait for postgres upstream connection to be established.
  FakeRawConnectionPtr fake_postgres_upstream_connection;
  std::string postgres_upstream_received;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_postgres_upstream_connection));

  // Move the time to test that the connection will not be closed because of timeout.
  // We set the timeout to be 1 second. So moving by 2 seconds should trigger the timeout if there
  // is a bug with the code.
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2000));

  // Wait for SSL request to be sent to the upstream.
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(8, &postgres_upstream_received));
  ASSERT_EQ(PostgresConstants::POSTGRES_SSL_REQUEST_MESSAGE, postgres_upstream_received);
  // Now that wait for data succeeded, we can clear the buffered data that fake upstream received.
  fake_postgres_upstream_connection->clearData();

  // Reply that upstream support SSL.
  ASSERT_TRUE(fake_postgres_upstream_connection->write(ssl_support_response));
  // Wait for the upstream reply to flush from the current transport socket by
  // confirming that envoy received the reply before switching the fake upstream transport socket
  // to TLS.
  config_factory_.recv_sync_.WaitForNotification();

  enableTLSOnFakeUpstream(fake_postgres_upstream_connection);

  // Now we can signal the envoy to proceed with the TLS handshake.
  // This will forward the reply the upstream support SSL to the postgres filter.
  // After which the filter will switch the upstream to TLS and send the TLS handshake message to
  // the upstream.
  config_factory_.proceed_sync_.Notify();

  // Upstream connection waits for postgres startup message from the filter.
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(postgres_startup_message.length(),
                                                             &postgres_upstream_received));
  ASSERT_EQ(postgres_startup_message.toString(), postgres_upstream_received);
  fake_postgres_upstream_connection->clearData();

  // Client send the next message.
  std::string next_message("next message");
  ASSERT_TRUE(client->write(next_message));
  // Upstream should receive the next message
  ASSERT_TRUE(fake_postgres_upstream_connection->waitForData(next_message.size(),
                                                             &postgres_upstream_received));
  ASSERT_EQ(next_message, postgres_upstream_received);
  fake_postgres_upstream_connection->clearData();

  // Upstream is closing the connection before the handshake is complete.
  ASSERT_TRUE(fake_postgres_upstream_connection->write("", true /*end_stream*/));

  if (fake_ext_authz_upstream_connection != nullptr) {
    ASSERT_TRUE(fake_ext_authz_upstream_connection->close());
    ASSERT_TRUE(fake_ext_authz_upstream_connection->waitForDisconnect());
  }

  // Client should be in half close state because upstream send end_stream
  client->waitForHalfClose();

  ASSERT_TRUE(fake_postgres_upstream_connection->close(std::chrono::milliseconds(1000)));

  client->close();

  // Verify the stat is incremented.
  EXPECT_EQ(
      0,
      test_server_->gauge("databricks_sql_proxy.postgres_stats.buffered_first_message")->value());
  EXPECT_EQ(0,
            test_server_->counter("databricks_sql_proxy.postgres_stats.successful_login")->value());

  verifyAccessLog(access_log_path, fmt::format("Protocol={} "
                                               "handshake_state=4 "
                                               "upstream_handshake_state=2 "
                                               "user=testuser "
                                               "database=testdb "
                                               "upstream_ip=- "
                                               "cancellation_secret_key=- "
                                               "termination_detail=Remote close:  "
                                               "response_code_details=- "
                                               "response_flags=- "
                                               "DOWNSTREAM_WIRE_BYTES_SENT=1 "
                                               "DOWNSTREAM_WIRE_BYTES_RECEIVED=59 "
                                               "UPSTREAM_WIRE_BYTES_SENT=59 "
                                               "UPSTREAM_WIRE_BYTES_RECEIVED=1"
                                               "\r?.*",
                                               DatabricksSqlProxyProto::Protocol_Name(
                                                   DatabricksSqlProxyProto::POSTGRES),
                                               static_cast<int>(HandshakeState::Init),
                                               static_cast<int>(UpstreamHandshakeState::Init)));
}

class DatabricksSqlProxyPostgresIntegrationTestNoUpstreamSSL
    : public DatabricksSqlProxyPostgresIntegrationTest {
public:
  DatabricksSqlProxyPostgresIntegrationTestNoUpstreamSSL()
      : DatabricksSqlProxyPostgresIntegrationTest(false) {}
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DatabricksSqlProxyPostgresIntegrationTestNoUpstreamSSL,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         Grpc::EnvoyGrpcClientIntegrationParamTest::protocolTestParamsToString);

// Integration test when both downstream is TLS enabled but upstream does not use TLS.
// The test follows the following scenario:

// Test client                     Envoy                  Upstream
// ----- Can I use SSL? ------------>
// <------- Yes---------------------
// <------- TLS handshake ---------->
// ------ Initial postgres msg ----->
//                                    --Initial postgres msg--->
// ------ close connection --------->
//                                    ------ close connection--->
//
TEST_P(DatabricksSqlProxyPostgresIntegrationTestNoUpstreamSSL, EndToEndNoUpstreamTLS) {
  envoy::extensions::filters::network::databricks_sql_proxy::v3::PostgresRoutingConfig
      postgres_config;
  runEndToEndTest(
      false, DatabricksSqlProxyProto::SIDECAR_SERVICE, postgres_config,
      fmt::format("Protocol={} "
                  "handshake_state={} "
                  "upstream_handshake_state={} "
                  "user=testuser "
                  "database=testdb "
                  "upstream_ip={} "
                  "cancellation_secret_key=9876 "
                  "termination_detail=Local close:  "
                  "response_code_details=- "
                  "response_flags=- "
                  "DOWNSTREAM_WIRE_BYTES_SENT=13 "
                  "DOWNSTREAM_WIRE_BYTES_RECEIVED=51 "
                  "UPSTREAM_WIRE_BYTES_SENT=51 "
                  "UPSTREAM_WIRE_BYTES_RECEIVED=13"
                  "\r?.*",
                  DatabricksSqlProxyProto::Protocol_Name(DatabricksSqlProxyProto::POSTGRES),
                  static_cast<int>(HandshakeState::UpstreamConnected),
                  static_cast<int>(UpstreamHandshakeState::ProcessedBackendKeyData),
                  Network::Test::getLoopbackAddressString(version_)));
}

} // namespace
} // namespace Envoy
