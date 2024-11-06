#include "envoy/extensions/filters/listener/proxy_protocol/v3/proxy_protocol.pb.h"

#include "test/integration/integration.h"
#include "test/mocks/secret/mocks.h"

#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "gtest/gtest.h"

using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;
using ConnectionCreationFunction = std::function<Envoy::Network::ClientConnectionPtr()>;

namespace Envoy {
namespace {

// Simple integration test to test that we can integrate proxy protocol filter with
// databricks_sql_inspector filter.
class DatabricksSqlInspectorProxyProtocolIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public BaseIntegrationTest {
public:
  DatabricksSqlInspectorProxyProtocolIntegrationTest()
      : BaseIntegrationTest(GetParam(),
                            ConfigHelper::baseConfig(false /* multiple_addresses */) + R"EOF(
    filter_chains:
      filters:
       -  name: envoy.filters.network.echo
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.echo.v3.Echo
)EOF") {}

  ~DatabricksSqlInspectorProxyProtocolIntegrationTest() override = default;

  void initializeWithDatabricksSqlInspector(const std::string& log_format) {

    std::string proxy_protocol_config = R"EOF(
name: envoy.listener.proxy_protocol
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol
  rules:
  - tlv_type: 2
    on_tlv_present:
      key: PP2TypeAuthority
  )EOF";

    std::string databricks_sql_inspector_config = R"EOF(
name: "envoy.filters.listener.databricks_sql_inspector"
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.listener.databricks_sql_inspector.v3.DatabricksSqlInspector
  stat_prefix: "test"
  protocol: POSTGRES
)EOF";

    config_helper_.renameListener("databricks_sql_inspector");
    // addListenerFilter() add the listener to the front of the list.
    // We need proxy protocol filter to be the first filter in the list to parse the proxy protocol
    // header, so we add it after databricks_sql_inspector filter.
    config_helper_.addListenerFilter(databricks_sql_inspector_config);
    config_helper_.addListenerFilter(proxy_protocol_config);

    // Modify listener filter timeout to 1 second.
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* timeout = bootstrap.mutable_static_resources()
                          ->mutable_listeners(0)
                          ->mutable_listener_filters_timeout();
      timeout->MergeFrom(ProtobufUtil::TimeUtil::MillisecondsToDuration(1000));
    });

    useListenerAccessLog(log_format);
    initialize();
  }

  void setupConnections(
      const std::string& log_format =
          "Protocol=%DYNAMIC_METADATA(envoy.filters.listener.databricks_sql_proxy:protocol)%") {
    initializeWithDatabricksSqlInspector(log_format);

    client_ = makeTcpConnection(lookupPort("databricks_sql_inspector"));
  }

  std::string listenerStatPrefix(const std::string& stat_name) {
    if (version_ == Network::Address::IpVersion::v4) {
      return "listener.127.0.0.1_0." + stat_name;
    }
    return "listener.[__1]_0." + stat_name;
  }

  IntegrationTcpClientPtr client_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DatabricksSqlInspectorProxyProtocolIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Basic test that we can send proxy protocol header, follow by postgres ssl request
// and postgres listener can parse postgres ssl request correctly.
TEST_P(DatabricksSqlInspectorProxyProtocolIntegrationTest, ProxyProtocolV2) {
  setupConnections("%DYNAMIC_METADATA(envoy.filters.listener.proxy_protocol:PP2TypeAuthority)%");
  ASSERT_TRUE(client_->connected());

  // Write proxy protocol Tlv to the connection.
  constexpr uint8_t buffer[] = {
      0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, // signature
      0x21, 0x11,             // version, command, address, proto
      0x00, 0x1a,             // address length
      0x01, 0x02, 0x03, 0x04, // source addr
      0x00, 0x01, 0x01, 0x02, // dest addr
      0x03, 0x05,             // soruce port
      0x00, 0x02,             // dest port
      0x00, 0x00, 0x01, 0xff, // type (1 byte), length-hi (1 byte), length-lo (1 byte), value (255)
      0x02, 0x00, 0x07, 0x66, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d}; // type (1 byte) - (0x02 =
                                                                   // PP2_TYPE_AUTHORITY), length-hi
                                                                   // (1 byte), length-lo (1 byte),
                                                                   // value (255)
  Buffer::OwnedImpl buf(buffer, sizeof(buffer));
  ASSERT_TRUE(client_->write(buf.toString(), false));

  std::string postgres_ssl_request("\x00\x00\x00\x08\x04\xd2\x16\x2f", 8);
  ASSERT_TRUE(client_->write(postgres_ssl_request, false));

  std::string response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);
  client_->waitForData(response, true);
  client_->close(Network::ConnectionCloseType::NoFlush);

  // Verify the access log that proxy protocol listener is able to parse the proxy protocol header.
  const std::string log_line = waitForAccessLog(listener_access_log_name_);
  EXPECT_EQ(log_line, "foo.com");

  // Verify databricks_sql_inspector filter stat is incremented for successful handshake.
  Stats::CounterSharedPtr counter =
      test_server_->counter("databricks_sql_inspector.test.handshake_success");
  EXPECT_EQ(1, counter->value());
}

} // namespace
} // namespace Envoy
