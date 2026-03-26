#include "envoy/extensions/transport_sockets/dynamic_modules/v3/dynamic_modules.pb.h"

#include "test/integration/integration.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

namespace Envoy {

class DynamicModulesTransportSocketIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public BaseIntegrationTest {
public:
  DynamicModulesTransportSocketIntegrationTest()
      : BaseIntegrationTest(GetParam(), ConfigHelper::tcpProxyConfig()) {
    skip_tag_extraction_rule_check_ = true;
    enableHalfClose(true);
  }

  void initializeTransportSocket(const std::string& module_name, const std::string& search_path) {
    TestEnvironment::setEnvVar("ENVOY_DYNAMIC_MODULES_SEARCH_PATH",
                               TestEnvironment::substitute(search_path), 1);

    config_helper_.addConfigModifier(
        [module_name](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
          auto* filter_chain = listener->mutable_filter_chains(0);

          envoy::extensions::transport_sockets::dynamic_modules::v3::
              DynamicModuleDownstreamTransportSocket dm_ts_config;
          dm_ts_config.mutable_dynamic_module_config()->set_name(module_name);
          dm_ts_config.set_socket_name("test");

          auto* ts = filter_chain->mutable_transport_socket();
          ts->set_name("envoy.transport_sockets.dynamic_modules");
          ts->mutable_typed_config()->PackFrom(dm_ts_config);
        });

    BaseIntegrationTest::initialize();
  }

  void initializeCTransportSocket(const std::string& module_name) {
    initializeTransportSocket(module_name,
                              "{{ test_rundir }}/test/extensions/dynamic_modules/test_data/c");
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DynamicModulesTransportSocketIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Verifies that a passthrough transport socket module can forward TCP data in both directions.
TEST_P(DynamicModulesTransportSocketIntegrationTest, PassThrough) {
  initializeCTransportSocket("transport_socket_no_op");

  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("listener_0"));
  ASSERT_TRUE(tcp_client->connected());

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(tcp_client->write("hello", false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->write("world"));
  tcp_client->waitForData("world");

  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  tcp_client->waitForHalfClose();
  tcp_client->close();
}

// Verifies that large payloads are forwarded correctly through the passthrough transport socket.
TEST_P(DynamicModulesTransportSocketIntegrationTest, LargeData) {
  initializeCTransportSocket("transport_socket_no_op");

  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("listener_0"));
  ASSERT_TRUE(tcp_client->connected());

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  const std::string large_payload(1024 * 64, 'x');
  ASSERT_TRUE(tcp_client->write(large_payload, false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(large_payload.size()));

  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  tcp_client->waitForHalfClose();
  tcp_client->close();
}

} // namespace Envoy
