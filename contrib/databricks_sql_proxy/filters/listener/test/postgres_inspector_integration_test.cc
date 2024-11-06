#include "test/integration/integration.h"
#include "test/mocks/secret/mocks.h"

#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "gtest/gtest.h"

using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

namespace Envoy {
namespace {

class DatabricksSqlInspectorIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public BaseIntegrationTest {
public:
  DatabricksSqlInspectorIntegrationTest()
      : BaseIntegrationTest(GetParam(),
                            ConfigHelper::baseConfig(false /* multiple_addresses */) + R"EOF(
    filter_chains:
      filters:
       -  name: envoy.filters.network.echo
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.echo.v3.Echo
)EOF") {}

  ~DatabricksSqlInspectorIntegrationTest() override = default;

  void initializeWithDatabricksSqlInspector(const std::string& log_format,
                                            const std::string& databricks_sql_inspector_config) {
    config_helper_.renameListener("databricks_sql_inspector");
    config_helper_.addListenerFilter(databricks_sql_inspector_config);

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
    std::string databricks_sql_inspector_config = R"EOF(
name: "envoy.filters.listener.databricks_sql_inspector"
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.listener.databricks_sql_inspector.v3.DatabricksSqlInspector
  stat_prefix: "test"
  protocol: POSTGRES
)EOF";

    initializeWithDatabricksSqlInspector(log_format, databricks_sql_inspector_config);

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

INSTANTIATE_TEST_SUITE_P(IpVersions, DatabricksSqlInspectorIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(DatabricksSqlInspectorIntegrationTest, PostgresInspectorSuccess) {
  setupConnections();
  std::string postgres_ssl_request("\x00\x00\x00\x08\x04\xd2\x16\x2f", 8);
  ASSERT_TRUE(client_->connected());
  ASSERT_TRUE(client_->write(postgres_ssl_request, false));

  std::string response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);
  client_->waitForData(response, true);
  client_->close(Network::ConnectionCloseType::NoFlush);
  EXPECT_THAT(waitForAccessLog(listener_access_log_name_), testing::Eq("Protocol=POSTGRES"));

  // Verify the stat is incremented.
  Stats::CounterSharedPtr counter =
      test_server_->counter("databricks_sql_inspector.test.handshake_success");
  EXPECT_EQ(1, counter->value());
}

// Test that listener timeout if we did not receive enough data to process the first handshake
// message.
TEST_P(DatabricksSqlInspectorIntegrationTest, ListenerTimeout) {
  setupConnections();
  // Send payload less than 8 bytes to force the listener to wait for more data.
  std::string postgres_ssl_request("\x00\x00\x00\x08\x04\xd2\x16", 7);
  ASSERT_TRUE(client_->connected());
  ASSERT_TRUE(client_->write(postgres_ssl_request, false));

  // The timeout is set as one seconds, advance 2 seconds to trigger the timeout.
  timeSystem().advanceTimeWaitImpl(std::chrono::milliseconds(2000));
  client_->close(Network::ConnectionCloseType::NoFlush);
  EXPECT_THAT(waitForAccessLog(listener_access_log_name_), testing::Eq("Protocol=POSTGRES"));

  // Verify the timeout counter is incremented.
  Stats::CounterSharedPtr socket_timeout_counter =
      test_server_->counter(listenerStatPrefix("downstream_pre_cx_timeout"));
  EXPECT_EQ(1, socket_timeout_counter->value());

  // Verify the stat is not incremented because timeout occurs before the handshake is
  // completed.
  Stats::CounterSharedPtr counter =
      test_server_->counter("databricks_sql_inspector.test.need_more_data");
  EXPECT_EQ(1, counter->value());
}

// Create 2 concurrent connections and verify the listener filter processes SSL request of both
// connection and the stat is incremented incorrectly.
TEST_P(DatabricksSqlInspectorIntegrationTest, TwoConcurrentConnections) {
  setupConnections();
  std::string postgres_ssl_request("\x00\x00\x00\x08\x04\xd2\x16\x2f", 8);
  ASSERT_TRUE(client_->connected());
  ASSERT_TRUE(client_->write(postgres_ssl_request, false));

  std::string response(1, PostgresConstants::POSTGRES_SUPPORT_SSL);
  client_->waitForData(response, true);

  IntegrationTcpClientPtr client_2 = makeTcpConnection(lookupPort("databricks_sql_inspector"));
  ASSERT_TRUE(client_2->connected());
  ASSERT_TRUE(client_2->write(postgres_ssl_request, false));
  client_2->waitForData(response, true);

  client_->close(Network::ConnectionCloseType::NoFlush);
  client_2->close(Network::ConnectionCloseType::NoFlush);
  EXPECT_THAT(waitForAccessLog(listener_access_log_name_),
              testing::ContainsRegex("Protocol=POSTGRES"));

  // Verify the stat is incremented.
  Stats::CounterSharedPtr counter =
      test_server_->counter("databricks_sql_inspector.test.handshake_success");
  EXPECT_EQ(2, counter->value());
}

} // namespace
} // namespace Envoy
