#include "envoy/extensions/access_loggers/dynamic_modules/v3/dynamic_modules.pb.h"

#include "test/integration/http_integration.h"

namespace Envoy {

class DynamicModulesAccessLogIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public HttpIntegrationTest {
public:
  DynamicModulesAccessLogIntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP2, GetParam()) {
    setUpstreamProtocol(Http::CodecType::HTTP2);
  };

  void initializeWithAccessLogger() {
    TestEnvironment::setEnvVar(
        "ENVOY_DYNAMIC_MODULES_SEARCH_PATH",
        TestEnvironment::substitute(
            "{{ test_rundir }}/test/extensions/dynamic_modules/test_data/rust"),
        1);

    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          constexpr auto config = R"EOF(
name: envoy.access_loggers.dynamic_modules
typed_config:
  "@type": type.googleapis.com/envoy.extensions.access_loggers.dynamic_modules.v3.DynamicModuleAccessLog
  dynamic_module_config:
    name: access_log_integration_test
  logger_name: test_logger
  logger_config:
    "@type": type.googleapis.com/google.protobuf.StringValue
    value: test_config
)EOF";
          envoy::config::accesslog::v3::AccessLog access_log;
          TestUtility::loadFromYaml(config, access_log);
          hcm.add_access_log()->CopyFrom(access_log);
        });

    initialize();
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DynamicModulesAccessLogIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(DynamicModulesAccessLogIntegrationTest, BasicLogging) {
  initializeWithAccessLogger();

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));

  Http::TestRequestHeaderMapImpl request_headers{
      {":method", "GET"}, {":path", "/test"}, {":scheme", "http"}, {":authority", "host"}};

  auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);

  // Verify the response was received.
  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().Status()->value().getStringView());

  // The access logger was called. We can't easily verify this from the test since the logger
  // doesn't modify headers, but the test passing means the logger loaded and ran without crashing.
}

TEST_P(DynamicModulesAccessLogIntegrationTest, MultipleRequests) {
  initializeWithAccessLogger();

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));

  // Send multiple requests to verify logging works across requests.
  for (int i = 0; i < 3; i++) {
    Http::TestRequestHeaderMapImpl request_headers{
        {":method", "GET"}, {":path", "/test"}, {":scheme", "http"}, {":authority", "host"}};

    auto response = sendRequestAndWaitForResponse(request_headers, 0, default_response_headers_, 0);
    EXPECT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().Status()->value().getStringView());
  }
}

// Cover the factory's `None`-return path end-to-end: a logger_name the
// module's factory rejects must fail config load rather than crash or
// silently accept. This pins the dispatch-by-name contract introduced
// alongside `NEW_ACCESS_LOGGER_CONFIG_FUNCTION` — the factory returns
// `Option<Box<dyn AccessLoggerConfig>>`, and `None` maps to a null
// module_ptr which the loader turns into `InvalidArgumentError`.
TEST_P(DynamicModulesAccessLogIntegrationTest, UnknownLoggerNameRejectedAtConfigLoad) {
  TestEnvironment::setEnvVar(
      "ENVOY_DYNAMIC_MODULES_SEARCH_PATH",
      TestEnvironment::substitute(
          "{{ test_rundir }}/test/extensions/dynamic_modules/test_data/rust"),
      1);

  config_helper_.addConfigModifier(
      [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
             hcm) {
        constexpr auto config = R"EOF(
name: envoy.access_loggers.dynamic_modules
typed_config:
  "@type": type.googleapis.com/envoy.extensions.access_loggers.dynamic_modules.v3.DynamicModuleAccessLog
  dynamic_module_config:
    name: access_log_integration_test
  logger_name: no_such_logger
  logger_config:
    "@type": type.googleapis.com/google.protobuf.StringValue
    value: irrelevant
)EOF";
        envoy::config::accesslog::v3::AccessLog access_log;
        TestUtility::loadFromYaml(config, access_log);
        hcm.add_access_log()->CopyFrom(access_log);
      });

  // The test's Rust factory accepts only `test_logger`; every other
  // name maps to `None` and the config loader surfaces it as a
  // startup failure. `EXPECT_DEATH` / `EXPECT_THROW` shapes vary by
  // HttpIntegrationTest; `initialize()` throws `EnvoyException` on
  // config-parse failures.
  EXPECT_THROW_WITH_REGEX(initialize(), EnvoyException,
                          "Failed to initialize dynamic module access logger config");
}

} // namespace Envoy
