#include <string>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/extensions/access_loggers/file/v3/file.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"

#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"

#include "test/integration/http_integration.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace {

class CelStringExtensionsIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public HttpIntegrationTest {
public:
  CelStringExtensionsIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, GetParam()) {
    // Create a temp file for access logs
    access_log_path_ = TestEnvironment::temporaryPath(TestUtility::uniqueFilename());
  }

  void initialize() override {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // Enable CEL string extensions
      auto* cel_options = bootstrap.mutable_cel_extension_options();
      cel_options->set_enable_string_extensions(true);

      // Configure access log with CEL formatters for string transformations
      configureAccessLog(bootstrap);
    });

    HttpIntegrationTest::initialize();
  }

  void configureAccessLog(envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    // Get the HTTP connection manager
    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* hcm_filter = filter_chain->mutable_filters(0);
    auto* hcm = hcm_filter->mutable_typed_config()
                    ->MutableAs<envoy::extensions::filters::network::http_connection_manager::v3::
                                    HttpConnectionManager>();

    // Configure access logs with various CEL string transformations
    auto* access_log = hcm->add_access_log();
    access_log->set_name("envoy.access_loggers.file");

    envoy::extensions::access_loggers::file::v3::FileAccessLog file_access_log;
    file_access_log.set_path(access_log_path_);

    // Add multiple CEL format strings to test different string functions
    envoy::config::core::v3::SubstitutionFormatString format_string;
    auto* formatters = format_string.add_formatters();
    formatters->set_name("envoy.formatter.cel");

    // Configure CEL formatter with string extensions
    auto* typed_config = formatters->mutable_typed_config();
    typed_config->set_type_url("type.googleapis.com/envoy.extensions.formatter.cel.v3.Cel");

    // Protocol to lowercase test
    format_string.mutable_text_format_source()->set_inline_string(
        "PROTOCOL_LOWER:%CEL(request.protocol.lowerAscii())%;");

    // Protocol to uppercase test
    formatters = format_string.add_formatters();
    formatters->set_name("envoy.formatter.cel");
    typed_config = formatters->mutable_typed_config();
    typed_config->set_type_url("type.googleapis.com/envoy.extensions.formatter.cel.v3.Cel");
    absl::StrAppend(format_string.mutable_text_format_source()->mutable_inline_string(),
                    "PROTOCOL_UPPER:%CEL(request.protocol.upperAscii())%;");

    // User-Agent header to lowercase test
    formatters = format_string.add_formatters();
    formatters->set_name("envoy.formatter.cel");
    typed_config = formatters->mutable_typed_config();
    typed_config->set_type_url("type.googleapis.com/envoy.extensions.formatter.cel.v3.Cel");
    absl::StrAppend(format_string.mutable_text_format_source()->mutable_inline_string(),
                    "UA_LOWER:%CEL(request.headers['user-agent'].lowerAscii())%\n");

    file_access_log.mutable_log_format()->MergeFrom(format_string);
    access_log->mutable_typed_config()->PackFrom(file_access_log);
  }

  std::string getAccessLog() {
    // Read the entire access log
    return TestEnvironment::readFileToStringForTest(access_log_path_);
  }

protected:
  std::string access_log_path_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CelStringExtensionsIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CelStringExtensionsIntegrationTest, CelStringTransformations) {
  initialize();

  // Send a request with a custom user-agent header
  Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                         {":path", "/"},
                                         {":scheme", "http"},
                                         {":authority", "host"},
                                         {"user-agent", "Envoy-Test-Client"}};

  // Send request
  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

  // Check we got a valid response
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());

  // Verify access log has correctly transformed strings
  std::string log = getAccessLog();

  // HTTP/1.1 should be transformed to lowercase and uppercase versions
  EXPECT_THAT(log, testing::HasSubstr("PROTOCOL_LOWER:http/1.1"));
  EXPECT_THAT(log, testing::HasSubstr("PROTOCOL_UPPER:HTTP/1.1"));

  // User-agent should be transformed to lowercase
  EXPECT_THAT(log, testing::HasSubstr("UA_LOWER:envoy-test-client"));

  // Clean up
  cleanupUpstreamAndDownstream();
}

} // namespace
} // namespace Envoy
