#include "source/common/http/filter_chain_matcher/inputs.h"

#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

using testing::NiceMock;
using testing::ReturnRef;

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {
namespace {

// Test factory names and basic factory creation.
TEST(HttpRequestHeaderInputFactoryTest, BasicFactory) {
  HttpRequestHeaderInputFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.inputs.http_request_header");

  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);
}

TEST(HttpRequestMethodInputFactoryTest, BasicFactory) {
  HttpRequestMethodInputFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.inputs.http_request_method");

  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);
}

TEST(HttpRequestPathInputFactoryTest, BasicFactory) {
  HttpRequestPathInputFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.inputs.http_request_path");

  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);
}

TEST(HttpRequestMetadataInputFactoryTest, BasicFactory) {
  HttpRequestMetadataInputFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.inputs.http_request_metadata");

  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);
}

TEST(HttpRequestFilterStateInputFactoryTest, BasicFactory) {
  HttpRequestFilterStateInputFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.inputs.http_request_filter_state");

  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);
}

// Test that factories can create data input callbacks.
TEST(HttpRequestHeaderInputFactoryTest, CreatesDataInputCallback) {
  HttpRequestHeaderInputFactory factory;
  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestHeaderMatchInput
      config;
  config.set_header_name("x-test-header");

  auto callback =
      factory.createDataInputFactoryCb(config, ProtobufMessage::getNullValidationVisitor());
  EXPECT_NE(callback, nullptr);

  // Verify we can create an input from the callback.
  auto input = callback();
  EXPECT_NE(input, nullptr);
}

TEST(HttpRequestMetadataInputFactoryTest, CreatesDataInputCallback) {
  HttpRequestMetadataInputFactory factory;
  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestMetadataMatchInput
      config;
  config.mutable_metadata_key()->set_key("test.filter");
  config.mutable_metadata_key()->add_path()->set_key("metadata_key");

  auto callback =
      factory.createDataInputFactoryCb(config, ProtobufMessage::getNullValidationVisitor());
  EXPECT_NE(callback, nullptr);

  auto input = callback();
  EXPECT_NE(input, nullptr);
}

TEST(HttpRequestFilterStateInputFactoryTest, CreatesDataInputCallback) {
  HttpRequestFilterStateInputFactory factory;
  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestFilterStateMatchInput
      config;
  config.set_key("test_key");

  auto callback =
      factory.createDataInputFactoryCb(config, ProtobufMessage::getNullValidationVisitor());
  EXPECT_NE(callback, nullptr);

  auto input = callback();
  EXPECT_NE(input, nullptr);
}

} // namespace
} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
