#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace HttpConnectionManager {
namespace {

// Test that http_filter_chains field exists and can be populated.
TEST(HttpFilterChainMatcherConfigTest, HttpFilterChainsFieldExists) {
  envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager config;

  // Add a named filter chain.
  auto* chain = config.add_http_filter_chains();
  chain->set_name("test-chain");

  EXPECT_EQ(config.http_filter_chains_size(), 1);
  EXPECT_EQ(config.http_filter_chains(0).name(), "test-chain");
}

// Test that http_filter_chain_matcher field exists and can be populated.
TEST(HttpFilterChainMatcherConfigTest, HttpFilterChainMatcherFieldExists) {
  envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager config;

  // Set a matcher.
  config.mutable_http_filter_chain_matcher();

  EXPECT_TRUE(config.has_http_filter_chain_matcher());
}

// Test that the new input protos exist and can be created.
TEST(HttpFilterChainMatcherConfigTest, InputProtosExist) {
  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestHeaderMatchInput
      header_input;
  header_input.set_header_name("x-test");
  EXPECT_EQ(header_input.header_name(), "x-test");

  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestMethodMatchInput
      method_input;
  EXPECT_TRUE(method_input.IsInitialized());

  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestPathMatchInput
      path_input;
  EXPECT_TRUE(path_input.IsInitialized());

  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestMetadataMatchInput
      metadata_input;
  metadata_input.mutable_metadata_key()->set_key("test");
  metadata_input.mutable_metadata_key()->add_path()->set_key("key");
  EXPECT_EQ(metadata_input.metadata_key().key(), "test");

  envoy::extensions::filters::network::http_connection_manager::v3::HttpRequestFilterStateMatchInput
      filter_state_input;
  filter_state_input.set_key("test_key");
  EXPECT_EQ(filter_state_input.key(), "test_key");
}

// Test that the action proto exists and can be created.
TEST(HttpFilterChainMatcherConfigTest, ActionProtoExists) {
  envoy::extensions::filters::network::http_connection_manager::v3::HttpFilterChainAction action;
  action.set_name("test-chain");
  EXPECT_EQ(action.name(), "test-chain");
}

// Test that a complete matcher configuration can be created.
TEST(HttpFilterChainMatcherConfigTest, CompleteMatcherConfiguration) {
  envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager config;

  // Add named filter chains.
  auto* chain1 = config.add_http_filter_chains();
  chain1->set_name("api-chain");

  auto* chain2 = config.add_http_filter_chains();
  chain2->set_name("admin-chain");

  // Configure matcher.
  auto* matcher = config.mutable_http_filter_chain_matcher();
  auto* matcher_tree = matcher->mutable_matcher_tree();

  // Set input.
  auto* input = matcher_tree->mutable_input();
  input->set_name("envoy.matching.inputs.http_request_path");
  input->mutable_typed_config()->PackFrom(
      envoy::extensions::filters::network::http_connection_manager::v3::
          HttpRequestPathMatchInput());

  // Add a match.
  auto& map = *matcher_tree->mutable_prefix_match_map()->mutable_map();
  auto* on_match = &map["/api"];
  auto* action = on_match->mutable_action();
  action->set_name("envoy.matching.action.http_filter_chain");

  envoy::extensions::filters::network::http_connection_manager::v3::HttpFilterChainAction
      action_config;
  action_config.set_name("api-chain");
  action->mutable_typed_config()->PackFrom(action_config);

  // Verify the configuration is complete.
  EXPECT_EQ(config.http_filter_chains_size(), 2);
  EXPECT_TRUE(config.has_http_filter_chain_matcher());
  EXPECT_TRUE(config.http_filter_chain_matcher().has_matcher_tree());
  EXPECT_TRUE(config.http_filter_chain_matcher().matcher_tree().has_prefix_match_map());
}

} // namespace
} // namespace HttpConnectionManager
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
