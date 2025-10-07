#include "source/common/http/filter_chain_matcher/action.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {
namespace {

TEST(HttpFilterChainActionTest, ReturnsCorrectName) {
  HttpFilterChainAction action("test-chain");
  EXPECT_EQ(action.name(), "test-chain");
}

TEST(HttpFilterChainActionTest, ReturnsCorrectTypeUrl) {
  HttpFilterChainAction action("test-chain");
  EXPECT_EQ(action.typeUrl(),
            "type.googleapis.com/"
            "envoy.extensions.filters.network.http_connection_manager.v3.HttpFilterChainAction");
}

TEST(HttpFilterChainActionFactoryTest, CreatesAction) {
  NiceMock<Server::Configuration::MockServerFactoryContext> context;
  HttpFilterChainActionFactory factory;

  envoy::extensions::filters::network::http_connection_manager::v3::HttpFilterChainAction config;
  config.set_name("api-chain");

  auto action = factory.createAction(config, context, ProtobufMessage::getNullValidationVisitor());

  ASSERT_NE(action, nullptr);
  const auto* typed_action = dynamic_cast<const HttpFilterChainAction*>(action.get());
  ASSERT_NE(typed_action, nullptr);
  EXPECT_EQ(typed_action->name(), "api-chain");
}

TEST(HttpFilterChainActionFactoryTest, ReturnsCorrectName) {
  HttpFilterChainActionFactory factory;
  EXPECT_EQ(factory.name(), "envoy.matching.action.http_filter_chain");
}

TEST(HttpFilterChainActionFactoryTest, CreatesEmptyConfigProto) {
  HttpFilterChainActionFactory factory;
  auto proto = factory.createEmptyConfigProto();
  ASSERT_NE(proto, nullptr);

  const auto* typed_proto =
      dynamic_cast<const envoy::extensions::filters::network::http_connection_manager::v3::
                       HttpFilterChainAction*>(proto.get());
  EXPECT_NE(typed_proto, nullptr);
}

} // namespace
} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
