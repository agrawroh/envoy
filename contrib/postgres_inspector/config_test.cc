#include "source/common/protobuf/protobuf.h"

#include "test/mocks/server/listener_factory_context.h"

#include "contrib/envoy/extensions/filters/listener/postgres_inspector/v3alpha/postgres_inspector.pb.h"
#include "contrib/postgres_inspector/postgres_inspector.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Invoke;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace PostgresInspector {
namespace {

TEST(PostgresInspectorConfigFactoryTest, TestCreateFactory) {
  const std::string PostgresInspectorName = "envoy.filters.listener.postgres_inspector";
  Server::Configuration::NamedListenerFilterConfigFactory* factory = Registry::FactoryRegistry<
      Server::Configuration::NamedListenerFilterConfigFactory>::getFactory(PostgresInspectorName);

  EXPECT_EQ(factory->name(), PostgresInspectorName);

  // Test with valid proto message (stat_prefix is required to be non-empty)
  auto proto_config = std::make_unique<
      envoy::extensions::filters::listener::postgres_inspector::v3alpha::PostgresInspector>();
  proto_config->set_stat_prefix("test_postgres_inspector");

  NiceMock<Server::Configuration::MockListenerFactoryContext> context;
  EXPECT_CALL(context, scope());
  Network::ListenerFilterFactoryCb cb =
      factory->createListenerFilterFactoryFromProto(*proto_config, nullptr, context);

  Network::MockListenerFilterManager manager;
  Network::ListenerFilterPtr added_filter;
  EXPECT_CALL(manager, addAcceptFilter_(_, _))
      .WillOnce(Invoke([&added_filter](const Network::ListenerFilterMatcherSharedPtr&,
                                       Network::ListenerFilterPtr& filter) {
        added_filter = std::move(filter);
      }));
  cb(manager);

  // Make sure we actually create the correct type!
  EXPECT_NE(dynamic_cast<PostgresInspector::Filter*>(added_filter.get()), nullptr);
}

} // namespace
} // namespace PostgresInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
