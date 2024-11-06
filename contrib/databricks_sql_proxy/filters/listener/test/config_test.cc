#include "test/mocks/server/factory_context.h"

#include "contrib/databricks_sql_proxy/filters/listener/source/config.h"
#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.h"
#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.validate.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {
namespace {

TEST(DatabricksSqlFilterConfigFactoryTest, TestCreateFactory) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  DatabricksSqlInspectorConfigFactory factory;

  const std::string yaml = R"EOF(
    stat_prefix: "test"
    protocol: POSTGRES
)EOF";

  ProtobufTypes::MessagePtr proto_config = factory.createEmptyConfigProto();
  TestUtility::loadFromYaml(yaml, *proto_config);

  Network::ListenerFilterFactoryCb cb =
      factory.createListenerFilterFactoryFromProto(*proto_config, nullptr, context);
  Network::MockListenerFilterManager manager;
  Network::ListenerFilterPtr added_filter;
  EXPECT_CALL(manager, addAcceptFilter_(_, _))
      .WillOnce(Invoke([&added_filter](const Network::ListenerFilterMatcherSharedPtr&,
                                       Network::ListenerFilterPtr& filter) {
        added_filter = std::move(filter);
      }));
  cb(manager);
}

} // namespace
} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
