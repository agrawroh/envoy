#include "test/mocks/server/factory_context.h"

#include "contrib/databricks_sql_proxy/filters/network/source/config.h"
#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.h"
#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.validate.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {
namespace {

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;

TEST(DatabricksSqlFilterConfigFactoryTest, TestCreateFactory) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  DatabricksSqlProxyConfigFactory factory;

  const std::string yaml = R"EOF(
    stat_prefix: "test"
    protocol: POSTGRES
    enable_upstream_tls: true
    destination_cluster_source: SIDECAR_SERVICE
    ext_authz_service:
        envoy_grpc:
          cluster_name: ext_authz_server
)EOF";

  DatabricksSqlProxyProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  Network::FilterFactoryCb cb;
  EXPECT_NO_THROW({ cb = factory.createFilterFactoryFromProto(proto_config, context).value(); });
  Network::MockConnection connection;
  EXPECT_CALL(connection, addFilter(_));
  cb(connection);
}

TEST(DatabricksSqlFilterConfigFactoryTest, SniDestinationClusterSource) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  DatabricksSqlProxyConfigFactory factory;

  const std::string yaml = R"EOF(
    stat_prefix: "test"
    protocol: POSTGRES
    enable_upstream_tls: true
    destination_cluster_source: SNI
)EOF";

  DatabricksSqlProxyProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  Network::FilterFactoryCb cb;
  EXPECT_NO_THROW({ cb = factory.createFilterFactoryFromProto(proto_config, context).value(); });
  Network::MockConnection connection;
  EXPECT_CALL(connection, addFilter(_));
  cb(connection);
}

TEST(DatabricksSqlFilterConfigFactoryTest, BadConfigSidecarServiceNoGrpcService) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  DatabricksSqlProxyConfigFactory factory;

  const std::string yaml = R"EOF(
    stat_prefix: "test"
    protocol: POSTGRES
    enable_upstream_tls: true
    destination_cluster_source: SIDECAR_SERVICE
)EOF";

  DatabricksSqlProxyProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  Network::FilterFactoryCb cb;
  EXPECT_THROW({ factory.createFilterFactoryFromProto(proto_config, context).value(); },
               EnvoyException);
}

} // namespace
} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
