#include "contrib/databricks_sql_proxy/filters/network/source/config.h"

#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/common/config/utility.h"
#include "source/extensions/filters/common/ext_authz/ext_authz_grpc_impl.h"

#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

// envoy.extensions.filters.network.databricks_sql_proxy.v3
/**
 * Config registration for the Postgres proxy filter. @see NamedNetworkFilterConfigFactory.
 */
Network::FilterFactoryCb DatabricksSqlProxyConfigFactory::createFilterFactoryFromProtoTyped(
    const DatabricksSqlProxyProto& proto_config, Server::Configuration::FactoryContext& context) {

  ASSERT(!proto_config.stat_prefix().empty());

  const std::string stat_prefix =
      fmt::format("databricks_sql_proxy.{}", proto_config.stat_prefix());

  if (proto_config.destination_cluster_source() == DatabricksSqlProxyProto::SIDECAR_SERVICE) {
    // If we are using sidecar to determine the target cluster, we need to make sure grpc service is
    // configured.
    if (!proto_config.has_ext_authz_service()) {
      throw EnvoyException(
          "databricks_sql_proxy: ext_authz_service must be configured when using sidecar service.");
    }
  }

  ConfigSharedPtr filter_config(std::make_shared<Config>(proto_config, context, stat_prefix));

  const uint32_t timeout_ms =
      PROTOBUF_GET_MS_OR_DEFAULT(proto_config.ext_authz_service(), timeout,
                                 DatabricksSqlProxyConfigFactory::DEFAULT_EXT_AUTH_TIMEOUT_MS);

  return [filter_config, timeout_ms, &context,
          ext_authz_service =
              proto_config.ext_authz_service()](Network::FilterManager& filter_manager) -> void {
    std::unique_ptr<Filters::Common::ExtAuthz::GrpcClientImpl> ext_authz_client = nullptr;
    if (filter_config->destinationClusterSource() == DatabricksSqlProxyProto::SIDECAR_SERVICE) {
      // Create gRPC client.
      auto factory_or_error = context.serverFactoryContext()
                                  .clusterManager()
                                  .grpcAsyncClientManager()
                                  .factoryForGrpcService(ext_authz_service, context.scope(), true);
      THROW_IF_NOT_OK_REF(factory_or_error.status());
      ext_authz_client = std::make_unique<Filters::Common::ExtAuthz::GrpcClientImpl>(
          THROW_OR_RETURN_VALUE(factory_or_error.value()->createUncachedRawAsyncClient(),
                                Grpc::RawAsyncClientPtr),
          std::chrono::milliseconds(timeout_ms));
    }

    filter_manager.addFilter(std::make_shared<Filter>(filter_config, std::move(ext_authz_client)));
  };
}

/**
 * Static registration for the Postgres proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(DatabricksSqlProxyConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
