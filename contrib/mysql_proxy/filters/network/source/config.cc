#include "contrib/mysql_proxy/filters/network/source/config.h"

#include "external/envoy_api/envoy/extensions/filters/network/mysql_connect_proxy/v3/mysql_connect_proxy.pb.h"
#include "envoy/registry/registry.h"

#include "contrib/mysql_proxy/filters/network/source/mysql_connect_proxy.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLConnectProxy {

Network::FilterFactoryCb MySQLConnectProxyConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::mysql_connect_proxy::v3::MySQLConnectProxy&
        proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  Envoy::MySQLConnectProxy::ConfigSharedPtr filter_config(
      std::make_shared<Envoy::MySQLConnectProxy::Config>(proto_config, context));
  return [filter_config, &context](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<Envoy::MySQLConnectProxy::Filter>(
        filter_config, context.clusterManager()));
  };
}

/**
 * Static registration for the MySQL Connect Proxy filter. @see RegisterFactory.
 */
LEGACY_REGISTER_FACTORY(MySQLConnectProxyConfigFactory,
                        Server::Configuration::NamedNetworkFilterConfigFactory,
                        "envoy.mysql_connect_proxy");

} // namespace MySQLConnectProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
