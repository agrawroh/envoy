#pragma once

#include "external/envoy_api/envoy/extensions/filters/network/mysql_connect_proxy/v3/mysql_connect_proxy.pb.h"
#include "external/envoy_api/envoy/extensions/filters/network/mysql_connect_proxy/v3/mysql_connect_proxy.pb.validate.h"

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLConnectProxy {

/**
 * Config registration for the MySQL proxy filter. @see NamedNetworkFilterConfigFactory.
 */
class MySQLConnectProxyConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::mysql_connect_proxy::v3::MySQLConnectProxy> {
public:
  MySQLConnectProxyConfigFactory()
      : FactoryBase("envoy.filters.network.mysql_connect_proxy", true) {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::mysql_connect_proxy::v3::MySQLConnectProxy&
          proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace MySQLConnectProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
