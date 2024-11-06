#pragma once

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.h"
#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Config registration for the Postgres proxy filter.
 */
class DatabricksSqlProxyConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy> {
public:
  DatabricksSqlProxyConfigFactory() : FactoryBase(NetworkFilterNames::get().DatabricksSqlProxy) {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy&
          proto_config,
      Server::Configuration::FactoryContext& context) override;

  // External authorization connection timeout in milliseconds.
  static constexpr uint64_t DEFAULT_EXT_AUTH_TIMEOUT_MS = 200;
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
