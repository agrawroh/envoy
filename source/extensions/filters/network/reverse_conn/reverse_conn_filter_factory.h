#pragma once

#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/generic_proxy/interface/filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConn {

/**
 * Config registration for the reverse connection filter.
 */
class ReverseConnFilterConfigFactory : public GenericProxy::NamedFilterConfigFactory {
public:
  ReverseConnFilterConfigFactory() : FactoryBase("envoy.filters.generic.reverse_conn") {}

private:
  GenericProxy::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::reverse_conn::v3::ReverseConn& proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace ReverseConn
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
