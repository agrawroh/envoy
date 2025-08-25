#include "source/extensions/filters/network/reverse_conn/reverse_conn_filter_factory.h"

#include "source/extensions/filters/network/reverse_conn/reverse_conn_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConn {

GenericProxy::FilterFactoryCb ReverseConnFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::reverse_conn::v3::ReverseConn& proto_config,
    Server::Configuration::FactoryContext& context) {
  UNREFERENCED_PARAMETER(proto_config);
  UNREFERENCED_PARAMETER(context);

  auto config = std::make_shared<ReverseConnFilterConfig>();

  return [config](GenericProxy::FilterChainManager& filter_chain_manager) -> void {
    filter_chain_manager.addFilter(
        [config](GenericProxy::FilterChainFactoryCallbacks& callbacks) -> void {
          callbacks.addFilter(std::make_shared<ReverseConnFilter>(config));
        });
  };
}

REGISTER_FACTORY(ReverseConnFilterConfigFactory, GenericProxy::NamedFilterConfigFactory);

} // namespace ReverseConn
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
