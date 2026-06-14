#include "source/extensions/filters/http/web_transport/config.h"

#include <memory>

#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/web_transport/web_transport_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WebTransport {

Http::FilterFactoryCb WebTransportFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::web_transport::v3::WebTransport&, const std::string&,
    Server::Configuration::FactoryContext&) {
  return [](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<WebTransportFilter>());
  };
}

// Static registration for the WebTransport filter. @see RegisterFactory.
REGISTER_FACTORY(WebTransportFilterConfigFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace WebTransport
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
