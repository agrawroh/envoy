#pragma once

#include "envoy/extensions/filters/http/web_transport/v3/web_transport.pb.h"
#include "envoy/extensions/filters/http/web_transport/v3/web_transport.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WebTransport {

class WebTransportFilterConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::web_transport::v3::WebTransport> {
public:
  WebTransportFilterConfigFactory() : FactoryBase("envoy.filters.http.web_transport") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::web_transport::v3::WebTransport& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace WebTransport
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
