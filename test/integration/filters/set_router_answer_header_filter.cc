#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/integration/filters/test_filters.pb.h"

namespace Envoy {

// A filter that runs after route matching resolved the route and sets the header the router answer
// of the dynamic module reads, so a test can observe that the router answers on the headers it
// forwards rather than on the ones route matching saw.
class SetRouterAnswerHeaderFilter : public Http::PassThroughDecoderFilter {
public:
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override {
    headers.setCopy(Http::LowerCaseString("x-router-virtual-cluster"), "rides");
    return Http::FilterHeadersStatus::Continue;
  }
};

class SetRouterAnswerHeaderFilterConfig
    : public Extensions::HttpFilters::Common::UniqueEmptyHttpFilterConfig<
          test::integration::filters::SetRouterAnswerHeaderFilterConfig> {
public:
  SetRouterAnswerHeaderFilterConfig()
      : UniqueEmptyHttpFilterConfig<test::integration::filters::SetRouterAnswerHeaderFilterConfig>(
            "set-router-answer-header") {}
  absl::StatusOr<Http::FilterFactoryCb>
  createFilter(const std::string&, Server::Configuration::FactoryContext&) override {
    return [](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamDecoderFilter(std::make_shared<SetRouterAnswerHeaderFilter>());
    };
  }
};

// perform static registration
static Registry::RegisterFactory<SetRouterAnswerHeaderFilterConfig,
                                 Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Envoy
