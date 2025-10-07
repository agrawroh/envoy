#include "source/common/http/filter_chain_matcher/action.h"

#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {

Matcher::ActionConstSharedPtr
HttpFilterChainActionFactory::createAction(const Protobuf::Message& config,
                                           HttpFilterChainActionFactoryContext&,
                                           ProtobufMessage::ValidationVisitor& validation_visitor) {
  const auto& typed_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::filters::network::
                                           http_connection_manager::v3::HttpFilterChainAction&>(
          config, validation_visitor);

  return std::make_shared<HttpFilterChainAction>(typed_config.name());
}

REGISTER_FACTORY(HttpFilterChainActionFactory,
                 Matcher::ActionFactory<HttpFilterChainActionFactoryContext>);

} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
