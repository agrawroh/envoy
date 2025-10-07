#pragma once

#include "envoy/extensions/filters/network/http_connection_manager/v3/http_filter_chain_matcher.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_filter_chain_matcher.pb.validate.h"
#include "envoy/matcher/matcher.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"

#include "source/common/http/filter_chain_matcher/matching_data.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {

/**
 * Action that returns the name of the HTTP filter chain to use.
 */
class HttpFilterChainAction : public Matcher::Action {
public:
  explicit HttpFilterChainAction(absl::string_view name) : name_(name) {}

  // Returns the name of the filter chain.
  absl::string_view name() const { return name_; }

  // Matcher::Action
  absl::string_view typeUrl() const override {
    return "type.googleapis.com/"
           "envoy.extensions.filters.network.http_connection_manager.v3.HttpFilterChainAction";
  }

private:
  const std::string name_;
};

// Action factory context for HTTP filter chain matching.
// Uses Server::Configuration::ServerFactoryContext as the context type.
using HttpFilterChainActionFactoryContext = Server::Configuration::ServerFactoryContext;

/**
 * Action factory that creates HttpFilterChainAction instances.
 * [#extension: envoy.matching.action.http_filter_chain]
 */
class HttpFilterChainActionFactory
    : public Matcher::ActionFactory<HttpFilterChainActionFactoryContext> {
public:
  std::string name() const override { return "envoy.matching.action.http_filter_chain"; }

  Matcher::ActionConstSharedPtr
  createAction(const Protobuf::Message& config, HttpFilterChainActionFactoryContext& context,
               ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::filters::network::http_connection_manager::v3::HttpFilterChainAction>();
  }
};

DECLARE_FACTORY(HttpFilterChainActionFactory);

} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
