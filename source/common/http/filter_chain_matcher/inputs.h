#pragma once

#include "envoy/extensions/filters/network/http_connection_manager/v3/http_filter_chain_matcher.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_filter_chain_matcher.pb.validate.h"
#include "envoy/matcher/matcher.h"
#include "envoy/registry/registry.h"

#include "source/common/http/filter_chain_matcher/matching_data.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {

/**
 * Input factory that extracts a request header value for matching.
 * [#extension: envoy.matching.inputs.http_request_header]
 */
class HttpRequestHeaderInputFactory
    : public Matcher::DataInputFactory<HttpFilterChainMatchingData> {
public:
  std::string name() const override { return "envoy.matching.inputs.http_request_header"; }

  Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
  createDataInputFactoryCb(const Protobuf::Message& config,
                           ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::network::http_connection_manager::v3::
                                HttpRequestHeaderMatchInput>();
  }
};

DECLARE_FACTORY(HttpRequestHeaderInputFactory);

/**
 * Input factory that extracts the HTTP request method for matching.
 * [#extension: envoy.matching.inputs.http_request_method]
 */
class HttpRequestMethodInputFactory
    : public Matcher::DataInputFactory<HttpFilterChainMatchingData> {
public:
  std::string name() const override { return "envoy.matching.inputs.http_request_method"; }

  Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
  createDataInputFactoryCb(const Protobuf::Message& config,
                           ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::network::http_connection_manager::v3::
                                HttpRequestMethodMatchInput>();
  }
};

DECLARE_FACTORY(HttpRequestMethodInputFactory);

/**
 * Input factory that extracts the HTTP request path for matching.
 * [#extension: envoy.matching.inputs.http_request_path]
 */
class HttpRequestPathInputFactory : public Matcher::DataInputFactory<HttpFilterChainMatchingData> {
public:
  std::string name() const override { return "envoy.matching.inputs.http_request_path"; }

  Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
  createDataInputFactoryCb(const Protobuf::Message& config,
                           ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::network::http_connection_manager::v3::
                                HttpRequestPathMatchInput>();
  }
};

DECLARE_FACTORY(HttpRequestPathInputFactory);

/**
 * Input factory that extracts metadata for matching.
 * [#extension: envoy.matching.inputs.http_request_metadata]
 */
class HttpRequestMetadataInputFactory
    : public Matcher::DataInputFactory<HttpFilterChainMatchingData> {
public:
  std::string name() const override { return "envoy.matching.inputs.http_request_metadata"; }

  Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
  createDataInputFactoryCb(const Protobuf::Message& config,
                           ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::network::http_connection_manager::v3::
                                HttpRequestMetadataMatchInput>();
  }
};

DECLARE_FACTORY(HttpRequestMetadataInputFactory);

/**
 * Input factory that extracts filter state for matching.
 * [#extension: envoy.matching.inputs.http_request_filter_state]
 */
class HttpRequestFilterStateInputFactory
    : public Matcher::DataInputFactory<HttpFilterChainMatchingData> {
public:
  std::string name() const override { return "envoy.matching.inputs.http_request_filter_state"; }

  Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
  createDataInputFactoryCb(const Protobuf::Message& config,
                           ProtobufMessage::ValidationVisitor& validation_visitor) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::network::http_connection_manager::v3::
                                HttpRequestFilterStateMatchInput>();
  }
};

DECLARE_FACTORY(HttpRequestFilterStateInputFactory);

} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
