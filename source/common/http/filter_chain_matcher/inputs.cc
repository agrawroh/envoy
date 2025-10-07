#include "source/common/http/filter_chain_matcher/inputs.h"

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/http/header_map.h"
#include "envoy/registry/registry.h"

#include "source/common/config/metadata.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "google/protobuf/struct.pb.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {

namespace {

// Use google::protobuf::Value directly.
namespace ProtobufWkt = ::google::protobuf;

// Anonymous helper function to extract metadata value as string.
// Handles both dynamic metadata and route metadata.
absl::optional<std::string>
getMetadataValue(const HttpFilterChainMatchingData& data,
                 const envoy::extensions::filters::network::http_connection_manager::v3::
                     HttpRequestMetadataMatchInput& config) {
  const envoy::config::core::v3::Metadata* metadata = nullptr;

  if (config.kind() == envoy::extensions::filters::network::http_connection_manager::v3::
                           HttpRequestMetadataMatchInput::DYNAMIC) {
    metadata = &data.stream_info_.dynamicMetadata();
  } else if (config.kind() == envoy::extensions::filters::network::http_connection_manager::v3::
                                  HttpRequestMetadataMatchInput::ROUTE) {
    if (data.stream_info_.route()) {
      metadata = &(data.stream_info_.route()->metadata());
    } else {
      return absl::nullopt;
    }
  }

  if (!metadata) {
    return absl::nullopt;
  }

  const Protobuf::Value& value_ref =
      Config::Metadata::metadataValue(metadata, config.metadata_key());
  const Protobuf::Value* value = &value_ref;

  // Convert protobuf Value to string.
  switch (value->kind_case()) {
  case Protobuf::Value::KIND_NOT_SET:
    return absl::nullopt;
  case Protobuf::Value::kStringValue:
    return value->string_value();
  case Protobuf::Value::kNumberValue: {
    // Format numbers properly - integers without decimal places.
    double num = value->number_value();
    if (std::floor(num) == num) {
      return fmt::format("{:.0f}", num);
    }
    return fmt::format("{}", num);
  }
  case Protobuf::Value::kBoolValue:
    return value->bool_value() ? "true" : "false";
  case Protobuf::Value::kNullValue:
    return "null";
  case Protobuf::Value::kStructValue:
  case Protobuf::Value::kListValue:
    // Struct and list values are not supported.
    return absl::nullopt;
  }
}

} // namespace

// HttpRequestHeaderMatchInput implementation.
class HttpRequestHeaderMatchInput : public Matcher::DataInput<HttpFilterChainMatchingData> {
public:
  explicit HttpRequestHeaderMatchInput(absl::string_view header_name) : header_name_(header_name) {}

  Matcher::DataInputGetResult get(const HttpFilterChainMatchingData& data) const override {
    const auto header = data.headers_.get(header_name_);
    if (header.empty()) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
    }
    return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable,
            std::string(header[0]->value().getStringView())};
  }

private:
  const LowerCaseString header_name_;
};

Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
HttpRequestHeaderInputFactory::createDataInputFactoryCb(
    const Protobuf::Message& config, ProtobufMessage::ValidationVisitor& validation_visitor) {
  const auto& typed_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::filters::network::http_connection_manager::v3::
          HttpRequestHeaderMatchInput&>(config, validation_visitor);

  const std::string header_name = typed_config.header_name();
  return [header_name]() { return std::make_unique<HttpRequestHeaderMatchInput>(header_name); };
}

// HttpRequestMethodMatchInput implementation.
class HttpRequestMethodMatchInput : public Matcher::DataInput<HttpFilterChainMatchingData> {
public:
  Matcher::DataInputGetResult get(const HttpFilterChainMatchingData& data) const override {
    const auto method = data.headers_.getMethodValue();
    if (method.empty()) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
    }
    return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::string(method)};
  }
};

Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
HttpRequestMethodInputFactory::createDataInputFactoryCb(const Protobuf::Message&,
                                                        ProtobufMessage::ValidationVisitor&) {
  return []() { return std::make_unique<HttpRequestMethodMatchInput>(); };
}

// HttpRequestPathMatchInput implementation.
class HttpRequestPathMatchInput : public Matcher::DataInput<HttpFilterChainMatchingData> {
public:
  Matcher::DataInputGetResult get(const HttpFilterChainMatchingData& data) const override {
    const auto path = data.headers_.getPathValue();
    if (path.empty()) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
    }
    return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::string(path)};
  }
};

Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
HttpRequestPathInputFactory::createDataInputFactoryCb(const Protobuf::Message&,
                                                      ProtobufMessage::ValidationVisitor&) {
  return []() { return std::make_unique<HttpRequestPathMatchInput>(); };
}

// HttpRequestMetadataMatchInput implementation.
class HttpRequestMetadataMatchInput : public Matcher::DataInput<HttpFilterChainMatchingData> {
public:
  explicit HttpRequestMetadataMatchInput(
      const envoy::extensions::filters::network::http_connection_manager::v3::
          HttpRequestMetadataMatchInput& config)
      : config_(config) {}

  Matcher::DataInputGetResult get(const HttpFilterChainMatchingData& data) const override {
    auto value = getMetadataValue(data, config_);
    if (value.has_value()) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, value.value()};
    }
    return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
  }

private:
  const envoy::extensions::filters::network::http_connection_manager::v3::
      HttpRequestMetadataMatchInput config_;
};

Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
HttpRequestMetadataInputFactory::createDataInputFactoryCb(
    const Protobuf::Message& config, ProtobufMessage::ValidationVisitor& validation_visitor) {
  const auto& typed_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::filters::network::http_connection_manager::v3::
          HttpRequestMetadataMatchInput&>(config, validation_visitor);

  return [typed_config]() { return std::make_unique<HttpRequestMetadataMatchInput>(typed_config); };
}

// HttpRequestFilterStateMatchInput implementation.
class HttpRequestFilterStateMatchInput : public Matcher::DataInput<HttpFilterChainMatchingData> {
public:
  explicit HttpRequestFilterStateMatchInput(absl::string_view key) : key_(key) {}

  Matcher::DataInputGetResult get(const HttpFilterChainMatchingData& data) const override {
    const StreamInfo::FilterState& filter_state = *data.stream_info_.filterState();
    if (!filter_state.hasDataWithName(key_)) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
    }

    // Try to get the filter state object as a string.
    const auto* object = filter_state.getDataReadOnly<StreamInfo::FilterState::Object>(key_);
    if (!object) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
    }

    // Serialize the filter state object to string.
    absl::optional<std::string> serialized = object->serializeAsString();
    if (serialized.has_value()) {
      return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, serialized.value()};
    }
    return {Matcher::DataInputGetResult::DataAvailability::AllDataAvailable, std::monostate()};
  }

private:
  const std::string key_;
};

Matcher::DataInputFactoryCb<HttpFilterChainMatchingData>
HttpRequestFilterStateInputFactory::createDataInputFactoryCb(
    const Protobuf::Message& config, ProtobufMessage::ValidationVisitor& validation_visitor) {
  const auto& typed_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::filters::network::http_connection_manager::v3::
          HttpRequestFilterStateMatchInput&>(config, validation_visitor);

  return [key = typed_config.key()]() {
    return std::make_unique<HttpRequestFilterStateMatchInput>(key);
  };
}

// Register the factories.
REGISTER_FACTORY(HttpRequestHeaderInputFactory,
                 Matcher::DataInputFactory<HttpFilterChainMatchingData>);
REGISTER_FACTORY(HttpRequestMethodInputFactory,
                 Matcher::DataInputFactory<HttpFilterChainMatchingData>);
REGISTER_FACTORY(HttpRequestPathInputFactory,
                 Matcher::DataInputFactory<HttpFilterChainMatchingData>);
REGISTER_FACTORY(HttpRequestMetadataInputFactory,
                 Matcher::DataInputFactory<HttpFilterChainMatchingData>);
REGISTER_FACTORY(HttpRequestFilterStateInputFactory,
                 Matcher::DataInputFactory<HttpFilterChainMatchingData>);

} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
