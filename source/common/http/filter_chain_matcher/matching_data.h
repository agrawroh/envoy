#pragma once

#include "envoy/http/header_map.h"
#include "envoy/matcher/matcher.h"
#include "envoy/router/router.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/logger.h"
#include "source/common/matcher/validation_visitor.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Http {
namespace FilterChainMatcher {

/**
 * Data structure that holds the context for HTTP filter chain matching.
 * This data is passed to the matcher framework inputs to extract match criteria
 * from the incoming request.
 */
struct HttpFilterChainMatchingData {
  HttpFilterChainMatchingData(const RequestHeaderMap& headers, StreamInfo::StreamInfo& stream_info)
      : headers_(headers), stream_info_(stream_info) {}

  // Returns the name for this matching data type used in factory registration.
  static absl::string_view name() { return "http-filter-chain"; }

  // The request headers from the downstream client.
  const RequestHeaderMap& headers_;

  // Stream information containing metadata, filter state, and other request context.
  StreamInfo::StreamInfo& stream_info_;
};

/**
 * Simple validation visitor for HTTP filter chain matcher that accepts all data inputs.
 */
class HttpFilterChainMatchTreeValidationVisitor
    : public Matcher::MatchTreeValidationVisitor<HttpFilterChainMatchingData> {
protected:
  absl::Status
  performDataInputValidation(const Matcher::DataInputFactory<HttpFilterChainMatchingData>&,
                             absl::string_view) override {
    // Accept all data inputs without specific requirements.
    return absl::OkStatus();
  }
};

} // namespace FilterChainMatcher
} // namespace Http
} // namespace Envoy
