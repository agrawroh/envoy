#include "source/server/admin/reverse_tunnels_params.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#include "source/common/common/utility.h"

#include "absl/strings/ascii.h"
#include "absl/strings/str_format.h"

namespace Envoy {
namespace Server {

Http::Code ReverseTunnelParams::parse(absl::string_view url, Buffer::Instance& response) {
  query_ = Http::Utility::QueryParamsMulti::parseAndDecodeQueryString(url);

  // Parse node_id filter.
  auto node_id_val = query_.getFirstValue("node_id");
  if (node_id_val.has_value() && !node_id_val.value().empty()) {
    node_id_filter = node_id_val.value();
  }

  // Parse cluster_id filter.
  auto cluster_id_val = query_.getFirstValue("cluster_id");
  if (cluster_id_val.has_value() && !cluster_id_val.value().empty()) {
    cluster_id_filter = cluster_id_val.value();
  }

  // Tenant ID filter is not supported.

  // Parse regex filter.
  auto filter_val = query_.getFirstValue("filter");
  if (filter_val.has_value() && !filter_val.value().empty()) {
    filter_string_ = filter_val.value();
    re2::RE2::Options options;
    options.set_log_errors(false);
    re2_filter_ = std::make_shared<re2::RE2>(filter_string_, options);
    if (!re2_filter_->ok()) {
      response.add("Invalid re2 regex for filter parameter.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse format parameter.
  auto format_val = query_.getFirstValue("format");
  if (format_val.has_value() && !format_val.value().empty()) {
    const std::string format_str = absl::AsciiStrToLower(format_val.value());
    if (format_str == "json") {
      format_ = ReverseTunnelFormat::Json;
    } else if (format_str == "text") {
      format_ = ReverseTunnelFormat::Text;
    } else if (format_str == "prometheus") {
      format_ = ReverseTunnelFormat::Prometheus;
    } else {
      response.add("Invalid format parameter. Use 'json', 'text', or 'prometheus'.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse health filter parameter.
  auto health_val = query_.getFirstValue("health");
  if (health_val.has_value() && !health_val.value().empty()) {
    const std::string health_str = absl::AsciiStrToLower(health_val.value());
    if (health_str == ReverseTunnelLabels::All) {
      health_filter_ = HealthFilter::All;
    } else if (health_str == ReverseTunnelLabels::Healthy) {
      health_filter_ = HealthFilter::Healthy;
    } else if (health_str == ReverseTunnelLabels::Unhealthy) {
      health_filter_ = HealthFilter::Unhealthy;
    } else {
      response.add("Invalid health parameter. Use 'all', 'healthy', or 'unhealthy'.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse boolean flags.
  include_metadata_ = query_.getFirstValue("include_metadata") == "true";
  aggregate_only_ = query_.getFirstValue("aggregate_only") == "true";
  sort_descending_ = query_.getFirstValue("desc") == "true";

  // Parse sort_by parameter.
  auto sort_val = query_.getFirstValue("sort_by");
  if (sort_val.has_value() && !sort_val.value().empty()) {
    const std::string sort_str = absl::AsciiStrToLower(sort_val.value());
    if (sort_str == "node_id") {
      sort_by_ = SortField::NodeId;
    } else if (sort_str == "cluster_id") {
      sort_by_ = SortField::ClusterId;
    } else if (sort_str == "established_time") {
      sort_by_ = SortField::EstablishedTime;
    } else if (sort_str == "last_activity") {
      sort_by_ = SortField::LastActivity;
    } else if (sort_str == "ping_latency") {
      sort_by_ = SortField::PingLatency;
    } else if (sort_str == "failures") {
      sort_by_ = SortField::Failures;
    } else {
      response.add("Invalid sort_by parameter. Use 'node_id', 'cluster_id', 'tenant_id', "
                   "'established_time', 'last_activity', 'ping_latency', or 'failures'.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse limit parameter.
  auto limit_val = query_.getFirstValue("limit");
  if (limit_val.has_value() && !limit_val.value().empty()) {
    try {
      limit_ = std::stoul(limit_val.value());
      if (limit_ > 10000) {
        response.add("Limit parameter too large. Maximum is 10000.\n");
        return Http::Code::BadRequest;
      }
    } catch (const std::exception&) {
      response.add("Invalid limit parameter. Must be a valid number.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse offset parameter for pagination.
  auto offset_val = query_.getFirstValue("offset");
  if (offset_val.has_value() && !offset_val.value().empty()) {
    try {
      offset_ = std::stoul(offset_val.value());
    } catch (const std::exception&) {
      response.add("Invalid offset parameter. Must be a valid number.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse since timestamp.
  auto since_val = query_.getFirstValue("since");
  if (since_val.has_value() && !since_val.value().empty()) {
    since_time_ = parseTimestamp(since_val.value());
    if (!since_time_.has_value()) {
      response.add("Invalid 'since' timestamp format. Use ISO8601 format: YYYY-MM-DDTHH:MM:SSZ.\n");
      return Http::Code::BadRequest;
    }
  }

  // Parse until timestamp.
  auto until_val = query_.getFirstValue("until");
  if (until_val.has_value() && !until_val.value().empty()) {
    until_time_ = parseTimestamp(until_val.value());
    if (!until_time_.has_value()) {
      response.add("Invalid 'until' timestamp format. Use ISO8601 format: YYYY-MM-DDTHH:MM:SSZ.\n");
      return Http::Code::BadRequest;
    }
  }

  return Http::Code::OK;
}

absl::string_view ReverseTunnelParams::formatToString(ReverseTunnelFormat format) {
  switch (format) {
  case ReverseTunnelFormat::Json:
    return "json";
  case ReverseTunnelFormat::Text:
    return "text";
  case ReverseTunnelFormat::Prometheus:
    return "prometheus";
  }
  return "unknown";
}

absl::string_view ReverseTunnelParams::sortFieldToString(SortField field) {
  switch (field) {
  case SortField::NodeId:
    return "node_id";
  case SortField::ClusterId:
    return "cluster_id";
  case SortField::EstablishedTime:
    return "established_time";
  case SortField::LastActivity:
    return "last_activity";
  case SortField::PingLatency:
    return "ping_latency";
  case SortField::Failures:
    return "failures";
  }
  return "unknown";
}

bool ReverseTunnelParams::shouldShowConnection(
    const std::string& node_id, const std::string& cluster_id, bool is_healthy,
    const std::chrono::system_clock::time_point& established_time) const {
  // Apply node ID filter.
  if (!node_id_filter.empty() && node_id != node_id_filter) {
    return false;
  }

  // Apply cluster ID filter.
  if (!cluster_id_filter.empty() && cluster_id != cluster_id_filter) {
    return false;
  }

  // Tenant ID filtering is not supported.

  // Apply health filter.
  if (health_filter_ == HealthFilter::Healthy && !is_healthy) {
    return false;
  }
  if (health_filter_ == HealthFilter::Unhealthy && is_healthy) {
    return false;
  }

  // Apply time filters.
  if (since_time_.has_value() && established_time < since_time_.value()) {
    return false;
  }
  if (until_time_.has_value() && established_time > until_time_.value()) {
    return false;
  }

  // Apply regex filter (matches node_id or cluster_id).
  if (re2_filter_ != nullptr) {
    if (!re2::RE2::PartialMatch(node_id, *re2_filter_) &&
        !re2::RE2::PartialMatch(cluster_id, *re2_filter_)) {
      return false;
    }
  }

  return true;
}

absl::optional<std::chrono::system_clock::time_point>
ReverseTunnelParams::parseTimestamp(const std::string& timestamp_str) {
  // Parse ISO8601 format: `YYYY-MM-DDTHH:MM:SSZ`
  std::istringstream ss(timestamp_str);
  std::tm tm = {};
  ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  if (ss.fail()) {
    return absl::nullopt;
  }

  std::time_t time = std::mktime(&tm);
  return std::chrono::system_clock::from_time_t(time);
}

} // namespace Server
} // namespace Envoy
