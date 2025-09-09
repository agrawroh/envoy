#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/http/codes.h"

#include "source/common/http/utility.h"

#include "re2/re2.h"

namespace Envoy {
namespace Server {

namespace ReverseTunnelLabels {
constexpr absl::string_view All = "all";
constexpr absl::string_view Healthy = "healthy";
constexpr absl::string_view Unhealthy = "unhealthy";
constexpr absl::string_view Connected = "connected";
constexpr absl::string_view Stale = "stale";
} // namespace ReverseTunnelLabels

/**
 * Format for reverse tunnel output.
 */
enum class ReverseTunnelFormat {
  Json,
  Text,
  Prometheus,
};

/**
 * Health status filter for reverse tunnel connections.
 */
enum class HealthFilter {
  All,       // Show all connections.
  Healthy,   // Show only healthy connections.
  Unhealthy, // Show only unhealthy connections.
};

/**
 * Sort field for reverse tunnel connections.
 */
enum class SortField {
  NodeId,
  ClusterId,
  EstablishedTime,
  LastActivity,
  PingLatency,
  Failures,
};

/**
 * Parameters for reverse tunnel endpoint queries.
 */
struct ReverseTunnelParams {
  /**
   * Parses the URL's query parameter, populating this.
   *
   * @param url the URL from which to parse the query params.
   * @param response used to write error messages, if necessary.
   * @return HTTP response code.
   */
  Http::Code parse(absl::string_view url, Buffer::Instance& response);

  /**
   * @return a string representation for a format.
   */
  static absl::string_view formatToString(ReverseTunnelFormat format);

  /**
   * @return a string representation for a sort field.
   */
  static absl::string_view sortFieldToString(SortField field);

  /**
   * Determines whether a connection should be shown based on the specified query-parameters.
   *
   * @param node_id the node ID to test.
   * @param cluster_id the cluster ID to test.
   * @param is_healthy whether the connection is healthy.
   * @param established_time when the connection was established.
   * @return true if the connection should be included in results.
   */
  bool shouldShowConnection(const std::string& node_id, const std::string& cluster_id,
                            bool is_healthy,
                            const std::chrono::system_clock::time_point& established_time) const;

  // Filtering parameters.
  std::string node_id_filter;
  std::string cluster_id_filter;
  std::string filter_string_;
  std::shared_ptr<re2::RE2> re2_filter_;
  HealthFilter health_filter_{HealthFilter::All};
  ReverseTunnelFormat format_{ReverseTunnelFormat::Json};

  // Time filtering.
  absl::optional<std::chrono::system_clock::time_point> since_time_;
  absl::optional<std::chrono::system_clock::time_point> until_time_;

  // Output control.
  bool include_metadata_{false};
  bool aggregate_only_{false};
  SortField sort_by_{SortField::NodeId};
  bool sort_descending_{false};
  uint32_t limit_{0};
  uint32_t offset_{0};

  // Query storage.
  Http::Utility::QueryParamsMulti query_;

private:
  /**
   * Parse ISO8601 timestamp string.
   *
   * @param timestamp_str Timestamp string in ISO8601 format.
   * @return Parsed time point or nullopt if invalid.
   */
  static absl::optional<std::chrono::system_clock::time_point>
  parseTimestamp(const std::string& timestamp_str);
};

} // namespace Server
} // namespace Envoy
