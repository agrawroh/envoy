#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/http/codes.h"
#include "envoy/http/header_map.h"
#include "envoy/server/admin.h"
#include "envoy/server/instance.h"

#include "source/server/admin/handler_ctx.h"
#include "source/server/admin/reverse_tunnels_params.h"

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace Envoy {
namespace Server {

/**
 * Admin handler for reverse tunnel connections visibility.
 * Provides endpoint at /reverse_tunnels for monitoring active reverse connections.
 */
class ReverseTunnelsHandler : public HandlerContextBase,
                              public Logger::Loggable<Logger::Id::admin> {

public:
  ReverseTunnelsHandler(Server::Instance& server);

  /**
   * Main handler for /reverse_tunnels endpoint.
   * @param response_headers HTTP response headers to set.
   * @param response Buffer to write response body.
   * @param admin_stream Admin stream for accessing query parameters.
   * @return HTTP response code.
   */
  Http::Code handlerReverseTunnels(Http::ResponseHeaderMap& response_headers,
                                   Buffer::Instance& response, AdminStream& admin_stream);

  /**
   * Enhanced reverse tunnels handler with comprehensive parameter parsing.
   * @param path_and_query the URL path and query.
   * @param response buffer into which to write response.
   * @return HTTP response code.
   */
  Http::Code reverseTunnels(absl::string_view path_and_query, Buffer::Instance& response);

  /**
   * Create streaming request for large responses.
   * @param admin_stream Admin stream for accessing query parameters.
   * @return Request object for chunked response handling.
   */
  Admin::RequestPtr makeRequest(AdminStream& admin_stream);

private:
  /**
   * Connection information structure.
   */
  struct ConnectionInfo {
    std::string node_id;
    std::string cluster_id;
    std::string tenant_id;
    std::string remote_address;
    std::string local_address;
    std::chrono::system_clock::time_point established_time;
    std::chrono::system_clock::time_point last_activity;
    std::chrono::system_clock::time_point last_ping_sent;
    std::chrono::system_clock::time_point last_ping_received;
    bool is_healthy{true};
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    uint32_t consecutive_ping_failures{0};
    uint64_t total_pings_sent{0};
    uint64_t total_pings_received{0};
    std::chrono::milliseconds ping_interval{0};
    std::chrono::milliseconds average_ping_latency{0};
    std::string worker_thread_name;
  };

  /**
   * Aggregated statistics structure.
   */
  struct AggregatedStats {
    std::vector<ConnectionInfo> connections;
    absl::flat_hash_map<std::string, uint64_t> nodes_count;
    absl::flat_hash_map<std::string, uint64_t> clusters_count;
    absl::flat_hash_map<std::string, uint64_t> tenants_count;
    absl::flat_hash_map<std::string, uint64_t> workers_count;
    uint64_t total_connections{0};
    uint64_t healthy_connections{0};
    uint64_t unhealthy_connections{0};
  };

  /**
   * Aggregate connection data across all worker threads.
   * @param params Query parameters for filtering.
   * @return Aggregated statistics.
   */
  AggregatedStats aggregateConnectionData(const ReverseTunnelParams& params);

  /**
   * Format response as JSON.
   * @param stats Aggregated statistics to format.
   * @param response Buffer to write JSON response.
   * @param params Query parameters.
   */
  void formatJsonResponse(const AggregatedStats& stats, Buffer::Instance& response,
                          const ReverseTunnelParams& params);

  /**
   * Format response as plain text.
   * @param stats Aggregated statistics to format.
   * @param response Buffer to write text response.
   * @param params Query parameters.
   */
  void formatTextResponse(const AggregatedStats& stats, Buffer::Instance& response,
                          const ReverseTunnelParams& params);

  /**
   * Format response as Prometheus metrics.
   * @param stats Aggregated statistics to format.
   * @param response Buffer to write Prometheus response.
   * @param params Query parameters.
   */
  void formatPrometheusResponse(const AggregatedStats& stats, Buffer::Instance& response,
                                const ReverseTunnelParams& params);

  /**
   * Filter connections based on query parameters.
   * @param connections All connections to filter.
   * @param params Query parameters with filter criteria.
   * @return Filtered connections.
   */
  std::vector<ConnectionInfo> filterConnections(const std::vector<ConnectionInfo>& connections,
                                                const ReverseTunnelParams& params);

  /**
   * Sort connections based on specified field.
   * @param connections Connections to sort (modified in place).
   * @param params Query parameters with sort criteria.
   */
  void sortConnections(std::vector<ConnectionInfo>& connections, const ReverseTunnelParams& params);

  /**
   * Format time point as ISO8601 string.
   * @param time_point Time point to format.
   * @return ISO8601 formatted string.
   */
  std::string formatTimestamp(const std::chrono::system_clock::time_point& time_point);
};

} // namespace Server
} // namespace Envoy
