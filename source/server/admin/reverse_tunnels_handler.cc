#include "source/server/admin/reverse_tunnels_handler.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "envoy/network/socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/extensions/bootstrap/reverse_tunnel/upstream_socket_interface/reverse_tunnel_acceptor.h"
#include "source/extensions/bootstrap/reverse_tunnel/upstream_socket_interface/reverse_tunnel_acceptor_extension.h"
#include "source/extensions/bootstrap/reverse_tunnel/upstream_socket_interface/upstream_socket_manager.h"
#include "source/server/admin/utils.h"

#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Server {

using namespace Extensions::Bootstrap::ReverseConnection;

ReverseTunnelsHandler::ReverseTunnelsHandler(Server::Instance& server)
    : HandlerContextBase(server) {}

Http::Code ReverseTunnelsHandler::handlerReverseTunnels(Http::ResponseHeaderMap& response_headers,
                                                        Buffer::Instance& response,
                                                        AdminStream& admin_stream) {
  ReverseTunnelParams params;
  Http::Code code = params.parse(admin_stream.getRequestHeaders().getPathValue(), response);
  if (code != Http::Code::OK) {
    return code;
  }

  // Set content type based on format.
  if (params.format_ == ReverseTunnelFormat::Json) {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Json);
  } else {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Text);
  }

  return reverseTunnels(admin_stream.getRequestHeaders().getPathValue(), response);
}

Http::Code ReverseTunnelsHandler::reverseTunnels(absl::string_view path_and_query,
                                                 Buffer::Instance& response) {
  ReverseTunnelParams params;
  Http::Code code = params.parse(path_and_query, response);
  if (code != Http::Code::OK) {
    return code;
  }

  // Aggregate connection data across all threads.
  AggregatedStats stats = aggregateConnectionData(params);

  // Filter and sort connections if needed.
  if (!params.aggregate_only_) {
    stats.connections = filterConnections(stats.connections, params);
    sortConnections(stats.connections, params);

    // Apply pagination (offset + limit).
    if (params.offset_ > 0) {
      if (params.offset_ >= stats.connections.size()) {
        stats.connections.clear();
      } else {
        stats.connections.erase(stats.connections.begin(),
                                stats.connections.begin() + params.offset_);
      }
    }

    if (params.limit_ > 0 && stats.connections.size() > params.limit_) {
      stats.connections.resize(params.limit_);
    }
  }

  // Format response based on requested format.
  if (params.format_ == ReverseTunnelFormat::Json) {
    formatJsonResponse(stats, response, params);
  } else if (params.format_ == ReverseTunnelFormat::Text) {
    formatTextResponse(stats, response, params);
  } else if (params.format_ == ReverseTunnelFormat::Prometheus) {
    formatPrometheusResponse(stats, response, params);
  }

  return Http::Code::OK;
}

Admin::RequestPtr ReverseTunnelsHandler::makeRequest(AdminStream& admin_stream) {
  UNREFERENCED_PARAMETER(admin_stream);
  // For large responses, we could implement streaming here.
  // For now, use the standard synchronous handler.
  return Admin::RequestPtr{};
}

ReverseTunnelsHandler::AggregatedStats
ReverseTunnelsHandler::aggregateConnectionData(const ReverseTunnelParams& params) {
  AggregatedStats stats;

  // Get the reverse tunnel acceptor extension.
  auto* base_interface =
      Network::socketInterface("envoy.bootstrap.reverse_tunnel.upstream_socket_interface");
  if (!base_interface) {
    ENVOY_LOG(debug, "ReverseTunnels: No reverse tunnel socket interface found");
    return stats;
  }

  auto* acceptor = dynamic_cast<const ReverseTunnelAcceptor*>(base_interface);
  if (!acceptor || !acceptor->extension_) {
    ENVOY_LOG(debug, "ReverseTunnels: No acceptor extension found");
    return stats;
  }

  auto* extension = acceptor->extension_;

  // Use the existing getCrossWorkerStatMap for basic aggregation.
  // This provides the stats-based view similar to the original implementation.
  auto global_stats = extension->getCrossWorkerStatMap();

  // Parse connection information from global stats.
  for (const auto& [stat_name, count] : global_stats) {
    if (count > 0) {
      if (stat_name.find("reverse_connections.nodes.") != std::string::npos) {
        // Extract node ID from stat name.
        size_t pos = stat_name.find("reverse_connections.nodes.");
        if (pos != std::string::npos) {
          std::string node_id = stat_name.substr(pos + strlen("reverse_connections.nodes."));

          // Apply node filter early.
          if (!params.node_id_filter.empty() && node_id != params.node_id_filter) {
            continue;
          }

          stats.nodes_count[node_id] = count;
          stats.total_connections += count;
          // Assume connections are healthy unless we have more detailed data.
          stats.healthy_connections += count;
        }
      } else if (stat_name.find("reverse_connections.clusters.") != std::string::npos) {
        // Extract cluster ID from stat name.
        size_t pos = stat_name.find("reverse_connections.clusters.");
        if (pos != std::string::npos) {
          std::string cluster_id = stat_name.substr(pos + strlen("reverse_connections.clusters."));

          // Apply cluster filter early.
          if (!params.cluster_id_filter.empty() && cluster_id != params.cluster_id_filter) {
            continue;
          }

          stats.clusters_count[cluster_id] = count;
        }
      }
    }
  }

  ENVOY_LOG(debug, "ReverseTunnels: Collected {} global stats for {} nodes, {} clusters",
            global_stats.size(), stats.nodes_count.size(), stats.clusters_count.size());

  return stats;
}

void ReverseTunnelsHandler::formatJsonResponse(const AggregatedStats& stats,
                                               Buffer::Instance& response,
                                               const ReverseTunnelParams& params) {
  // Build JSON response as string.
  std::string json_response = "{\n";

  // Add timestamp.
  auto now = std::chrono::system_clock::now();
  json_response += absl::StrFormat("  \"timestamp\": \"%s\",\n", formatTimestamp(now));

  // Add summary.
  json_response += "  \"summary\": {\n";
  json_response += absl::StrFormat("    \"total_connections\": %d,\n", stats.total_connections);
  json_response += absl::StrFormat("    \"healthy_connections\": %d,\n", stats.healthy_connections);
  json_response +=
      absl::StrFormat("    \"unhealthy_connections\": %d,\n", stats.unhealthy_connections);
  json_response += absl::StrFormat("    \"unique_nodes\": %d,\n", stats.nodes_count.size());
  json_response += absl::StrFormat("    \"unique_clusters\": %d,\n", stats.clusters_count.size());
  json_response += absl::StrFormat("    \"unique_tenants\": %d\n", stats.tenants_count.size());
  json_response += "  },\n";

  // Add aggregations.
  json_response += "  \"aggregations\": {\n";

  // By node.
  json_response += "    \"by_node\": {\n";
  bool first = true;
  for (const auto& [node, count] : stats.nodes_count) {
    if (!first)
      json_response += ",\n";
    json_response += absl::StrFormat("      \"%s\": %d", node, count);
    first = false;
  }
  json_response += "\n    },\n";

  // By cluster.
  json_response += "    \"by_cluster\": {\n";
  first = true;
  for (const auto& [cluster, count] : stats.clusters_count) {
    if (!first)
      json_response += ",\n";
    json_response += absl::StrFormat("      \"%s\": %d", cluster, count);
    first = false;
  }
  json_response += "\n    },\n";

  // By tenant.
  json_response += "    \"by_tenant\": {\n";
  first = true;
  for (const auto& [tenant, count] : stats.tenants_count) {
    if (!first)
      json_response += ",\n";
    json_response += absl::StrFormat("      \"%s\": %d", tenant, count);
    first = false;
  }
  json_response += "\n    },\n";

  // By worker.
  json_response += "    \"by_worker\": {\n";
  first = true;
  for (const auto& [worker, count] : stats.workers_count) {
    if (!first)
      json_response += ",\n";
    json_response += absl::StrFormat("      \"%s\": %d", worker, count);
    first = false;
  }
  json_response += "\n    }\n";
  json_response += "  }";

  // Add connection details (if not aggregate_only).
  if (!params.aggregate_only_) {
    json_response += ",\n  \"connections\": [\n";
    first = true;
    for (const auto& conn : stats.connections) {
      if (!first)
        json_response += ",\n";
      json_response += "    {\n";
      json_response += absl::StrFormat("      \"node_id\": \"%s\",\n", conn.node_id);
      json_response += absl::StrFormat("      \"cluster_id\": \"%s\",\n", conn.cluster_id);
      // Tenant ID is not emitted.
      json_response += absl::StrFormat("      \"remote_address\": \"%s\",\n", conn.remote_address);
      json_response += absl::StrFormat("      \"local_address\": \"%s\",\n", conn.local_address);
      json_response += absl::StrFormat("      \"established_time\": \"%s\",\n",
                                       formatTimestamp(conn.established_time));
      json_response += absl::StrFormat("      \"last_activity\": \"%s\",\n",
                                       formatTimestamp(conn.last_activity));
      json_response += absl::StrFormat("      \"last_ping_sent\": \"%s\",\n",
                                       formatTimestamp(conn.last_ping_sent));
      json_response += absl::StrFormat("      \"last_ping_received\": \"%s\",\n",
                                       formatTimestamp(conn.last_ping_received));
      json_response +=
          absl::StrFormat("      \"is_healthy\": %s,\n", conn.is_healthy ? "true" : "false");
      json_response +=
          absl::StrFormat("      \"worker_thread\": \"%s\",\n", conn.worker_thread_name);
      json_response += absl::StrFormat("      \"bytes_sent\": %d,\n", conn.bytes_sent);
      json_response += absl::StrFormat("      \"bytes_received\": %d,\n", conn.bytes_received);
      json_response += absl::StrFormat("      \"consecutive_ping_failures\": %d,\n",
                                       conn.consecutive_ping_failures);
      json_response += absl::StrFormat("      \"total_pings_sent\": %d,\n", conn.total_pings_sent);
      json_response +=
          absl::StrFormat("      \"total_pings_received\": %d", conn.total_pings_received);

      // Add extended metadata if requested.
      if (params.include_metadata_) {
        json_response += ",\n      \"metadata\": {\n";
        json_response +=
            absl::StrFormat("        \"ping_interval_ms\": %d,\n", conn.ping_interval.count());
        json_response += absl::StrFormat("        \"average_ping_latency_ms\": %d\n",
                                         conn.average_ping_latency.count());
        json_response += "      }";
      }

      json_response += "\n    }";
      first = false;
    }
    json_response += "\n  ]";
  }

  json_response += "\n}";
  response.add(json_response);
}

void ReverseTunnelsHandler::formatTextResponse(const AggregatedStats& stats,
                                               Buffer::Instance& response,
                                               const ReverseTunnelParams& params) {
  response.add("Reverse Tunnel Connections\n");
  response.add("==========================\n");

  auto now = std::chrono::system_clock::now();
  response.add(absl::StrFormat("Generated: %s\n\n", formatTimestamp(now)));

  // Summary.
  response.add("Summary:\n");
  response.add(absl::StrFormat("  Total Connections: %d\n", stats.total_connections));
  response.add(absl::StrFormat("  Healthy: %d\n", stats.healthy_connections));
  response.add(absl::StrFormat("  Unhealthy: %d\n", stats.unhealthy_connections));
  response.add(absl::StrFormat("  Unique Nodes: %d\n", stats.nodes_count.size()));
  response.add(absl::StrFormat("  Unique Clusters: %d\n", stats.clusters_count.size()));
  response.add(absl::StrFormat("  Unique Tenants: %d\n\n", stats.tenants_count.size()));

  // Connections by cluster.
  if (!stats.clusters_count.empty()) {
    response.add("Connections by Cluster:\n");
    for (const auto& [cluster, count] : stats.clusters_count) {
      response.add(absl::StrFormat("  %s: %d\n", cluster, count));
    }
    response.add("\n");
  }

  // Connections by tenant.
  if (!stats.tenants_count.empty()) {
    response.add("Connections by Tenant:\n");
    for (const auto& [tenant, count] : stats.tenants_count) {
      response.add(absl::StrFormat("  %s: %d\n", tenant, count));
    }
    response.add("\n");
  }

  // Connection details.
  if (!params.aggregate_only_ && !stats.connections.empty()) {
    response.add("Connection Details:\n");
    response.add("NodeID | ClusterID | TenantID | Remote -> Local | Health | Worker\n");
    response.add("-------|-----------|----------|-----------------|--------|-------\n");
    for (const auto& conn : stats.connections) {
      response.add(absl::StrFormat(
          "%s | %s | %s -> %s | %s | %s\n", conn.node_id, conn.cluster_id, conn.remote_address,
          conn.local_address, conn.is_healthy ? "HEALTHY" : "UNHEALTHY", conn.worker_thread_name));
    }
  }
}

void ReverseTunnelsHandler::formatPrometheusResponse(const AggregatedStats& stats,
                                                     Buffer::Instance& response,
                                                     const ReverseTunnelParams& /* params */) {
  // Total connections.
  response.add("# HELP envoy_reverse_tunnels_total Total number of reverse tunnel connections\n");
  response.add("# TYPE envoy_reverse_tunnels_total gauge\n");
  response.add(absl::StrFormat("envoy_reverse_tunnels_total %d\n\n", stats.total_connections));

  // Healthy connections.
  response.add(
      "# HELP envoy_reverse_tunnels_healthy Number of healthy reverse tunnel connections\n");
  response.add("# TYPE envoy_reverse_tunnels_healthy gauge\n");
  response.add(absl::StrFormat("envoy_reverse_tunnels_healthy %d\n\n", stats.healthy_connections));

  // Unhealthy connections.
  response.add(
      "# HELP envoy_reverse_tunnels_unhealthy Number of unhealthy reverse tunnel connections\n");
  response.add("# TYPE envoy_reverse_tunnels_unhealthy gauge\n");
  response.add(
      absl::StrFormat("envoy_reverse_tunnels_unhealthy %d\n\n", stats.unhealthy_connections));

  // By cluster.
  if (!stats.clusters_count.empty()) {
    response.add("# HELP envoy_reverse_tunnels_by_cluster Reverse tunnel connections by cluster\n");
    response.add("# TYPE envoy_reverse_tunnels_by_cluster gauge\n");
    for (const auto& [cluster, count] : stats.clusters_count) {
      response.add(
          absl::StrFormat("envoy_reverse_tunnels_by_cluster{cluster=\"%s\"} %d\n", cluster, count));
    }
    response.add("\n");
  }

  // By node.
  if (!stats.nodes_count.empty()) {
    response.add("# HELP envoy_reverse_tunnels_by_node Reverse tunnel connections by node\n");
    response.add("# TYPE envoy_reverse_tunnels_by_node gauge\n");
    for (const auto& [node, count] : stats.nodes_count) {
      response.add(absl::StrFormat("envoy_reverse_tunnels_by_node{node=\"%s\"} %d\n", node, count));
    }
    response.add("\n");
  }

  // Tenant-based metrics are not emitted.
}

std::vector<ReverseTunnelsHandler::ConnectionInfo>
ReverseTunnelsHandler::filterConnections(const std::vector<ConnectionInfo>& connections,
                                         const ReverseTunnelParams& params) {
  std::vector<ConnectionInfo> filtered;
  filtered.reserve(connections.size());

  for (const auto& conn : connections) {
    // Use the comprehensive filtering logic from ReverseTunnelParams.
    if (params.shouldShowConnection(conn.node_id, conn.cluster_id, conn.is_healthy,
                                    conn.established_time)) {
      filtered.push_back(conn);
    }
  }

  return filtered;
}

void ReverseTunnelsHandler::sortConnections(std::vector<ConnectionInfo>& connections,
                                            const ReverseTunnelParams& params) {
  const bool desc = params.sort_descending_;

  switch (params.sort_by_) {
  case SortField::NodeId:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.node_id > b.node_id) : (a.node_id < b.node_id);
              });
    break;
  case SortField::ClusterId:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.cluster_id > b.cluster_id) : (a.cluster_id < b.cluster_id);
              });
    break;
  // TenantId sort is not supported.
  case SortField::EstablishedTime:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.established_time > b.established_time)
                            : (a.established_time < b.established_time);
              });
    break;
  case SortField::LastActivity:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.last_activity > b.last_activity)
                            : (a.last_activity < b.last_activity);
              });
    break;
  case SortField::PingLatency:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.average_ping_latency > b.average_ping_latency)
                            : (a.average_ping_latency < b.average_ping_latency);
              });
    break;
  case SortField::Failures:
    std::sort(connections.begin(), connections.end(),
              [desc](const ConnectionInfo& a, const ConnectionInfo& b) {
                return desc ? (a.consecutive_ping_failures > b.consecutive_ping_failures)
                            : (a.consecutive_ping_failures < b.consecutive_ping_failures);
              });
    break;
  }
}

std::string
ReverseTunnelsHandler::formatTimestamp(const std::chrono::system_clock::time_point& time_point) {
  std::time_t time = std::chrono::system_clock::to_time_t(time_point);
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

} // namespace Server
} // namespace Envoy
