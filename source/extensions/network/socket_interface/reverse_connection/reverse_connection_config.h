#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/exception.h"

#include "source/common/common/fmt.h"
#include "source/common/common/logger.h"

#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Production-grade configuration for reverse connections with validation.
 */
class ReverseConnectionConfig : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  struct ClusterConnectionConfig {
    std::string cluster_name;
    uint32_t connection_count;
    std::chrono::milliseconds connection_timeout{std::chrono::seconds(30)};
    std::chrono::milliseconds retry_interval{std::chrono::seconds(5)};
    uint32_t max_retries{3};

    void validate() const {
      if (cluster_name.empty()) {
        throw EnvoyException("cluster_name cannot be empty");
      }
      if (connection_count == 0 || connection_count > 1000) {
        throw EnvoyException("connection_count must be between 1 and 1000");
      }
      if (connection_timeout.count() <= 0) {
        throw EnvoyException("connection_timeout must be positive");
      }
    }
  };

  struct ConnectionLimits {
    uint32_t max_total_connections{10000};
    uint32_t max_connections_per_cluster{1000};
    uint32_t descriptor_pool_size{100};
    std::chrono::milliseconds descriptor_idle_timeout{std::chrono::minutes(5)};
  };

  struct SecurityConfig {
    bool enable_connection_verification{true};
    bool require_cluster_authentication{true};
    std::string authentication_token;
    std::chrono::milliseconds handshake_timeout{std::chrono::seconds(10)};
  };

  // Core configuration
  std::string source_cluster_id;
  std::string source_node_id;
  std::string source_tenant_id;
  std::vector<ClusterConnectionConfig> remote_clusters;

  // Performance and limits
  ConnectionLimits limits;
  SecurityConfig security;

  // Advanced settings
  bool enable_health_checks{true};
  bool enable_metrics{true};
  bool enable_connection_pooling{true};
  std::chrono::milliseconds stats_flush_interval{std::chrono::seconds(30)};

  /**
   * Validate the entire configuration.
   */
  void validate() const {
    if (source_cluster_id.empty()) {
      throw EnvoyException("source_cluster_id is required");
    }

    if (remote_clusters.empty()) {
      throw EnvoyException("at least one remote cluster must be configured");
    }

    uint32_t total_connections = 0;
    for (const auto& cluster : remote_clusters) {
      cluster.validate();
      total_connections += cluster.connection_count;

      if (cluster.connection_count > limits.max_connections_per_cluster) {
        throw EnvoyException(fmt::format(
            "Cluster {} exceeds max connections per cluster limit: {} > {}", cluster.cluster_name,
            cluster.connection_count, limits.max_connections_per_cluster));
      }
    }

    if (total_connections > limits.max_total_connections) {
      throw EnvoyException(fmt::format("Total connections {} exceeds limit {}", total_connections,
                                       limits.max_total_connections));
    }

    ENVOY_LOG(info,
              "ReverseConnectionConfig validated successfully - {} clusters, {} total connections",
              remote_clusters.size(), total_connections);
  }

  /**
   * Get configuration summary for logging.
   */
  std::string getSummary() const {
    return fmt::format("ReverseConnectionConfig[source={}, clusters={}, total_connections={}]",
                       source_cluster_id, remote_clusters.size(), getTotalConnectionCount());
  }

private:
  uint32_t getTotalConnectionCount() const {
    uint32_t total = 0;
    for (const auto& cluster : remote_clusters) {
      total += cluster.connection_count;
    }
    return total;
  }
};

/**
 * Statistics collector for reverse connections.
 */
class ReverseConnectionStats : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  struct ConnectionMetrics {
    uint64_t connections_established{0};
    uint64_t connections_failed{0};
    uint64_t connections_active{0};
    uint64_t bytes_transferred{0};
    uint64_t descriptors_reused{0};
    uint64_t fallback_connections{0};
  };

  void recordConnectionEstablished() { ++metrics_.connections_established; }
  void recordConnectionFailed() { ++metrics_.connections_failed; }
  void recordConnectionActive() { ++metrics_.connections_active; }
  void recordConnectionClosed() { --metrics_.connections_active; }
  void recordBytesTransferred(uint64_t bytes) { metrics_.bytes_transferred += bytes; }
  void recordDescriptorReused() { ++metrics_.descriptors_reused; }
  void recordFallbackConnection() { ++metrics_.fallback_connections; }

  const ConnectionMetrics& getMetrics() const { return metrics_; }

  void logStats() const {
    ENVOY_LOG(info,
              "ReverseConnection Stats - Established: {}, Failed: {}, Active: {}, "
              "BytesTransferred: {}, DescriptorsReused: {}, Fallbacks: {}",
              metrics_.connections_established, metrics_.connections_failed,
              metrics_.connections_active, metrics_.bytes_transferred, metrics_.descriptors_reused,
              metrics_.fallback_connections);
  }

private:
  ConnectionMetrics metrics_;
  mutable absl::Mutex stats_mutex_;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
