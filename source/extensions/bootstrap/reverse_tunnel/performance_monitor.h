#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

/**
 * Performance metrics for reverse tunnel operations.
 * Provides comprehensive monitoring and analysis of reverse connection performance.
 */
#define ALL_REVERSE_TUNNEL_PERFORMANCE_STATS(COUNTER, GAUGE, HISTOGRAM)                            \
  COUNTER(connection_attempts)                                                                     \
  COUNTER(connection_successes)                                                                    \
  COUNTER(connection_failures)                                                                     \
  COUNTER(handshake_attempts)                                                                      \
  COUNTER(handshake_successes)                                                                     \
  COUNTER(handshake_failures)                                                                      \
  COUNTER(tunnel_establishes)                                                                      \
  COUNTER(tunnel_closures)                                                                         \
  COUNTER(ping_requests)                                                                           \
  COUNTER(ping_responses)                                                                          \
  COUNTER(ping_timeouts)                                                                           \
  GAUGE(active_connections, Accumulate)                                                            \
  GAUGE(active_tunnels, Accumulate)                                                                \
  GAUGE(queued_connections, Accumulate)                                                            \
  GAUGE(memory_usage_bytes, Accumulate)                                                            \
  HISTOGRAM(connection_establishment_time, Milliseconds)                                           \
  HISTOGRAM(handshake_duration, Milliseconds)                                                      \
  HISTOGRAM(tunnel_lifetime, Seconds)                                                              \
  HISTOGRAM(ping_response_time, Milliseconds)                                                      \
  HISTOGRAM(throughput_bytes_per_second, Units)                                                    \
  HISTOGRAM(queue_depth, Units)

/**
 * Struct definition for reverse tunnel performance stats.
 */
struct ReverseTunnelPerformanceStats {
  ALL_REVERSE_TUNNEL_PERFORMANCE_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                                       GENERATE_HISTOGRAM_STRUCT)
};

using ReverseTunnelPerformanceStatsPtr = std::unique_ptr<ReverseTunnelPerformanceStats>;

/**
 * Performance metrics collector for reverse tunnel operations.
 */
class PerformanceMetrics {
public:
  struct ConnectionMetrics {
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point handshake_complete_time;
    std::chrono::steady_clock::time_point tunnel_established_time;
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    uint32_t ping_count{0};
    uint32_t ping_failures{0};
    std::chrono::milliseconds avg_ping_time{0};
  };

  struct TunnelMetrics {
    std::chrono::steady_clock::time_point creation_time;
    uint64_t connections_processed{0};
    uint64_t total_bytes_transferred{0};
    uint32_t current_connections{0};
    uint32_t max_concurrent_connections{0};
  };

private:
  // Connection-level metrics
  absl::flat_hash_map<std::string, ConnectionMetrics> connection_metrics_;
  // Tunnel-level metrics
  absl::flat_hash_map<std::string, TunnelMetrics> tunnel_metrics_;
  // Thread safety
  mutable absl::Mutex metrics_mutex_;
};

/**
 * Performance monitor for reverse tunnel operations.
 * Provides real-time monitoring, alerting, and analysis capabilities.
 */
class ReverseTunnelPerformanceMonitor : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Constructor for ReverseTunnelPerformanceMonitor.
   * @param scope the stats scope for metrics collection
   * @param component_name name of the component being monitored (acceptor/initiator)
   */
  ReverseTunnelPerformanceMonitor(Stats::Scope& scope, const std::string& component_name);

  ~ReverseTunnelPerformanceMonitor() = default;

  /**
   * Record connection attempt.
   * @param connection_id unique identifier for the connection
   * @param cluster_name name of the target cluster
   * @param node_id identifier of the target node
   */
  void recordConnectionAttempt(const std::string& connection_id, const std::string& cluster_name,
                               const std::string& node_id);

  /**
   * Record successful connection establishment.
   * @param connection_id unique identifier for the connection
   * @param establishment_time time taken to establish the connection
   */
  void recordConnectionSuccess(const std::string& connection_id,
                               std::chrono::milliseconds establishment_time);

  /**
   * Record connection failure.
   * @param connection_id unique identifier for the connection
   * @param failure_reason reason for the connection failure
   */
  void recordConnectionFailure(const std::string& connection_id, const std::string& failure_reason);

  /**
   * Record handshake attempt.
   * @param connection_id unique identifier for the connection
   */
  void recordHandshakeAttempt(const std::string& connection_id);

  /**
   * Record successful handshake completion.
   * @param connection_id unique identifier for the connection
   * @param handshake_duration time taken for handshake
   */
  void recordHandshakeSuccess(const std::string& connection_id,
                              std::chrono::milliseconds handshake_duration);

  /**
   * Record handshake failure.
   * @param connection_id unique identifier for the connection
   * @param failure_reason reason for the handshake failure
   */
  void recordHandshakeFailure(const std::string& connection_id, const std::string& failure_reason);

  /**
   * Record tunnel establishment.
   * @param tunnel_id unique identifier for the tunnel
   * @param connection_id associated connection identifier
   */
  void recordTunnelEstablishment(const std::string& tunnel_id, const std::string& connection_id);

  /**
   * Record tunnel closure.
   * @param tunnel_id unique identifier for the tunnel
   * @param lifetime duration the tunnel was active
   * @param closure_reason reason for tunnel closure
   */
  void recordTunnelClosure(const std::string& tunnel_id, std::chrono::seconds lifetime,
                           const std::string& closure_reason);

  /**
   * Record ping request.
   * @param connection_id unique identifier for the connection
   */
  void recordPingRequest(const std::string& connection_id);

  /**
   * Record ping response.
   * @param connection_id unique identifier for the connection
   * @param response_time time taken for ping response
   */
  void recordPingResponse(const std::string& connection_id,
                          std::chrono::milliseconds response_time);

  /**
   * Record ping timeout.
   * @param connection_id unique identifier for the connection
   */
  void recordPingTimeout(const std::string& connection_id);

  /**
   * Record data transfer metrics.
   * @param connection_id unique identifier for the connection
   * @param bytes_sent number of bytes sent
   * @param bytes_received number of bytes received
   */
  void recordDataTransfer(const std::string& connection_id, uint64_t bytes_sent,
                          uint64_t bytes_received);

  /**
   * Update queue depth metrics.
   * @param queue_depth current depth of connection queue
   */
  void updateQueueDepth(uint32_t queue_depth);

  /**
   * Update memory usage metrics.
   * @param memory_bytes current memory usage in bytes
   */
  void updateMemoryUsage(uint64_t memory_bytes);

  /**
   * Get performance summary for the monitored component.
   * @return performance summary string
   */
  std::string getPerformanceSummary() const;

  /**
   * Get detailed performance report.
   * @return detailed performance analysis
   */
  std::string getDetailedPerformanceReport() const;

  /**
   * Check if performance thresholds are exceeded.
   * @return true if any critical thresholds are exceeded
   */
  bool checkPerformanceThresholds() const;

  /**
   * Reset performance counters.
   */
  void resetCounters();

  /**
   * Export performance metrics for external monitoring systems.
   * @return map of metric names to values
   */
  absl::flat_hash_map<std::string, double> exportMetrics() const;

private:
  /**
   * Calculate throughput metrics.
   * @return current throughput in bytes per second
   */
  double calculateThroughput() const;

  /**
   * Calculate average connection establishment time.
   * @return average time in milliseconds
   */
  double calculateAverageConnectionTime() const;

  /**
   * Calculate success rate percentage.
   * @return success rate as percentage
   */
  double calculateSuccessRate() const;

  /**
   * Update gauge metrics.
   */
  void updateGaugeMetrics();

  /**
   * Log performance alerts if thresholds are exceeded.
   */
  void logPerformanceAlerts() const;

  // Component identification
  std::string component_name_;

  // Performance statistics
  ReverseTunnelPerformanceStatsPtr stats_;
  Stats::ScopeSharedPtr performance_scope_;

  // Metrics collection
  std::unique_ptr<PerformanceMetrics> metrics_;

  // Performance thresholds
  struct PerformanceThresholds {
    std::chrono::milliseconds max_connection_time{10000};   // 10 seconds
    std::chrono::milliseconds max_handshake_time{5000};     // 5 seconds
    std::chrono::milliseconds max_ping_response_time{1000}; // 1 second
    double min_success_rate{0.95};                          // 95%
    uint32_t max_queue_depth{100};                          // 100 connections
    uint64_t max_memory_usage{100 * 1024 * 1024};           // 100MB
  } thresholds_;

  // Performance tracking
  mutable absl::Mutex performance_mutex_;
  std::chrono::steady_clock::time_point start_time_;
  uint64_t total_bytes_processed_{0};
  uint32_t current_active_connections_{0};
  uint32_t current_active_tunnels_{0};
};

/**
 * Performance analysis utilities for reverse tunnel operations.
 */
class PerformanceAnalyzer : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Analyze connection patterns for optimization opportunities.
   * @param monitor the performance monitor to analyze
   * @return analysis report with recommendations
   */
  static std::string analyzeConnectionPatterns(const ReverseTunnelPerformanceMonitor& monitor);

  /**
   * Identify performance bottlenecks.
   * @param monitor the performance monitor to analyze
   * @return bottleneck analysis report
   */
  static std::string identifyBottlenecks(const ReverseTunnelPerformanceMonitor& monitor);

  /**
   * Generate performance optimization recommendations.
   * @param monitor the performance monitor to analyze
   * @return optimization recommendations
   */
  static std::string
  generateOptimizationRecommendations(const ReverseTunnelPerformanceMonitor& monitor);

  /**
   * Predict capacity requirements based on current metrics.
   * @param monitor the performance monitor to analyze
   * @param growth_factor expected growth factor
   * @return capacity planning report
   */
  static std::string predictCapacityRequirements(const ReverseTunnelPerformanceMonitor& monitor,
                                                 double growth_factor = 1.5);
};

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
