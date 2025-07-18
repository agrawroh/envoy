#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "envoy/server/health_checker_config.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"
#include "source/common/http/header_map_impl.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// Forward declarations
class ReverseTunnelAcceptorExtension;
class ReverseTunnelInitiatorExtension;

/**
 * Health status enumeration for reverse tunnel components.
 */
enum class HealthStatus {
  Healthy,   // Component is functioning normally
  Degraded,  // Component is functioning but with reduced performance
  Unhealthy, // Component has issues that need attention
  Critical,  // Component is failing and requires immediate action
  Unknown    // Health status cannot be determined
};

/**
 * Health check result for reverse tunnel operations.
 */
struct HealthCheckResult {
  HealthStatus status;
  std::string component_name;
  std::string status_message;
  std::chrono::steady_clock::time_point check_time;
  std::vector<std::string> details;
  absl::flat_hash_map<std::string, std::string> metrics;
};

/**
 * Health check configuration for reverse tunnel monitoring.
 */
struct HealthCheckConfig {
  std::chrono::seconds check_interval{30};     // How often to perform health checks
  std::chrono::seconds timeout{5};             // Timeout for individual health checks
  uint32_t consecutive_failures_threshold{3};  // Number of failures before marking unhealthy
  uint32_t consecutive_successes_threshold{2}; // Number of successes to mark healthy again
  bool enable_deep_checks{true};               // Enable comprehensive health checks
  bool enable_connectivity_checks{true};       // Enable connectivity verification
  bool enable_performance_checks{true};        // Enable performance monitoring
};

/**
 * Health checker for reverse tunnel acceptor operations.
 * Monitors the health and performance of the acceptor component.
 */
class ReverseTunnelAcceptorHealthChecker : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Constructor for ReverseTunnelAcceptorHealthChecker.
   * @param extension reference to the acceptor extension
   * @param config health check configuration
   */
  ReverseTunnelAcceptorHealthChecker(ReverseTunnelAcceptorExtension& extension,
                                     const HealthCheckConfig& config);

  ~ReverseTunnelAcceptorHealthChecker() = default;

  /**
   * Perform comprehensive health check of the acceptor.
   * @return health check result with detailed status
   */
  HealthCheckResult performHealthCheck();

  /**
   * Check thread local storage health.
   * @return health status and details
   */
  std::pair<HealthStatus, std::string> checkThreadLocalHealth();

  /**
   * Check socket manager health across all threads.
   * @return health status and details
   */
  std::pair<HealthStatus, std::string> checkSocketManagerHealth();

  /**
   * Check connection statistics and performance.
   * @return health status and performance metrics
   */
  std::pair<HealthStatus, absl::flat_hash_map<std::string, std::string>> checkConnectionStats();

  /**
   * Check stats system integration.
   * @return health status and stats details
   */
  std::pair<HealthStatus, std::string> checkStatsIntegration();

  /**
   * Check memory usage and resource consumption.
   * @return health status and resource metrics
   */
  std::pair<HealthStatus, absl::flat_hash_map<std::string, std::string>> checkResourceUsage();

  /**
   * Perform connectivity test by attempting to process a test connection.
   * @return health status and connectivity details
   */
  std::pair<HealthStatus, std::string> performConnectivityTest();

private:
  /**
   * Evaluate performance metrics against thresholds.
   * @param metrics current performance metrics
   * @return health status based on performance
   */
  HealthStatus
  evaluatePerformanceMetrics(const absl::flat_hash_map<std::string, std::string>& metrics);

  /**
   * Check for resource leaks or excessive usage.
   * @return true if resource usage is within acceptable limits
   */
  bool checkResourceLeaks();

  ReverseTunnelAcceptorExtension& extension_;
  HealthCheckConfig config_;
  uint32_t consecutive_failures_{0};
  uint32_t consecutive_successes_{0};
  HealthStatus last_status_{HealthStatus::Unknown};
};

/**
 * Health checker for reverse tunnel initiator operations.
 * Monitors the health and performance of the initiator component.
 */
class ReverseTunnelInitiatorHealthChecker : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Constructor for ReverseTunnelInitiatorHealthChecker.
   * @param extension reference to the initiator extension
   * @param config health check configuration
   */
  ReverseTunnelInitiatorHealthChecker(ReverseTunnelInitiatorExtension& extension,
                                      const HealthCheckConfig& config);

  ~ReverseTunnelInitiatorHealthChecker() = default;

  /**
   * Perform comprehensive health check of the initiator.
   * @return health check result with detailed status
   */
  HealthCheckResult performHealthCheck();

  /**
   * Check thread local registry health.
   * @return health status and details
   */
  std::pair<HealthStatus, std::string> checkThreadLocalHealth();

  /**
   * Check cluster manager connectivity.
   * @return health status and cluster details
   */
  std::pair<HealthStatus, std::string> checkClusterConnectivity();

  /**
   * Check reverse connection establishment capabilities.
   * @return health status and connection details
   */
  std::pair<HealthStatus, std::string> checkReverseConnectionCapability();

  /**
   * Check socket interface health.
   * @return health status and socket interface details
   */
  std::pair<HealthStatus, std::string> checkSocketInterfaceHealth();

  /**
   * Perform end-to-end connectivity test.
   * @return health status and test results
   */
  std::pair<HealthStatus, std::string> performEndToEndTest();

private:
  /**
   * Test socket creation functionality.
   * @return true if socket creation works correctly
   */
  bool testSocketCreation();

  /**
   * Check dispatcher availability and health.
   * @return true if dispatcher is available and functional
   */
  bool checkDispatcherHealth();

  ReverseTunnelInitiatorExtension& extension_;
  HealthCheckConfig config_;
  uint32_t consecutive_failures_{0};
  uint32_t consecutive_successes_{0};
  HealthStatus last_status_{HealthStatus::Unknown};
};

/**
 * Comprehensive health monitor for the entire reverse tunnel system.
 * Coordinates health checks across all components and provides system-wide health status.
 */
class ReverseTunnelSystemHealthMonitor : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Constructor for ReverseTunnelSystemHealthMonitor.
   * @param config health check configuration
   */
  explicit ReverseTunnelSystemHealthMonitor(const HealthCheckConfig& config);

  ~ReverseTunnelSystemHealthMonitor() = default;

  /**
   * Register an acceptor component for health monitoring.
   * @param name component name
   * @param extension acceptor extension to monitor
   */
  void registerAcceptor(const std::string& name, ReverseTunnelAcceptorExtension& extension);

  /**
   * Register an initiator component for health monitoring.
   * @param name component name
   * @param extension initiator extension to monitor
   */
  void registerInitiator(const std::string& name, ReverseTunnelInitiatorExtension& extension);

  /**
   * Perform system-wide health check.
   * @return overall system health status and detailed results
   */
  std::pair<HealthStatus, std::vector<HealthCheckResult>> performSystemHealthCheck();

  /**
   * Get health check results for a specific component.
   * @param component_name name of the component
   * @return health check result or nullptr if not found
   */
  std::unique_ptr<HealthCheckResult> getComponentHealth(const std::string& component_name);

  /**
   * Get overall system health status.
   * @return current system health status
   */
  HealthStatus getSystemHealthStatus();

  /**
   * Generate health report for monitoring systems.
   * @return detailed health report in structured format
   */
  std::string generateHealthReport();

  /**
   * Check if system is ready to handle traffic.
   * @return true if system is ready for production traffic
   */
  bool isSystemReady();

  /**
   * Enable or disable automatic health checking.
   * @param enabled whether to enable automatic checks
   */
  void setAutomaticHealthChecking(bool enabled);

  /**
   * Start automatic health checking with configured intervals.
   */
  void startAutomaticHealthChecking();

  /**
   * Stop automatic health checking.
   */
  void stopAutomaticHealthChecking();

private:
  /**
   * Determine overall system health from component health results.
   * @param results individual component health results
   * @return overall system health status
   */
  HealthStatus determineOverallHealth(const std::vector<HealthCheckResult>& results);

  /**
   * Log health check results for debugging and monitoring.
   * @param results health check results to log
   */
  void logHealthResults(const std::vector<HealthCheckResult>& results);

  /**
   * Update health metrics in stats system.
   * @param results health check results
   */
  void updateHealthMetrics(const std::vector<HealthCheckResult>& results);

  HealthCheckConfig config_;

  // Component health checkers
  absl::flat_hash_map<std::string, std::unique_ptr<ReverseTunnelAcceptorHealthChecker>>
      acceptor_checkers_;
  absl::flat_hash_map<std::string, std::unique_ptr<ReverseTunnelInitiatorHealthChecker>>
      initiator_checkers_;

  // Health tracking
  absl::flat_hash_map<std::string, HealthCheckResult> last_results_;
  HealthStatus overall_health_{HealthStatus::Unknown};

  // Automatic health checking
  bool automatic_checking_enabled_{false};
  std::unique_ptr<Event::Timer> health_check_timer_;

  // Thread safety
  mutable absl::Mutex health_mutex_;
};

/**
 * Health check utilities for reverse tunnel diagnostics.
 */
class HealthCheckUtils {
public:
  /**
   * Convert health status to string representation.
   * @param status health status to convert
   * @return string representation of the status
   */
  static std::string healthStatusToString(HealthStatus status);

  /**
   * Convert string to health status.
   * @param status_str string representation of health status
   * @return health status enum value
   */
  static HealthStatus stringToHealthStatus(const std::string& status_str);

  /**
   * Create HTTP response for health check endpoint.
   * @param result health check result
   * @return HTTP response headers and body
   */
  static std::pair<Http::ResponseHeaderMapPtr, std::string>
  createHealthCheckResponse(const HealthCheckResult& result);

  /**
   * Validate health check configuration.
   * @param config configuration to validate
   * @return validation status and error message if any
   */
  static std::pair<bool, std::string> validateConfig(const HealthCheckConfig& config);

  /**
   * Create default health check configuration.
   * @return default configuration with reasonable values
   */
  static HealthCheckConfig createDefaultConfig();

  /**
   * Parse health check configuration from JSON.
   * @param json_config JSON configuration string
   * @return parsed configuration or error status
   */
  static absl::StatusOr<HealthCheckConfig> parseConfigFromJson(const std::string& json_config);

  /**
   * Export health check configuration to JSON.
   * @param config configuration to export
   * @return JSON representation of the configuration
   */
  static std::string exportConfigToJson(const HealthCheckConfig& config);
};

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
