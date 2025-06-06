#pragma once

#include <chrono>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>

#include "envoy/api/io_error.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"
#include "envoy/singleton/instance.h"
#include "envoy/singleton/manager.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/network/io_socket_handle_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

/**
 * Configuration for socket handoff connection pools
 */
struct SocketHandoffPoolConfig {
  uint32_t max_connections_per_cluster{10};
  uint32_t min_connections_per_cluster{2};
  std::chrono::milliseconds connection_idle_timeout{std::chrono::minutes(5)};
  std::chrono::milliseconds connection_max_lifetime{std::chrono::hours(1)};
  std::chrono::milliseconds health_check_interval{std::chrono::seconds(30)};
  bool enable_preconnect{true};
  float preconnect_ratio{0.8f};
};

/**
 * Represents a pre-established connection with metadata
 */
class HandoffConnection {
public:
  HandoffConnection(Network::ClientConnectionPtr connection,
                    std::chrono::steady_clock::time_point created_time);
  ~HandoffConnection();

  Network::Connection* connection() const { return connection_.get(); }
  std::chrono::steady_clock::time_point createdTime() const { return created_time_; }
  std::chrono::steady_clock::time_point lastUsedTime() const { return last_used_time_; }

  void markUsed() { last_used_time_ = std::chrono::steady_clock::now(); }
  bool isIdle(std::chrono::milliseconds idle_timeout) const;
  bool isExpired(std::chrono::milliseconds max_lifetime) const;
  bool isHealthy() const;

  // Transfer ownership of the connection
  Network::ClientConnectionPtr release();

private:
  Network::ClientConnectionPtr connection_;
  std::chrono::steady_clock::time_point created_time_;
  std::chrono::steady_clock::time_point last_used_time_;
};

using HandoffConnectionPtr = std::unique_ptr<HandoffConnection>;

/**
 * Per-cluster connection pool for socket handoff optimization
 */
class ClusterConnectionPool : public Logger::Loggable<Logger::Id::connection> {
public:
  ClusterConnectionPool(const std::string& cluster_name, const SocketHandoffPoolConfig& config,
                        Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher);
  ~ClusterConnectionPool();

  // Get an available connection or nullptr if none available
  Network::ClientConnectionPtr getConnection();

  // Return a connection to the pool (if it's still healthy)
  void returnConnection(Network::ClientConnectionPtr connection);

  // Ensure minimum number of connections are available
  void ensureMinConnections();

  // Preconnect additional connections based on load
  void preconnectIfNeeded();

  // Cleanup idle and expired connections
  void cleanupConnections();

  // Get pool statistics
  struct PoolStats {
    uint32_t available_connections;
    uint32_t active_connections;
    uint32_t total_connections_created;
    uint32_t total_connections_reused;
    uint32_t total_connections_expired;
  };
  PoolStats getStats() const;

private:
  void createNewConnection() ABSL_EXCLUSIVE_LOCKS_REQUIRED(pool_mutex_);
  void scheduleHealthCheck();
  void performHealthCheck();
  bool shouldCreateConnection() const;

  const std::string cluster_name_;
  const SocketHandoffPoolConfig config_;
  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;

  mutable absl::Mutex pool_mutex_;
  std::queue<HandoffConnectionPtr> available_connections_ ABSL_GUARDED_BY(pool_mutex_);
  absl::flat_hash_map<Network::Connection*, std::chrono::steady_clock::time_point>
      active_connections_ ABSL_GUARDED_BY(pool_mutex_);

  // Statistics
  mutable absl::Mutex stats_mutex_;
  uint32_t total_connections_created_ ABSL_GUARDED_BY(stats_mutex_){0};
  uint32_t total_connections_reused_ ABSL_GUARDED_BY(stats_mutex_){0};
  uint32_t total_connections_expired_ ABSL_GUARDED_BY(stats_mutex_){0};

  Event::TimerPtr health_check_timer_;
};

/**
 * Global socket handoff manager singleton for optimal connection reuse
 * Follows Envoy's established singleton pattern with Singleton::Instance
 */
class SocketHandoffManager : public Singleton::Instance,
                             public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Get singleton instance via Envoy's Singleton::Manager
   * This is the proper Envoy pattern for singleton access
   */
  static std::shared_ptr<SocketHandoffManager> singleton(Singleton::Manager& singleton_manager);

  SocketHandoffManager();
  ~SocketHandoffManager() override = default;

  // Configuration management
  void configureClusterPool(const std::string& cluster_name, const SocketHandoffPoolConfig& config);

  // Connection pool management with dispatcher-aware pooling
  std::shared_ptr<ClusterConnectionPool>
  getConnectionPool(const std::string& cluster_name, Upstream::ClusterManager& cluster_manager,
                    Event::Dispatcher& dispatcher);

  // Direct connection optimization
  Network::ClientConnectionPtr getOptimizedConnection(const std::string& cluster_name);

  // Connection return for reuse (dispatcher-aware)
  void returnConnection(const std::string& cluster_name, Network::ClientConnectionPtr connection);

  // Helper overload for explicit dispatcher specification
  void returnConnection(const std::string& cluster_name, Network::ClientConnectionPtr connection,
                        Event::Dispatcher& dispatcher);

  // Preconnect optimization
  void preconnectForCluster(const std::string& cluster_name, uint32_t expected_connections);

  // Maintenance and stats
  void performMaintenance();

  // Get aggregate statistics across all pools
  struct GlobalStats {
    uint32_t total_pools;
    uint32_t total_available_connections;
    uint32_t total_active_connections;
    uint32_t total_reused_connections;
    float average_pool_utilization;
  };
  GlobalStats getGlobalStats() const;

private:
  // Create dispatcher-aware pool key for thread safety
  std::string createPoolKey(const std::string& cluster_name, Event::Dispatcher& dispatcher) const;

  mutable absl::Mutex pools_mutex_;
  // Use dispatcher-aware keys to prevent cross-thread connection usage
  absl::flat_hash_map<std::string, std::shared_ptr<ClusterConnectionPool>>
      cluster_pools_ ABSL_GUARDED_BY(pools_mutex_);
  absl::flat_hash_map<std::string, SocketHandoffPoolConfig>
      cluster_configs_ ABSL_GUARDED_BY(pools_mutex_);

  Event::TimerPtr maintenance_timer_;
  static constexpr std::chrono::milliseconds MAINTENANCE_INTERVAL{std::chrono::minutes(1)};
};

/**
 * Socket handoff-optimized IO handle that uses pre-established connections
 */
class HandoffOptimizedIOHandle : public Network::IoSocketHandleImpl {
public:
  HandoffOptimizedIOHandle(os_fd_t fd, const std::string& cluster_name);
  ~HandoffOptimizedIOHandle() override;

  // Override connect to use pre-established connection
  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr address) override;

  // Override close to return connection to pool if possible
  Api::IoCallUint64Result close() override;

private:
  const std::string cluster_name_;
  bool connection_reused_{false};
};

/**
 * Factory for creating handoff-optimized connections
 */
class HandoffConnectionFactory : public Logger::Loggable<Logger::Id::connection> {
public:
  static Network::ClientConnectionPtr createOptimizedConnection(
      const std::string& cluster_name, Upstream::ClusterManager& cluster_manager,
      Event::Dispatcher& dispatcher, Network::Address::InstanceConstSharedPtr address);

  static std::unique_ptr<HandoffOptimizedIOHandle>
  createOptimizedIOHandle(const std::string& cluster_name);
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
