#include "source/extensions/filters/network/reverse_connection/reverse_connection_socket_handoff_manager.h"

#include "envoy/network/connection.h"
#include "envoy/singleton/manager.h"

#include "source/common/network/raw_buffer_socket.h"

#include "fmt/format.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

// Singleton registration via Envoy's established pattern
SINGLETON_MANAGER_REGISTRATION(socket_handoff_manager);

// Singleton factory method following Envoy conventions
std::shared_ptr<SocketHandoffManager>
SocketHandoffManager::singleton(Singleton::Manager& singleton_manager) {
  return singleton_manager.getTyped<SocketHandoffManager>(
      SINGLETON_MANAGER_REGISTERED_NAME(socket_handoff_manager),
      [] { return std::make_shared<SocketHandoffManager>(); });
}

// HandoffConnection implementation
HandoffConnection::HandoffConnection(Network::ClientConnectionPtr connection,
                                     std::chrono::steady_clock::time_point created_time)
    : connection_(std::move(connection)), created_time_(created_time),
      last_used_time_(created_time) {}

HandoffConnection::~HandoffConnection() {
  if (connection_) {
    connection_->close(Network::ConnectionCloseType::NoFlush);
  }
}

bool HandoffConnection::isIdle(std::chrono::milliseconds idle_timeout) const {
  auto now = std::chrono::steady_clock::now();
  return (now - last_used_time_) > idle_timeout;
}

bool HandoffConnection::isExpired(std::chrono::milliseconds max_lifetime) const {
  auto now = std::chrono::steady_clock::now();
  return (now - created_time_) > max_lifetime;
}

bool HandoffConnection::isHealthy() const {
  return connection_ && connection_->state() == Envoy::Network::Connection::State::Open &&
         !connection_->aboveHighWatermark();
}

Network::ClientConnectionPtr HandoffConnection::release() {
  markUsed();
  return std::move(connection_);
}

// ClusterConnectionPool implementation
ClusterConnectionPool::ClusterConnectionPool(const std::string& cluster_name,
                                             const SocketHandoffPoolConfig& config,
                                             Upstream::ClusterManager& cluster_manager,
                                             Event::Dispatcher& dispatcher)
    : cluster_name_(cluster_name), config_(config), cluster_manager_(cluster_manager),
      dispatcher_(dispatcher) {

  ENVOY_LOG(debug,
            "Creating ClusterConnectionPool for cluster: {} with max_connections: {}, "
            "min_connections: {}",
            cluster_name_, config_.max_connections_per_cluster,
            config_.min_connections_per_cluster);

  // Schedule periodic health checks
  scheduleHealthCheck();

  // Pre-establish minimum connections
  ensureMinConnections();
}

ClusterConnectionPool::~ClusterConnectionPool() {
  if (health_check_timer_) {
    health_check_timer_->disableTimer();
  }

  absl::MutexLock lock(&pool_mutex_);

  // Close all available connections
  while (!available_connections_.empty()) {
    available_connections_.pop();
  }

  ENVOY_LOG(debug, "Destroyed ClusterConnectionPool for cluster: {}", cluster_name_);
}

Network::ClientConnectionPtr ClusterConnectionPool::getConnection() {
  absl::MutexLock lock(&pool_mutex_);

  // Try to get a healthy connection from the pool
  while (!available_connections_.empty()) {
    auto& handoff_conn = available_connections_.front();

    if (handoff_conn->isHealthy() && !handoff_conn->isExpired(config_.connection_max_lifetime)) {

      auto connection = handoff_conn->release();
      available_connections_.pop();

      // Track as active connection
      active_connections_[connection.get()] = std::chrono::steady_clock::now();

      {
        absl::MutexLock stats_lock(&stats_mutex_);
        total_connections_reused_++;
      }

      ENVOY_LOG(debug, "Reusing existing connection for cluster: {} (pool size: {})", cluster_name_,
                available_connections_.size());
      return connection;
    } else {
      // Remove unhealthy/expired connection
      ENVOY_LOG(debug, "Removing unhealthy/expired connection from pool for cluster: {}",
                cluster_name_);
      available_connections_.pop();

      {
        absl::MutexLock stats_lock(&stats_mutex_);
        total_connections_expired_++;
      }
    }
  }

  ENVOY_LOG(debug, "No available connections in pool for cluster: {}, creating new connection",
            cluster_name_);
  return nullptr; // No available connections
}

void ClusterConnectionPool::returnConnection(Network::ClientConnectionPtr connection) {
  if (!connection || connection->state() != Envoy::Network::Connection::State::Open) {
    ENVOY_LOG(debug, "Cannot return unhealthy connection to pool for cluster: {}", cluster_name_);
    return;
  }

  absl::MutexLock lock(&pool_mutex_);

  // Remove from active connections
  active_connections_.erase(connection.get());

  // Check if we're at capacity
  if (available_connections_.size() >= config_.max_connections_per_cluster) {
    ENVOY_LOG(debug, "Pool at capacity for cluster: {}, closing returned connection",
              cluster_name_);
    connection->close(Network::ConnectionCloseType::NoFlush);
    return;
  }

  // Add to available pool
  auto handoff_conn =
      std::make_unique<HandoffConnection>(std::move(connection), std::chrono::steady_clock::now());
  available_connections_.push(std::move(handoff_conn));

  ENVOY_LOG(debug, "Returned connection to pool for cluster: {} (pool size: {})", cluster_name_,
            available_connections_.size());
}

void ClusterConnectionPool::ensureMinConnections() {
  absl::MutexLock lock(&pool_mutex_);

  uint32_t current_total = available_connections_.size() + active_connections_.size();
  uint32_t needed = config_.min_connections_per_cluster;

  if (current_total < needed) {
    uint32_t to_create = needed - current_total;
    ENVOY_LOG(debug, "Creating {} connections to reach minimum for cluster: {}", to_create,
              cluster_name_);

    for (uint32_t i = 0; i < to_create; ++i) {
      createNewConnection();
    }
  }
}

void ClusterConnectionPool::preconnectIfNeeded() {
  if (!config_.enable_preconnect) {
    return;
  }

  absl::MutexLock lock(&pool_mutex_);

  uint32_t current_available = available_connections_.size();
  uint32_t target_available =
      static_cast<uint32_t>(config_.max_connections_per_cluster * config_.preconnect_ratio);

  if (current_available < target_available) {
    uint32_t to_create = target_available - current_available;
    ENVOY_LOG(debug, "Preconnecting {} connections for cluster: {}", to_create, cluster_name_);

    for (uint32_t i = 0; i < to_create; ++i) {
      createNewConnection();
    }
  }
}

void ClusterConnectionPool::cleanupConnections() {
  absl::MutexLock lock(&pool_mutex_);

  std::queue<HandoffConnectionPtr> healthy_connections;
  uint32_t cleaned_up = 0;

  // Filter out idle and expired connections
  while (!available_connections_.empty()) {
    auto& handoff_conn = available_connections_.front();

    if (handoff_conn->isHealthy() && !handoff_conn->isIdle(config_.connection_idle_timeout) &&
        !handoff_conn->isExpired(config_.connection_max_lifetime)) {
      healthy_connections.push(std::move(handoff_conn));
    } else {
      cleaned_up++;
      {
        absl::MutexLock stats_lock(&stats_mutex_);
        total_connections_expired_++;
      }
    }
    available_connections_.pop();
  }

  available_connections_ = std::move(healthy_connections);

  if (cleaned_up > 0) {
    ENVOY_LOG(debug, "Cleaned up {} idle/expired connections for cluster: {} (remaining: {})",
              cleaned_up, cluster_name_, available_connections_.size());
  }
}

ClusterConnectionPool::PoolStats ClusterConnectionPool::getStats() const {
  absl::MutexLock pool_lock(&pool_mutex_);
  absl::MutexLock stats_lock(&stats_mutex_);

  return {.available_connections = static_cast<uint32_t>(available_connections_.size()),
          .active_connections = static_cast<uint32_t>(active_connections_.size()),
          .total_connections_created = total_connections_created_,
          .total_connections_reused = total_connections_reused_,
          .total_connections_expired = total_connections_expired_};
}

void ClusterConnectionPool::createNewConnection() {
  // CRITICAL DEADLOCK FIX: This method is called with pool_mutex_ already held by callers
  // (ensureMinConnections, preconnectIfNeeded), so we must NOT acquire it again

  auto cluster = cluster_manager_.getThreadLocalCluster(cluster_name_);
  if (!cluster) {
    ENVOY_LOG(error, "Cluster not found for preconnection: {}", cluster_name_);
    return;
  }

  Upstream::LoadBalancerContext* lb_context = nullptr;
  auto host_response = cluster->loadBalancer().chooseHost(lb_context);
  if (!host_response.host) {
    ENVOY_LOG(error, "No healthy hosts available for preconnection to cluster: {}", cluster_name_);
    return;
  }

  auto connection = dispatcher_.createClientConnection(
      host_response.host->address(), Network::Address::InstanceConstSharedPtr(),
      std::make_unique<Network::RawBufferSocket>(), nullptr, nullptr);

  if (!connection) {
    ENVOY_LOG(error, "Failed to create preconnection to cluster: {}", cluster_name_);
    return;
  }

  // Connect asynchronously
  connection->connect();

  auto handoff_conn =
      std::make_unique<HandoffConnection>(std::move(connection), std::chrono::steady_clock::now());

  // No mutex lock here - callers already hold pool_mutex_
  available_connections_.push(std::move(handoff_conn));

  {
    absl::MutexLock stats_lock(&stats_mutex_);
    total_connections_created_++;
  }

  ENVOY_LOG(debug, "Created new preconnection for cluster: {} (pool size: {})", cluster_name_,
            available_connections_.size());
}

void ClusterConnectionPool::scheduleHealthCheck() {
  health_check_timer_ = dispatcher_.createTimer([this]() { performHealthCheck(); });

  health_check_timer_->enableTimer(config_.health_check_interval);
}

void ClusterConnectionPool::performHealthCheck() {
  cleanupConnections();
  preconnectIfNeeded();
  ensureMinConnections();

  // Reschedule next health check
  health_check_timer_->enableTimer(config_.health_check_interval);
}

bool ClusterConnectionPool::shouldCreateConnection() const {
  absl::MutexLock pool_lock(&pool_mutex_);
  uint32_t current_total = available_connections_.size() + active_connections_.size();
  return current_total < config_.max_connections_per_cluster;
}

// SocketHandoffManager implementation
SocketHandoffManager::SocketHandoffManager() {
  ENVOY_LOG(info, "Initializing SocketHandoffManager singleton via Envoy pattern for optimized "
                  "connection reuse");
}

// Note: Destructor is private and will never be called for static singleton

std::shared_ptr<ClusterConnectionPool>
SocketHandoffManager::getConnectionPool(const std::string& cluster_name,
                                        Upstream::ClusterManager& cluster_manager,
                                        Event::Dispatcher& dispatcher) {

  absl::MutexLock lock(&pools_mutex_);

  // CRITICAL FIX: Use dispatcher-aware pool key to prevent cross-thread connection usage
  std::string pool_key = createPoolKey(cluster_name, dispatcher);

  auto it = cluster_pools_.find(pool_key);
  if (it != cluster_pools_.end()) {
    ENVOY_LOG(debug, "Reusing existing connection pool for cluster: {} on dispatcher: {}",
              cluster_name, static_cast<void*>(&dispatcher));
    return it->second;
  }

  // Get or create configuration for this cluster
  SocketHandoffPoolConfig config;
  auto config_it = cluster_configs_.find(cluster_name);
  if (config_it != cluster_configs_.end()) {
    config = config_it->second;
  }

  // Create new connection pool with dispatcher-aware key
  auto pool =
      std::make_shared<ClusterConnectionPool>(cluster_name, config, cluster_manager, dispatcher);
  cluster_pools_[pool_key] = pool;

  ENVOY_LOG(
      info,
      "Created new DISPATCHER-AWARE connection pool for cluster: {} on dispatcher: {} (key: {})",
      cluster_name, static_cast<void*>(&dispatcher), pool_key);
  return pool;
}

// CRITICAL: Create unique key combining cluster name + dispatcher pointer for thread safety
std::string SocketHandoffManager::createPoolKey(const std::string& cluster_name,
                                                Event::Dispatcher& dispatcher) const {
  // Use dispatcher pointer address to create unique key per thread
  return fmt::format("{}@{}", cluster_name, static_cast<void*>(&dispatcher));
}

void SocketHandoffManager::configureClusterPool(const std::string& cluster_name,
                                                const SocketHandoffPoolConfig& config) {
  absl::MutexLock lock(&pools_mutex_);
  cluster_configs_[cluster_name] = config;

  ENVOY_LOG(debug, "Configured connection pool for cluster: {} with max_connections: {}",
            cluster_name, config.max_connections_per_cluster);
}

Network::ClientConnectionPtr
SocketHandoffManager::getOptimizedConnection(const std::string& cluster_name) {
  // NOTE: This method is deprecated in favor of dispatcher-aware getConnectionPool()
  // It's kept for backward compatibility but will not work properly with cross-thread usage
  ENVOY_LOG(warn, "DEPRECATED: getOptimizedConnection() called without dispatcher - use "
                  "getConnectionPool() instead");

  absl::MutexLock lock(&pools_mutex_);

  // Try to find any pool for this cluster (without dispatcher filtering)
  for (const auto& [pool_key, pool] : cluster_pools_) {
    if (pool_key.find(cluster_name + "@") == 0) {
      ENVOY_LOG(debug, "Found connection pool for cluster: {} (may be cross-dispatcher)",
                cluster_name);
      return pool->getConnection();
    }
  }

  ENVOY_LOG(debug, "No connection pool found for cluster: {}", cluster_name);
  return nullptr;
}

void SocketHandoffManager::returnConnection(const std::string& cluster_name,
                                            Network::ClientConnectionPtr connection) {
  if (!connection) {
    return;
  }

  absl::MutexLock lock(&pools_mutex_);

  // CRITICAL FIX: Find the correct dispatcher-aware pool for this connection
  // We need to check which dispatcher the connection belongs to
  Event::Dispatcher* connection_dispatcher = &connection->dispatcher();
  std::string pool_key = createPoolKey(cluster_name, *connection_dispatcher);

  auto it = cluster_pools_.find(pool_key);
  if (it != cluster_pools_.end()) {
    ENVOY_LOG(debug,
              "Returning connection to DISPATCHER-AWARE pool for cluster: {} on dispatcher: {}",
              cluster_name, static_cast<void*>(connection_dispatcher));
    it->second->returnConnection(std::move(connection));
  } else {
    ENVOY_LOG(debug,
              "No dispatcher-aware connection pool found for cluster: {} on dispatcher: {} - "
              "closing connection",
              cluster_name, static_cast<void*>(connection_dispatcher));
    connection->close(Network::ConnectionCloseType::NoFlush);
  }
}

// Helper overload for dispatcher-aware connection return
void SocketHandoffManager::returnConnection(const std::string& cluster_name,
                                            Network::ClientConnectionPtr connection,
                                            Event::Dispatcher& dispatcher) {
  if (!connection) {
    return;
  }

  absl::MutexLock lock(&pools_mutex_);

  std::string pool_key = createPoolKey(cluster_name, dispatcher);
  auto it = cluster_pools_.find(pool_key);
  if (it != cluster_pools_.end()) {
    ENVOY_LOG(debug,
              "Returning connection to dispatcher-aware pool for cluster: {} (explicit dispatcher)",
              cluster_name);
    it->second->returnConnection(std::move(connection));
  } else {
    ENVOY_LOG(
        debug,
        "No connection pool found for returning connection to cluster: {} - closing connection",
        cluster_name);
    connection->close(Network::ConnectionCloseType::NoFlush);
  }
}

void SocketHandoffManager::preconnectForCluster(const std::string& cluster_name,
                                                uint32_t expected_connections) {
  absl::MutexLock lock(&pools_mutex_);

  auto it = cluster_pools_.find(cluster_name);
  if (it != cluster_pools_.end()) {
    // Configure preconnect based on expected load
    SocketHandoffPoolConfig config = cluster_configs_[cluster_name];
    config.max_connections_per_cluster =
        std::max(config.max_connections_per_cluster, expected_connections);
    config.min_connections_per_cluster =
        std::min(config.min_connections_per_cluster, expected_connections / 2);

    cluster_configs_[cluster_name] = config;
    it->second->preconnectIfNeeded();

    ENVOY_LOG(debug, "Preconnecting for expected {} connections to cluster: {}",
              expected_connections, cluster_name);
  }
}

void SocketHandoffManager::performMaintenance() {
  absl::MutexLock lock(&pools_mutex_);

  for (auto& [cluster_name, pool] : cluster_pools_) {
    pool->cleanupConnections();
  }

  ENVOY_LOG(trace, "Performed maintenance on {} connection pools", cluster_pools_.size());
}

SocketHandoffManager::GlobalStats SocketHandoffManager::getGlobalStats() const {
  absl::MutexLock lock(&pools_mutex_);

  GlobalStats stats{};
  stats.total_pools = cluster_pools_.size();

  uint32_t total_available = 0;
  uint32_t total_active = 0;
  uint32_t total_reused = 0;

  for (const auto& [cluster_name, pool] : cluster_pools_) {
    auto pool_stats = pool->getStats();
    total_available += pool_stats.available_connections;
    total_active += pool_stats.active_connections;
    total_reused += pool_stats.total_connections_reused;
  }

  stats.total_available_connections = total_available;
  stats.total_active_connections = total_active;
  stats.total_reused_connections = total_reused;

  if (stats.total_pools > 0) {
    uint32_t total_connections = total_available + total_active;
    stats.average_pool_utilization =
        static_cast<float>(total_active) / std::max(1u, total_connections);
  }

  return stats;
}

// HandoffOptimizedIOHandle implementation
HandoffOptimizedIOHandle::HandoffOptimizedIOHandle(os_fd_t fd, const std::string& cluster_name)
    : IoSocketHandleImpl(fd), cluster_name_(cluster_name) {}

HandoffOptimizedIOHandle::~HandoffOptimizedIOHandle() = default;

Api::SysCallIntResult
HandoffOptimizedIOHandle::connect(Network::Address::InstanceConstSharedPtr address) {
  // Thread-safe connection acquisition with atomic state management
  try {
    // Note: In a real implementation, we'd need access to the singleton manager
    // For now, this is a placeholder that would need proper context injection
    ENVOY_LOG(debug, "HandoffOptimizedIOHandle would use singleton manager access for cluster: {}",
              cluster_name_);
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception in HandoffOptimizedIOHandle for cluster {}: {}", cluster_name_,
              e.what());
  }

  // Fallback to normal connection
  ENVOY_LOG(debug, "Falling back to normal connection for cluster: {}", cluster_name_);
  return IoSocketHandleImpl::connect(address);
}

Api::IoCallUint64Result HandoffOptimizedIOHandle::close() {
  if (connection_reused_) {
    ENVOY_LOG(debug, "Returning reused connection to pool for cluster: {}", cluster_name_);
    // Note: In a real implementation, we'd need to track the actual connection object
    // and return it to the pool here via SocketHandoffManager::getInstance().returnConnection()
  }

  return IoSocketHandleImpl::close();
}

// HandoffConnectionFactory implementation
Network::ClientConnectionPtr HandoffConnectionFactory::createOptimizedConnection(
    const std::string& cluster_name, Upstream::ClusterManager& cluster_manager,
    Event::Dispatcher& dispatcher, Network::Address::InstanceConstSharedPtr address) {

  // Get singleton instance of handoff manager
  // For now, create a static instance (proper singleton implementation would require factory
  // registration)
  static auto manager = std::make_shared<SocketHandoffManager>();

  auto pool = manager->getConnectionPool(cluster_name, cluster_manager, dispatcher);
  auto connection = pool->getConnection();

  if (connection) {
    ENVOY_LOG(debug, "Created optimized connection for cluster: {} using connection pool",
              cluster_name);
    return connection;
  }

  // Fallback to creating new connection
  ENVOY_LOG(debug, "Creating new connection for cluster: {} (pool empty)", cluster_name);
  return dispatcher.createClientConnection(address, Network::Address::InstanceConstSharedPtr(),
                                           std::make_unique<Network::RawBufferSocket>(), nullptr,
                                           nullptr);
}

std::unique_ptr<HandoffOptimizedIOHandle>
HandoffConnectionFactory::createOptimizedIOHandle(const std::string& cluster_name) {

  // Create a placeholder file descriptor (would be replaced with actual socket fd)
  os_fd_t fd = -1; // This would be obtained from a real socket
  return std::make_unique<HandoffOptimizedIOHandle>(fd, cluster_name);
}

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
