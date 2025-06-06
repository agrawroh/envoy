#pragma once

#include <functional>
#include <memory>

#include "envoy/common/callback.h"
#include "envoy/common/pure.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stream_info/stream_info.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Network {

/**
 * Callbacks for reverse connection events.
 */
class ReverseConnectionCallbacks {
public:
  virtual ~ReverseConnectionCallbacks() = default;

  /**
   * Called when a reverse connection is established and ready for use.
   * @param connection the established connection
   * @param cluster_name the target cluster name
   */
  virtual void onReverseConnectionReady(ConnectionPtr&& connection,
                                        const std::string& cluster_name) PURE;

  /**
   * Called when a reverse connection fails to establish.
   * @param cluster_name the target cluster name
   * @param failure_reason description of the failure
   */
  virtual void onReverseConnectionFailure(const std::string& cluster_name,
                                          const std::string& failure_reason) PURE;

  /**
   * Called when a reverse connection is closed.
   * @param cluster_name the target cluster name
   * @param close_reason description of close reason
   */
  virtual void onReverseConnectionClosed(const std::string& cluster_name,
                                         const std::string& close_reason) PURE;
};

/**
 * Represents a cached reverse connection.
 */
class CachedReverseConnection {
public:
  virtual ~CachedReverseConnection() = default;

  /**
   * @return the underlying network connection
   */
  virtual Connection& connection() PURE;

  /**
   * @return true if the connection is available for use
   */
  virtual bool isAvailable() const PURE;

  /**
   * Mark the connection as in use.
   */
  virtual void markInUse() PURE;

  /**
   * Mark the connection as available for reuse.
   */
  virtual void markAvailable() PURE;

  /**
   * @return the cluster name this connection belongs to
   */
  virtual const std::string& clusterName() const PURE;

  /**
   * @return connection establishment time
   */
  virtual std::chrono::steady_clock::time_point establishedTime() const PURE;

  /**
   * @return last keepalive response time
   */
  virtual std::chrono::steady_clock::time_point lastKeepaliveTime() const PURE;

  /**
   * Update the last keepalive response time.
   */
  virtual void updateKeepaliveTime() PURE;

  /**
   * @return number of consecutive failed keepalives
   */
  virtual uint32_t consecutiveKeepaliveFailures() const PURE;

  /**
   * Increment the consecutive keepalive failure count.
   */
  virtual void incrementKeepaliveFailures() PURE;

  /**
   * Reset the consecutive keepalive failure count.
   */
  virtual void resetKeepaliveFailures() PURE;
};

using CachedReverseConnectionPtr = std::unique_ptr<CachedReverseConnection>;

/**
 * Configuration for reverse connection clusters.
 */
struct ReverseConnectionClusterConfig {
  std::string cluster_name_;
  uint32_t reverse_connection_count_;
  uint32_t max_retry_attempts_;
  std::chrono::milliseconds connection_timeout_;
};

/**
 * Configuration for reverse connection keepalive.
 */
struct ReverseConnectionKeepaliveConfig {
  std::chrono::milliseconds keepalive_interval_;
  std::chrono::milliseconds keepalive_timeout_;
  uint32_t max_failures_;
};

/**
 * Manager for reverse connections. Handles connection establishment, caching, and lifecycle.
 */
class ReverseConnectionManager : public Logger::Loggable<Logger::Id::connection> {
public:
  virtual ~ReverseConnectionManager() = default;

  /**
   * Initialize the reverse connection manager with configuration.
   * @param cluster_configs configuration for target clusters
   * @param keepalive_config configuration for keepalive behavior
   * @param callbacks callbacks for connection events
   */
  virtual void initialize(const std::vector<ReverseConnectionClusterConfig>& cluster_configs,
                          const ReverseConnectionKeepaliveConfig& keepalive_config,
                          ReverseConnectionCallbacks& callbacks) PURE;

  /**
   * Start establishing reverse connections to all configured clusters.
   */
  virtual void startReverseConnections() PURE;

  /**
   * Stop all reverse connections and cleanup resources.
   */
  virtual void stopReverseConnections() PURE;

  /**
   * Get an available reverse connection for the specified cluster.
   * @param cluster_name the target cluster name
   * @return cached connection if available, nullptr otherwise
   */
  virtual CachedReverseConnectionPtr getReverseConnection(const std::string& cluster_name) PURE;

  /**
   * Return a reverse connection to the pool for reuse.
   * @param connection the connection to return
   */
  virtual void returnReverseConnection(CachedReverseConnectionPtr&& connection) PURE;

  /**
   * Get statistics for reverse connections.
   * @return stats scope containing reverse connection metrics
   */
  virtual Stats::Scope& stats() PURE;

  /**
   * Force refresh of connections for a specific cluster.
   * @param cluster_name the cluster to refresh connections for
   */
  virtual void refreshClusterConnections(const std::string& cluster_name) PURE;
};

using ReverseConnectionManagerPtr = std::unique_ptr<ReverseConnectionManager>;

/**
 * Factory for creating reverse connection managers.
 */
class ReverseConnectionManagerFactory {
public:
  virtual ~ReverseConnectionManagerFactory() = default;

  /**
   * Create a new reverse connection manager.
   * @param dispatcher the event dispatcher
   * @param cluster_manager the cluster manager
   * @param stats_scope the stats scope for metrics
   * @return new reverse connection manager instance
   */
  virtual ReverseConnectionManagerPtr
  createReverseConnectionManager(Event::Dispatcher& dispatcher,
                                 Upstream::ClusterManager& cluster_manager,
                                 Stats::Scope& stats_scope) PURE;
};

using ReverseConnectionManagerFactoryPtr = std::unique_ptr<ReverseConnectionManagerFactory>;

} // namespace Network
} // namespace Envoy
