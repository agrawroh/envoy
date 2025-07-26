#pragma once

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <queue>
#include <string>
#include <vector>

#include "envoy/api/io_error.h"
#include "envoy/extensions/bootstrap/reverse_connection_socket_interface/v3/reverse_connection_socket_interface.pb.h"
#include "envoy/extensions/bootstrap/reverse_connection_socket_interface/v3/reverse_connection_socket_interface.pb.validate.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/bootstrap_extension_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/network/filter_impl.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_interface.h"
#include "source/common/upstream/load_balancer_context_base.h"
#include "source/extensions/bootstrap/reverse_tunnel/factory_base.h"
#include "source/extensions/bootstrap/reverse_tunnel/grpc_reverse_tunnel_client.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// Forward declaration for friend class
class ReverseConnectionIOHandleTest;

// Forward declarations.
class ReverseTunnelInitiator;
class ReverseTunnelInitiatorExtension;
class GrpcReverseTunnelClient;
class ReverseConnectionIOHandle;

/**
 * RCConnectionWrapper manages the lifecycle of a ClientConnectionPtr for reverse connections.
 * It handles the handshake process (both gRPC and HTTP fallback) and manages connection
 * callbacks and cleanup.
 */
class RCConnectionWrapper : public Network::ConnectionCallbacks,
                            public Event::DeferredDeletable,
                            public ReverseConnection::GrpcReverseTunnelCallbacks,
                            Logger::Loggable<Logger::Id::main> {
public:
  /**
   * Constructor for RCConnectionWrapper.
   * @param parent reference to the parent ReverseConnectionIOHandle
   * @param connection the client connection to wrap
   * @param host the upstream host description
   * @param cluster_name the name of the cluster
   */
  RCConnectionWrapper(ReverseConnectionIOHandle& parent, Network::ClientConnectionPtr connection,
                      Upstream::HostDescriptionConstSharedPtr host,
                      const std::string& cluster_name);

  /**
   * Destructor for RCConnectionWrapper.
   * Performs defensive cleanup to prevent crashes during shutdown.
   */
  ~RCConnectionWrapper() override;

  // Network::ConnectionCallbacks overrides
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // ReverseConnection::GrpcReverseTunnelCallbacks overrides
  void onHandshakeSuccess(
      std::unique_ptr<envoy::service::reverse_tunnel::v3::EstablishTunnelResponse> response)
      override;
  void onHandshakeFailure(Grpc::Status::GrpcStatus status, const std::string& message) override;

  /**
   * Initiate the reverse connection handshake (gRPC or HTTP fallback).
   * @param src_tenant_id the tenant identifier
   * @param src_cluster_id the cluster identifier
   * @param src_node_id the node identifier
   * @return the local address as string
   */
  std::string connect(const std::string& src_tenant_id, const std::string& src_cluster_id,
                      const std::string& src_node_id);

  /**
   * Handle connection failure and initiate graceful shutdown.
   */
  void onFailure();

  /**
   * Perform graceful shutdown of the connection.
   */
  void shutdown();

  /**
   * Get the underlying connection.
   * @return pointer to the client connection
   */
  Network::ClientConnection* getConnection() { return connection_.get(); }

  /**
   * Get the host description.
   * @return shared pointer to the host description
   */
  Upstream::HostDescriptionConstSharedPtr getHost() { return host_; }

  /**
   * Release the connection when handshake succeeds.
   * @return the released connection
   */
  Network::ClientConnectionPtr releaseConnection() { return std::move(connection_); }

private:
  /**
   * Simplified read filter for HTTP fallback during gRPC migration.
   */
  struct SimpleConnReadFilter : public Network::ReadFilterBaseImpl {
    SimpleConnReadFilter(RCConnectionWrapper* parent) : parent_(parent) {}

    Network::FilterStatus onData(Buffer::Instance& buffer, bool) override;

    RCConnectionWrapper* parent_;
  };

  ReverseConnectionIOHandle& parent_;
  Network::ClientConnectionPtr connection_;
  Upstream::HostDescriptionConstSharedPtr host_;
  const std::string cluster_name_;
  std::unique_ptr<ReverseConnection::GrpcReverseTunnelClient> reverse_tunnel_client_;
  
  // Handshake data for HTTP fallback
  std::string handshake_tenant_id_;
  std::string handshake_cluster_id_;
  std::string handshake_node_id_;
  bool handshake_sent_{false};
};

namespace {
// HTTP protocol constants.
static constexpr absl::string_view kCrlf = "\r\n";
static constexpr absl::string_view kDoubleCrlf = "\r\n\r\n";

// Connection timing constants.
static constexpr uint32_t kDefaultReconnectIntervalMs = 5000; // 5 seconds.
static constexpr uint32_t kDefaultMaxReconnectAttempts = 10;
static constexpr uint32_t kDefaultHealthCheckIntervalMs = 30000; // 30 seconds.
static constexpr uint32_t kDefaultConnectionTimeoutMs = 10000;   // 10 seconds.
} // namespace

/**
 * Connection state tracking for reverse connections.
 */
enum class ReverseConnectionState {
  Connecting,    // Connection is being established (handshake initiated).
  Connected,     // Connection has been successfully established.
  Recovered,     // Connection has recovered from a previous failure.
  Failed,        // Connection establishment failed during handshake.
  CannotConnect, // Connection cannot be initiated (early failure).
  Backoff        // Connection is in backoff state due to failures.
};

/**
 * Configuration for remote cluster connections.
 * Defines connection parameters for each remote cluster that reverse connections should be
 * established to.
 */
struct RemoteClusterConnectionConfig {
  std::string cluster_name;          // Name of the remote cluster.
  uint32_t reverse_connection_count; // Number of reverse connections to maintain per host.
  uint32_t reconnect_interval_ms;    // Interval between reconnection attempts in milliseconds.
  uint32_t max_reconnect_attempts;   // Maximum number of reconnection attempts.
  bool enable_health_check;          // Whether to enable health checks for this cluster.

  RemoteClusterConnectionConfig(const std::string& name, uint32_t count,
                                uint32_t reconnect_ms = kDefaultReconnectIntervalMs,
                                uint32_t max_attempts = kDefaultMaxReconnectAttempts,
                                bool health_check = true)
      : cluster_name(name), reverse_connection_count(count), reconnect_interval_ms(reconnect_ms),
        max_reconnect_attempts(max_attempts), enable_health_check(health_check) {}
};

/**
 * Configuration for reverse connection socket interface.
 */
struct ReverseConnectionSocketConfig {
  std::string src_cluster_id; // Cluster identifier of local envoy instance.
  std::string src_node_id;    // Node identifier of local envoy instance.
  std::string src_tenant_id;  // Tenant identifier of local envoy instance.
  std::vector<RemoteClusterConnectionConfig>
      remote_clusters;               // List of remote cluster configurations.
  uint32_t health_check_interval_ms; // Interval for health checks in milliseconds.
  uint32_t connection_timeout_ms;    // Connection timeout in milliseconds.
  bool enable_metrics;               // Whether to enable metrics collection.
  bool enable_circuit_breaker;       // Whether to enable circuit breaker functionality.
  
  // gRPC service configuration for reverse tunnel handshake
  absl::optional<envoy::service::reverse_tunnel::v3::ReverseTunnelGrpcConfig> grpc_service_config;
  bool enable_legacy_http_handshake; // Whether to enable legacy HTTP handshake

  ReverseConnectionSocketConfig()
      : health_check_interval_ms(kDefaultHealthCheckIntervalMs),
        connection_timeout_ms(kDefaultConnectionTimeoutMs), enable_metrics(true),
        enable_circuit_breaker(true), enable_legacy_http_handshake(true) {}
};

/**
 * This class handles the lifecycle of reverse connections, including establishment,
 * maintenance, and cleanup of connections to remote clusters.
 */
class ReverseConnectionIOHandle : public Network::IoSocketHandleImpl,
                                  public Network::ConnectionCallbacks {

  friend class ReverseConnectionIOHandleTest;
public:
  /**
   * Constructor for ReverseConnectionIOHandle.
   * @param fd the file descriptor for listener socket.
   * @param config the configuration for reverse connections.
   * @param cluster_manager the cluster manager for accessing upstream clusters.
   * @param socket_interface reference to the parent socket interface.
   * @param scope the stats scope for metrics collection.
   */
  ReverseConnectionIOHandle(os_fd_t fd, const ReverseConnectionSocketConfig& config,
                            Upstream::ClusterManager& cluster_manager,
                            ReverseTunnelInitiatorExtension* extension, Stats::Scope& scope);

  ~ReverseConnectionIOHandle() override;

  // Network::IoHandle overrides.
  /**
   * Override of listen method for reverse connections.
   * Initiates reverse connection establishment to configured remote clusters.
   * @param backlog the listen backlog (unused for reverse connections).
   * @return SysCallIntResult with success status.
   */
  Api::SysCallIntResult listen(int backlog) override;

  /**
   * Override of accept method for reverse connections.
   * Returns established reverse connections when they become available. This is woken up using the
   * trigger pipe when a tcp connection to an upstream cluster is established.
   * @param addr pointer to store the client address information.
   * @param addrlen pointer to the length of the address structure.
   * @return IoHandlePtr for the accepted reverse connection, or nullptr if none available.
   */
  Network::IoHandlePtr accept(struct sockaddr* addr, socklen_t* addrlen) override;

  /**
   * Override of read method for reverse connections.
   * @param buffer the buffer to read data into.
   * @param max_length optional maximum number of bytes to read.
   * @return IoCallUint64Result indicating the result of the read operation.
   */
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               absl::optional<uint64_t> max_length) override;

  /**
   * Override of write method for reverse connections.
   * @param buffer the buffer containing data to write.
   * @return IoCallUint64Result indicating the result of the write operation.
   */
  Api::IoCallUint64Result write(Buffer::Instance& buffer) override;

  /**
   * Override of connect method for reverse connections.
   * For reverse connections, this is not used since we connect to the upstream clusters in
   * listen().
   * @param address the target address (unused for reverse connections).
   * @return SysCallIntResult with success status.
   */
  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr address) override;

  /**
   * Override of close method for reverse connections.
   * @return IoCallUint64Result indicating the result of the close operation.
   */
  Api::IoCallUint64Result close() override;

  /**
   * Override of initializeFileEvent to defer work to worker thread.
   * @param dispatcher the event dispatcher.
   * @param cb the file ready callback.
   * @param trigger the file trigger type.
   * @param events the events to monitor.
   */
  void initializeFileEvent(Event::Dispatcher& dispatcher, Event::FileReadyCb cb,
                          Event::FileTriggerType trigger, uint32_t events) override;

  // Network::ConnectionCallbacks.
  /**
   * Called when connection events occur.
   * For reverse connections, we handle these events through RCConnectionWrapper.
   * @param event the connection event that occurred.
   */
  void onEvent(Network::ConnectionEvent event) override;

  /**
   * No-op for reverse connections.
   */
  void onAboveWriteBufferHighWatermark() override {}

  /**
   * No-op for reverse connections.
   */
  void onBelowWriteBufferLowWatermark() override {}

  /**
   * Check if trigger mechanism is ready for accepting connections.
   * @return true if the trigger mechanism is initialized and ready.
   */
  bool isTriggerReady() const;

  /**
   * Get the file descriptor for the pipe monitor used to wake up accept().
   * @return the file descriptor for the pipe monitor
   */
  int getPipeMonitorFd() const;

  // Callbacks from RCConnectionWrapper.
  /**
   * Called when a reverse connection handshake completes.
   * @param error error message if the handshake failed, empty string if successful.
   * @param wrapper pointer to the connection wrapper that wraps over the established connection.
   * @param closed whether the connection was closed during handshake.
   */
  void onConnectionDone(const std::string& error, RCConnectionWrapper* wrapper, bool closed);

  // Backoff logic for connection failures.
  /**
   * Determine if connections should be initiated to a host, i.e., if host is in backoff period.
   * @param host_address the address of the host to check.
   * @param cluster_name the name of the cluster the host belongs to.
   * @return true if connection attempt should be made, false if in backoff.
   */
  bool shouldAttemptConnectionToHost(const std::string& host_address,
                                     const std::string& cluster_name);

  /**
   * Track a connection failure for a specific host and cluster and apply backoff logic.
   * @param host_address the address of the host that failed.
   * @param cluster_name the name of the cluster the host belongs to.
   */
  void trackConnectionFailure(const std::string& host_address, const std::string& cluster_name);

  /**
   * Reset backoff state for a specific host. Called when a connection is established successfully.
   * @param host_address the address of the host to reset backoff for.
   */
  void resetHostBackoff(const std::string& host_address);

  /**
   * Update the connection state for a specific connection and update metrics.
   * @param host_address the address of the host.
   * @param cluster_name the name of the cluster.
   * @param connection_key the unique key identifying the connection.
   * @param new_state the new state to set for the connection.
   */
  void updateConnectionState(const std::string& host_address, const std::string& cluster_name,
                             const std::string& connection_key, ReverseConnectionState new_state);

  /**
   * Update state-specific gauge using switch case logic (combined increment/decrement).
   * @param host_address the address of the host
   * @param cluster_name the name of the cluster  
   * @param state the connection state to update
   * @param increment whether to increment (true) or decrement (false) the gauge
   */
  void updateStateGauge(const std::string& host_address, const std::string& cluster_name,
                        ReverseConnectionState state, bool increment);

  /**
   * Remove connection state tracking for a specific connection.
   * @param host_address the address of the host.
   * @param cluster_name the name of the cluster.
   * @param connection_key the unique key identifying the connection.
   */
  void removeConnectionState(const std::string& host_address, const std::string& cluster_name,
                             const std::string& connection_key);

  /**
   * Handle downstream connection closure and trigger re-initiation.
   * @param connection_key the unique key identifying the closed connection.
   */
  void onDownstreamConnectionClosed(const std::string& connection_key);

  /**
   * Get reference to the cluster manager.
   * @return reference to the cluster manager
   */
  Upstream::ClusterManager& getClusterManager() { return cluster_manager_; }

  /**
   * Get pointer to the gRPC service configuration if available.
   * @return pointer to the gRPC config, nullptr if not available
   */
  const envoy::service::reverse_tunnel::v3::ReverseTunnelGrpcConfig* getGrpcConfig() const {
    if (!config_.grpc_service_config.has_value()) {
      return nullptr;
    }
    return &config_.grpc_service_config.value();
  }

  /**
   * Get pointer to the downstream extension for stats updates.
   * @return pointer to the extension, nullptr if not available
   */
  ReverseTunnelInitiatorExtension* getDownstreamExtension() const;

private:
  
  /**
   * @return reference to the thread-local dispatcher
   */
  Event::Dispatcher& getThreadLocalDispatcher() const;

  /**
   * Check if thread-local dispatcher is available (not destroyed during shutdown)
   * @return true if dispatcher is available and safe to use
   */
  bool isThreadLocalDispatcherAvailable() const;

  /**
   * Create the trigger mechanism used to wake up accept() when connections are established.
   */
  void createTriggerMechanism();

  // Functions to maintain connections to remote clusters.

  /**
   * Maintain reverse connections for all configured clusters.
   * Initiates and maintains the required number of connections to each remote cluster.
   */
  void maintainReverseConnections();

  /**
   * Maintain reverse connections for a specific cluster.
   * @param cluster_name the name of the cluster to maintain connections for
   * @param cluster_config the configuration for the cluster
   */
  void maintainClusterConnections(const std::string& cluster_name,
                                  const RemoteClusterConnectionConfig& cluster_config);

  /**
   * Initiate a single reverse connection to a specific host.
   * @param cluster_name the name of the cluster the host belongs to
   * @param host_address the address of the host to connect to
   * @param host the host object containing connection information
   * @return true if connection initiation was successful, false otherwise
   */
  bool initiateOneReverseConnection(const std::string& cluster_name,
                                    const std::string& host_address,
                                    Upstream::HostConstSharedPtr host);

  /**
   * Clean up all reverse connection resources.
   * Called during shutdown to properly close connections and free resources.
   */
  void cleanup();

  // Pipe trigger mechanism helpers
  /**
   * Create trigger pipe used to wake up accept() when a connection is established.
   */
  void createTriggerPipe();

  /**
   * Check if trigger pipe is ready for use.
   * @return true if initialized and ready
   */
  bool isTriggerPipeReady() const;

  // Host/cluster mapping management
  /**
   * Update cluster -> host mappings from the cluster manager. Called before connection initiation
   * to a cluster.
   * @param cluster_id the ID of the cluster
   * @param hosts the list of hosts in the cluster
   */
  void maybeUpdateHostsMappingsAndConnections(const std::string& cluster_id,
                                              const std::vector<std::string>& hosts);

  /**
   * Remove stale host entries and close associated connections.
   * @param host the address of the host to remove
   */
  void removeStaleHostAndCloseConnections(const std::string& host);

  /**
   * Per-host connection tracking for better management.
   * Contains all information needed to track and manage connections to a specific host.
   */
  struct HostConnectionInfo {
    std::string host_address;                         // Host address
    std::string cluster_name;                         // Cluster to which host belongs
    absl::flat_hash_set<std::string> connection_keys; // Connection keys for stats tracking
    uint32_t target_connection_count;                 // Target connection count for the host
    uint32_t failure_count{0};                        // Number of consecutive failures
    std::chrono::steady_clock::time_point last_failure_time{
        std::chrono::steady_clock::now()}; // Time of last failure
    std::chrono::steady_clock::time_point backoff_until{
        std::chrono::steady_clock::now()}; // Backoff end time
    absl::flat_hash_map<std::string, ReverseConnectionState>
        connection_states; // State tracking per connection
  };

  // Map from host address to connection info.
  std::unordered_map<std::string, HostConnectionInfo> host_to_conn_info_map_;
  // Map from cluster name to set of resolved hosts
  absl::flat_hash_map<std::string, absl::flat_hash_set<std::string>> cluster_to_resolved_hosts_map_;

  // Core components
  const ReverseConnectionSocketConfig config_; // Configuration for reverse connections
  Upstream::ClusterManager& cluster_manager_;
  ReverseTunnelInitiatorExtension* extension_;

  // Connection wrapper management
  std::vector<std::unique_ptr<RCConnectionWrapper>>
      connection_wrappers_; // Active connection wrappers
  // Mapping from wrapper to host. This designates the number of successful connections to a host.
  std::unordered_map<RCConnectionWrapper*, std::string> conn_wrapper_to_host_map_;

  // Simple pipe-based trigger mechanism to wake up accept() when a connection is established.
  // Inlined directly for simplicity and reduced test coverage requirements.
  int trigger_pipe_read_fd_{-1};
  int trigger_pipe_write_fd_{-1};

  // Connection management : We store the established connections in a queue
  // and pop the last established connection when data is read on trigger_pipe_read_fd_
  // to determine the connection that got established last.
  std::queue<Envoy::Network::ClientConnectionPtr> established_connections_;

  // Socket cache to prevent socket objects from going out of scope
  // Maps connection key to socket object.
  // Socket cache removed - sockets are now managed via RAII in DownstreamReverseConnectionIOHandle

  // Single retry timer for all clusters
  Event::TimerPtr rev_conn_retry_timer_;

  // gRPC reverse tunnel client for handshake operations
  std::unique_ptr<GrpcReverseTunnelClient> reverse_tunnel_client_;

  bool is_reverse_conn_started_{false}; // Whether reverse connections have been started on worker thread
  Event::Dispatcher* worker_dispatcher_{nullptr}; // Dispatcher for the worker thread

  // Store original socket FD for cleanup
  os_fd_t original_socket_fd_{-1};
};

/**
 * Thread local storage for ReverseTunnelInitiator.
 * Stores the thread-local dispatcher and stats scope for each worker thread.
 */
class DownstreamSocketThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  DownstreamSocketThreadLocal(Event::Dispatcher& dispatcher, Stats::Scope& scope)
      : dispatcher_(dispatcher), scope_(scope) {}

  /**
   * @return reference to the thread-local dispatcher
   */
  Event::Dispatcher& dispatcher() { return dispatcher_; }

  /**
   * @return reference to the stats scope
   */
  Stats::Scope& scope() { return scope_; }

private:
  Event::Dispatcher& dispatcher_;
  Stats::Scope& scope_;
};

/**
 * Socket interface that creates reverse connection sockets.
 * This class implements the SocketInterface interface to provide reverse connection
 * functionality for downstream connections. It manages the establishment and maintenance
 * of reverse TCP connections to remote clusters.
 */
class ReverseTunnelInitiator : public Envoy::Network::SocketInterfaceBase,
                               public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
  // Friend class for testing
  friend class ReverseTunnelInitiatorTest;
  
public:
  ReverseTunnelInitiator(Server::Configuration::ServerFactoryContext& context);

  // Default constructor for registry
  ReverseTunnelInitiator() : extension_(nullptr), context_(nullptr) {}

  /**
   * Create a ReverseConnectionIOHandle and kick off the reverse connection establishment.
   * @param socket_type the type of socket to create
   * @param addr_type the address type
   * @param version the IP version
   * @param socket_v6only whether to create IPv6-only socket
   * @param options socket creation options
   * @return IoHandlePtr for the created socket, or nullptr for unsupported types
   */
  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type, Envoy::Network::Address::Type addr_type,
         Envoy::Network::Address::IpVersion version, bool socket_v6only,
         const Envoy::Network::SocketCreationOptions& options) const override;

  // No-op for reverse connections.
  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type,
         const Envoy::Network::Address::InstanceConstSharedPtr addr,
         const Envoy::Network::SocketCreationOptions& options) const override;

  /**
   * @return true if the IP family is supported
   */
  bool ipFamilySupported(int domain) override;

  /**
   * @return pointer to the thread-local registry, or nullptr if not available.
   */
  DownstreamSocketThreadLocal* getLocalRegistry() const;

  /**
   * Thread-safe helper method to create reverse connection socket with config.
   * @param socket_type the type of socket to create
   * @param addr_type the address type
   * @param version the IP version
   * @param config the reverse connection configuration
   * @return IoHandlePtr for the reverse connection socket
   */
  Envoy::Network::IoHandlePtr
  createReverseConnectionSocket(Envoy::Network::Socket::Type socket_type,
                                Envoy::Network::Address::Type addr_type,
                                Envoy::Network::Address::IpVersion version,
                                const ReverseConnectionSocketConfig& config) const;

  // Socket interface functionality only - factory methods moved to ReverseTunnelInitiatorFactory



  /**
   * Get the extension instance for accessing cross-thread aggregation capabilities.
   * @return pointer to the extension, or nullptr if not available
   */
  ReverseTunnelInitiatorExtension* getExtension() const { return extension_; }

  // BootstrapExtensionFactory implementation
  Server::BootstrapExtensionPtr createBootstrapExtension(
      const Protobuf::Message& config,
      Server::Configuration::ServerFactoryContext& context) override;
  
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  
  std::string name() const override { 
    return "envoy.bootstrap.reverse_connection.downstream_reverse_connection_socket_interface"; 
  }

private:
  ReverseTunnelInitiatorExtension* extension_;
  Server::Configuration::ServerFactoryContext* context_;
};

DECLARE_FACTORY(ReverseTunnelInitiator);

/**
 * Bootstrap extension for ReverseTunnelInitiator.
 */
class ReverseTunnelInitiatorExtension : public Server::BootstrapExtension,
                                        public Logger::Loggable<Logger::Id::connection> {
  // Friend class for testing
  friend class ReverseTunnelInitiatorExtensionTest;
  
public:
  ReverseTunnelInitiatorExtension(
      Server::Configuration::ServerFactoryContext& context,
      const envoy::extensions::bootstrap::reverse_connection_socket_interface::v3::
          DownstreamReverseConnectionSocketInterface& config);

  void onServerInitialized() override;
  void onWorkerThreadInitialized() override;

  /**
   * @return pointer to the thread-local registry, or nullptr if not available.
   */
  DownstreamSocketThreadLocal* getLocalRegistry() const;

  /**
   * @return true if gRPC service config is available in the configuration
   */
  bool hasGrpcConfig() const {
    return config_.has_grpc_service_config();
  }

  /**
   * @return reference to the gRPC service config
   */
  const envoy::service::reverse_tunnel::v3::ReverseTunnelGrpcConfig& getGrpcConfig() const {
    return config_.grpc_service_config();
  }

  /**
   * Update connection stats for reverse connections.
   * @param node_id the node identifier for the connection
   * @param cluster_id the cluster identifier for the connection  
   * @param state_suffix the state suffix (e.g., "connecting", "connected", "failed")
   * @param increment whether to increment (true) or decrement (false) the connection count
   */
  void updateConnectionStats(const std::string& node_id, const std::string& cluster_id,
                             const std::string& state_suffix, bool increment);

  /**
   * Update per-worker connection stats for debugging purposes.
   * Creates worker-specific stats "reverse_connections.{worker_name}.node.{node_id}.{state_suffix}".
   * @param node_id the node identifier for the connection
   * @param cluster_id the cluster identifier for the connection
   * @param state_suffix the state suffix for the connection
   * @param increment whether to increment (true) or decrement (false) the connection count
   */
  void updatePerWorkerConnectionStats(const std::string& node_id, const std::string& cluster_id,
                                      const std::string& state_suffix, bool increment);

  /**
   * Get per-worker stat map for the current dispatcher.
   * @return map of stat names to values for the current worker thread
   */
  absl::flat_hash_map<std::string, uint64_t> getPerWorkerStatMap();

  /**
   * Get cross-worker stat map across all dispatchers.
   * @return map of stat names to values across all worker threads
   */
  absl::flat_hash_map<std::string, uint64_t> getCrossWorkerStatMap();

  /**
   * Get connection stats synchronously with timeout.
   * @param timeout_ms timeout for the operation
   * @return pair of vectors containing connected nodes and accepted connections
   */
  std::pair<std::vector<std::string>, std::vector<std::string>> 
  getConnectionStatsSync(std::chrono::milliseconds timeout_ms);

  /**
   * Get the stats scope for accessing stats.
   * @return reference to the stats scope.
   */
  Stats::Scope& getStatsScope() const { return context_.scope(); }

  /**
   * Test-only method to set the thread local slot for testing purposes.
   * This allows tests to inject a custom thread local registry without
   * requiring friend class access.
   * @param slot the thread local slot to set
   */
  void setTestOnlyTLSRegistry(std::unique_ptr<ThreadLocal::TypedSlot<DownstreamSocketThreadLocal>> slot) {
    tls_slot_ = std::move(slot);
  }

private:
  Server::Configuration::ServerFactoryContext& context_;
  const envoy::extensions::bootstrap::reverse_connection_socket_interface::v3::
      DownstreamReverseConnectionSocketInterface config_;
  ThreadLocal::TypedSlotPtr<DownstreamSocketThreadLocal> tls_slot_;
};

/**
 * Custom load balancer context for reverse connections. This class enables the
 * ReverseConnectionIOHandle to propagate upstream host details to the cluster_manager, ensuring
 * that connections are initiated to specified hosts rather than random ones. It inherits
 * from the LoadBalancerContextBase class and overrides the `overrideHostToSelect` method.
 */
class ReverseConnectionLoadBalancerContext : public Upstream::LoadBalancerContextBase {
public:
  explicit ReverseConnectionLoadBalancerContext(const std::string& host_to_select) {
    host_to_select_ = std::make_pair(host_to_select, false);
  }

  /**
   * @return optional OverrideHost specifying the host to initiate reverse connection to.
   */
  absl::optional<OverrideHost> overrideHostToSelect() const override {
    return absl::make_optional(host_to_select_);
  }

private:
  OverrideHost host_to_select_;
};

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
