#pragma once

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <queue>
#include <string>
#include <vector>

#include "envoy/api/io_error.h"
#include "envoy/registry/registry.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/server/bootstrap_extension_config.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/network/filter_impl.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_interface.h"
#include "source/common/upstream/load_balancer_context_base.h"

#include "absl/synchronization/mutex.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/flat_hash_map.h"
#include "contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha/reverse_connection_socket_interface.pb.h"
#include "contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha/reverse_connection_socket_interface.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// Forward declarations
class RCConnectionWrapper;
class DownstreamReverseSocketInterface;
class DownstreamReverseSocketInterfaceExtension;

static const char CRLF[] = "\r\n";
static const char DOUBLE_CRLF[] = "\r\n\r\n";

/**
 * Configuration for remote cluster connections.
 */
struct RemoteClusterConnectionConfig {
  std::string cluster_name;
  uint32_t reverse_connection_count;
  uint32_t reconnect_interval_ms;
  uint32_t max_reconnect_attempts;
  bool enable_health_check;

  RemoteClusterConnectionConfig(const std::string& name, uint32_t count,
                                uint32_t reconnect_ms = 5000, uint32_t max_attempts = 10,
                                bool health_check = true)
      : cluster_name(name), reverse_connection_count(count), reconnect_interval_ms(reconnect_ms),
        max_reconnect_attempts(max_attempts), enable_health_check(health_check) {}
};

/**
 * Connection state tracking.
 */
enum class ReverseConnectionState {
  Disconnected,
  Connecting,
  Connected,
  Reconnecting,
  Failed,
  HealthCheckFailed
};

/**
 * Connection metadata for monitoring.
 */
struct ReverseConnectionMetadata {
  std::string cluster_name;
  ReverseConnectionState state;
  std::chrono::steady_clock::time_point last_connected;
  std::chrono::steady_clock::time_point last_attempt;
  uint32_t reconnect_attempts;
  uint64_t bytes_forwarded;
  uint64_t connection_count;
  bool health_check_passed;

  ReverseConnectionMetadata() = default;

  ReverseConnectionMetadata(const std::string& cluster)
      : cluster_name(cluster), state(ReverseConnectionState::Disconnected),
        last_connected(std::chrono::steady_clock::now()),
        last_attempt(std::chrono::steady_clock::now()), reconnect_attempts(0), bytes_forwarded(0),
        connection_count(0), health_check_passed(true) {}
};

/**
 * Configuration for reverse connection socket interface.
 */
struct ReverseConnectionSocketConfig {
  std::string src_cluster_id;
  std::string src_node_id;
  std::string src_tenant_id;
  std::vector<RemoteClusterConnectionConfig> remote_clusters;
  uint32_t health_check_interval_ms;
  uint32_t connection_timeout_ms;
  bool enable_metrics;
  bool enable_circuit_breaker;

  ReverseConnectionSocketConfig()
      : health_check_interval_ms(30000), connection_timeout_ms(10000), enable_metrics(true),
        enable_circuit_breaker(true) {}
};

/**
 * Custom IoHandle for reverse connections that manages multiple reverse TCP connections
 * and triggers the listener's accept() when a connection is established.
 */
class ReverseConnectionIOHandle : public Network::IoSocketHandleImpl,
                                 public Network::ConnectionCallbacks {
public:
  ReverseConnectionIOHandle(os_fd_t fd,
                           const ReverseConnectionSocketConfig& config,
                           Upstream::ClusterManager& cluster_manager,
                           const DownstreamReverseSocketInterface& socket_interface);

  ~ReverseConnectionIOHandle() override;

  // Network::IoHandle overrides
  Api::SysCallIntResult listen(int backlog) override;
  Network::IoHandlePtr accept(struct sockaddr* addr, socklen_t* addrlen) override;
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               absl::optional<uint64_t> max_length) override;
  Api::IoCallUint64Result write(Buffer::Instance& buffer) override;
  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr address) override;
  Api::IoCallUint64Result close() override;
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // Check if trigger pipe is ready
  bool isTriggerPipeReady() const;

  // Get connection metadata for monitoring
  const std::unordered_map<std::string, ReverseConnectionMetadata>& getConnectionMetadata() const;

  // Callbacks from RCConnectionWrapper
  void onConnectionDone(const std::string& error, RCConnectionWrapper* wrapper, bool closed);
  void onConnectionWrapperClosed(RCConnectionWrapper* wrapper, bool remote_close);

private:
  // Get the thread-local dispatcher from the registry
  Event::Dispatcher& getThreadLocalDispatcher() const;

  void createTriggerPipe();
  void initiateReverseTcpConnections();
  bool initiateOneReverseConnection(const std::string& cluster_name, 
                                    const std::string& host_address,
                                    Upstream::HostConstSharedPtr host);

  /*
  void performHealthCheck(const std::string& cluster_name);
  void scheduleHealthCheck(const std::string& cluster_name);
  */
  bool shouldAttemptConnection(const std::string& cluster_name);

  /*
  void updateConnectionMetrics(const std::string& cluster_name, ReverseConnectionState new_state);
  void updateConnectionMetricsUnsafe(const std::string& cluster_name,
                                     ReverseConnectionState new_state);
  */
  void cleanup();

  // Host/cluster mapping management
  void maybeUpdateHostsMappingsAndConnections(const std::string& cluster_id, 
                                              const std::vector<std::string>& hosts);
  void removeStaleHostAndCloseConnections(const std::string& host);

  // Per-host connection tracking for better management
  struct HostConnectionInfo {
    // Host address
    std::string host_address;
    // Cluster to which host belongs
    std::string cluster_name;
    // Active connections are tracked via conn_wrapper_to_host_map_ instead
    // Connection keys are stored for stats tracking
    absl::flat_hash_set<std::string> connection_keys;
    // Target connection count for the host
    uint32_t target_connection_count;
  };
  
  // Map from host address to connection info
  std::unordered_map<std::string, HostConnectionInfo> host_to_conn_info_map_;
  // Map from cluster name to set of resolved hosts
  absl::flat_hash_map<std::string, absl::flat_hash_set<std::string>> cluster_to_resolved_hosts_map_;
  // NOTE: All operations on this map should be thread-local
  // TODO(Basu): Remove the mutex once we confirm thread-locality
  mutable absl::Mutex host_connections_mutex_;
  
  // Core components
  const ReverseConnectionSocketConfig config_;
  Upstream::ClusterManager& cluster_manager_;
  const DownstreamReverseSocketInterface& socket_interface_;

  // Connection wrapper management
  std::vector<std::unique_ptr<RCConnectionWrapper>> connection_wrappers_;
  std::unordered_map<RCConnectionWrapper*, std::string> conn_wrapper_to_host_map_;

  // Pipe used to wake up accept() when a connection is established.
  // We write a single byte to the write end of the pipe when the reverse 
  // connection request is accepted and read the byte in the accept() call.
  int trigger_pipe_read_fd_{-1};
  int trigger_pipe_write_fd_{-1};

  // Connection management : We store the established connections in a queue
  // and pop the last established connection when data is read on trigger_pipe_read_fd_
  // to determine the connection that got established last.
  // TODO(Basu): Implement backoff or max retries for connection establishment
  // so that queue does not grow indefinitely.
  std::queue<Envoy::Network::ClientConnectionPtr> established_connections_;
  mutable absl::Mutex connection_mutex_;

  // Socket cache to prevent socket objects from going out of scope
  // Maps connection key to socket object
  std::unordered_map<std::string, Envoy::Network::ConnectionSocketPtr> socket_cache_;
  mutable absl::Mutex socket_cache_mutex_;

  // Connection metadata tracking
  std::unordered_map<std::string, uint32_t> cluster_connection_counts_;
  std::unordered_map<std::string, ReverseConnectionMetadata> connection_metadata_;

  // Single retry timer for all clusters
  Event::TimerPtr rev_conn_retry_timer_;
  
  // Health check timers per cluster
  std::unordered_map<std::string, Event::TimerPtr> health_check_timers_;

  // Track if we've initiated reverse connections.
  bool listening_initiated_{false};
  mutable absl::Mutex metadata_mutex_;
};

/**
 * Thread local storage for DownstreamReverseSocketInterface.
 * Stores the thread-local dispatcher for each worker thread.
 */
class DownstreamSocketThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  DownstreamSocketThreadLocal(Event::Dispatcher& dispatcher) : dispatcher_(dispatcher) {}
  
  Event::Dispatcher& dispatcher() { return dispatcher_; }

private:
  Event::Dispatcher& dispatcher_;
};

/**
 * Socket interface that creates reverse connection sockets.
 */
class DownstreamReverseSocketInterface
    : public Envoy::Network::SocketInterfaceBase,
      public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  DownstreamReverseSocketInterface(Server::Configuration::ServerFactoryContext& context);
  
  // Default constructor for registry
  DownstreamReverseSocketInterface() : extension_(nullptr), context_(nullptr) {}

  // SocketInterface
  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type, Envoy::Network::Address::Type addr_type,
         Envoy::Network::Address::IpVersion version, bool socket_v6only,
         const Envoy::Network::SocketCreationOptions& options) const override;

  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type,
         const Envoy::Network::Address::InstanceConstSharedPtr addr,
         const Envoy::Network::SocketCreationOptions& options) const override;

  bool ipFamilySupported(int domain) override;

  // Get thread local registry for the current thread
  DownstreamSocketThreadLocal* getLocalRegistry() const;

  // BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override {
    return "envoy.bootstrap.reverse_connection.downstream_reverse_connection_socket_interface";
  }

  DownstreamReverseSocketInterfaceExtension* extension_{nullptr};

private:
  Server::Configuration::ServerFactoryContext* context_;
  
  // Temporary storage for config extracted from address  
  mutable std::unique_ptr<ReverseConnectionSocketConfig> temp_rc_config_;
};

/**
 * Socket interface extension for reverse connections.
 */
class DownstreamReverseSocketInterfaceExtension : public Envoy::Network::SocketInterfaceExtension,
                                                  public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  DownstreamReverseSocketInterfaceExtension(Envoy::Network::SocketInterface& sock_interface,
                                           Server::Configuration::ServerFactoryContext& context,
                                           const envoy::extensions::bootstrap::reverse_connection_socket_interface::v3alpha::DownstreamReverseConnectionSocketInterface& config)
      : Envoy::Network::SocketInterfaceExtension(sock_interface), context_(context),
        socket_interface_(static_cast<DownstreamReverseSocketInterface*>(&sock_interface)) {
          ENVOY_LOG(debug, "DownstreamReverseSocketInterfaceExtension: creating downstream reverse connection socket interface with stat_prefix: {}", stat_prefix_);
          stat_prefix_ = PROTOBUF_GET_STRING_OR_DEFAULT(config, stat_prefix, "downstream_reverse_connection");
        }

  // Server::BootstrapExtension (inherited from SocketInterfaceExtension)
  void onServerInitialized() override;
  void onWorkerThreadInitialized() override {}

  // Get thread local registry for the current thread
  DownstreamSocketThreadLocal* getLocalRegistry() const;

  // Get the stat prefix for stats/monitoring
  const std::string& statPrefix() const { return stat_prefix_; }

private:
  Server::Configuration::ServerFactoryContext& context_;
  std::unique_ptr<ThreadLocal::TypedSlot<DownstreamSocketThreadLocal>> tls_slot_;
  DownstreamReverseSocketInterface* socket_interface_;
  std::string stat_prefix_;
};

DECLARE_FACTORY(DownstreamReverseSocketInterface);

/**
 * Custom load balancer context for reverse connections. This class enables the
 * rc_initiator to propagate upstream host details to the cluster_manager, ensuring
 * that connections are initiated to specified hosts rather than random ones. It inherits
 * from the LoadBalancerContextBase class and overrides the `overrideHostToSelect` method.
 */
class ReverseConnectionLoadBalancerContext : public Upstream::LoadBalancerContextBase {
public:
  ReverseConnectionLoadBalancerContext(const std::string& host_to_select) {
    host_to_select_ = std::make_pair(host_to_select, false);
  }

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