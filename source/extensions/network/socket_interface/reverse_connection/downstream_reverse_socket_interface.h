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
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_interface_impl.h"
#include "source/extensions/network/socket_interface/reverse_connection/protocol.h"

#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

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
 * Custom IOHandle that implements reverse connections using a single-byte trigger mechanism.
 *
 * Key features:
 * - Advanced reconnection with exponential backoff
 * - Connection health monitoring and circuit breaker
 * - Zero-copy data forwarding where possible
 * - Comprehensive error recovery
 */
class ReverseConnectionIOHandle : public Envoy::Network::IoSocketHandleImpl,
                                  public Envoy::Network::ConnectionCallbacks {
public:
  ReverseConnectionIOHandle(os_fd_t fd, const ReverseConnectionSocketConfig& config,
                            Upstream::ClusterManager& cluster_manager,
                            Event::Dispatcher& dispatcher, bool test_mode = false);

  ~ReverseConnectionIOHandle() override;

  // IoSocketHandleImpl
  Api::SysCallIntResult listen(int backlog) override;
  Envoy::Network::IoHandlePtr accept(struct sockaddr* addr, socklen_t* addrlen) override;
  Api::SysCallIntResult connect(Envoy::Network::Address::InstanceConstSharedPtr address) override;
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               absl::optional<uint64_t> max_length) override;
  Api::IoCallUint64Result write(Buffer::Instance& buffer) override;
  Api::IoCallUint64Result close() override;

  bool isTriggerPipeReady() const;
  const std::unordered_map<std::string, ReverseConnectionMetadata>& getConnectionMetadata() const;

  // ConnectionCallbacks
  void onEvent(Envoy::Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  void initiateReverseTcpConnections();
  bool createReverseConnection(const std::string& cluster_name, uint32_t connection_count);
  void scheduleReconnection(const std::string& cluster_name, uint32_t delay_ms);
  void performHealthCheck(const std::string& cluster_name);
  void scheduleHealthCheck(const std::string& cluster_name);
  bool shouldAttemptConnection(const std::string& cluster_name);
  void onConnectionEstablished(Envoy::Network::ClientConnectionPtr connection);
  void onConnectionClosed(const std::string& cluster_name);
  void sendConnectionIdentification(Envoy::Network::Connection& connection);
  void forwardData(Buffer::Instance& source_buffer, Envoy::Network::Connection& target_connection);
  void updateConnectionMetrics(const std::string& cluster_name, ReverseConnectionState new_state);
  void updateConnectionMetricsUnsafe(const std::string& cluster_name,
                                     ReverseConnectionState new_state);
  void createTriggerPipe();
  void cleanup();

  const ReverseConnectionSocketConfig config_;
  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;

  // Single-byte trigger mechanism
  int trigger_pipe_read_fd_{-1};
  int trigger_pipe_write_fd_{-1};
  std::queue<Envoy::Network::ClientConnectionPtr> established_connections_;

  // Connection management
  std::vector<Envoy::Network::ClientConnectionPtr> reverse_tcp_connections_;
  std::unordered_map<std::string, uint32_t> cluster_connection_counts_;
  std::unordered_map<std::string, ReverseConnectionMetadata> connection_metadata_;
  std::unordered_map<std::string, Event::TimerPtr> reconnection_timers_;
  std::unordered_map<std::string, Event::TimerPtr> health_check_timers_;

  bool listening_initiated_{false};
  absl::Mutex connection_mutex_;
  mutable absl::Mutex metadata_mutex_;
};

/**
 * Socket interface that creates reverse connection sockets.
 */
class DownstreamReverseSocketInterface
    : public Envoy::Network::SocketInterfaceBase,
      public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  DownstreamReverseSocketInterface(const ReverseConnectionSocketConfig& config,
                                   Upstream::ClusterManager& cluster_manager,
                                   Event::Dispatcher& dispatcher, bool test_mode = false);

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

  // BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override {
    return "envoy.extensions.network.socket_interface.reverse_connection";
  }

  static bool validateConfig(const ReverseConnectionSocketConfig& config);

private:
  const ReverseConnectionSocketConfig config_;
  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;
  bool test_mode_;
};

/**
 * Address implementation for reverse connection metadata.
 */
class ReverseConnectionAddress : public Envoy::Network::Address::Instance {
public:
  ReverseConnectionAddress(const std::string& metadata_json,
                           Envoy::Network::Address::InstanceConstSharedPtr base_address);

  // Address::Instance
  bool operator==(const Envoy::Network::Address::Instance& other) const override;
  const std::string& asString() const override;
  absl::string_view asStringView() const override;
  absl::string_view addressAsString() const;
  const sockaddr* sockAddr() const override;
  socklen_t sockAddrLen() const override;
  Envoy::Network::Address::Type type() const override;
  Envoy::Network::Address::IpVersion version() const;
  const Envoy::Network::Address::Ip* ip() const override;
  const Envoy::Network::Address::Pipe* pipe() const override;
  const Envoy::Network::Address::EnvoyInternalAddress* envoyInternalAddress() const override;

  const ReverseConnectionSocketConfig& getReverseConnectionConfig() const { return config_; }
  DownstreamReverseSocketInterface* getSocketInterface() const { return socket_interface_.get(); }

private:
  ReverseConnectionSocketConfig config_;
  Envoy::Network::Address::InstanceConstSharedPtr base_address_;
  std::string address_string_;
  std::unique_ptr<DownstreamReverseSocketInterface> socket_interface_;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
