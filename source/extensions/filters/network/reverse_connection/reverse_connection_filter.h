#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "envoy/buffer/buffer.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/network/socket.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

/**
 * Configuration for reverse connection filter.
 */
struct ReverseConnectionFilterConfig {
  std::string stat_prefix;
  std::string cluster_name;
  uint32_t max_connections_per_cluster{5};
  std::chrono::milliseconds connection_timeout{30000};
  bool debug_logging{false};
};

/**
 * Stats for reverse connection filter.
 */
#define ALL_REVERSE_CONNECTION_STATS(COUNTER, GAUGE)                                               \
  COUNTER(connections_created)                                                                     \
  COUNTER(connections_failed)                                                                      \
  COUNTER(connections_closed)                                                                      \
  COUNTER(bytes_forwarded_upstream)                                                                \
  COUNTER(bytes_forwarded_downstream)                                                              \
  COUNTER(http_requests_forwarded)                                                                 \
  COUNTER(http_responses_forwarded)                                                                \
  GAUGE(active_connections, NeverImport)                                                           \
  GAUGE(pending_connections, NeverImport)

struct ReverseConnectionStats {
  ALL_REVERSE_CONNECTION_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

/**
 * Connection state tracking.
 */
enum class ConnectionState { Initializing, Connected, HttpTunneling, Closing, Closed };

/**
 * HTTP tunnel state for end-to-end forwarding.
 */
struct HttpTunnelState {
  bool request_headers_parsed{false};
  bool response_headers_parsed{false};
  std::string method;
  std::string path;
  std::string host;
  size_t content_length{0};
  size_t bytes_forwarded{0};
  ConnectionState state{ConnectionState::Initializing};
};

/**
 * Connection metadata for tracking.
 */
struct ConnectionMetadata {
  std::string cluster_name;
  std::chrono::steady_clock::time_point established_time;
  HttpTunnelState tunnel_state;
  Envoy::Network::Connection* downstream_connection{nullptr};
  Envoy::Network::Connection* upstream_connection{nullptr};
};

/**
 * Thread-local connection cache.
 */
class ReverseConnectionCache : public ThreadLocal::ThreadLocalObject,
                               public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  ReverseConnectionCache() = default;

  void addConnection(Envoy::Network::Connection& connection, const std::string& cluster_name);
  Envoy::Network::Connection* getConnection(const std::string& cluster_name);
  void removeConnection(Envoy::Network::Connection& connection);
  size_t getConnectionCount() const;

private:
  absl::flat_hash_map<std::string, std::vector<Envoy::Network::Connection*>> cluster_connections_;
  absl::flat_hash_map<Envoy::Network::Connection*, ConnectionMetadata> connection_metadata_;
  mutable absl::Mutex cache_mutex_;
};

// Forward declarations
class ReverseConnectionNetworkFilter;

/**
 * Handler for upstream connection events.
 */
class UpstreamConnectionHandler : public Envoy::Network::ConnectionCallbacks,
                                  public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  UpstreamConnectionHandler(ReverseConnectionNetworkFilter& parent) : parent_(parent) {}

  // Network::ConnectionCallbacks
  void onEvent(Envoy::Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  ReverseConnectionNetworkFilter& parent_;
};

/**
 * Handler for upstream data.
 */
class UpstreamDataHandler : public Envoy::Network::ReadFilter,
                            public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  UpstreamDataHandler(ReverseConnectionNetworkFilter& parent) : parent_(parent) {}

  // Network::ReadFilter
  Envoy::Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Envoy::Network::FilterStatus onNewConnection() override {
    return Envoy::Network::FilterStatus::Continue;
  }
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& /*callbacks*/) override {}

private:
  ReverseConnectionNetworkFilter& parent_;
};

/**
 * Terminal network filter that handles reverse connections and HTTP tunneling.
 */
class ReverseConnectionNetworkFilter : public Envoy::Network::ReadFilter,
                                       public Envoy::Network::WriteFilter,
                                       public Envoy::Network::ConnectionCallbacks,
                                       public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  ReverseConnectionNetworkFilter(const std::string& stat_prefix, const std::string& cluster_name,
                                 uint32_t max_connections_per_cluster,
                                 std::chrono::milliseconds connection_timeout, bool debug_logging,
                                 Upstream::ClusterManager& cluster_manager,
                                 Thread::ThreadFactory& thread_factory);

  ~ReverseConnectionNetworkFilter() override;

  // Network::ReadFilter
  Envoy::Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Envoy::Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override;

  // Network::WriteFilter
  Envoy::Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
  void initializeWriteFilterCallbacks(Envoy::Network::WriteFilterCallbacks& callbacks) override;

  // Network::ConnectionCallbacks
  void onEvent(Envoy::Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override;
  void onBelowWriteBufferLowWatermark() override;

  // Upstream event handling (public for helper classes)
  void handleUpstreamData(Buffer::Instance& data, bool end_stream);
  void handleUpstreamConnectionEvent(Envoy::Network::ConnectionEvent event);

private:
  // Connection management
  void establishUpstreamConnection();
  void handleConnectionEstablished(Envoy::Network::Connection& upstream_connection);
  void handleConnectionFailure();
  void cleanupConnections();

  // HTTP tunneling
  bool parseHttpRequest(Buffer::Instance& data, HttpTunnelState& tunnel_state);
  bool parseHttpResponse(Buffer::Instance& data, HttpTunnelState& tunnel_state);
  void forwardHttpData(Buffer::Instance& data);
  void handleHttpRequest(const std::string& method, const std::string& path,
                         const std::string& host);
  void handleHttpResponse();

  // Protocol handling
  void handleClusterIdentification(Buffer::Instance& data);
  void sendClusterIdentification();
  std::string extractClusterName(Buffer::Instance& data);

  // Performance optimizations
  void enableZeroCopyForwarding();
  void optimizeSocketSettings();

  // Stats and monitoring
  void updateConnectionStats(ConnectionState new_state);
  void recordForwardingMetrics(size_t bytes_forwarded, bool is_upstream);

  // Configuration
  const std::string stat_prefix_;
  const std::string cluster_name_;
  [[maybe_unused]] const uint32_t max_connections_per_cluster_;
  const std::chrono::milliseconds connection_timeout_;
  const bool debug_logging_;

  // Dependencies
  Upstream::ClusterManager& cluster_manager_;
  [[maybe_unused]] Thread::ThreadFactory& thread_factory_;

  // Connection state
  Envoy::Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  Envoy::Network::WriteFilterCallbacks* write_callbacks_{nullptr};
  ::Envoy::Network::ConnectionInfoSetter* connection_info_setter_{nullptr};

  // Connections
  Envoy::Network::ClientConnectionPtr upstream_connection_;
  std::unique_ptr<UpstreamConnectionHandler> upstream_connection_handler_;
  ConnectionMetadata connection_metadata_;

  // HTTP state
  HttpTunnelState http_tunnel_state_;
  Buffer::OwnedImpl upstream_buffer_;
  Buffer::OwnedImpl downstream_buffer_;

  // Stats - TODO: Implement proper stats integration

  // Keepalive and timers
  Event::TimerPtr keepalive_timer_;
  Event::TimerPtr connection_timeout_timer_;

  // State tracking
  bool is_established_{false};
  bool is_http_tunnel_active_{false};
  std::string identified_cluster_;
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
