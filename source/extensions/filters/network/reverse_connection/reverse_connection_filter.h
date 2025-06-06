#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/event/timer.h"
#include "envoy/http/codec.h"
#include "envoy/http/conn_pool.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/thread_local_cluster.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

/**
 * Connection state for monitoring and debugging.
 */
enum class ConnectionState { Initializing, Connected, HttpTunneling, Closing, Closed };

// Forward declarations
class ReverseConnectionNetworkFilter;
class SocketHandoffManager;
struct SocketHandoffPoolConfig;

/**
 * Handles upstream connection events.
 */
class UpstreamConnectionHandler : public Envoy::Network::ConnectionCallbacks,
                                  public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  explicit UpstreamConnectionHandler(ReverseConnectionNetworkFilter& parent) : parent_(parent) {}

  // Network::ConnectionCallbacks
  void onEvent(Envoy::Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  ReverseConnectionNetworkFilter& parent_;
};

/**
 * Handles data from upstream connections.
 */
class UpstreamDataHandler : public Envoy::Network::ReadFilter,
                            public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  explicit UpstreamDataHandler(ReverseConnectionNetworkFilter& parent) : parent_(parent) {}

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
 * HTTP Response Decoder for reverse connection HTTP tunneling
 */
class ReverseConnectionHttpDecoder : public Http::ResponseDecoder {
public:
  ReverseConnectionHttpDecoder(class ReverseConnectionNetworkFilter& parent);
  ~ReverseConnectionHttpDecoder() override = default;

  // Http::ResponseDecoder
  void decode1xxHeaders(Http::ResponseHeaderMapPtr&&) override {}
  void decodeHeaders(Http::ResponseHeaderMapPtr&& headers, bool end_stream) override;
  void decodeData(Buffer::Instance& data, bool end_stream) override;
  void decodeTrailers(Http::ResponseTrailerMapPtr&&) override {}
  void decodeMetadata(Http::MetadataMapPtr&&) override {}
  void dumpState(std::ostream&, int = 0) const override {}

private:
  ReverseConnectionNetworkFilter& parent_;
};

/**
 * HTTP Connection Pool Callbacks for reverse connection HTTP tunneling
 */
class ReverseConnectionPoolCallbacks : public Http::ConnectionPool::Callbacks {
public:
  ReverseConnectionPoolCallbacks(ReverseConnectionNetworkFilter& parent);
  ~ReverseConnectionPoolCallbacks() override = default;

  // Http::ConnectionPool::Callbacks
  void onPoolFailure(ConnectionPool::PoolFailureReason reason,
                     absl::string_view transport_failure_reason,
                     Upstream::HostDescriptionConstSharedPtr host) override;
  void onPoolReady(Http::RequestEncoder& request_encoder,
                   Upstream::HostDescriptionConstSharedPtr host, StreamInfo::StreamInfo& info,
                   absl::optional<Http::Protocol> protocol) override;

private:
  ReverseConnectionNetworkFilter& parent_;
};

/**
 * Configuration for reverse connection filter
 */
class ReverseConnectionConfig {
public:
  ReverseConnectionConfig(const std::string& stat_prefix, const std::string& cluster_name,
                          std::chrono::milliseconds connection_timeout, bool debug_logging,
                          bool enable_http_pooling = true, bool enable_socket_handoff = false);

  const std::string& statPrefix() const { return stat_prefix_; }
  const std::string& clusterName() const { return cluster_name_; }
  std::chrono::milliseconds connectionTimeout() const { return connection_timeout_; }
  bool debugLogging() const { return debug_logging_; }
  bool enableHttpPooling() const { return enable_http_pooling_; }
  bool enableSocketHandoff() const { return enable_socket_handoff_; }

private:
  const std::string stat_prefix_;
  const std::string cluster_name_;
  const std::chrono::milliseconds connection_timeout_;
  const bool debug_logging_;
  const bool enable_http_pooling_;
  const bool enable_socket_handoff_;
};

/**
 * Terminal network filter for HTTP tunneling through reverse connections.
 *
 * This filter:
 * - Establishes upstream connections lazily when HTTP data arrives
 * - Forwards HTTP requests/responses through the established connection
 * - Handles connection lifecycle and cleanup
 * - Acts as both ReadFilter and WriteFilter (terminal)
 */
class ReverseConnectionNetworkFilter : public Envoy::Network::ReadFilter,
                                       public Envoy::Network::WriteFilter,
                                       public Envoy::Network::ConnectionCallbacks,
                                       public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  ReverseConnectionNetworkFilter(
      const std::string& stat_prefix, const std::string& cluster_name,
      std::chrono::milliseconds connection_timeout, bool debug_logging,
      Upstream::ClusterManager& cluster_manager,
      std::shared_ptr<SocketHandoffManager> socket_handoff_manager = nullptr);

  ReverseConnectionNetworkFilter(
      const ReverseConnectionConfig& config, Upstream::ClusterManager& cluster_manager,
      std::shared_ptr<SocketHandoffManager> socket_handoff_manager = nullptr);

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

  // HTTP Connection Pool integration
  void handleHttpPoolReady(Http::RequestEncoder& request_encoder,
                           Upstream::HostDescriptionConstSharedPtr host);
  void handleHttpPoolFailure(ConnectionPool::PoolFailureReason reason,
                             absl::string_view transport_failure_reason);
  void handleHttpResponseHeaders(Http::ResponseHeaderMapPtr&& headers, bool end_stream);
  void handleHttpResponseData(Buffer::Instance& data, bool end_stream);

  // Socket handoff optimization
  void enableSocketHandoffOptimization();
  Envoy::Network::ClientConnectionPtr getOptimizedConnection();

  // Upstream event handling (public for helper classes)
  void handleUpstreamData(Buffer::Instance& data, bool end_stream);
  void handleUpstreamConnectionEvent(Envoy::Network::ConnectionEvent event);

private:
  // Connection management
  void establishUpstreamConnection();
  void establishHttpPoolConnection();
  void establishLegacyRawConnection();
  void cleanupConnections();
  void handleConnectionEstablished(Envoy::Network::Connection& upstream_connection);
  void handleConnectionFailure();

  // HTTP request forwarding
  void forwardHttpRequest(Buffer::Instance& data);

  // Protocol handling
  void handleClusterIdentification(Buffer::Instance& data);
  std::string extractClusterName(Buffer::Instance& data);

  // Production-ready optimizations
  bool detectHttpRequest(const Buffer::Instance& data);
  bool enforceBufferLimits(const Buffer::Instance& data);
  void sanitizeClusterName(std::string& cluster_name);

  // Stats and monitoring
  void updateConnectionStats(ConnectionState new_state);

  // Configuration
  const std::string stat_prefix_;
  const std::string cluster_name_;
  const std::chrono::milliseconds connection_timeout_;
  const bool debug_logging_;
  bool enable_http_pooling_;
  bool enable_socket_handoff_;

  // Dependencies
  Upstream::ClusterManager& cluster_manager_;

  // Connection state
  Envoy::Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  Envoy::Network::WriteFilterCallbacks* write_callbacks_{nullptr};

  // Connections
  Envoy::Network::ClientConnectionPtr upstream_connection_;
  std::unique_ptr<UpstreamConnectionHandler> upstream_connection_handler_;

  // Buffers
  Buffer::OwnedImpl upstream_buffer_;
  Buffer::OwnedImpl downstream_buffer_;

  // Timers
  Event::TimerPtr connection_timeout_timer_;

  // State tracking
  bool is_established_{false};
  bool is_http_tunnel_active_{false};
  std::string identified_cluster_;
  ConnectionState connection_state_{ConnectionState::Initializing};

  // HTTP Connection Pool support
  absl::optional<Upstream::HttpPoolData> http_conn_pool_data_;
  Http::ConnectionPool::Cancellable* http_conn_pool_handle_{nullptr};
  std::unique_ptr<ReverseConnectionHttpDecoder> http_response_decoder_;
  std::unique_ptr<ReverseConnectionPoolCallbacks> http_pool_callbacks_;
  Http::RequestEncoder* http_request_encoder_{nullptr};

  // Socket handoff optimization support
  std::shared_ptr<SocketHandoffManager> socket_handoff_manager_;
  std::unique_ptr<SocketHandoffPoolConfig> handoff_pool_config_;
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
