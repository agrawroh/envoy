#pragma once

#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/upstream/cluster_manager.h"

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
  ReverseConnectionNetworkFilter(const std::string& stat_prefix, const std::string& cluster_name,
                                 std::chrono::milliseconds connection_timeout, bool debug_logging,
                                 Upstream::ClusterManager& cluster_manager);

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

  // Protocol handling
  void handleClusterIdentification(Buffer::Instance& data);
  std::string extractClusterName(Buffer::Instance& data);

  // Stats and monitoring
  void updateConnectionStats(ConnectionState new_state);

  // Configuration
  const std::string stat_prefix_;
  const std::string cluster_name_;
  const std::chrono::milliseconds connection_timeout_;
  const bool debug_logging_;

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
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
