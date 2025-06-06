#include "source/extensions/filters/network/reverse_connection/reverse_connection_filter.h"

#include <algorithm>
#include <regex>

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/connection.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

// ReverseConnectionNetworkFilter implementation
ReverseConnectionNetworkFilter::ReverseConnectionNetworkFilter(
    const std::string& stat_prefix, const std::string& cluster_name,
    std::chrono::milliseconds connection_timeout, bool debug_logging,
    Upstream::ClusterManager& cluster_manager)
    : stat_prefix_(stat_prefix), cluster_name_(cluster_name),
      connection_timeout_(connection_timeout), debug_logging_(debug_logging),
      cluster_manager_(cluster_manager) {

  ENVOY_LOG(debug, "Created ReverseConnectionNetworkFilter for cluster: {}", cluster_name_);
}

ReverseConnectionNetworkFilter::~ReverseConnectionNetworkFilter() {
  ENVOY_LOG(debug, "Destroying ReverseConnectionNetworkFilter");
  try {
    cleanupConnections();
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception during destructor cleanup: {}", e.what());
  } catch (...) {
    ENVOY_LOG(error, "Unknown exception during destructor cleanup");
  }
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onNewConnection() {
  ENVOY_LOG(debug, "New connection established");
  updateConnectionStats(ConnectionState::Connected);
  return Envoy::Network::FilterStatus::Continue;
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onData(Buffer::Instance& data,
                                                                    bool end_stream) {
  ENVOY_LOG(debug, "onData: Received {} bytes, end_stream: {}", data.length(), end_stream);

  if (data.length() == 0) {
    return Envoy::Network::FilterStatus::Continue;
  }

  // Check if this is HTTP data
  std::string data_str = data.toString();
  bool is_http_request = (data_str.find("GET ") == 0 || data_str.find("POST ") == 0 ||
                          data_str.find("PUT ") == 0 || data_str.find("DELETE ") == 0 ||
                          data_str.find("HEAD ") == 0 || data_str.find("OPTIONS ") == 0);

  if (is_http_request) {
    if (debug_logging_) {
      ENVOY_LOG(debug, "Detected HTTP request - establishing upstream connection");
    }
    if (!is_established_) {
      establishUpstreamConnection();
    }
  } else {
    handleClusterIdentification(data);
    if (!identified_cluster_.empty()) {
      ENVOY_LOG(debug, "Identified cluster: {}", identified_cluster_);
      return Envoy::Network::FilterStatus::StopIteration;
    }
  }

  // Buffer data until upstream connection is established
  if (!is_established_) {
    ENVOY_LOG(debug, "Buffering {} bytes until upstream connection established", data.length());
    downstream_buffer_.move(data);
    return Envoy::Network::FilterStatus::StopIteration;
  }

  // Forward data to upstream
  if (upstream_connection_ &&
      upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
    ENVOY_LOG(trace, "Forwarding {} bytes to upstream connection", data.length());
    upstream_connection_->write(data, false);
  } else {
    ENVOY_LOG(debug, "Upstream connection not ready - buffering {} bytes", data.length());
    upstream_buffer_.move(data);
  }

  return Envoy::Network::FilterStatus::StopIteration;
}

void ReverseConnectionNetworkFilter::initializeReadFilterCallbacks(
    Envoy::Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
  read_callbacks_->connection().addConnectionCallbacks(*this);

  // Create connection timeout timer
  connection_timeout_timer_ =
      read_callbacks_->connection().dispatcher().createTimer([this]() -> void {
        ENVOY_LOG(warn, "Connection timeout - cleaning up");
        cleanupConnections();
      });
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onWrite(Buffer::Instance&, bool) {
  return Envoy::Network::FilterStatus::Continue;
}

void ReverseConnectionNetworkFilter::initializeWriteFilterCallbacks(
    Envoy::Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
}

void ReverseConnectionNetworkFilter::onEvent(Envoy::Network::ConnectionEvent event) {
  switch (event) {
  case Envoy::Network::ConnectionEvent::LocalClose:
  case Envoy::Network::ConnectionEvent::RemoteClose:
    ENVOY_LOG(debug, "Downstream connection closed");
    cleanupConnections();
    break;
  case Envoy::Network::ConnectionEvent::Connected:
    ENVOY_LOG(debug, "Downstream connection established");
    break;
  default:
    break;
  }
}

void ReverseConnectionNetworkFilter::onAboveWriteBufferHighWatermark() {}

void ReverseConnectionNetworkFilter::onBelowWriteBufferLowWatermark() {}

void ReverseConnectionNetworkFilter::establishUpstreamConnection() {
  if (is_established_) {
    return;
  }

  ENVOY_LOG(debug, "Establishing upstream connection to cluster: {}", cluster_name_);

  const std::string& target_cluster =
      identified_cluster_.empty() ? cluster_name_ : identified_cluster_;

  auto cluster = cluster_manager_.getThreadLocalCluster(target_cluster);
  if (!cluster) {
    ENVOY_LOG(error, "Cluster not found: {}", target_cluster);
    handleConnectionFailure();
    return;
  }

  Upstream::LoadBalancerContext* lb_context = nullptr;
  auto host_response = cluster->loadBalancer().chooseHost(lb_context);
  if (!host_response.host) {
    ENVOY_LOG(error, "No healthy hosts available in cluster: {}", target_cluster);
    handleConnectionFailure();
    return;
  }

  // Create upstream connection using the standard Envoy API
  upstream_connection_ = read_callbacks_->connection().dispatcher().createClientConnection(
      host_response.host->address(), Envoy::Network::Address::InstanceConstSharedPtr(),
      std::make_unique<Envoy::Network::RawBufferSocket>(), nullptr, nullptr);

  if (!upstream_connection_) {
    ENVOY_LOG(error, "Failed to create upstream connection");
    handleConnectionFailure();
    return;
  }

  // Set up connection handlers
  upstream_connection_handler_ = std::make_unique<UpstreamConnectionHandler>(*this);
  upstream_connection_->addConnectionCallbacks(*upstream_connection_handler_);

  auto upstream_data_handler = std::make_unique<UpstreamDataHandler>(*this);
  upstream_connection_->addReadFilter(std::move(upstream_data_handler));

  // Start connection timeout
  connection_timeout_timer_->enableTimer(connection_timeout_);

  // Connect the upstream connection
  upstream_connection_->connect();

  ENVOY_LOG(debug, "Upstream connection initiated");
}

void ReverseConnectionNetworkFilter::handleConnectionEstablished(
    Envoy::Network::Connection& upstream_connection) {
  ENVOY_LOG(debug, "Upstream connection established");

  is_established_ = true;
  is_http_tunnel_active_ = true;
  connection_timeout_timer_->disableTimer();

  updateConnectionStats(ConnectionState::HttpTunneling);

  // Forward any buffered downstream data
  if (downstream_buffer_.length() > 0) {
    ENVOY_LOG(debug, "Forwarding {} buffered HTTP bytes to upstream", downstream_buffer_.length());
    upstream_connection.write(downstream_buffer_, false);
    downstream_buffer_.drain(downstream_buffer_.length());
  }
}

void ReverseConnectionNetworkFilter::handleConnectionFailure() {
  ENVOY_LOG(warn, "Upstream connection failed");

  updateConnectionStats(ConnectionState::Closing);
  cleanupConnections();

  // DO NOT force-close downstream connection here - let natural lifecycle handle it
  // The downstream connection will close naturally when appropriate
}

void ReverseConnectionNetworkFilter::cleanupConnections() {
  ENVOY_LOG(debug, "Cleaning up connections");

  if (connection_timeout_timer_) {
    connection_timeout_timer_->disableTimer();
  }

  if (upstream_connection_) {
    if (upstream_connection_handler_) {
      upstream_connection_->removeConnectionCallbacks(*upstream_connection_handler_);
    }
    upstream_connection_->close(Envoy::Network::ConnectionCloseType::NoFlush);
    upstream_connection_.reset();
  }

  if (read_callbacks_) {
    read_callbacks_->connection().removeConnectionCallbacks(*this);
  }

  upstream_connection_handler_.reset();
  is_established_ = false;
  is_http_tunnel_active_ = false;

  updateConnectionStats(ConnectionState::Closed);
}

void ReverseConnectionNetworkFilter::handleUpstreamData(Buffer::Instance& data, bool end_stream) {
  size_t bytes_to_forward = data.length();

  ENVOY_LOG(debug, "handleUpstreamData: Received {} bytes from upstream, end_stream: {}",
            bytes_to_forward, end_stream);

  if (bytes_to_forward == 0) {
    return;
  }

  try {
    // Use filter chain injection for proper data forwarding
    if (write_callbacks_) {
      Buffer::OwnedImpl response_buffer;
      response_buffer.move(data);
      write_callbacks_->injectWriteDataToFilterChain(response_buffer, end_stream);
      ENVOY_LOG(debug, "Forwarded {} bytes via filter chain", bytes_to_forward);
    } else {
      // Fallback to direct connection write
      auto& downstream_conn = read_callbacks_->connection();
      downstream_conn.write(data, false);
      ENVOY_LOG(debug, "Forwarded {} bytes via direct write", bytes_to_forward);
    }

  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception forwarding upstream data: {}", e.what());
  }

  if (end_stream) {
    ENVOY_LOG(debug, "Upstream stream ended - closing downstream connection");
    if (read_callbacks_) {
      read_callbacks_->connection().close(Envoy::Network::ConnectionCloseType::FlushWrite);
    }
  }
}

void ReverseConnectionNetworkFilter::handleUpstreamConnectionEvent(
    Envoy::Network::ConnectionEvent event) {
  switch (event) {
  case Envoy::Network::ConnectionEvent::Connected:
    handleConnectionEstablished(*upstream_connection_);
    break;
  case Envoy::Network::ConnectionEvent::RemoteClose:
    ENVOY_LOG(debug, "Upstream connection remote close");
    // DON'T force close downstream - let it close naturally or client will close it
    // Forcing close here causes recursive cleanup and segfault
    ENVOY_LOG(debug, "Upstream closed - cleaning up upstream only");
    // Just clean up our upstream connection reference, don't force downstream close
    if (upstream_connection_) {
      upstream_connection_.reset();
    }
    if (upstream_connection_handler_) {
      upstream_connection_handler_.reset();
    }
    // Mark tunnel as inactive
    is_established_ = false;
    is_http_tunnel_active_ = false;
    break;
  case Envoy::Network::ConnectionEvent::LocalClose:
    ENVOY_LOG(debug, "Upstream connection local close");
    // Local close of upstream - this is expected during cleanup
    break;
  default:
    ENVOY_LOG(debug, "Upstream connection event: {}", static_cast<int>(event));
    break;
  }
}

void ReverseConnectionNetworkFilter::handleClusterIdentification(Buffer::Instance& data) {
  if (data.length() < 2) {
    return;
  }

  auto cluster_name = extractClusterName(data);
  if (!cluster_name.empty()) {
    identified_cluster_ = cluster_name;
    ENVOY_LOG(debug, "Identified cluster: {}", identified_cluster_);
    data.drain(data.length());
    return;
  }

  // Legacy protocol fallback
  uint8_t* buffer_data = reinterpret_cast<uint8_t*>(data.linearize(data.length()));
  uint16_t cluster_name_length = ntohs(*reinterpret_cast<uint16_t*>(buffer_data));

  if (cluster_name_length > 0 && data.length() >= (2 + cluster_name_length)) {
    std::string cluster_name(reinterpret_cast<char*>(buffer_data + 2), cluster_name_length);
    identified_cluster_ = cluster_name;
    ENVOY_LOG(debug, "Identified cluster (legacy): {}", identified_cluster_);
    data.drain(2 + cluster_name_length);
  }
}

std::string ReverseConnectionNetworkFilter::extractClusterName(Buffer::Instance& data) {
  if (data.length() < 3) {
    return "";
  }

  uint8_t* buffer_data = reinterpret_cast<uint8_t*>(data.linearize(data.length()));

  // Check for enhanced protocol (version byte = 1)
  if (buffer_data[0] == 1) {
    uint16_t cluster_name_length = ntohs(*reinterpret_cast<uint16_t*>(buffer_data + 1));
    if (cluster_name_length > 0 && data.length() >= (3 + cluster_name_length)) {
      return std::string(reinterpret_cast<char*>(buffer_data + 3), cluster_name_length);
    }
  }

  return "";
}

void ReverseConnectionNetworkFilter::updateConnectionStats(ConnectionState new_state) {
  connection_state_ = new_state;
  ENVOY_LOG(trace, "Updated connection state to: {}", static_cast<int>(new_state));
}

// UpstreamDataHandler implementation
Envoy::Network::FilterStatus UpstreamDataHandler::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(debug, "UpstreamDataHandler: Received {} bytes, end_stream: {}", data.length(),
            end_stream);

  try {
    if (data.length() > 0) {
      parent_.handleUpstreamData(data, end_stream);
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception in UpstreamDataHandler: {}", e.what());
    return Envoy::Network::FilterStatus::StopIteration;
  }

  return Envoy::Network::FilterStatus::StopIteration;
}

// UpstreamConnectionHandler implementation
void UpstreamConnectionHandler::onEvent(Envoy::Network::ConnectionEvent event) {
  ENVOY_LOG(debug, "UpstreamConnectionHandler: Connection event: {}", static_cast<int>(event));
  parent_.handleUpstreamConnectionEvent(event);
}

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
