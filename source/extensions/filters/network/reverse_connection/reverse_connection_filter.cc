#include "source/extensions/filters/network/reverse_connection/reverse_connection_filter.h"

#include <algorithm>
#include <cstring>
#include <regex>
#include <sstream>

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/http/header_map.h"
#include "envoy/http/message.h"
#include "envoy/network/connection.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/extensions/filters/network/reverse_connection/reverse_connection_socket_handoff_manager.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

#include "fmt/format.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

// ReverseConnectionNetworkFilter implementation
ReverseConnectionNetworkFilter::ReverseConnectionNetworkFilter(
    const std::string& stat_prefix, const std::string& cluster_name,
    std::chrono::milliseconds connection_timeout, bool debug_logging,
    Upstream::ClusterManager& cluster_manager,
    std::shared_ptr<SocketHandoffManager> socket_handoff_manager)
    : stat_prefix_(stat_prefix), cluster_name_(cluster_name),
      connection_timeout_(connection_timeout), debug_logging_(debug_logging),
      enable_http_pooling_(true), cluster_manager_(cluster_manager),
      socket_handoff_manager_(socket_handoff_manager) {

  ENVOY_LOG(debug,
            "Created ReverseConnectionNetworkFilter for cluster: {} with HTTP pooling enabled",
            cluster_name_);
}

ReverseConnectionNetworkFilter::ReverseConnectionNetworkFilter(
    const ReverseConnectionConfig& config, Upstream::ClusterManager& cluster_manager,
    std::shared_ptr<SocketHandoffManager> socket_handoff_manager)
    : stat_prefix_(config.statPrefix()), cluster_name_(config.clusterName()),
      connection_timeout_(config.connectionTimeout()), debug_logging_(config.debugLogging()),
      enable_http_pooling_(config.enableHttpPooling()),
      enable_socket_handoff_(config.enableSocketHandoff()), cluster_manager_(cluster_manager),
      socket_handoff_manager_(socket_handoff_manager) {

  ENVOY_LOG(debug,
            "Created ReverseConnectionNetworkFilter for cluster: {} with HTTP pooling: {}, socket "
            "handoff: {}",
            cluster_name_, enable_http_pooling_ ? "enabled" : "disabled",
            enable_socket_handoff_ ? "enabled" : "disabled");

  if (enable_socket_handoff_ && socket_handoff_manager_) {
    enableSocketHandoffOptimization();
  }
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

  // Enhanced HTTP detection with security and performance optimizations
  bool is_http_request = detectHttpRequest(data);

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

  // Enhanced buffer management with size limits
  if (!is_established_) {
    if (!enforceBufferLimits(data)) {
      ENVOY_LOG(error, "Buffer limit exceeded - rejecting connection");
      handleConnectionFailure();
      return Envoy::Network::FilterStatus::StopIteration;
    }

    ENVOY_LOG(debug, "Buffering {} bytes until upstream connection established", data.length());
    downstream_buffer_.move(data);
    return Envoy::Network::FilterStatus::StopIteration;
  }

  // Forward data to upstream
  if (enable_http_pooling_ && http_request_encoder_) {
    // Forward data through HTTP connection pool
    ENVOY_LOG(trace, "Forwarding {} bytes through HTTP connection pool", data.length());
    forwardHttpRequest(data);
  } else if (upstream_connection_ &&
             upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
    // Forward data through legacy raw connection
    ENVOY_LOG(trace, "Forwarding {} bytes to upstream connection", data.length());
    upstream_connection_->write(data, false);
  } else {
    ENVOY_LOG(debug, "Upstream connection not ready - buffering {} bytes", data.length());
    if (enable_http_pooling_) {
      downstream_buffer_.move(data);
    } else {
      upstream_buffer_.move(data);
    }
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

  // CRITICAL FIX: Check socket handoff optimization FIRST, regardless of HTTP pooling setting
  if (enable_socket_handoff_) {
    upstream_connection_ = getOptimizedConnection();
    if (upstream_connection_) {
      ENVOY_LOG(info, "🚀 Using optimized socket handoff connection for cluster: {} (REUSED)",
                cluster_name_);

      // Set up connection handlers for optimized connection
      upstream_connection_handler_ = std::make_unique<UpstreamConnectionHandler>(*this);
      upstream_connection_->addConnectionCallbacks(*upstream_connection_handler_);

      auto upstream_data_handler = std::make_unique<UpstreamDataHandler>(*this);
      upstream_connection_->addReadFilter(std::move(upstream_data_handler));

      // Connection is already established, so trigger the established handler
      handleConnectionEstablished(*upstream_connection_);
      return;
    } else {
      ENVOY_LOG(debug, "Socket handoff pool MISS for cluster: {} - falling back to connection pool",
                cluster_name_);
    }
  }

  // Fallback to HTTP connection pooling or legacy raw connection
  if (enable_http_pooling_) {
    establishHttpPoolConnection();
  } else {
    establishLegacyRawConnection();
  }
}

void ReverseConnectionNetworkFilter::establishHttpPoolConnection() {
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

  // Create HTTP connection pool data
  absl::optional<Http::Protocol> protocol =
      Http::Protocol::Http11; // Default to HTTP/1.1 for tunneling
  http_conn_pool_data_ = cluster->httpConnPool(
      host_response.host, Upstream::ResourcePriority::Default, protocol, lb_context);

  if (!http_conn_pool_data_.has_value()) {
    ENVOY_LOG(error, "Failed to get HTTP connection pool for cluster: {}", target_cluster);
    handleConnectionFailure();
    return;
  }

  // Create HTTP response decoder and pool callbacks
  http_response_decoder_ = std::make_unique<ReverseConnectionHttpDecoder>(*this);
  http_pool_callbacks_ = std::make_unique<ReverseConnectionPoolCallbacks>(*this);

  // Start connection timeout
  connection_timeout_timer_->enableTimer(connection_timeout_);

  // Request new stream from connection pool
  Http::ConnectionPool::Instance::StreamOptions stream_options;
  stream_options.can_send_early_data_ = false;
  stream_options.can_use_http3_ = false;

  http_conn_pool_handle_ = http_conn_pool_data_.value().newStream(
      *http_response_decoder_, *http_pool_callbacks_, stream_options);

  ENVOY_LOG(debug, "HTTP connection pool stream requested for cluster: {}", target_cluster);
}

void ReverseConnectionNetworkFilter::establishLegacyRawConnection() {
  const std::string& target_cluster =
      identified_cluster_.empty() ? cluster_name_ : identified_cluster_;

  // Note: Socket handoff optimization is now handled in establishUpstreamConnection()

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

  // Fallback: Create upstream connection using the standard Envoy API
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

  ENVOY_LOG(debug, "Legacy upstream connection initiated");
}

void ReverseConnectionNetworkFilter::handleHttpPoolReady(
    Http::RequestEncoder& request_encoder, Upstream::HostDescriptionConstSharedPtr host) {
  ENVOY_LOG(debug, "HTTP connection pool ready for host: {}", host->hostname());

  http_request_encoder_ = &request_encoder;
  http_conn_pool_handle_ = nullptr;
  is_established_ = true;
  is_http_tunnel_active_ = false; // Start with tunnel inactive for HTTP request parsing
  connection_timeout_timer_->disableTimer();

  updateConnectionStats(ConnectionState::HttpTunneling);

  // Forward any buffered downstream data as parsed HTTP request
  if (downstream_buffer_.length() > 0) {
    ENVOY_LOG(debug, "Forwarding {} buffered bytes as HTTP request", downstream_buffer_.length());
    forwardHttpRequest(downstream_buffer_);
  }
}

void ReverseConnectionNetworkFilter::handleHttpPoolFailure(
    ConnectionPool::PoolFailureReason reason, absl::string_view transport_failure_reason) {
  ENVOY_LOG(warn, "HTTP connection pool failure: {} - {}", static_cast<int>(reason),
            transport_failure_reason);

  http_conn_pool_handle_ = nullptr;
  handleConnectionFailure();
}

void ReverseConnectionNetworkFilter::handleHttpResponseHeaders(Http::ResponseHeaderMapPtr&& headers,
                                                               bool end_stream) {
  ENVOY_LOG(debug, "Received HTTP response headers, end_stream: {}", end_stream);

  // For HTTP request forwarding, we expect standard HTTP status codes (200, 404, etc.)
  const auto status = Http::Utility::getResponseStatus(*headers);
  ENVOY_LOG(debug, "HTTP response status: {}", status);

  // Forward response headers to downstream client
  try {
    if (write_callbacks_) {
      // Convert response headers to buffer format for forwarding
      std::string response_line = fmt::format("HTTP/1.1 {} {}\r\n", status,
                                              status == 200   ? "OK"
                                              : status == 404 ? "Not Found"
                                              : status == 500 ? "Internal Server Error"
                                                              : "Unknown");

      // Add headers
      headers->iterate(
          [&response_line](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
            response_line += fmt::format("{}: {}\r\n", header.key().getStringView(),
                                         header.value().getStringView());
            return Http::HeaderMap::Iterate::Continue;
          });

      response_line += "\r\n"; // End of headers

      Buffer::OwnedImpl response_buffer(response_line);
      write_callbacks_->injectWriteDataToFilterChain(response_buffer, end_stream);
      ENVOY_LOG(debug, "Forwarded HTTP response headers with status: {}", status);
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception forwarding HTTP response headers: {}", e.what());
  }

  if (end_stream) {
    ENVOY_LOG(debug, "HTTP response ended - closing downstream connection");
    if (read_callbacks_) {
      read_callbacks_->connection().close(Envoy::Network::ConnectionCloseType::FlushWrite);
    }
  }
}

void ReverseConnectionNetworkFilter::handleHttpResponseData(Buffer::Instance& data,
                                                            bool end_stream) {
  size_t bytes_to_forward = data.length();

  ENVOY_LOG(debug, "handleHttpResponseData: Received {} bytes from HTTP pool, end_stream: {}",
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
    ENVOY_LOG(error, "Exception forwarding HTTP response data: {}", e.what());
  }

  if (end_stream) {
    ENVOY_LOG(debug, "HTTP response stream ended - closing downstream connection");
    if (read_callbacks_) {
      read_callbacks_->connection().close(Envoy::Network::ConnectionCloseType::FlushWrite);
    }
  }
}

void ReverseConnectionNetworkFilter::forwardHttpRequest(Buffer::Instance& data) {
  if (!http_request_encoder_) {
    ENVOY_LOG(error, "No HTTP request encoder available for forwarding");
    return;
  }

  if (data.length() == 0) {
    return;
  }

  if (!is_http_tunnel_active_) {
    // Parse and forward the original HTTP request (not CONNECT)
    ENVOY_LOG(debug, "Parsing HTTP request from {} bytes", data.length());

    // Extract HTTP headers and body from the raw data
    std::string request_str = data.toString();
    size_t header_end = request_str.find("\r\n\r\n");

    if (header_end == std::string::npos) {
      ENVOY_LOG(debug, "Incomplete HTTP request - buffering for more data");
      return; // Wait for complete headers
    }

    std::string headers_str = request_str.substr(0, header_end);
    std::string body_str = request_str.substr(header_end + 4);

    // Parse request line and headers
    std::istringstream header_stream(headers_str);
    std::string request_line;
    std::getline(header_stream, request_line);

    // Parse method, path, and version
    std::istringstream request_stream(request_line);
    std::string method, path, version;
    request_stream >> method >> path >> version;

    if (method.empty() || path.empty()) {
      ENVOY_LOG(error, "Invalid HTTP request line: {}", request_line);
      handleConnectionFailure();
      return;
    }

    ENVOY_LOG(debug, "Forwarding HTTP request: {} {}", method, path);

    // Create header map with parsed values
    auto headers = Http::RequestHeaderMapImpl::create();
    headers->setMethod(method);
    headers->setPath(path);

    // Parse and add other headers
    std::string header_line;
    while (std::getline(header_stream, header_line) && !header_line.empty()) {
      if (header_line.back() == '\r') {
        header_line.pop_back(); // Remove \r
      }

      size_t colon_pos = header_line.find(':');
      if (colon_pos != std::string::npos) {
        std::string header_name = header_line.substr(0, colon_pos);
        std::string header_value = header_line.substr(colon_pos + 1);

        // Trim whitespace
        header_value.erase(0, header_value.find_first_not_of(" \t"));
        header_value.erase(header_value.find_last_not_of(" \t") + 1);

        if (!header_name.empty() && !header_value.empty()) {
          headers->addCopy(Http::LowerCaseString(header_name), header_value);
        }
      }
    }

    // Send the parsed HTTP request
    bool end_stream = body_str.empty();
    auto status = http_request_encoder_->encodeHeaders(*headers, end_stream);
    if (!status.ok()) {
      ENVOY_LOG(error, "Failed to encode HTTP headers");
      handleConnectionFailure();
      return;
    }

    // Send body if present
    if (!body_str.empty()) {
      Buffer::OwnedImpl body_buffer(body_str);
      http_request_encoder_->encodeData(body_buffer, true);
    }

    // Drain the processed data
    data.drain(data.length());
    is_http_tunnel_active_ = true;

    ENVOY_LOG(debug, "Successfully forwarded HTTP request: {} {}", method, path);
  } else {
    // Forward additional data (for requests with bodies)
    ENVOY_LOG(trace, "Forwarding {} additional bytes", data.length());
    http_request_encoder_->encodeData(data, false);
  }
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

  // Exception-safe cleanup with individual try-catch blocks
  try {
    if (connection_timeout_timer_) {
      connection_timeout_timer_->disableTimer();
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception disabling timeout timer: {}", e.what());
  }

  // Cleanup HTTP connection pool resources
  try {
    if (http_conn_pool_handle_) {
      http_conn_pool_handle_->cancel(ConnectionPool::CancelPolicy::Default);
      http_conn_pool_handle_ = nullptr;
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception canceling HTTP pool handle: {}", e.what());
  }

  // Safe cleanup of HTTP pool resources
  http_request_encoder_ = nullptr;
  http_response_decoder_.reset();
  http_pool_callbacks_.reset();
  http_conn_pool_data_.reset();

  // Cleanup legacy raw connection resources
  try {
    if (upstream_connection_) {
      if (upstream_connection_handler_) {
        upstream_connection_->removeConnectionCallbacks(*upstream_connection_handler_);
      }
      upstream_connection_->close(Envoy::Network::ConnectionCloseType::NoFlush);
      upstream_connection_.reset();
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception cleaning up upstream connection: {}", e.what());
  }

  try {
    if (read_callbacks_) {
      read_callbacks_->connection().removeConnectionCallbacks(*this);
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception removing connection callbacks: {}", e.what());
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

    // Return connection to pool if it's from socket handoff optimization
    if (enable_socket_handoff_ && socket_handoff_manager_ && upstream_connection_) {
      try {
        // Check if connection is still healthy for reuse
        if (upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
          ENVOY_LOG(debug,
                    "Returning healthy connection to DISPATCHER-AWARE socket handoff pool for "
                    "cluster: {}",
                    cluster_name_);
          // CRITICAL FIX: Use dispatcher-aware connection return to prevent cross-thread usage
          if (read_callbacks_) {
            socket_handoff_manager_->returnConnection(cluster_name_,
                                                      std::move(upstream_connection_),
                                                      read_callbacks_->connection().dispatcher());
          } else {
            socket_handoff_manager_->returnConnection(cluster_name_,
                                                      std::move(upstream_connection_));
          }
        } else {
          ENVOY_LOG(debug, "Connection not healthy for reuse, disposing for cluster: {}",
                    cluster_name_);
          upstream_connection_.reset();
        }
      } catch (const std::exception& e) {
        ENVOY_LOG(error, "Exception returning connection to pool: {}", e.what());
        upstream_connection_.reset();
      }
    } else {
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
    sanitizeClusterName(cluster_name);
    identified_cluster_ = cluster_name;
    ENVOY_LOG(debug, "Identified cluster: {}", identified_cluster_);
    data.drain(data.length());
    return;
  }

  // Legacy protocol fallback with enhanced security
  uint8_t* buffer_data = reinterpret_cast<uint8_t*>(data.linearize(data.length()));
  uint16_t cluster_name_length = ntohs(*reinterpret_cast<uint16_t*>(buffer_data));

  // Enhanced security checks
  static constexpr uint16_t MAX_LEGACY_CLUSTER_NAME_LENGTH = 64;
  if (cluster_name_length > 0 && cluster_name_length <= MAX_LEGACY_CLUSTER_NAME_LENGTH &&
      data.length() >= (2 + cluster_name_length)) {
    std::string cluster_name(reinterpret_cast<char*>(buffer_data + 2), cluster_name_length);
    sanitizeClusterName(cluster_name);
    identified_cluster_ = cluster_name;
    ENVOY_LOG(debug, "Identified cluster (legacy): {}", identified_cluster_);
    data.drain(2 + cluster_name_length);
  } else if (cluster_name_length > MAX_LEGACY_CLUSTER_NAME_LENGTH) {
    ENVOY_LOG(warn, "Legacy cluster name length {} exceeds maximum {}, ignoring",
              cluster_name_length, MAX_LEGACY_CLUSTER_NAME_LENGTH);
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

bool ReverseConnectionNetworkFilter::detectHttpRequest(const Buffer::Instance& data) {
  // Production-optimized HTTP detection with security safeguards
  static constexpr size_t MIN_HTTP_REQUEST_SIZE = 4; // "GET "
  static constexpr size_t MAX_METHOD_CHECK_SIZE = 8; // "OPTIONS "

  if (data.length() < MIN_HTTP_REQUEST_SIZE) {
    return false;
  }

  // Limit inspection to first few bytes for security
  const size_t inspect_size = std::min(static_cast<size_t>(data.length()), MAX_METHOD_CHECK_SIZE);
  uint8_t header[MAX_METHOD_CHECK_SIZE];
  data.copyOut(0, inspect_size, header);

  // Direct byte comparison - much faster than string operations
  if (inspect_size >= 4 && std::memcmp(header, "GET ", 4) == 0)
    return true;
  if (inspect_size >= 5 && std::memcmp(header, "POST ", 5) == 0)
    return true;
  if (inspect_size >= 4 && std::memcmp(header, "PUT ", 4) == 0)
    return true;
  if (inspect_size >= 7 && std::memcmp(header, "DELETE ", 7) == 0)
    return true;
  if (inspect_size >= 5 && std::memcmp(header, "HEAD ", 5) == 0)
    return true;
  if (inspect_size >= 8 && std::memcmp(header, "OPTIONS ", 8) == 0)
    return true;
  if (inspect_size >= 6 && std::memcmp(header, "PATCH ", 6) == 0)
    return true;
  if (inspect_size >= 6 && std::memcmp(header, "TRACE ", 6) == 0)
    return true;

  return false;
}

bool ReverseConnectionNetworkFilter::enforceBufferLimits(const Buffer::Instance& data) {
  // Production buffer limits to prevent memory exhaustion
  static constexpr size_t MAX_BUFFER_SIZE = 64 * 1024;        // 64KB per connection
  static constexpr size_t MAX_SINGLE_PACKET_SIZE = 16 * 1024; // 16KB per packet

  // Check single packet size
  if (data.length() > MAX_SINGLE_PACKET_SIZE) {
    ENVOY_LOG(warn, "Single packet size {} exceeds limit {}", data.length(),
              MAX_SINGLE_PACKET_SIZE);
    return false;
  }

  // Check total buffered size
  const size_t total_buffered =
      downstream_buffer_.length() + upstream_buffer_.length() + data.length();
  if (total_buffered > MAX_BUFFER_SIZE) {
    ENVOY_LOG(warn, "Total buffer size {} would exceed limit {}", total_buffered, MAX_BUFFER_SIZE);
    return false;
  }

  return true;
}

void ReverseConnectionNetworkFilter::sanitizeClusterName(std::string& cluster_name) {
  // Production cluster name sanitization
  static constexpr size_t MAX_CLUSTER_NAME_LENGTH = 64;

  if (cluster_name.length() > MAX_CLUSTER_NAME_LENGTH) {
    ENVOY_LOG(warn, "Cluster name length {} exceeds maximum {}, truncating", cluster_name.length(),
              MAX_CLUSTER_NAME_LENGTH);
    cluster_name.resize(MAX_CLUSTER_NAME_LENGTH);
  }

  // Remove potentially dangerous characters
  std::regex unsafe_chars(R"([^a-zA-Z0-9\-_.])");
  cluster_name = std::regex_replace(cluster_name, unsafe_chars, "_");

  if (cluster_name.empty()) {
    cluster_name = "sanitized_cluster";
  }
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

// ReverseConnectionConfig implementation
ReverseConnectionConfig::ReverseConnectionConfig(const std::string& stat_prefix,
                                                 const std::string& cluster_name,
                                                 std::chrono::milliseconds connection_timeout,
                                                 bool debug_logging, bool enable_http_pooling,
                                                 bool enable_socket_handoff)
    : stat_prefix_(stat_prefix), cluster_name_(cluster_name),
      connection_timeout_(connection_timeout), debug_logging_(debug_logging),
      enable_http_pooling_(enable_http_pooling), enable_socket_handoff_(enable_socket_handoff) {}

// ReverseConnectionHttpDecoder implementation
ReverseConnectionHttpDecoder::ReverseConnectionHttpDecoder(ReverseConnectionNetworkFilter& parent)
    : parent_(parent) {}

void ReverseConnectionHttpDecoder::decodeHeaders(Http::ResponseHeaderMapPtr&& headers,
                                                 bool end_stream) {
  parent_.handleHttpResponseHeaders(std::move(headers), end_stream);
}

void ReverseConnectionHttpDecoder::decodeData(Buffer::Instance& data, bool end_stream) {
  parent_.handleHttpResponseData(data, end_stream);
}

// ReverseConnectionPoolCallbacks implementation
ReverseConnectionPoolCallbacks::ReverseConnectionPoolCallbacks(
    ReverseConnectionNetworkFilter& parent)
    : parent_(parent) {}

void ReverseConnectionPoolCallbacks::onPoolFailure(ConnectionPool::PoolFailureReason reason,
                                                   absl::string_view transport_failure_reason,
                                                   Upstream::HostDescriptionConstSharedPtr) {
  parent_.handleHttpPoolFailure(reason, transport_failure_reason);
}

void ReverseConnectionPoolCallbacks::onPoolReady(Http::RequestEncoder& request_encoder,
                                                 Upstream::HostDescriptionConstSharedPtr host,
                                                 StreamInfo::StreamInfo&,
                                                 absl::optional<Http::Protocol>) {
  parent_.handleHttpPoolReady(request_encoder, host);
}

// Socket handoff optimization implementation
void ReverseConnectionNetworkFilter::enableSocketHandoffOptimization() {
  // Use the pre-created singleton instance from configuration (CRITICAL: Fixes threading issue!)
  if (!socket_handoff_manager_) {
    ENVOY_LOG(warn, "Socket handoff manager not available for cluster: {}", cluster_name_);
    return;
  }

  // Configure optimization parameters for this cluster
  handoff_pool_config_ = std::make_unique<SocketHandoffPoolConfig>();
  handoff_pool_config_->max_connections_per_cluster = 20; // Configurable
  handoff_pool_config_->min_connections_per_cluster = 5;  // Configurable
  handoff_pool_config_->connection_idle_timeout = std::chrono::minutes(10);
  handoff_pool_config_->connection_max_lifetime = std::chrono::hours(2);
  handoff_pool_config_->enable_preconnect = true;
  handoff_pool_config_->preconnect_ratio = 0.8f;

  socket_handoff_manager_->configureClusterPool(cluster_name_, *handoff_pool_config_);

  ENVOY_LOG(info,
            "✅ Enabled socket handoff optimization for cluster: {} with max_connections: {} "
            "(THREAD-SAFE)",
            cluster_name_, handoff_pool_config_->max_connections_per_cluster);
}

Envoy::Network::ClientConnectionPtr ReverseConnectionNetworkFilter::getOptimizedConnection() {
  if (!enable_socket_handoff_ || !socket_handoff_manager_) {
    ENVOY_LOG(debug, "Socket handoff not enabled or manager not available");
    return nullptr;
  }

  // Get connection pool for this cluster - this will create it if it doesn't exist
  if (read_callbacks_) {
    try {
      auto pool = socket_handoff_manager_->getConnectionPool(
          cluster_name_, cluster_manager_, read_callbacks_->connection().dispatcher());

      auto connection = pool->getConnection();
      if (connection) {
        ENVOY_LOG(info, "🎯 Socket handoff pool HIT for cluster: {} - reusing connection",
                  cluster_name_);
        return connection;
      } else {
        ENVOY_LOG(debug, "Socket handoff pool MISS for cluster: {} - no available connections",
                  cluster_name_);
      }
    } catch (const std::exception& e) {
      ENVOY_LOG(error, "Exception getting connection from socket handoff pool for cluster {}: {}",
                cluster_name_, e.what());
    }
  }

  return nullptr;
}

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
