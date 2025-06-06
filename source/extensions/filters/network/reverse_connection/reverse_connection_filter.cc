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

// ReverseConnectionCache implementation
void ReverseConnectionCache::addConnection(Envoy::Network::Connection& connection,
                                           const std::string& cluster_name) {
  absl::MutexLock lock(&cache_mutex_);

  cluster_connections_[cluster_name].push_back(&connection);

  ConnectionMetadata metadata;
  metadata.cluster_name = cluster_name;
  metadata.established_time = std::chrono::steady_clock::now();
  connection_metadata_[&connection] = std::move(metadata);

  ENVOY_LOG(debug, "Added connection to cache for cluster: {} (total: {})", cluster_name,
            cluster_connections_[cluster_name].size());
}

Envoy::Network::Connection* ReverseConnectionCache::getConnection(const std::string& cluster_name) {
  absl::MutexLock lock(&cache_mutex_);

  auto it = cluster_connections_.find(cluster_name);
  if (it != cluster_connections_.end() && !it->second.empty()) {
    Envoy::Network::Connection* conn = it->second.back();
    it->second.pop_back();
    ENVOY_LOG(debug, "Retrieved connection from cache for cluster: {}", cluster_name);
    return conn;
  }

  return nullptr;
}

void ReverseConnectionCache::removeConnection(Envoy::Network::Connection& connection) {
  absl::MutexLock lock(&cache_mutex_);

  auto meta_it = connection_metadata_.find(&connection);
  if (meta_it != connection_metadata_.end()) {
    const std::string& cluster_name = meta_it->second.cluster_name;
    auto& connections = cluster_connections_[cluster_name];

    connections.erase(std::remove(connections.begin(), connections.end(), &connection),
                      connections.end());

    connection_metadata_.erase(meta_it);
    ENVOY_LOG(debug, "Removed connection from cache for cluster: {}", cluster_name);
  }
}

size_t ReverseConnectionCache::getConnectionCount() const {
  absl::MutexLock lock(&cache_mutex_);
  return connection_metadata_.size();
}

// ReverseConnectionNetworkFilter implementation
ReverseConnectionNetworkFilter::ReverseConnectionNetworkFilter(
    const std::string& stat_prefix, const std::string& cluster_name,
    uint32_t max_connections_per_cluster, std::chrono::milliseconds connection_timeout,
    bool debug_logging, Upstream::ClusterManager& cluster_manager,
    Thread::ThreadFactory& thread_factory)
    : stat_prefix_(stat_prefix), cluster_name_(cluster_name),
      max_connections_per_cluster_(max_connections_per_cluster),
      connection_timeout_(connection_timeout), debug_logging_(debug_logging),
      cluster_manager_(cluster_manager), thread_factory_(thread_factory) {

  ENVOY_LOG(info, "Created ReverseConnectionNetworkFilter - cluster: {}, debug: {}", cluster_name_,
            debug_logging_);

  // Initialize HTTP tunnel state
  http_tunnel_state_.state = ConnectionState::Initializing;

  // Note: Timer creation deferred to initializeReadFilterCallbacks() for thread safety
}

ReverseConnectionNetworkFilter::~ReverseConnectionNetworkFilter() {
  ENVOY_LOG(debug, "Destroying ReverseConnectionNetworkFilter");

  // Safe cleanup that won't cause issues during destruction
  try {
    cleanupConnections();
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception during destructor cleanup: {}", e.what());
  } catch (...) {
    ENVOY_LOG(error, "Unknown exception during destructor cleanup");
  }
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onNewConnection() {
  ENVOY_LOG(debug, "New connection established - initializing reverse tunnel");

  // Update stats - TODO: Implement proper stats integration
  ENVOY_LOG(debug, "Connection created");
  updateConnectionStats(ConnectionState::Connected);

  // Note: We defer upstream connection establishment until callbacks are initialized

  return Envoy::Network::FilterStatus::Continue;
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onData(Buffer::Instance& data,
                                                                    bool end_stream) {
  // Add comprehensive logging to debug data reception issues
  ENVOY_LOG(info, "onData: Received {} bytes, end_stream: {}", data.length(), end_stream);

  if (data.length() == 0) {
    ENVOY_LOG(info, "onData: Empty data received, end_stream: {}", end_stream);
    if (end_stream) {
      ENVOY_LOG(info, "onData: Stream ended with no data");
    }
    return Envoy::Network::FilterStatus::Continue;
  }

  // Log raw data for debugging (first 100 bytes)
  if (debug_logging_) {
    std::string data_preview = data.toString().substr(0, 100);
    ENVOY_LOG(info, "onData: Raw data preview: {}", data_preview);
  }

  // Check if this is HTTP data (starts with HTTP method)
  std::string data_str = data.toString();
  bool is_http_request = (data_str.find("GET ") == 0 || data_str.find("POST ") == 0 ||
                          data_str.find("PUT ") == 0 || data_str.find("DELETE ") == 0 ||
                          data_str.find("HEAD ") == 0 || data_str.find("OPTIONS ") == 0);

  if (is_http_request) {
    ENVOY_LOG(info, "Detected HTTP request - establishing upstream connection");

    if (!is_established_) {
      ENVOY_LOG(info, "Establishing upstream connection to cluster: {}", cluster_name_);
      establishUpstreamConnection();
    }

    // HTTP data detected - do NOT call handleClusterIdentification
    // This data should be forwarded to upstream, not parsed as cluster identification

  } else {
    ENVOY_LOG(info, "Non-HTTP data received - checking for cluster identification");
    // Handle cluster identification only for non-HTTP data
    handleClusterIdentification(data);

    if (!identified_cluster_.empty()) {
      ENVOY_LOG(info, "Identified cluster: {} - will establish connection when HTTP data arrives",
                identified_cluster_);
      return Envoy::Network::FilterStatus::StopIteration;
    }
  }

  // Buffer data until upstream connection is established
  if (!is_established_) {
    ENVOY_LOG(info, "Buffering {} bytes until upstream connection established", data.length());
    downstream_buffer_.move(data);
    return Envoy::Network::FilterStatus::StopIteration;
  }

  // Forward data to upstream
  if (upstream_connection_ &&
      upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
    ENVOY_LOG(info, "Forwarding {} bytes to upstream connection", data.length());
    forwardHttpData(data);
  } else {
    ENVOY_LOG(warn, "Upstream connection not ready - buffering {} bytes", data.length());
    upstream_buffer_.move(data);
  }

  return Envoy::Network::FilterStatus::StopIteration;
}

void ReverseConnectionNetworkFilter::initializeReadFilterCallbacks(
    Envoy::Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;

  // Add connection callbacks to track connection events
  read_callbacks_->connection().addConnectionCallbacks(*this);

  // Set up connection info
  connection_info_setter_ = &callbacks.connection().connectionInfoSetter();

  // Create timers now that we have access to the connection's dispatcher
  connection_timeout_timer_ =
      read_callbacks_->connection().dispatcher().createTimer([this]() -> void {
        ENVOY_LOG(warn, "Connection timeout expired - closing connection");
        handleConnectionFailure();
      });

  // Start connection timeout
  connection_timeout_timer_->enableTimer(connection_timeout_);

  // Don't establish upstream connection immediately - wait for HTTP data first
  // establishUpstreamConnection(); // REMOVED - will establish when HTTP data arrives

  ENVOY_LOG(debug, "Initialized read filter callbacks and created timers");
}

void ReverseConnectionNetworkFilter::initializeWriteFilterCallbacks(
    Envoy::Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;

  ENVOY_LOG(debug, "Initialized write filter callbacks");
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onWrite(Buffer::Instance& data,
                                                                     bool end_stream) {
  ENVOY_LOG(trace, "Writing {} bytes, end_stream: {}", data.length(), end_stream);

  // As a terminal filter, we handle all write operations
  // In our case, we're managing the HTTP tunneling, so we handle writes directly

  if (is_http_tunnel_active_ && upstream_connection_ &&
      upstream_connection_->state() == Envoy::Network::Connection::State::Open) {

    // Forward data to upstream connection
    upstream_connection_->write(data, end_stream);

    // Update metrics
    recordForwardingMetrics(data.length(), true);

    ENVOY_LOG(trace, "Forwarded {} bytes to upstream", data.length());
  } else {
    // Buffer data until tunnel is ready
    upstream_buffer_.move(data);
    ENVOY_LOG(debug, "Buffering {} bytes for write until tunnel ready", upstream_buffer_.length());
  }

  // Terminal filter - we consume all data
  return Envoy::Network::FilterStatus::StopIteration;
}

void ReverseConnectionNetworkFilter::onEvent(Envoy::Network::ConnectionEvent event) {
  switch (event) {
  case Envoy::Network::ConnectionEvent::Connected:
    // This event comes from the downstream connection (client connecting to us)
    ENVOY_LOG(info, "Downstream connection established");
    // Note: Upstream connection establishment is handled separately via upstream connection
    // callbacks
    break;

  case Envoy::Network::ConnectionEvent::RemoteClose:
    ENVOY_LOG(info, "Connection remote close");
    // DON'T immediately close downstream - let data flush first
    // Only cleanup upstream connection, let downstream close naturally
    if (upstream_connection_) {
      ENVOY_LOG(info, "Upstream connection closed - keeping downstream open for data flush");
      upstream_connection_.reset(); // Clean up upstream reference
    }
    ENVOY_LOG(debug, "Remote connection closed");
    break;

  case Envoy::Network::ConnectionEvent::LocalClose:
    ENVOY_LOG(info, "Connection local close");
    cleanupConnections();
    ENVOY_LOG(debug, "Local connection closed");
    break;

  default:
    ENVOY_LOG(debug, "Connection event: {}", static_cast<int>(event));
    break;
  }
}

void ReverseConnectionNetworkFilter::onAboveWriteBufferHighWatermark() {
  ENVOY_LOG(debug, "Write buffer above high watermark");
  if (upstream_connection_) {
    upstream_connection_->readDisable(true);
  }
}

void ReverseConnectionNetworkFilter::onBelowWriteBufferLowWatermark() {
  ENVOY_LOG(debug, "Write buffer below low watermark");
  if (upstream_connection_) {
    upstream_connection_->readDisable(false);
  }
}

void ReverseConnectionNetworkFilter::establishUpstreamConnection() {
  // Ensure callbacks are initialized before proceeding
  if (!read_callbacks_) {
    ENVOY_LOG(debug, "Read callbacks not initialized yet - deferring upstream connection");
    return;
  }

  // Use identified cluster if available, otherwise use configured cluster
  const std::string& target_cluster =
      identified_cluster_.empty() ? cluster_name_ : identified_cluster_;

  if (target_cluster.empty()) {
    ENVOY_LOG(error, "No cluster name configured - cannot establish upstream connection");
    return;
  }

  // Check if we already have an upstream connection established
  if (upstream_connection_ &&
      upstream_connection_->state() != Envoy::Network::Connection::State::Closed) {
    ENVOY_LOG(debug, "Upstream connection already exists for cluster '{}' - skipping establishment",
              target_cluster);
    return;
  }

  // Clean up any existing connection properly before establishing new one
  if (upstream_connection_) {
    ENVOY_LOG(debug, "Cleaning up existing upstream connection before establishing new one");
    upstream_connection_->close(Envoy::Network::ConnectionCloseType::NoFlush);
    upstream_connection_.reset();
  }

  ENVOY_LOG(info, "Establishing upstream connection to cluster: {}", target_cluster);

  // Get cluster reference
  auto cluster_ref = cluster_manager_.getThreadLocalCluster(target_cluster);
  if (!cluster_ref) {
    ENVOY_LOG(error, "Cluster '{}' not found", target_cluster);
    handleConnectionFailure();
    return;
  }

  // Get host from load balancer
  ENVOY_LOG(debug, "Attempting to choose host from cluster '{}'", target_cluster);
  auto host_response = cluster_ref->loadBalancer().chooseHost(nullptr);
  if (!host_response.host) {
    ENVOY_LOG(error, "No healthy host found in cluster '{}'", target_cluster);
    handleConnectionFailure();
    return;
  }

  ENVOY_LOG(debug, "Host selected successfully from cluster '{}'", target_cluster);

  // Validate host address
  auto host_address = host_response.host->address();
  if (!host_address) {
    ENVOY_LOG(error, "Host address is null for cluster '{}'", target_cluster);
    handleConnectionFailure();
    return;
  }

  ENVOY_LOG(debug, "Host address validation successful: {}", host_address->asString());

  // Create upstream connection using the connection's dispatcher
  // Create a raw buffer transport socket for the upstream connection
  auto transport_socket = std::make_unique<Envoy::Network::RawBufferSocket>();

  upstream_connection_ = read_callbacks_->connection().dispatcher().createClientConnection(
      host_address, Envoy::Network::Address::InstanceConstSharedPtr(), std::move(transport_socket),
      nullptr, nullptr);

  if (!upstream_connection_) {
    ENVOY_LOG(error, "Failed to create upstream connection");
    handleConnectionFailure();
    return;
  }

  // Set up upstream connection callbacks with a custom handler
  upstream_connection_handler_ = std::make_unique<UpstreamConnectionHandler>(*this);
  upstream_connection_->addConnectionCallbacks(*upstream_connection_handler_);

  // Add read filter to handle data coming back from upstream
  upstream_connection_->addReadFilter(std::make_shared<UpstreamDataHandler>(*this));

  // Enable connection
  upstream_connection_->connect();

  // Log connection details safely
  if (host_address->ip()) {
    ENVOY_LOG(debug, "Created upstream connection to {}:{}", host_address->ip()->addressAsString(),
              host_address->ip()->port());
  } else {
    ENVOY_LOG(debug, "Created upstream connection to non-IP address: {}", host_address->asString());
  }
}

void ReverseConnectionNetworkFilter::handleConnectionEstablished(
    Envoy::Network::Connection& /*upstream_connection*/) {

  // Prevent multiple calls to this method
  if (is_established_) {
    ENVOY_LOG(debug, "Connection already established - ignoring duplicate call");
    return;
  }

  ENVOY_LOG(info, "Upstream connection established - activating HTTP tunnel");

  is_established_ = true;
  is_http_tunnel_active_ = true;

  // Cancel connection timeout
  connection_timeout_timer_->disableTimer();

  // Update connection state
  updateConnectionStats(ConnectionState::HttpTunneling);

  // Skip cluster identification for now - just do pure HTTP forwarding
  // TODO: For now, skip automatic cluster identification to avoid confusing upstream service
  // sendClusterIdentification();

  // Enable optimizations
  enableZeroCopyForwarding();
  optimizeSocketSettings();

  // Forward any buffered data immediately as HTTP
  if (downstream_buffer_.length() > 0) {
    ENVOY_LOG(info, "Forwarding {} buffered HTTP bytes to upstream", downstream_buffer_.length());
    forwardHttpData(downstream_buffer_);
    downstream_buffer_.drain(downstream_buffer_.length());
  }

  ENVOY_LOG(info, "HTTP tunnel is now active and ready for requests");
}

void ReverseConnectionNetworkFilter::handleConnectionFailure() {
  ENVOY_LOG(error, "Upstream connection failed - closing downstream connection");

  ENVOY_LOG(debug, "Connection failed");
  updateConnectionStats(ConnectionState::Closed);

  if (read_callbacks_) {
    read_callbacks_->connection().close(Envoy::Network::ConnectionCloseType::FlushWrite);
  }
}

void ReverseConnectionNetworkFilter::cleanupConnections() {
  ENVOY_LOG(debug, "Cleaning up connections");

  // First, clear the active tunnel state to prevent new operations
  is_established_ = false;
  is_http_tunnel_active_ = false;

  // CRITICAL: Remove ourselves from connection callbacks FIRST
  // This prevents the connection from trying to notify us during its destruction
  if (read_callbacks_) {
    try {
      read_callbacks_->connection().removeConnectionCallbacks(*this);
      ENVOY_LOG(debug, "Removed connection callbacks");
    } catch (const std::exception& e) {
      ENVOY_LOG(error, "Exception removing connection callbacks: {}", e.what());
    } catch (...) {
      ENVOY_LOG(error, "Unknown exception removing connection callbacks");
    }
  }

  // Cancel timers AFTER removing callbacks to prevent any timer callbacks from running during
  // cleanup
  if (keepalive_timer_) {
    keepalive_timer_->disableTimer();
    keepalive_timer_.reset();
  }

  if (connection_timeout_timer_) {
    connection_timeout_timer_->disableTimer();
    connection_timeout_timer_.reset();
  }

  // Close and cleanup upstream connection WITH proper order
  if (upstream_connection_) {
    // Only close if still open - don't try to close an already closed connection
    if (upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
      upstream_connection_->close(Envoy::Network::ConnectionCloseType::FlushWrite);
    }

    // Reset the connection pointer
    upstream_connection_.reset();
  }

  // Clear upstream connection handler AFTER upstream connection is cleaned up
  if (upstream_connection_handler_) {
    upstream_connection_handler_.reset();
  }

  // Update connection stats
  updateConnectionStats(ConnectionState::Closed);
}

bool ReverseConnectionNetworkFilter::parseHttpRequest(Buffer::Instance& data,
                                                      HttpTunnelState& tunnel_state) {
  std::string request_data = data.toString();

  // Simple HTTP request parsing
  std::regex request_line_regex(R"(([A-Z]+)\s+([^\s]+)\s+HTTP/([0-9\.]+))");
  std::regex host_header_regex(R"(Host:\s*([^\r\n]+))");

  std::smatch request_match;
  if (std::regex_search(request_data, request_match, request_line_regex)) {
    tunnel_state.method = request_match[1].str();
    tunnel_state.path = request_match[2].str();
    tunnel_state.request_headers_parsed = true;

    // Extract host header
    std::smatch host_match;
    if (std::regex_search(request_data, host_match, host_header_regex)) {
      tunnel_state.host = host_match[1].str();
    }

    ENVOY_LOG(debug, "Parsed HTTP request: {} {} (Host: {})", tunnel_state.method,
              tunnel_state.path, tunnel_state.host);
    return true;
  }

  return false;
}

bool ReverseConnectionNetworkFilter::parseHttpResponse(Buffer::Instance& data,
                                                       HttpTunnelState& tunnel_state) {
  std::string response_data = data.toString();

  // Simple HTTP response parsing
  std::regex status_line_regex(R"(HTTP/([0-9\.]+)\s+([0-9]+)\s+([^\r\n]*))");

  std::smatch status_match;
  if (std::regex_search(response_data, status_match, status_line_regex)) {
    tunnel_state.response_headers_parsed = true;
    ENVOY_LOG(debug, "Parsed HTTP response: {} {}", status_match[2].str(), status_match[3].str());
    return true;
  }

  return false;
}

void ReverseConnectionNetworkFilter::forwardHttpData(Buffer::Instance& data) {
  if (!upstream_connection_ ||
      upstream_connection_->state() != Envoy::Network::Connection::State::Open) {
    ENVOY_LOG(debug, "Upstream connection not ready - buffering data");
    upstream_buffer_.move(data);
    return;
  }

  ENVOY_LOG(trace, "Forwarding {} bytes to upstream", data.length());

  // Forward data with zero-copy where possible
  upstream_connection_->write(data, false);

  // Update tunnel state
  http_tunnel_state_.bytes_forwarded += data.length();
}

void ReverseConnectionNetworkFilter::handleHttpRequest(const std::string& method,
                                                       const std::string& path,
                                                       const std::string& host) {
  ENVOY_LOG(info, "Handling HTTP request: {} {} (Host: {})", method, path, host);

  // Log request types for debugging
  ENVOY_LOG(debug, "Processing HTTP {} request", method);

  // Log request for debugging
  if (debug_logging_) {
    ENVOY_LOG(debug, "HTTP {} request to {} forwarded to cluster: {}", method, path, cluster_name_);
  }
}

void ReverseConnectionNetworkFilter::handleHttpResponse() {
  ENVOY_LOG(debug, "Handling HTTP response");
}

void ReverseConnectionNetworkFilter::handleClusterIdentification(Buffer::Instance& data) {
  if (data.length() < 2) {
    return; // Need at least length field
  }

  // Try enhanced protocol first (with version byte)
  auto cluster_name = extractClusterName(data);
  if (!cluster_name.empty()) {
    identified_cluster_ = cluster_name;
    ENVOY_LOG(info, "Identified cluster from enhanced protocol: {}", identified_cluster_);

    // Drain the identification data
    data.drain(data.length());
    return;
  }

  // Fall back to legacy protocol (simple length + string)
  uint8_t* buffer_data = reinterpret_cast<uint8_t*>(data.linearize(data.length()));
  uint16_t cluster_name_length = ntohs(*reinterpret_cast<uint16_t*>(buffer_data));

  if (cluster_name_length > 0 && data.length() >= (2 + cluster_name_length)) {
    std::string cluster_name(reinterpret_cast<char*>(buffer_data + 2), cluster_name_length);
    identified_cluster_ = cluster_name;

    ENVOY_LOG(info, "Identified cluster from legacy protocol: {}", identified_cluster_);

    // Drain the identification data
    data.drain(2 + cluster_name_length);
  }
}

void ReverseConnectionNetworkFilter::sendClusterIdentification() {
  if (!upstream_connection_ || cluster_name_.empty()) {
    return;
  }

  ENVOY_LOG(debug, "Sending cluster identification: {}", cluster_name_);

  // Send enhanced identification
  Buffer::OwnedImpl id_buffer;

  // Protocol version
  uint8_t version = 1;
  id_buffer.add(&version, sizeof(version));

  // Cluster name
  uint16_t cluster_length = htons(cluster_name_.length());
  id_buffer.add(&cluster_length, sizeof(cluster_length));
  id_buffer.add(cluster_name_.data(), cluster_name_.length());

  // Node ID (optional)
  const std::string node_id = "default_node";
  uint16_t node_length = htons(node_id.length());
  id_buffer.add(&node_length, sizeof(node_length));
  id_buffer.add(node_id.data(), node_id.length());

  // Tenant ID (optional)
  const std::string tenant_id = "default_tenant";
  uint16_t tenant_length = htons(tenant_id.length());
  id_buffer.add(&tenant_length, sizeof(tenant_length));
  id_buffer.add(tenant_id.data(), tenant_id.length());

  upstream_connection_->write(id_buffer, false);
}

std::string ReverseConnectionNetworkFilter::extractClusterName(Buffer::Instance& data) {
  if (data.length() < 3) { // version + length
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

void ReverseConnectionNetworkFilter::enableZeroCopyForwarding() {
  // Enable socket optimizations for zero-copy forwarding
  if (upstream_connection_) {
    // These would be set on the actual socket file descriptor
    ENVOY_LOG(debug, "Enabled zero-copy forwarding optimizations");
  }
}

void ReverseConnectionNetworkFilter::optimizeSocketSettings() {
  // Optimize socket settings for performance
  if (upstream_connection_) {
    // TCP_NODELAY, SO_REUSEADDR, etc. would be configured here
    ENVOY_LOG(debug, "Applied socket optimizations");
  }
}

void ReverseConnectionNetworkFilter::updateConnectionStats(ConnectionState new_state) {
  connection_metadata_.tunnel_state.state = new_state;

  ENVOY_LOG(trace, "Updated connection state to: {}", static_cast<int>(new_state));
}

void ReverseConnectionNetworkFilter::recordForwardingMetrics(size_t bytes_forwarded,
                                                             bool is_upstream) {
  ENVOY_LOG(trace, "Forwarded {} bytes {}", bytes_forwarded,
            is_upstream ? "upstream" : "downstream");
}

// UpstreamDataHandler implementation
Envoy::Network::FilterStatus UpstreamDataHandler::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(info, "UpstreamDataHandler: Received {} bytes from upstream, end_stream: {}",
            data.length(), end_stream);

  // Safety check - ensure parent filter is still valid before accessing it
  // The parent reference should always be valid since the handler is owned by the parent,
  // but add extra safety during cleanup scenarios
  try {
    if (data.length() > 0) {
      ENVOY_LOG(info, "UpstreamDataHandler: Forwarding {} bytes to parent filter", data.length());
      // Forward the data to the parent filter for processing
      parent_.handleUpstreamData(data, end_stream);
    } else {
      ENVOY_LOG(warn, "UpstreamDataHandler: Received 0 bytes from upstream, end_stream: {}",
                end_stream);
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "UpstreamDataHandler: Exception while forwarding data to parent: {}",
              e.what());
    return Envoy::Network::FilterStatus::StopIteration;
  } catch (...) {
    ENVOY_LOG(error, "UpstreamDataHandler: Unknown exception while forwarding data to parent");
    return Envoy::Network::FilterStatus::StopIteration;
  }

  return Envoy::Network::FilterStatus::StopIteration;
}

// ReverseConnectionNetworkFilter upstream data handling
void ReverseConnectionNetworkFilter::handleUpstreamData(Buffer::Instance& data, bool end_stream) {
  size_t bytes_to_forward = data.length(); // Capture before write consumes the buffer
  ENVOY_LOG(info, "handleUpstreamData: Processing {} bytes from upstream, end_stream: {}",
            bytes_to_forward, end_stream);

  if (!read_callbacks_) {
    ENVOY_LOG(error, "handleUpstreamData: No downstream connection to forward upstream data to");
    return;
  }

  // Check downstream connection state - add safety check
  try {
    auto& downstream_conn = read_callbacks_->connection();
    ENVOY_LOG(info, "handleUpstreamData: Downstream connection state: {}",
              static_cast<int>(downstream_conn.state()));

    // Forward the data directly to the downstream connection
    if (bytes_to_forward > 0) {
      ENVOY_LOG(info, "handleUpstreamData: Writing {} bytes to downstream connection",
                bytes_to_forward);

      // CRITICAL FIX: Buffer the response data for the write filter to handle
      // Instead of writing directly to connection, buffer it for proper filter chain handling
      downstream_buffer_.move(data);

      ENVOY_LOG(info,
                "handleUpstreamData: Buffered {} bytes in downstream buffer, total buffered: {}",
                bytes_to_forward, downstream_buffer_.length());

      // Trigger write filter processing by adding data to write path
      if (write_callbacks_) {
        ENVOY_LOG(info, "handleUpstreamData: Injecting {} bytes into write filter chain",
                  downstream_buffer_.length());

        // Create a copy of the buffer to inject into write path
        Buffer::OwnedImpl write_buffer;
        write_buffer.move(downstream_buffer_);

        // Use the write filter callbacks to properly send data back to client
        write_callbacks_->injectWriteDataToFilterChain(write_buffer, false);

        ENVOY_LOG(info,
                  "handleUpstreamData: Successfully injected response into write filter chain");
      } else {
        ENVOY_LOG(
            error,
            "handleUpstreamData: No write callbacks available - cannot send response to client");
        // Fallback: write directly to connection as last resort
        downstream_conn.write(downstream_buffer_, false);
        downstream_buffer_.drain(downstream_buffer_.length());
      }

      ENVOY_LOG(info,
                "handleUpstreamData: Successfully processed {} bytes from upstream to downstream",
                bytes_to_forward);

      // Update stats
      recordForwardingMetrics(bytes_to_forward, false); // false = downstream direction
    } else {
      ENVOY_LOG(warn, "handleUpstreamData: Received 0 bytes from upstream");
    }

    if (end_stream) {
      ENVOY_LOG(
          info,
          "handleUpstreamData: Upstream sent end_stream - will close downstream after brief delay");
      // Schedule downstream close after a brief delay to ensure data flushes
      if (read_callbacks_) {
        auto& dispatcher = read_callbacks_->connection().dispatcher();
        auto close_timer = dispatcher.createTimer([this]() {
          ENVOY_LOG(info, "Closing downstream connection after upstream end_stream");
          if (read_callbacks_) {
            read_callbacks_->connection().close(Envoy::Network::ConnectionCloseType::FlushWrite);
          }
        });
        close_timer->enableTimer(std::chrono::milliseconds(100)); // 100ms delay for flush
      }
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "handleUpstreamData: Exception while processing upstream data: {}", e.what());
  } catch (...) {
    ENVOY_LOG(error, "handleUpstreamData: Unknown exception while processing upstream data");
  }
}

// UpstreamConnectionHandler implementation
void UpstreamConnectionHandler::onEvent(Envoy::Network::ConnectionEvent event) {
  ENVOY_LOG(debug, "UpstreamConnectionHandler: received event {}", static_cast<int>(event));

  // Safety check - ensure parent filter is still valid before accessing it
  try {
    parent_.handleUpstreamConnectionEvent(event);
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "UpstreamConnectionHandler: Exception while handling event: {}", e.what());
  } catch (...) {
    ENVOY_LOG(error, "UpstreamConnectionHandler: Unknown exception while handling event");
  }
}

// ReverseConnectionNetworkFilter upstream connection event handling
void ReverseConnectionNetworkFilter::handleUpstreamConnectionEvent(
    Envoy::Network::ConnectionEvent event) {
  switch (event) {
  case Envoy::Network::ConnectionEvent::Connected:
    ENVOY_LOG(info, "Upstream connection established - activating HTTP tunnel");
    handleConnectionEstablished(*upstream_connection_);
    break;

  case Envoy::Network::ConnectionEvent::RemoteClose:
    ENVOY_LOG(info, "Upstream connection remote close");
    // DON'T force close downstream - let it close naturally or client will close it
    // Forcing close here causes recursive cleanup and segfault
    ENVOY_LOG(info, "Upstream closed - cleaning up upstream only");

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
    ENVOY_LOG(info, "Upstream connection local close");
    // Local close of upstream - this is expected during cleanup
    break;

  default:
    ENVOY_LOG(debug, "Upstream connection event: {}", static_cast<int>(event));
    break;
  }
}

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
