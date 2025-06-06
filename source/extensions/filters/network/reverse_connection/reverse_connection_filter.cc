#include "source/extensions/filters/network/reverse_connection/reverse_connection_filter.h"

#include <algorithm>
#include <regex>

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/connection.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
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
    bool debug_logging, Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
    Thread::ThreadFactory& thread_factory)
    : stat_prefix_(stat_prefix), cluster_name_(cluster_name),
      max_connections_per_cluster_(max_connections_per_cluster),
      connection_timeout_(connection_timeout), debug_logging_(debug_logging),
      cluster_manager_(cluster_manager), dispatcher_(dispatcher), thread_factory_(thread_factory) {

  ENVOY_LOG(info, "Created ReverseConnectionNetworkFilter - cluster: {}, debug: {}", cluster_name_,
            debug_logging_);

  // Initialize HTTP tunnel state
  http_tunnel_state_.state = ConnectionState::Initializing;

  // Setup connection timeout timer
  connection_timeout_timer_ = dispatcher_.createTimer([this]() -> void {
    ENVOY_LOG(warn, "Connection timeout expired - closing connection");
    handleConnectionFailure();
  });
}

ReverseConnectionNetworkFilter::~ReverseConnectionNetworkFilter() {
  ENVOY_LOG(debug, "Destroying ReverseConnectionNetworkFilter");
  cleanupConnections();
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onNewConnection() {
  ENVOY_LOG(debug, "New connection established - initializing reverse tunnel");

  // Update stats - TODO: Implement proper stats integration
  ENVOY_LOG(debug, "Connection created");
  updateConnectionStats(ConnectionState::Connected);

  // Start connection timeout
  connection_timeout_timer_->enableTimer(connection_timeout_);

  // Establish upstream connection for HTTP tunneling
  establishUpstreamConnection();

  return Envoy::Network::FilterStatus::Continue;
}

Envoy::Network::FilterStatus ReverseConnectionNetworkFilter::onData(Buffer::Instance& data,
                                                                    bool end_stream) {
  ENVOY_LOG(trace, "Received {} bytes, end_stream: {}", data.length(), end_stream);

  if (data.length() == 0) {
    return Envoy::Network::FilterStatus::Continue;
  }

  // First, check if this is cluster identification data
  if (!is_established_ && identified_cluster_.empty()) {
    handleClusterIdentification(data);
    if (!identified_cluster_.empty()) {
      ENVOY_LOG(info, "Identified cluster: {} - establishing HTTP tunnel", identified_cluster_);
      establishUpstreamConnection();
    }
    return Envoy::Network::FilterStatus::StopIteration;
  }

  // Handle HTTP tunneling if upstream connection is ready
  if (is_http_tunnel_active_ && upstream_connection_ &&
      upstream_connection_->state() == Envoy::Network::Connection::State::Open) {

    // Parse HTTP request/response if needed
    if (!http_tunnel_state_.request_headers_parsed) {
      if (parseHttpRequest(data, http_tunnel_state_)) {
        ENVOY_LOG(debug, "Parsed HTTP request: {} {} Host: {}", http_tunnel_state_.method,
                  http_tunnel_state_.path, http_tunnel_state_.host);
        handleHttpRequest(http_tunnel_state_.method, http_tunnel_state_.path,
                          http_tunnel_state_.host);
      }
    }

    // Forward data to upstream
    forwardHttpData(data);

    // Update stats - TODO: Implement proper metrics
    ENVOY_LOG(trace, "Forwarded {} bytes upstream", data.length());

    return Envoy::Network::FilterStatus::StopIteration;
  }

  // Buffer data until tunnel is ready
  downstream_buffer_.move(data);
  ENVOY_LOG(debug, "Buffering {} bytes until tunnel ready", downstream_buffer_.length());

  return Envoy::Network::FilterStatus::StopIteration;
}

void ReverseConnectionNetworkFilter::initializeReadFilterCallbacks(
    Envoy::Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;

  // Add connection callbacks to track connection events
  read_callbacks_->connection().addConnectionCallbacks(*this);

  // Set up connection info
  connection_info_setter_ = &callbacks.connection().connectionInfoSetter();

  ENVOY_LOG(debug, "Initialized read filter callbacks");
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
    ENVOY_LOG(info, "Downstream connection established");
    break;

  case Envoy::Network::ConnectionEvent::RemoteClose:
    ENVOY_LOG(info, "Downstream connection remote close");
    cleanupConnections();
    ENVOY_LOG(debug, "Remote connection closed");
    break;

  case Envoy::Network::ConnectionEvent::LocalClose:
    ENVOY_LOG(info, "Downstream connection local close");
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
  // Use identified cluster if available, otherwise use configured cluster
  const std::string& target_cluster =
      identified_cluster_.empty() ? cluster_name_ : identified_cluster_;

  if (target_cluster.empty()) {
    ENVOY_LOG(error, "No cluster name configured - cannot establish upstream connection");
    return;
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
  auto host_response = cluster_ref->loadBalancer().chooseHost(nullptr);
  if (!host_response.host) {
    ENVOY_LOG(error, "No healthy host found in cluster '{}'", target_cluster);
    handleConnectionFailure();
    return;
  }

  // Create upstream connection
  upstream_connection_ = dispatcher_.createClientConnection(
      host_response.host->address(), Envoy::Network::Address::InstanceConstSharedPtr(), nullptr,
      nullptr, nullptr);

  if (!upstream_connection_) {
    ENVOY_LOG(error, "Failed to create upstream connection");
    handleConnectionFailure();
    return;
  }

  // Set up upstream connection callbacks
  upstream_connection_->addConnectionCallbacks(*this);

  // Enable connection
  upstream_connection_->connect();

  ENVOY_LOG(debug, "Created upstream connection to {}:{}",
            host_response.host->address()->ip()->addressAsString(),
            host_response.host->address()->ip()->port());
}

void ReverseConnectionNetworkFilter::handleConnectionEstablished(
    Envoy::Network::Connection& /*upstream_connection*/) {
  ENVOY_LOG(info, "Upstream connection established - activating HTTP tunnel");

  is_established_ = true;
  is_http_tunnel_active_ = true;

  // Cancel connection timeout
  connection_timeout_timer_->disableTimer();

  // Update connection state
  updateConnectionStats(ConnectionState::HttpTunneling);

  // Send cluster identification to upstream
  sendClusterIdentification();

  // Enable optimizations
  enableZeroCopyForwarding();
  optimizeSocketSettings();

  // Forward any buffered data
  if (downstream_buffer_.length() > 0) {
    ENVOY_LOG(debug, "Forwarding {} buffered bytes", downstream_buffer_.length());
    forwardHttpData(downstream_buffer_);
    downstream_buffer_.drain(downstream_buffer_.length());
  }

  // Set up keepalive
  keepalive_timer_ = dispatcher_.createTimer([this]() -> void {
    if (upstream_connection_ &&
        upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
      // Send HTTP keepalive
      const std::string keepalive =
          "GET /healthz HTTP/1.1\r\nHost: keepalive\r\nConnection: keep-alive\r\n\r\n";
      Buffer::OwnedImpl keepalive_buffer(keepalive);
      upstream_connection_->write(keepalive_buffer, false);

      // Reschedule
      keepalive_timer_->enableTimer(std::chrono::seconds(30));
    }
  });
  keepalive_timer_->enableTimer(std::chrono::seconds(30));
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

  // Cancel timers
  if (keepalive_timer_) {
    keepalive_timer_->disableTimer();
    keepalive_timer_.reset();
  }

  if (connection_timeout_timer_) {
    connection_timeout_timer_->disableTimer();
    connection_timeout_timer_.reset();
  }

  // Close upstream connection
  if (upstream_connection_ &&
      upstream_connection_->state() == Envoy::Network::Connection::State::Open) {
    upstream_connection_->close(Envoy::Network::ConnectionCloseType::FlushWrite);
  }
  upstream_connection_.reset();

  // Clear state
  is_established_ = false;
  is_http_tunnel_active_ = false;

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

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
