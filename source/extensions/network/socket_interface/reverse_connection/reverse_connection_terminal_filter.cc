#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_terminal_filter.h"

#include <unistd.h>

#include "envoy/registry/registry.h"

#include "source/common/common/logger.h"
#include "source/common/network/utility.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

// ReverseConnectionTerminalFilter implementation
ReverseConnectionTerminalFilter::ReverseConnectionTerminalFilter(
    std::shared_ptr<ReverseConnectionTerminalFilterConfig> config)
    : config_ptr_(config), config_(config.get()) {
  ENVOY_LOG(debug, "Created ReverseConnectionTerminalFilter with shared config");
}

ReverseConnectionTerminalFilter::ReverseConnectionTerminalFilter(
    const ReverseConnectionTerminalFilterConfig& config)
    : config_ptr_(nullptr), config_(&config) {
  ENVOY_LOG(debug, "Created ReverseConnectionTerminalFilter with reference config");
}

ReverseConnectionTerminalFilter::~ReverseConnectionTerminalFilter() {
  ENVOY_LOG(debug, "Destroyed ReverseConnectionTerminalFilter");
}

Envoy::Network::FilterStatus ReverseConnectionTerminalFilter::onNewConnection() {
  ENVOY_LOG(debug, "New reverse connection established");
  return Envoy::Network::FilterStatus::Continue;
}

Envoy::Network::FilterStatus ReverseConnectionTerminalFilter::onData(Buffer::Instance& data,
                                                                     bool end_stream) {
  ENVOY_LOG(trace, "Received {} bytes for reverse connection handoff, end_stream: {}",
            data.length(), end_stream);

  if (!connection_handed_off_) {
    std::string target_cluster = extractTargetCluster(data);

    if (!target_cluster.empty()) {
      handOffSocketToCluster(target_cluster);
      connection_handed_off_ = true;
    }
  }

  // Terminal filter - consume all data
  data.drain(data.length());
  return Envoy::Network::FilterStatus::StopIteration;
}

void ReverseConnectionTerminalFilter::initializeReadFilterCallbacks(
    Envoy::Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
  ENVOY_LOG(debug, "ReverseConnectionTerminalFilter initialized");
}

std::string ReverseConnectionTerminalFilter::extractTargetCluster(Buffer::Instance& data) {
  if (data.length() < 4) {
    return "";
  }

  // Simple protocol: 2-byte length + cluster name
  uint16_t cluster_name_length = 0;
  data.copyOut(0, sizeof(cluster_name_length), &cluster_name_length);
  cluster_name_length = ntohs(cluster_name_length);

  if (cluster_name_length > data.length() - sizeof(cluster_name_length) ||
      cluster_name_length > 255) {
    ENVOY_LOG(debug, "Invalid cluster name length: {}", cluster_name_length);
    return "";
  }

  std::string cluster_name(cluster_name_length, '\0');
  data.copyOut(sizeof(cluster_name_length), cluster_name_length,
               const_cast<char*>(cluster_name.data()));

  ENVOY_LOG(debug, "Extracted target cluster: {}", cluster_name);
  return cluster_name;
}

void ReverseConnectionTerminalFilter::handOffSocketToCluster(const std::string& cluster_name) {
  ENVOY_LOG(debug, "Handing off reverse connection to cluster: {}", cluster_name);

  if (!read_callbacks_) {
    ENVOY_LOG(error, "No read callbacks available for socket handoff");
    return;
  }

  auto& connection = read_callbacks_->connection();

  try {
    os_fd_t connection_status = getConnectionFileDescriptor(connection);
    if (connection_status == -1) {
      ENVOY_LOG(error, "Failed to process reverse connection");
      return;
    }

    // Register with upstream reverse connection manager
    UpstreamReverseConnectionManager::instance().addReverseConnectionDescriptor(cluster_name, 1);
    ENVOY_LOG(debug, "Registered reverse connection with cluster: {}", cluster_name);

  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception during reverse connection handoff: {}", e.what());
  }
}

os_fd_t ReverseConnectionTerminalFilter::getConnectionFileDescriptor(
    Envoy::Network::Connection& connection) {
  try {
    const auto& local_address = connection.connectionInfoProvider().localAddress();
    const auto& remote_address = connection.connectionInfoProvider().remoteAddress();

    if (!local_address || !remote_address) {
      ENVOY_LOG(error, "Connection missing address information");
      return -1;
    }

    ENVOY_LOG(debug, "Processing reverse connection from {} to {}", remote_address->asString(),
              local_address->asString());

    return 1; // Success indicator
  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception processing reverse connection: {}", e.what());
    return -1;
  }
}

// ReverseConnectionTerminalFilterConfig implementation
ReverseConnectionTerminalFilterConfig::ReverseConnectionTerminalFilterConfig(
    const std::string& cluster_name, uint32_t max_connections, uint32_t timeout_seconds,
    bool debug_logging)
    : enabled_(true), handoff_timeout_(timeout_seconds * 1000), cluster_name_(cluster_name),
      max_connections_(max_connections), debug_logging_(debug_logging) {
  ENVOY_LOG(debug, "Created config for cluster: {}", cluster_name);
}

ReverseConnectionTerminalFilterConfig::ReverseConnectionTerminalFilterConfig()
    : enabled_(true), handoff_timeout_(5000), cluster_name_("default"), max_connections_(100),
      debug_logging_(false) {
  ENVOY_LOG(debug, "Created default reverse connection config");
}

bool ReverseConnectionTerminalFilterConfig::isReverseConnectionEnabled() const { return enabled_; }

std::chrono::milliseconds ReverseConnectionTerminalFilterConfig::getHandoffTimeout() const {
  return handoff_timeout_;
}

const std::string& ReverseConnectionTerminalFilterConfig::getClusterName() const {
  return cluster_name_;
}

uint32_t ReverseConnectionTerminalFilterConfig::getMaxConnections() const {
  return max_connections_;
}

bool ReverseConnectionTerminalFilterConfig::isDebugLoggingEnabled() const { return debug_logging_; }

// ReverseConnectionTerminalFilterFactory implementation
ReverseConnectionTerminalFilterFactory::ReverseConnectionTerminalFilterFactory() {
  ENVOY_LOG(debug, "Created ReverseConnectionTerminalFilterFactory");
}

Envoy::Network::FilterFactoryCb
ReverseConnectionTerminalFilterFactory::createFilterFactory() const {
  auto config = std::make_shared<ReverseConnectionTerminalFilterConfig>();

  return [config](Envoy::Network::FilterManager& filter_manager) -> void {
    auto filter = std::make_shared<ReverseConnectionTerminalFilter>(config);
    filter_manager.addReadFilter(filter);
    ENVOY_LOG(debug, "Added ReverseConnectionTerminalFilter to filter manager");
  };
}

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
