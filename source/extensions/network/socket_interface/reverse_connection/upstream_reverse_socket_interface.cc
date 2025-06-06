#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

#include "source/common/common/logger.h"
#include "source/common/network/io_socket_handle_impl.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

// UpstreamReverseConnectionIOHandle implementation
UpstreamReverseConnectionIOHandle::UpstreamReverseConnectionIOHandle(
    os_fd_t fd, const std::string& cluster_name)
    : IoSocketHandleImpl(fd), cluster_name_(cluster_name) {

  ENVOY_LOG(debug, "Created UpstreamReverseConnectionIOHandle for cluster: {}", cluster_name_);
}

// Destructor handled by header default implementation

Api::SysCallIntResult UpstreamReverseConnectionIOHandle::connect(
    Envoy::Network::Address::InstanceConstSharedPtr address) {
  ENVOY_LOG(debug,
            "UpstreamReverseConnectionIOHandle::connect() to {} - connection already established "
            "through reverse tunnel",
            address->asString());

  // For reverse connections, the connection is already established
  // Return success immediately since the reverse tunnel provides the connection
  return Api::SysCallIntResult{0, 0};
}

// Other methods use default IoSocketHandleImpl implementation

// UpstreamReverseSocketInterface implementation
UpstreamReverseSocketInterface::UpstreamReverseSocketInterface(const std::string& cluster_name)
    : cluster_name_(cluster_name) {
  ENVOY_LOG(info, "Created UpstreamReverseSocketInterface for cluster: {}", cluster_name_);
}

Envoy::Network::IoHandlePtr UpstreamReverseSocketInterface::makeSocket(
    int socket_fd, bool socket_v6only, Envoy::Network::Socket::Type socket_type,
    absl::optional<int> domain, const Envoy::Network::SocketCreationOptions& options) const {

  ENVOY_LOG(debug, "UpstreamReverseSocketInterface::makeSocket() called for cluster: {}",
            cluster_name_);

  // Get the manager instance and request a descriptor
  // This allows us to work around const-correctness while maintaining thread safety
  auto& manager = UpstreamReverseConnectionManager::instance();
  auto interface = manager.getSocketInterface(cluster_name_);

  os_fd_t existing_fd = interface->getAvailableDescriptor();

  if (existing_fd != -1) {
    ENVOY_LOG(info, "Reusing existing reverse connection descriptor {} for cluster: {}",
              existing_fd, cluster_name_);

    // Return custom IOHandle that manages the existing descriptor
    return std::make_unique<UpstreamReverseConnectionIOHandle>(existing_fd, cluster_name_);
  }

  ENVOY_LOG(debug,
            "No available reverse connection for cluster: {}, falling back to standard socket",
            cluster_name_);

  // Fall back to standard socket creation if no reverse connection available
  return SocketInterfaceImpl::makeSocket(socket_fd, socket_v6only, socket_type, domain, options);
}

void UpstreamReverseSocketInterface::addReverseConnectionDescriptor(os_fd_t fd) {
  absl::MutexLock lock(&descriptors_mutex_);

  available_descriptors_.push(fd);

  ENVOY_LOG(debug, "Added descriptor {} to pool for cluster: {} (pool size: {})", fd, cluster_name_,
            available_descriptors_.size());
}

os_fd_t UpstreamReverseSocketInterface::getAvailableDescriptor() {
  absl::MutexLock lock(&descriptors_mutex_);

  if (!available_descriptors_.empty()) {
    os_fd_t fd = available_descriptors_.front();
    available_descriptors_.pop();
    active_descriptors_.insert(fd);

    ENVOY_LOG(debug, "Retrieved descriptor {} from pool for cluster: {} (remaining: {})", fd,
              cluster_name_, available_descriptors_.size());

    return fd;
  }

  ENVOY_LOG(debug, "No available descriptors in pool for cluster: {}", cluster_name_);
  return -1;
}

void UpstreamReverseSocketInterface::returnDescriptor(os_fd_t fd) {
  if (fd == -1) {
    return;
  }

  absl::MutexLock lock(&descriptors_mutex_);

  // Remove from active and add back to available pool
  active_descriptors_.erase(fd);
  available_descriptors_.push(fd);

  ENVOY_LOG(debug, "Returned descriptor {} to pool for cluster: {} (pool size: {})", fd,
            cluster_name_, available_descriptors_.size());
}

// UpstreamReverseConnectionManager implementation
UpstreamReverseConnectionManager& UpstreamReverseConnectionManager::instance() {
  static UpstreamReverseConnectionManager instance_;
  return instance_;
}

std::shared_ptr<UpstreamReverseSocketInterface>
UpstreamReverseConnectionManager::getSocketInterface(const std::string& cluster_name) {
  absl::MutexLock lock(&interfaces_mutex_);

  auto it = cluster_socket_interfaces_.find(cluster_name);
  if (it != cluster_socket_interfaces_.end()) {
    ENVOY_LOG(debug, "Found existing socket interface for cluster: {}", cluster_name);
    return it->second;
  }

  // Create new socket interface for this cluster
  auto interface = std::make_shared<UpstreamReverseSocketInterface>(cluster_name);
  cluster_socket_interfaces_[cluster_name] = interface;

  ENVOY_LOG(info, "Created new socket interface for cluster: {}", cluster_name);
  return interface;
}

void UpstreamReverseConnectionManager::addReverseConnectionDescriptor(
    const std::string& cluster_name, os_fd_t fd) {

  ENVOY_LOG(debug, "Adding reverse connection descriptor {} for cluster: {}", fd, cluster_name);

  auto interface = getSocketInterface(cluster_name);
  interface->addReverseConnectionDescriptor(fd);

  ENVOY_LOG(info, "Added reverse connection descriptor {} to cluster: {}", fd, cluster_name);
}

void UpstreamReverseConnectionManager::removeCluster(const std::string& cluster_name) {
  absl::MutexLock lock(&interfaces_mutex_);

  auto it = cluster_socket_interfaces_.find(cluster_name);
  if (it != cluster_socket_interfaces_.end()) {
    ENVOY_LOG(info, "Removing socket interface for cluster: {}", cluster_name);
    cluster_socket_interfaces_.erase(it);
  }
}

void UpstreamReverseConnectionManager::initiateReverseConnections(
    const std::string& downstream_address, uint16_t downstream_port, Event::Dispatcher& dispatcher,
    uint32_t connection_count) {

  ENVOY_LOG(info, "Initiating {} reverse connections to {}:{}", connection_count,
            downstream_address, downstream_port);

  for (uint32_t i = 0; i < connection_count; ++i) {
    // Schedule connection creation using dispatcher for proper thread handling
    dispatcher.post([downstream_address, downstream_port, i]() {
      ENVOY_LOG(debug, "Creating reverse connection {} to {}:{}", i, downstream_address,
                downstream_port);

      // In the production implementation, this would create actual TCP connections
      // to the downstream address. For this demo, we coordinate with the
      // downstream socket interface which handles the connection creation.

      // The downstream socket interface will receive these connections and
      // the terminal filter will process them for cluster routing.
    });
  }

  ENVOY_LOG(info, "Scheduled {} reverse connections to {}:{}", connection_count, downstream_address,
            downstream_port);
}

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
