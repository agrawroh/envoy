#pragma once

#include <memory>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "envoy/api/io_error.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_interface_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Custom IOHandle for upstream that uses existing reverse connection descriptors.
 *
 * Key approach for connection reuse:
 * 1. connect() becomes noop since connection already established
 * 2. Returns existing socket descriptors provided by terminal network filter
 * 3. Transparently uses reverse connections without cluster knowing the difference
 */
class UpstreamReverseConnectionIOHandle : public Envoy::Network::IoSocketHandleImpl {
public:
  UpstreamReverseConnectionIOHandle(os_fd_t fd, const std::string& cluster_name);

  ~UpstreamReverseConnectionIOHandle() override = default;

  // Override connect to be noop since connection already established
  Api::SysCallIntResult connect(Envoy::Network::Address::InstanceConstSharedPtr address) override;

private:
  const std::string cluster_name_;
};

/**
 * Socket interface for upstream that returns existing reverse connection descriptors.
 *
 * This works with UpstreamReverseConnectionManager to get pre-established
 * reverse connection descriptors instead of creating new sockets.
 */
class UpstreamReverseSocketInterface
    : public Envoy::Network::SocketInterfaceImpl,
      public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  UpstreamReverseSocketInterface(const std::string& cluster_name);

  // Override makeSocket to return existing reverse connection descriptors
  // Note: Cannot be const because it modifies descriptor pools
  Envoy::Network::IoHandlePtr
  makeSocket(int socket_fd, bool socket_v6only, Envoy::Network::Socket::Type socket_type,
             absl::optional<int> domain,
             const Envoy::Network::SocketCreationOptions& options) const override;

  /**
   * Add a reverse connection descriptor for this cluster.
   * Called by the terminal network filter when it receives a new reverse connection.
   */
  void addReverseConnectionDescriptor(os_fd_t fd);

  /**
   * Get an available reverse connection descriptor.
   * Returns -1 if none available.
   * Note: This method modifies internal state so it cannot be const.
   */
  os_fd_t getAvailableDescriptor();

  /**
   * Return a descriptor to the available pool (when connection closes).
   */
  void returnDescriptor(os_fd_t fd);

private:
  const std::string cluster_name_;
  mutable absl::Mutex descriptors_mutex_;
  std::queue<os_fd_t> available_descriptors_ ABSL_GUARDED_BY(descriptors_mutex_);
  std::unordered_set<os_fd_t> active_descriptors_ ABSL_GUARDED_BY(descriptors_mutex_);
};

/**
 * Manager for upstream reverse connection socket interfaces.
 *
 * This is a singleton that manages socket interfaces for different clusters
 * and coordinates with the terminal network filter.
 */
class UpstreamReverseConnectionManager
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  static UpstreamReverseConnectionManager& instance();

  /**
   * Get or create socket interface for a cluster.
   */
  std::shared_ptr<UpstreamReverseSocketInterface>
  getSocketInterface(const std::string& cluster_name);

  /**
   * Add a reverse connection descriptor for a cluster.
   * Called by the terminal network filter.
   */
  void addReverseConnectionDescriptor(const std::string& cluster_name, os_fd_t fd);

  /**
   * Remove all descriptors for a cluster (when cluster is removed).
   */
  void removeCluster(const std::string& cluster_name);

  /**
   * Initiate reverse connections to a downstream address.
   * This is the missing piece - it creates connections from upstream to downstream.
   */
  void initiateReverseConnections(const std::string& downstream_address, uint16_t downstream_port,
                                  Event::Dispatcher& dispatcher, uint32_t connection_count = 1);

private:
  UpstreamReverseConnectionManager() = default;

  absl::Mutex interfaces_mutex_;
  std::unordered_map<std::string, std::shared_ptr<UpstreamReverseSocketInterface>>
      cluster_socket_interfaces_ ABSL_GUARDED_BY(interfaces_mutex_);
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
