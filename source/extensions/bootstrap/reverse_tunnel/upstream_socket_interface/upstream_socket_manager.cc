#include "source/extensions/bootstrap/reverse_tunnel/upstream_socket_interface/upstream_socket_manager.h"

#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/common/random_generator.h"
#include "source/extensions/bootstrap/reverse_tunnel/common/reverse_connection_utility.h"
#include "source/extensions/bootstrap/reverse_tunnel/upstream_socket_interface/reverse_tunnel_acceptor_extension.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// UpstreamSocketManager implementation
UpstreamSocketManager::UpstreamSocketManager(Event::Dispatcher& dispatcher,
                                             ReverseTunnelAcceptorExtension* extension)
    : dispatcher_(dispatcher), random_generator_(std::make_unique<Random::RandomGeneratorImpl>()),
      extension_(extension) {
  ENVOY_LOG(debug, "reverse_tunnel: creating socket manager with stats integration");
  ping_timer_ = dispatcher_.createTimer([this]() { pingConnections(); });
}

void UpstreamSocketManager::addConnectionSocket(const std::string& node_id,
                                                const std::string& cluster_id,
                                                Network::ConnectionSocketPtr socket,
                                                const std::chrono::seconds& ping_interval, bool) {
  ENVOY_LOG(debug, "reverse_tunnel: adding connection for node: {}, cluster: {}", node_id,
            cluster_id);

  // Both node_id and cluster_id are mandatory for consistent state management and stats tracking.
  if (node_id.empty() || cluster_id.empty()) {
    ENVOY_LOG(error,
              "reverse_tunnel: node_id or cluster_id cannot be empty. node: '{}', cluster: '{}'",
              node_id, cluster_id);
    return;
  }

  const int fd = socket->ioHandle().fdDoNotUse();
  const std::string& connectionKey = socket->connectionInfoProvider().localAddress()->asString();

  ENVOY_LOG(debug, "reverse_tunnel: adding socket for node: {}, cluster: {}", node_id, cluster_id);

  // Store node -> cluster mapping.
  ENVOY_LOG(trace, "reverse_tunnel: adding mapping node: {} -> cluster: {}", node_id, cluster_id);
  if (node_to_cluster_map_.find(node_id) == node_to_cluster_map_.end()) {
    node_to_cluster_map_[node_id] = cluster_id;
    cluster_to_node_map_[cluster_id].push_back(node_id);
  }
  ENVOY_LOG(trace,
            "UpstreamSocketManager: node_to_cluster_map_ has {} entries, cluster_to_node_map_ has "
            "{} entries",
            node_to_cluster_map_.size(), cluster_to_node_map_.size());

  ENVOY_LOG(trace,
            "UpstreamSocketManager: added socket to accepted_reverse_connections_ for node: {} "
            "cluster: {}",
            node_id, cluster_id);

  // If local envoy is responding to reverse connections, add the socket to
  // accepted_reverse_connections_. Thereafter, initiate ping keepalives on the socket.
  accepted_reverse_connections_[node_id].push_back(std::move(socket));
  Network::ConnectionSocketPtr& socket_ref = accepted_reverse_connections_[node_id].back();

  ENVOY_LOG(debug, "reverse_tunnel: mapping fd {} to node: {}", fd, node_id);
  fd_to_node_map_[fd] = node_id;

  // Initialize connection metadata.
  ConnectionMetadata metadata;
  metadata.established_time = std::chrono::system_clock::now();
  metadata.last_activity = metadata.established_time;
  metadata.ping_interval = std::chrono::duration_cast<std::chrono::milliseconds>(ping_interval);
  fd_to_metadata_map_[fd] = metadata;

  ENVOY_LOG(
      debug, "UpstreamSocketManager: initialized metadata for fd {} at {}", fd,
      std::chrono::duration_cast<std::chrono::seconds>(metadata.established_time.time_since_epoch())
          .count());

  // Update stats registry
  if (auto extension = getUpstreamExtension()) {
    extension->updateConnectionStats(node_id, cluster_id, true /* increment */);
    ENVOY_LOG(debug, "UpstreamSocketManager: updated stats registry for node '{}' cluster '{}'",
              node_id, cluster_id);
  }

  // onPingResponse() expects a ping reply on the socket.
  fd_to_event_map_[fd] = dispatcher_.createFileEvent(
      fd,
      [this, &socket_ref](uint32_t events) {
        ASSERT(events == Event::FileReadyType::Read);
        onPingResponse(socket_ref->ioHandle());
        return absl::OkStatus();
      },
      Event::FileTriggerType::Edge, Event::FileReadyType::Read);

  fd_to_timer_map_[fd] = dispatcher_.createTimer([this, fd]() { markSocketDead(fd); });

  // Initiate ping keepalives on the socket.
  tryEnablePingTimer(std::chrono::seconds(ping_interval.count()));

  ENVOY_LOG(
      info,
      "UpstreamSocketManager: done adding socket to maps with node: {} connection key: {} fd: {}",
      node_id, connectionKey, fd);
}

Network::ConnectionSocketPtr
UpstreamSocketManager::getConnectionSocket(const std::string& node_id) {

  ENVOY_LOG(debug, "UpstreamSocketManager: getConnectionSocket() called with node_id: {}", node_id);

  if (node_to_cluster_map_.find(node_id) == node_to_cluster_map_.end()) {
    ENVOY_LOG(error, "UpstreamSocketManager: cluster -> node mapping changed for node: {}",
              node_id);
    return nullptr;
  }

  const std::string& cluster_id = node_to_cluster_map_[node_id];

  ENVOY_LOG(debug, "UpstreamSocketManager: Looking for socket with node: {} cluster: {}", node_id,
            cluster_id);

  // Find first available socket for the node.
  auto node_sockets_it = accepted_reverse_connections_.find(node_id);
  if (node_sockets_it == accepted_reverse_connections_.end() || node_sockets_it->second.empty()) {
    ENVOY_LOG(debug, "UpstreamSocketManager: No available sockets for node: {}", node_id);
    return nullptr;
  }

  // Debugging: Print the number of free sockets on this worker thread
  ENVOY_LOG(debug, "UpstreamSocketManager: Found {} sockets for node: {}",
            node_sockets_it->second.size(), node_id);

  // Fetch the socket from the accepted_reverse_connections_ and remove it from the list
  Network::ConnectionSocketPtr socket(std::move(node_sockets_it->second.front()));
  node_sockets_it->second.pop_front();

  const int fd = socket->ioHandle().fdDoNotUse();
  const std::string& remoteConnectionKey =
      socket->connectionInfoProvider().remoteAddress()->asString();

  ENVOY_LOG(debug,
            "UpstreamSocketManager: Reverse conn socket with FD:{} connection key:{} found for "
            "node: {} cluster: {}",
            fd, remoteConnectionKey, node_id, cluster_id);

  fd_to_event_map_.erase(fd);
  fd_to_timer_map_.erase(fd);

  cleanStaleNodeEntry(node_id);

  return socket;
}

std::string UpstreamSocketManager::getNodeID(const std::string& key) {
  ENVOY_LOG(debug, "UpstreamSocketManager: getNodeID() called with key: {}", key);

  // First check if the key exists as a cluster ID by checking global stats
  // This ensures we check across all threads, not just the current thread
  if (auto extension = getUpstreamExtension()) {
    // Check if any thread has sockets for this cluster by looking at global stats.
    std::string cluster_stat_name = fmt::format("reverse_connections.clusters.{}", key);
    auto& stats_store = extension->getStatsScope();
    Stats::StatNameManagedStorage cluster_stat_name_storage(cluster_stat_name,
                                                            stats_store.symbolTable());
    auto& cluster_gauge = stats_store.gaugeFromStatName(cluster_stat_name_storage.statName(),
                                                        Stats::Gauge::ImportMode::Accumulate);

    if (cluster_gauge.value() > 0) {
      // Key is a cluster ID with active connections, find a node from this cluster
      auto cluster_nodes_it = cluster_to_node_map_.find(key);
      if (cluster_nodes_it != cluster_to_node_map_.end() && !cluster_nodes_it->second.empty()) {
        // Return a random existing node from this cluster
        auto node_idx = random_generator_->random() % cluster_nodes_it->second.size();
        std::string node_id = cluster_nodes_it->second[node_idx];
        ENVOY_LOG(debug,
                  "UpstreamSocketManager: key '{}' is cluster ID with {} connections, returning "
                  "random node: {}",
                  key, cluster_gauge.value(), node_id);
        return node_id;
      }
      // If cluster has connections but no local mapping, assume key is a node ID
    }
  }

  // Key is not a cluster ID, has no connections, or has no local mapping
  // Treat it as a node ID and return it directly
  ENVOY_LOG(debug, "UpstreamSocketManager: key '{}' is node ID, returning as-is", key);
  return key;
}

void UpstreamSocketManager::markSocketDead(const int fd) {
  ENVOY_LOG(trace, "UpstreamSocketManager: markSocketDead called for fd {}", fd);

  auto node_it = fd_to_node_map_.find(fd);
  if (node_it == fd_to_node_map_.end()) {
    ENVOY_LOG(debug, "UpstreamSocketManager: FD {} not found in fd_to_node_map_", fd);
    return;
  }

  const std::string node_id = node_it->second; // Make a COPY, not a reference
  ENVOY_LOG(debug, "UpstreamSocketManager: found node '{}' for fd {}", node_id, fd);

  std::string cluster_id = (node_to_cluster_map_.find(node_id) != node_to_cluster_map_.end())
                               ? node_to_cluster_map_[node_id]
                               : "";
  fd_to_node_map_.erase(fd); // Now it's safe to erase since node_id is a copy

  // Clean up connection metadata.
  fd_to_metadata_map_.erase(fd);

  // Check if this is a used connection by looking for node_id in accepted_reverse_connections_
  auto& sockets = accepted_reverse_connections_[node_id];
  if (sockets.empty()) {
    // This is a used connection. Mark the stats and return. The socket will be closed by the
    // owning UpstreamReverseConnectionIOHandle.
    ENVOY_LOG(debug, "UpstreamSocketManager: Marking used socket dead. node: {} cluster: {} FD: {}",
              node_id, cluster_id, fd);
    // Update Envoy's stats system for production multi-tenant tracking
    // This ensures stats are decremented when connections are removed
    if (auto extension = getUpstreamExtension()) {
      extension->updateConnectionStats(node_id, cluster_id, false /* decrement */);
      ENVOY_LOG(debug,
                "UpstreamSocketManager: decremented stats registry for node '{}' cluster '{}'",
                node_id, cluster_id);
    }

    return;
  }

  // This is an idle connection, find and remove it from the pool
  bool socket_found = false;
  for (auto itr = sockets.begin(); itr != sockets.end(); itr++) {
    if (fd == itr->get()->ioHandle().fdDoNotUse()) {
      ENVOY_LOG(debug, "UpstreamSocketManager: Marking socket dead; node: {}, cluster: {} FD: {}",
                node_id, cluster_id, fd);
      ::shutdown(fd, SHUT_RDWR);
      itr = sockets.erase(itr);
      socket_found = true;

      fd_to_event_map_.erase(fd);
      fd_to_timer_map_.erase(fd);

      // Update Envoy's stats system for production multi-tenant tracking
      // This ensures stats are decremented when connections are removed
      if (auto extension = getUpstreamExtension()) {
        extension->updateConnectionStats(node_id, cluster_id, false /* decrement */);
        ENVOY_LOG(debug,
                  "UpstreamSocketManager: decremented stats registry for node '{}' cluster '{}'",
                  node_id, cluster_id);
      }
      break;
    }
  }

  if (!socket_found) {
    ENVOY_LOG(error, "UpstreamSocketManager: Marking an invalid socket dead. node: {} FD: {}",
              node_id, fd);
  }

  if (sockets.size() == 0) {
    cleanStaleNodeEntry(node_id);
  }
}

void UpstreamSocketManager::tryEnablePingTimer(const std::chrono::seconds& ping_interval) {
  ENVOY_LOG(debug, "UpstreamSocketManager: trying to enable ping timer, ping interval: {}",
            ping_interval.count());
  if (ping_interval_ != std::chrono::seconds::zero()) {
    return;
  }
  ENVOY_LOG(debug, "UpstreamSocketManager: enabling ping timer, ping interval: {}",
            ping_interval.count());
  ping_interval_ = ping_interval;
  ping_timer_->enableTimer(ping_interval_);
}

void UpstreamSocketManager::cleanStaleNodeEntry(const std::string& node_id) {
  // Clean the given node-id, if there are no active sockets.
  if (accepted_reverse_connections_.find(node_id) != accepted_reverse_connections_.end() &&
      accepted_reverse_connections_[node_id].size() > 0) {
    ENVOY_LOG(debug, "Found {} active sockets for node: {}",
              accepted_reverse_connections_[node_id].size(), node_id);
    return;
  }
  ENVOY_LOG(debug, "UpstreamSocketManager: Cleaning stale node entry for node: {}", node_id);

  // Check if given node-id, is present in node_to_cluster_map_. If present,
  // fetch the corresponding cluster-id. Use cluster-id and node-id to delete entry
  // from cluster_to_node_map_ and node_to_cluster_map_ respectively.
  const auto& node_itr = node_to_cluster_map_.find(node_id);
  if (node_itr != node_to_cluster_map_.end()) {
    const auto& cluster_itr = cluster_to_node_map_.find(node_itr->second);
    if (cluster_itr != cluster_to_node_map_.end()) {
      const auto& node_entry_itr =
          find(cluster_itr->second.begin(), cluster_itr->second.end(), node_id);

      if (node_entry_itr != cluster_itr->second.end()) {
        ENVOY_LOG(debug, "UpstreamSocketManager:Removing stale node {} from cluster {}", node_id,
                  cluster_itr->first);
        cluster_itr->second.erase(node_entry_itr);

        // If the cluster to node-list map has an empty vector, remove
        // the entry from map.
        if (cluster_itr->second.size() == 0) {
          cluster_to_node_map_.erase(cluster_itr);
        }
      }
    }
    node_to_cluster_map_.erase(node_itr);
  }

  // Remove empty node entry from accepted_reverse_connections_
  accepted_reverse_connections_.erase(node_id);
}

void UpstreamSocketManager::onPingResponse(Network::IoHandle& io_handle) {
  const int fd = io_handle.fdDoNotUse();

  Buffer::OwnedImpl buffer;
  const auto ping_size =
      ::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::PING_MESSAGE
          .size();
  Api::IoCallUint64Result result = io_handle.read(buffer, absl::make_optional(ping_size));
  if (!result.ok()) {
    ENVOY_LOG(debug, "UpstreamSocketManager: Read error on FD: {}: error - {}", fd,
              result.err_->getErrorDetails());
    markSocketDead(fd);
    return;
  }

  // In this case, there is no read error, but the socket has been closed by the remote
  // peer in a graceful manner, unlike a connection refused, or a reset.
  if (result.return_value_ == 0) {
    ENVOY_LOG(debug, "UpstreamSocketManager: FD: {}: reverse connection closed", fd);
    markSocketDead(fd);
    return;
  }

  if (result.return_value_ < ping_size) {
    ENVOY_LOG(debug, "UpstreamSocketManager: FD: {}: no complete ping data yet", fd);
    return;
  }

  if (!::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::isPingMessage(
          buffer.toString())) {
    ENVOY_LOG(debug, "UpstreamSocketManager: FD: {}: response is not RPING", fd);
    markSocketDead(fd);
    return;
  }

  // Update connection metadata for successful ping response.
  auto now = std::chrono::system_clock::now();
  if (auto metadata_it = fd_to_metadata_map_.find(fd); metadata_it != fd_to_metadata_map_.end()) {
    auto& metadata = metadata_it->second;
    metadata.last_ping_received = now;
    metadata.last_activity = now;
    metadata.total_pings_received++;
    metadata.consecutive_ping_failures = 0; // Reset failure count on successful ping.

    // Calculate average ping latency if we have sent time.
    if (metadata.last_ping_sent != std::chrono::system_clock::time_point{}) {
      auto latency =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - metadata.last_ping_sent);
      // Simple moving average with weight factor.
      if (metadata.average_ping_latency.count() == 0) {
        metadata.average_ping_latency = latency;
      } else {
        // Weighted average: 80% old, 20% new.
        metadata.average_ping_latency = std::chrono::milliseconds(
            (metadata.average_ping_latency.count() * 4 + latency.count()) / 5);
      }
    }

    ENVOY_LOG(trace, "UpstreamSocketManager: FD: {}: updated ping metadata, latency={}ms", fd,
              metadata.average_ping_latency.count());
  }

  ENVOY_LOG(trace, "UpstreamSocketManager: FD: {}: received ping response", fd);
  fd_to_timer_map_[fd]->disableTimer();
}

void UpstreamSocketManager::pingConnections(const std::string& node_id) {
  ENVOY_LOG(debug, "UpstreamSocketManager: Pinging connections for node: {}", node_id);
  auto& sockets = accepted_reverse_connections_[node_id];
  ENVOY_LOG(debug, "UpstreamSocketManager: node:{} Number of sockets:{}", node_id, sockets.size());

  auto itr = sockets.begin();
  while (itr != sockets.end()) {
    int fd = itr->get()->ioHandle().fdDoNotUse();
    auto buffer = ::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::
        createPingResponse();

    auto ping_response_timeout = ping_interval_ / 2;
    fd_to_timer_map_[fd]->enableTimer(ping_response_timeout);

    // Update ping metadata before sending.
    auto now = std::chrono::system_clock::now();
    if (auto metadata_it = fd_to_metadata_map_.find(fd); metadata_it != fd_to_metadata_map_.end()) {
      auto& metadata = metadata_it->second;
      metadata.last_ping_sent = now;
      metadata.total_pings_sent++;
    }

    // Use a flag to signal whether the socket needs to be marked dead. If the socket is marked dead
    // in markSocketDead(), it is erased from the list, and the iterator becomes invalid. We need to
    // break out of the loop to avoid a use after free error.
    bool socket_dead = false;
    while (buffer->length() > 0) {
      Api::IoCallUint64Result result = itr->get()->ioHandle().write(*buffer);
      ENVOY_LOG(trace,
                "UpstreamSocketManager: node:{} FD:{}: sending ping request. return_value: {}",
                node_id, fd, result.return_value_);
      if (result.return_value_ == 0) {
        ENVOY_LOG(trace, "UpstreamSocketManager: node:{} FD:{}: sending ping rc {}, error - ",
                  node_id, fd, result.return_value_, result.err_->getErrorDetails());
        if (result.err_->getErrorCode() != Api::IoError::IoErrorCode::Again) {
          ENVOY_LOG(error, "UpstreamSocketManager: node:{} FD:{}: failed to send ping", node_id,
                    fd);

          // Update ping failure metadata.
          if (auto metadata_it = fd_to_metadata_map_.find(fd);
              metadata_it != fd_to_metadata_map_.end()) {
            metadata_it->second.consecutive_ping_failures++;
          }

          markSocketDead(fd);
          socket_dead = true;
          break;
        }
      }
    }

    if (buffer->length() > 0) {
      // Move to next socket if current one couldn't be fully written
      ++itr;
      continue;
    }

    if (socket_dead) {
      // Socket was marked dead, iterator is now invalid, break out of the loop
      break;
    }

    // Move to next socket
    ++itr;
  }
}

void UpstreamSocketManager::pingConnections() {
  ENVOY_LOG(error, "UpstreamSocketManager: Pinging connections");
  for (auto& itr : accepted_reverse_connections_) {
    pingConnections(itr.first);
  }
  ping_timer_->enableTimer(ping_interval_);
}

UpstreamSocketManager::~UpstreamSocketManager() {
  ENVOY_LOG(debug, "UpstreamSocketManager destructor called");

  // Clean up all active file events and timers first
  for (auto& [fd, event] : fd_to_event_map_) {
    ENVOY_LOG(debug, "UpstreamSocketManager: cleaning up file event for FD: {}", fd);
    event.reset(); // This will cancel the file event.
  }
  fd_to_event_map_.clear();

  for (auto& [fd, timer] : fd_to_timer_map_) {
    ENVOY_LOG(debug, "UpstreamSocketManager: cleaning up timer for FD: {}", fd);
    timer.reset(); // This will cancel the timer.
  }
  fd_to_timer_map_.clear();

  // Now mark all sockets as dead
  std::vector<int> fds_to_cleanup;
  for (const auto& [fd, node_id] : fd_to_node_map_) {
    fds_to_cleanup.push_back(fd);
  }

  for (int fd : fds_to_cleanup) {
    ENVOY_LOG(trace, "UpstreamSocketManager: marking socket dead in destructor for FD: {}", fd);
    markSocketDead(fd); // false = not used, just cleanup
  }

  // Clear the ping timer
  if (ping_timer_) {
    ping_timer_->disableTimer();
    ping_timer_.reset();
  }
}

std::vector<UpstreamSocketManager::ConnectionSnapshot>
UpstreamSocketManager::getConnectionSnapshots() const {
  std::vector<ConnectionSnapshot> snapshots;

  // Iterate through all accepted connections.
  for (const auto& [node_id, sockets] : accepted_reverse_connections_) {
    std::string cluster_id;
    if (auto cluster_it = node_to_cluster_map_.find(node_id);
        cluster_it != node_to_cluster_map_.end()) {
      cluster_id = cluster_it->second;
    }

    // Process each socket for this node.
    for (const auto& socket : sockets) {
      if (!socket || !socket->ioHandle().isOpen()) {
        continue;
      }

      ConnectionSnapshot snapshot;
      snapshot.node_id = node_id;
      snapshot.cluster_id = cluster_id;
      // Note: tenant_id is not stored in socket manager, would need to be tracked separately.
      snapshot.tenant_id = "";
      snapshot.remote_address = socket->connectionInfoProvider().remoteAddress()->asString();
      snapshot.local_address = socket->connectionInfoProvider().localAddress()->asString();
      snapshot.fd = socket->ioHandle().fdDoNotUse();

      // Get connection metadata if available.
      if (auto metadata_it = fd_to_metadata_map_.find(snapshot.fd);
          metadata_it != fd_to_metadata_map_.end()) {
        const auto& metadata = metadata_it->second;
        snapshot.established_time = metadata.established_time;
        snapshot.last_activity = metadata.last_activity;
        snapshot.last_ping_sent = metadata.last_ping_sent;
        snapshot.last_ping_received = metadata.last_ping_received;
        snapshot.bytes_sent = metadata.bytes_sent;
        snapshot.bytes_received = metadata.bytes_received;
        snapshot.consecutive_ping_failures = metadata.consecutive_ping_failures;
        snapshot.total_pings_sent = metadata.total_pings_sent;
        snapshot.total_pings_received = metadata.total_pings_received;
        snapshot.ping_interval = metadata.ping_interval;
        snapshot.average_ping_latency = metadata.average_ping_latency;

        // Connection is healthy if consecutive ping failures are low.
        snapshot.is_healthy = metadata.consecutive_ping_failures < 3;
      } else {
        // Fallback if metadata not available.
        auto now = std::chrono::system_clock::now();
        snapshot.established_time = now;
        snapshot.last_activity = now;
        snapshot.is_healthy = true;
      }

      snapshots.push_back(snapshot);
    }
  }

  ENVOY_LOG(debug, "UpstreamSocketManager: collected {} connection snapshots", snapshots.size());
  return snapshots;
}

absl::flat_hash_map<std::string, uint64_t> UpstreamSocketManager::getLocalStats() const {
  absl::flat_hash_map<std::string, uint64_t> stats;

  // Count connections per node.
  for (const auto& [node_id, sockets] : accepted_reverse_connections_) {
    stats[fmt::format("node.{}.connections", node_id)] = sockets.size();
  }

  // Count connections per cluster.
  absl::flat_hash_map<std::string, uint64_t> cluster_counts;
  for (const auto& [node_id, cluster_id] : node_to_cluster_map_) {
    if (auto node_it = accepted_reverse_connections_.find(node_id);
        node_it != accepted_reverse_connections_.end()) {
      cluster_counts[cluster_id] += node_it->second.size();
    }
  }

  for (const auto& [cluster_id, count] : cluster_counts) {
    stats[fmt::format("cluster.{}.connections", cluster_id)] = count;
  }

  // Total connections.
  uint64_t total = 0;
  for (const auto& [node_id, sockets] : accepted_reverse_connections_) {
    total += sockets.size();
  }
  stats["total_connections"] = total;

  return stats;
}

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
