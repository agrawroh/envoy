#include "contrib/reverse_connection/bootstrap/source/downstream_reverse_socket_interface.h"

#include <sys/socket.h>

#include <cerrno>
#include <cstring>

#include "envoy/network/connection.h"
#include "envoy/network/address.h"
#include "envoy/registry/registry.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/http/headers.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_interface_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"

#include "contrib/reverse_connection/bootstrap/source/reverse_connection_address.h"

#include "google/protobuf/empty.pb.h"

// Include the reverse connection protobuf definitions
#include "contrib/envoy/extensions/filters/http/reverse_conn/v3alpha/reverse_conn.pb.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// Forward declaration
class ReverseConnectionIOHandle;
class DownstreamReverseSocketInterface;

/**
 * RCConnectionWrapper manages the lifecycle of a ClientConnectionPtr for reverse connections.
 * It handles connection callbacks, sends the handshake request, and processes the response.
 */
class RCConnectionWrapper : public Network::ConnectionCallbacks,
                            Logger::Loggable<Logger::Id::main>  {
public:
  RCConnectionWrapper(ReverseConnectionIOHandle& parent,
                     Network::ClientConnectionPtr connection,
                     Upstream::HostDescriptionConstSharedPtr host)
      : parent_(parent), 
        connection_(std::move(connection)),
        host_(std::move(host)) {}

  ~RCConnectionWrapper() {
    if (connection_) {
      connection_->removeConnectionCallbacks(*this);
    }
  }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // Initiate the reverse connection handshake
  std::string connect(const std::string& src_tenant_id,
                     const std::string& src_cluster_id,
                     const std::string& src_node_id);

  // Process the handshake response
  void onData(const std::string& error);

  // Clean up on failure
  void onFailure() {
    if (connection_) {
      connection_->removeConnectionCallbacks(*this);
    }
  }

  Network::ClientConnection* getConnection() { return connection_.get(); }
  Upstream::HostDescriptionConstSharedPtr getHost() { return host_; }

  // Release the connection when handshake succeeds
  Network::ClientConnectionPtr releaseConnection() {
    return std::move(connection_);
  }

private:
    /**
     * Read filter that is added to each connection initiated by the RCInitiator. Upon receiving a
     * response from remote envoy, the Read filter parses it and calls its parent RCConnectionWrapper
     * onData().
     */
    struct ConnReadFilter : public Network::ReadFilterBaseImpl {

      /**
       * expected response will be something like:
       * 'HTTP/1.1 200 OK\r\ncontent-length: 27\r\ncontent-type: text/plain\r\ndate: Tue, 11 Feb 2020
       * 07:37:24 GMT\r\nserver: envoy\r\n\r\nreverse connection accepted'
       */
      ConnReadFilter(RCConnectionWrapper* parent)
          : parent_(parent) {}

      // Implementation of Network::ReadFilter.
      Network::FilterStatus onData(Buffer::Instance& buffer, bool) {
        if (parent_ == nullptr) {
          ENVOY_LOG(error, "RC Connection Manager is null. Aborting read.");
          return Network::FilterStatus::StopIteration;
        }

        Network::ClientConnection *connection = parent_->getConnection();

        if (connection != nullptr) {
          ENVOY_LOG(info, "Connection read filter: reading data on connection ID: {}", connection->id());
        } else {
          ENVOY_LOG(error, "Connection read filter: connection is null. Aborting read.");
          return Network::FilterStatus::StopIteration;
        }

        response_buffer_string_ += buffer.toString();
        const size_t headers_end_index = response_buffer_string_.find(DOUBLE_CRLF);
        if (headers_end_index == std::string::npos) {
          ENVOY_LOG(debug, "Received {} bytes, but not all the headers.",
                          response_buffer_string_.length());
          return Network::FilterStatus::Continue;
        }

        const std::vector<absl::string_view>& headers =
            StringUtil::splitToken(response_buffer_string_.substr(0, headers_end_index), CRLF,
                                  false /* keep_empty_string */, true /* trim_whitespace */);
        const absl::string_view content_length_str = Http::Headers::get().ContentLength.get();
        absl::string_view length_header;
        for (const absl::string_view& header : headers) {
          if (!StringUtil::CaseInsensitiveCompare()(header.substr(0, content_length_str.length()),
                                                    content_length_str)) {
            continue;
          }
          length_header = header;
        }

        // Since the Ikat hub is expected to send a simple HTTP response which is not chunk
        // encoded, we should always find a content length header.
        RELEASE_ASSERT(length_header.length() > 0, "Could not find a valid Content-length header");

        // Decode response content length from a Header value to an unsigned integer.
        const std::vector<absl::string_view>& header_val =
            StringUtil::splitToken(length_header, ":", false, true);
        uint32_t body_size = std::stoi(std::string(header_val[1]));
        ENVOY_LOG(debug, "Decoding a Response of length {}", body_size);

        const size_t expected_response_size = headers_end_index + strlen(DOUBLE_CRLF) + body_size;
        if (response_buffer_string_.length() < expected_response_size) {
          // We have not received the complete body yet.
          ENVOY_LOG(trace, "Received {} of {} expected response bytes.",
                    response_buffer_string_.length(), expected_response_size);
          return Network::FilterStatus::Continue;
        }

        envoy::extensions::filters::http::reverse_conn::v3alpha::ReverseConnHandshakeRet ret;
        ret.ParseFromString(response_buffer_string_.substr(headers_end_index + strlen(DOUBLE_CRLF)));
        ENVOY_LOG(debug, "Found ReverseConnHandshakeRet {}",
                        ret.DebugString());
        parent_->onData(ret.status_message());
        return Network::FilterStatus::StopIteration;
      }

      RCConnectionWrapper* parent_;
      std::string response_buffer_string_;
    };
    ReverseConnectionIOHandle& parent_;
    Network::ClientConnectionPtr connection_;
    Upstream::HostDescriptionConstSharedPtr host_;
  };

void RCConnectionWrapper::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose) {
    if (!connection_) {
      ENVOY_LOG(debug, "RCConnectionWrapper: connection is null, skipping event handling");
      return;
    }
    
    const std::string& connectionKey = connection_->connectionInfoProvider().localAddress()->asString();
    ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, found connection {} remote closed",
              connection_->id(), connectionKey);
    onFailure();
    // Notify parent of connection closure
    parent_.onConnectionWrapperClosed(this, true);
  }
}

std::string RCConnectionWrapper::connect(const std::string& src_tenant_id,
                                         const std::string& src_cluster_id,
                                         const std::string& src_node_id) {
  // Register connection callbacks
  ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, adding connection callbacks",
            connection_->id());
  connection_->addConnectionCallbacks(*this);

  // Add read filter to handle response
  ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, adding read filter",
            connection_->id());
  connection_->addReadFilter(Network::ReadFilterSharedPtr{new ConnReadFilter(this)});
  connection_->connect();

  ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, sending reverse connection creation "
            "request through TCP", connection_->id());

  envoy::extensions::filters::http::reverse_conn::v3alpha::ReverseConnHandshakeArg arg;
  arg.set_tenant_uuid(src_tenant_id);
  arg.set_cluster_uuid(src_cluster_id);
  arg.set_node_uuid(src_node_id);
  std::string body = arg.SerializeAsString();

  std::string host_value;
  const auto& remote_address = connection_->connectionInfoProvider().remoteAddress();
  if (remote_address->type() == Network::Address::Type::EnvoyInternal) {
    const auto& internal_address = 
        std::dynamic_pointer_cast<const Network::Address::EnvoyInternalInstance>(remote_address);
    ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, remote address is internal "
              "listener {}, using endpoint ID in host header", connection_->id(), 
              internal_address->envoyInternalAddress()->addressId());
    host_value = internal_address->envoyInternalAddress()->endpointId();
  } else {
    host_value = remote_address->asString();
    ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, remote address is external, "
              "using address as host header", connection_->id());
  }

  // Build HTTP request with protobuf body
  Buffer::OwnedImpl reverse_connection_request(
      fmt::format("POST /reverse_connections/request HTTP/1.1\r\n"
                  "Host: {}\r\n"
                  "Accept: */*\r\n"
                  "Content-length: {}\r\n"
                  "\r\n{}",
                  host_value,
                  body.length(),
                  body));

  ENVOY_LOG(debug, "RCConnectionWrapper: connection: {}, writing request to connection: {}",
            connection_->id(), reverse_connection_request.toString());
  connection_->write(reverse_connection_request, false);
  
  return connection_->connectionInfoProvider().localAddress()->asString();
}

void RCConnectionWrapper::onData(const std::string& error) {
  // Notify parent about the result
  parent_.onConnectionDone(error, this, false);
}


ReverseConnectionIOHandle::ReverseConnectionIOHandle(os_fd_t fd,
                                                    const ReverseConnectionSocketConfig& config,
                                                    Upstream::ClusterManager& cluster_manager,
                                                    const DownstreamReverseSocketInterface& socket_interface)
    : IoSocketHandleImpl(fd), config_(config), cluster_manager_(cluster_manager),
      socket_interface_(socket_interface) {
  ENVOY_LOG(debug, "Created ReverseConnectionIOHandle: fd={}, src_node={}, num_clusters={}",
            fd_, config_.src_node_id, config_.remote_clusters.size());

  ENVOY_LOG(debug,
            "Creating ReverseConnectionIOHandle - src_cluster: {}, src_node: {}, "
            "health_check_interval: {}ms, connection_timeout: {}ms",
            config_.src_cluster_id, config_.src_node_id, config_.health_check_interval_ms,
            config_.connection_timeout_ms);

  for (const auto& cluster_config : config_.remote_clusters) {
    connection_metadata_[cluster_config.cluster_name] =
        ReverseConnectionMetadata(cluster_config.cluster_name);
  }

  // Create trigger pipe
  createTriggerPipe();

  // Always initiate reverse connections
  ENVOY_LOG(debug, "Auto-initiating reverse connections for {} clusters",
            config_.remote_clusters.size());
  // Defer actual connection initiation until listen() is called
}

ReverseConnectionIOHandle::~ReverseConnectionIOHandle() {
  ENVOY_LOG(info, "Destroying ReverseConnectionIOHandle - performing cleanup");
  cleanup();
}

void ReverseConnectionIOHandle::cleanup() {
  ENVOY_LOG(debug, "Starting cleanup of reverse connection resources");

  // Cancel the retry timer
  if (rev_conn_retry_timer_) {
    rev_conn_retry_timer_->disableTimer();
    ENVOY_LOG(debug, "Cancelled retry timer");
  }


  /*
  for (auto& [cluster_name, timer] : health_check_timers_) {
    if (timer) {
      timer->disableTimer();
      ENVOY_LOG(debug, "Cancelled health check timer for cluster: {}", cluster_name);
    }
  }
  health_check_timers_.clear();
  */

  // Cleanup connection wrappers
  ENVOY_LOG(debug, "Closing {} connection wrappers", connection_wrappers_.size());
  connection_wrappers_.clear();  // Destructors will handle cleanup
  conn_wrapper_to_host_map_.clear();
  
  // Clear cluster to hosts mapping
  cluster_to_resolved_hosts_map_.clear();
  host_to_conn_info_map_.clear();

  // Clear established connections queue.
  {
    absl::MutexLock lock(&connection_mutex_);
    while (!established_connections_.empty()) {
      auto connection = std::move(established_connections_.front());
      established_connections_.pop();
      if (connection && connection->state() == Envoy::Network::Connection::State::Open) {
        connection->close(Envoy::Network::ConnectionCloseType::FlushWrite);
      }
    }
  }

  // Clear socket cache
  {
    absl::MutexLock lock(&socket_cache_mutex_);
    ENVOY_LOG(debug, "Clearing {} cached sockets", socket_cache_.size());
    socket_cache_.clear();
  }

  // Cleanup trigger pipe.
  if (trigger_pipe_read_fd_ != -1) {
    ::close(trigger_pipe_read_fd_);
    trigger_pipe_read_fd_ = -1;
  }
  if (trigger_pipe_write_fd_ != -1) {
    ::close(trigger_pipe_write_fd_);
    trigger_pipe_write_fd_ = -1;
  }

  // Update final metrics.
  // {
  //   absl::MutexLock lock(&metadata_mutex_);
  //   for (auto& [cluster_name, metadata] : connection_metadata_) {
  //     updateConnectionMetricsUnsafe(cluster_name, ReverseConnectionState::Disconnected);
  //   }
  // }

  ENVOY_LOG(debug, "Completed cleanup of reverse connection resources");
}

Api::SysCallIntResult ReverseConnectionIOHandle::listen(int backlog) {
  (void)backlog; // Unused parameter
  ENVOY_LOG(debug, "ReverseConnectionIOHandle::listen() - initiating reverse connections to {} clusters",
            config_.remote_clusters.size());

  if (!listening_initiated_) {
    initiateReverseTcpConnections();
    listening_initiated_ = true;
  }

  return Api::SysCallIntResult{0, 0};
}

Envoy::Network::IoHandlePtr ReverseConnectionIOHandle::accept(struct sockaddr* addr,
                                                              socklen_t* addrlen) {

  if (trigger_pipe_read_fd_ != -1) {
    char trigger_byte;
    ssize_t bytes_read = ::read(trigger_pipe_read_fd_, &trigger_byte, 1);

    if (bytes_read == 1) {
      ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - received trigger, processing connection");

      absl::MutexLock lock(&connection_mutex_);

      if (!established_connections_.empty()) {
        ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - getting connection from queue");
        auto connection = std::move(established_connections_.front());
        established_connections_.pop();

        // Fill in address information for the reverse tunnel "client"
        // TODO(ROHIT): Use actual client address if available
        if (addr && addrlen) {
          // Use the remote address from the connection if available
          const auto& remote_addr = connection->connectionInfoProvider().remoteAddress();
          
          if (remote_addr) {
            ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - getting sockAddr");
            const sockaddr* sock_addr = remote_addr->sockAddr();
            socklen_t addr_len = remote_addr->sockAddrLen();
            
            if (*addrlen >= addr_len) {
              memcpy(addr, sock_addr, addr_len);
              *addrlen = addr_len;
            }
          } else {
            ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - using synthetic address");
            // Fallback to synthetic address
            auto synthetic_addr =
                std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 0);
            const sockaddr* sock_addr = synthetic_addr->sockAddr();
            socklen_t addr_len = synthetic_addr->sockAddrLen();

            if (*addrlen >= addr_len) {
              memcpy(addr, sock_addr, addr_len);
              *addrlen = addr_len;
            }
          }
        }
        
        const std::string connection_key = connection->connectionInfoProvider().localAddress()->asString();
        ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - got connection key: {}", connection_key);
        
        auto socket = connection->moveSocket();
        os_fd_t conn_fd = socket->ioHandle().fdDoNotUse();
        ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - got fd: {}. Creating IoHandle", conn_fd);
        
        // Cache the socket object so it doesn't go out of scope
        {
          absl::MutexLock lock(&socket_cache_mutex_);
          socket_cache_[connection_key] = std::move(socket);
          ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - cached socket for connection key: {}", connection_key);
        }
        
        auto io_handle = std::make_unique<Envoy::Network::IoSocketHandleImpl>(conn_fd);
        ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - IoHandle created");
        
        // Clean up connection key tracking for this host
        {
          absl::MutexLock lock(&host_connections_mutex_);
          
          // Find which host this connection belongs to
          for (auto& [host_address, host_info] : host_to_conn_info_map_) {
            if (host_info.connection_keys.erase(connection_key) > 0) {
              ENVOY_LOG(debug, "Cleaned up connection key {} for host {} after successful accept",
                        connection_key, host_address);
              break;
            }
          }
        }

        connection->close(Network::ConnectionCloseType::NoFlush);
        
        ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - returning io_handle");
        return io_handle;
      }
    } else if (bytes_read == 0) {
      ENVOY_LOG(debug, "ReverseConnectionIOHandle::accept() - trigger pipe closed");
      return nullptr;
    } else if (bytes_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
      ENVOY_LOG(error, "ReverseConnectionIOHandle::accept() - error reading from trigger pipe: {}", strerror(errno));
      return nullptr;
    }
  }

  return nullptr;
}

Api::IoCallUint64Result ReverseConnectionIOHandle::read(Buffer::Instance& buffer,
                                                        absl::optional<uint64_t> max_length) {
  ENVOY_LOG(trace, "Read operation - max_length: {}", max_length.value_or(0));

  auto result = IoSocketHandleImpl::read(buffer, max_length);

  // Update performance metrics if enabled.
  /*
  if (result.ok() && config_.enable_metrics) {
    // TODO: Implement metrics tracking
  }
  */

  return result;
}

Api::IoCallUint64Result ReverseConnectionIOHandle::write(Buffer::Instance& buffer) {
  ENVOY_LOG(trace, "Write operation - {} bytes", buffer.length());

  auto result = IoSocketHandleImpl::write(buffer);

  // Update performance metrics if enabled.
  /*
  if (result.ok() && config_.enable_metrics) {
    // TODO: Implement metrics tracking
  }
  */

  return result;
}

Api::SysCallIntResult
ReverseConnectionIOHandle::connect(Envoy::Network::Address::InstanceConstSharedPtr address) {
  ENVOY_LOG(debug, "ReverseConnectionIOHandle::connect() to {} - handling reverse tunnel semantics",
            address->asString());

  // For reverse connections, connect calls are handled through the tunnel mechanism.
  return IoSocketHandleImpl::connect(address);
}

Api::IoCallUint64Result ReverseConnectionIOHandle::close() {
  ENVOY_LOG(debug, "ReverseConnectionIOHandle::close() - performing graceful shutdown");

  cleanup();
  return IoSocketHandleImpl::close();
}

void ReverseConnectionIOHandle::onEvent(Network::ConnectionEvent event) {
  // This is called when connection events occur
  // For reverse connections, we handle these events through RCConnectionWrapper
  ENVOY_LOG(trace, "ReverseConnectionIOHandle::onEvent - event: {}", static_cast<int>(event));
}

bool ReverseConnectionIOHandle::isTriggerPipeReady() const {
  return trigger_pipe_read_fd_ != -1 && trigger_pipe_write_fd_ != -1;
}

const std::unordered_map<std::string, ReverseConnectionMetadata>&
ReverseConnectionIOHandle::getConnectionMetadata() const {
  absl::MutexLock lock(&metadata_mutex_);
  return connection_metadata_;
}

// Use the thread-local registry to get the dispatcher
Event::Dispatcher& ReverseConnectionIOHandle::getThreadLocalDispatcher() const {
  // Get the thread-local dispatcher from the socket interface's registry
  auto* local_registry = socket_interface_.getLocalRegistry();
  
  if (local_registry) {
    // Return the dispatcher from the thread-local registry
    ENVOY_LOG(debug, "ReverseConnectionIOHandle::getThreadLocalDispatcher() - dispatcher: {}", local_registry->dispatcher().name());
    return local_registry->dispatcher();
  }
  throw EnvoyException("Failed to get dispatcher from thread-local registry");
}

void ReverseConnectionIOHandle::maybeUpdateHostsMappingsAndConnections(
    const std::string& cluster_id, const std::vector<std::string>& hosts) {
  absl::MutexLock lock(&host_connections_mutex_);
  
  absl::flat_hash_set<std::string> new_hosts(hosts.begin(), hosts.end());
  absl::flat_hash_set<std::string> removed_hosts;

  const auto& cluster_to_resolved_hosts_itr = cluster_to_resolved_hosts_map_.find(cluster_id);
  if (cluster_to_resolved_hosts_itr != cluster_to_resolved_hosts_map_.end()) {
    // removed_hosts contains the hosts that were previously resolved.
    removed_hosts = cluster_to_resolved_hosts_itr->second;
  }

  for (const std::string& host : hosts) {
    if (removed_hosts.find(host) != removed_hosts.end()) {
      // Since the host still exists, we will remove it from removed_hosts.
      removed_hosts.erase(host);
    }

    ENVOY_LOG(debug, "Adding remote host {} to cluster {}", host, cluster_id);
    
    // Update or create host info
    auto host_it = host_to_conn_info_map_.find(host);
    if (host_it == host_to_conn_info_map_.end()) {
      host_to_conn_info_map_[host] = HostConnectionInfo{
          host,       // host_address
          cluster_id, // cluster_name
          {},         // connection_keys - empty set initially
          0           // target_connection_count will be updated
      };
    } else {
      // Update cluster name if host moved to different cluster
      host_it->second.cluster_name = cluster_id;
    }
  }

  cluster_to_resolved_hosts_map_[cluster_id] = new_hosts;

  ENVOY_LOG(debug, "Removing {} remote hosts from cluster {}", 
            removed_hosts.size(), cluster_id);
  
  // Remove the hosts present in removed_hosts.
  for (const std::string& host : removed_hosts) {
    removeStaleHostAndCloseConnections(host);
    host_to_conn_info_map_.erase(host);
  }
}

void ReverseConnectionIOHandle::removeStaleHostAndCloseConnections(const std::string& host) {
  // Note: Caller must hold host_connections_mutex_
  
  ENVOY_LOG(info, "Removing all connections to remote host {}", host);

  // Find all wrappers for this host
  std::vector<RCConnectionWrapper*> wrappers_to_remove;
  for (const auto& [wrapper, mapped_host] : conn_wrapper_to_host_map_) {
    if (mapped_host == host) {
      wrappers_to_remove.push_back(wrapper);
    }
  }

  ENVOY_LOG(info, "Found {} connections to remove for host {}", 
            wrappers_to_remove.size(), host);

  // Remove wrappers and close connections
  for (auto* wrapper : wrappers_to_remove) {
    ENVOY_LOG(debug, "Removing connection wrapper for host {}", host);
    
    // Remove from wrapper-to-host map
    conn_wrapper_to_host_map_.erase(wrapper);
    
    // Get the connection from wrapper and close it
    auto* connection = wrapper->getConnection();
    if (connection && connection->state() == Network::Connection::State::Open) {
      connection->close(Network::ConnectionCloseType::FlushWrite);
    }
    
    // Remove the wrapper from connection_wrappers_ vector
    connection_wrappers_.erase(
        std::remove_if(connection_wrappers_.begin(), connection_wrappers_.end(),
                       [wrapper](const std::unique_ptr<RCConnectionWrapper>& w) {
                         return w.get() == wrapper;
                       }),
        connection_wrappers_.end());
  }

  // Clear connection keys from host info
  auto host_it = host_to_conn_info_map_.find(host);
  if (host_it != host_to_conn_info_map_.end()) {
    host_it->second.connection_keys.clear();
  }
}

void ReverseConnectionIOHandle::initiateReverseTcpConnections() {
  ENVOY_LOG(debug, "Initiating reverse tunnels for {} clusters", config_.remote_clusters.size());

  // Create the retry timer on first use with thread-local dispatcher (like maintainConnCount)
  if (!rev_conn_retry_timer_) {
    rev_conn_retry_timer_ = getThreadLocalDispatcher().createTimer([this]() -> void { 
      ENVOY_LOG(debug, "Retry timer triggered - checking all clusters for missing connections");
      initiateReverseTcpConnections(); 
    });
    ENVOY_LOG(debug, "Created retry timer for periodic connection checks");
  }

  for (const auto& cluster_config : config_.remote_clusters) {
    const std::string& cluster_name = cluster_config.cluster_name;
    
    ENVOY_LOG(debug, "Processing cluster: {} with {} requested connections per host",
              cluster_name, cluster_config.reverse_connection_count);

    // Update connection state for the cluster
    // updateConnectionMetrics(cluster_name, ReverseConnectionState::Connecting);

    // Get thread local cluster to access resolved hosts
    auto thread_local_cluster = cluster_manager_.getThreadLocalCluster(cluster_name);
    if (thread_local_cluster == nullptr) {
      ENVOY_LOG(error, "Cluster '{}' not found for reverse tunnel - will retry later", cluster_name);
      // updateConnectionMetrics(cluster_name, ReverseConnectionState::Failed);
      continue;
    }

    // Get all resolved hosts for the cluster
    const auto& host_map_ptr = thread_local_cluster->prioritySet().crossPriorityHostMap();
    if (host_map_ptr == nullptr || host_map_ptr->empty()) {
      ENVOY_LOG(warn, "No hosts found in cluster '{}' - will retry later", cluster_name);
      // updateConnectionMetrics(cluster_name, ReverseConnectionState::Failed);
      continue;
    }

    // Retrieve the resolved hosts for a cluster and update the corresponding maps
    std::vector<std::string> resolved_hosts;
    for (const auto& host_iter : *host_map_ptr) {
      resolved_hosts.emplace_back(host_iter.first);
    }
    maybeUpdateHostsMappingsAndConnections(cluster_name, std::move(resolved_hosts));

    // Track successful connections for this cluster
    uint32_t total_successful_connections = 0;
    uint32_t total_required_connections = host_map_ptr->size() * cluster_config.reverse_connection_count;

    // Create connections to each host in the cluster
    for (const auto& [host_address, host] : *host_map_ptr) {
      ENVOY_LOG(debug, "Checking reverse connection count for host {} of cluster {}",
                host_address, cluster_name);

      // Get current number of connections to this host
      uint32_t current_connections = 0;
      {
        absl::MutexLock lock(&host_connections_mutex_);
        auto host_it = host_to_conn_info_map_.find(host_address);
        if (host_it != host_to_conn_info_map_.end()) {
          // Count active wrappers for this host
          for (const auto& [wrapper, mapped_host] : conn_wrapper_to_host_map_) {
            if (mapped_host == host_address) {
              current_connections++;
            }
          }
        }
      }

      ENVOY_LOG(info, 
                "Number of reverse connections to host {} of cluster {}: "
                "Current: {}, Required: {}",
                host_address, cluster_name, current_connections, cluster_config.reverse_connection_count);

      if (current_connections >= cluster_config.reverse_connection_count) {
        ENVOY_LOG(debug, "No more reverse connections needed to host {} of cluster {}",
                  host_address, cluster_name);
        total_successful_connections += current_connections;
        continue;
      }

      const uint32_t needed_connections = cluster_config.reverse_connection_count - current_connections;
      
      ENVOY_LOG(debug,
                "Initiating {} reverse connections to host {} of remote "
                "cluster '{}' from source node '{}'",
                needed_connections, host_address, cluster_name, config_.src_node_id);

      // Create the required number of connections to this specific host
      for (uint32_t i = 0; i < needed_connections; ++i) {
        ENVOY_LOG(debug, "Initiating reverse connection number {} to host {} of cluster {}", 
                  i + 1, host_address, cluster_name);
        
        bool success = initiateOneReverseConnection(cluster_name, host_address, host);
        
        if (success) {
          total_successful_connections++;
          ENVOY_LOG(debug, "Successfully initiated reverse connection number {} to host {} of cluster {}",
                    i + 1, host_address, cluster_name);
        } else {
          ENVOY_LOG(error, "Failed to initiate reverse connection number {} to host {} of cluster {}",
                    i + 1, host_address, cluster_name);
        }
      }
    }

    // Update metrics based on overall success for the cluster
    if (total_successful_connections > 0) {
      // updateConnectionMetrics(cluster_name, ReverseConnectionState::Connected);
      ENVOY_LOG(info, "Successfully created {}/{} total reverse connections to cluster {}",
                total_successful_connections, total_required_connections, cluster_name);
      
      // Schedule health checks if enabled
      /*
      if (cluster_config.enable_health_check) {
        scheduleHealthCheck(cluster_name);
      }
      */
    } else {
      // updateConnectionMetrics(cluster_name, ReverseConnectionState::Failed);
      ENVOY_LOG(error, "Failed to create any reverse connections to cluster {} - will retry later",
                cluster_name);
    }
  }

  ENVOY_LOG(debug, "Completed initial reverse TCP connection setup for all clusters");
  
  // Enable the retry timer to periodically check for missing connections (like maintainConnCount)
  if (rev_conn_retry_timer_) {
    const std::chrono::milliseconds retry_timeout(10000); // 10 seconds
    rev_conn_retry_timer_->enableTimer(retry_timeout);
    ENVOY_LOG(debug, "Enabled retry timer for next connection check in 10 seconds");
  }
}

bool ReverseConnectionIOHandle::initiateOneReverseConnection(const std::string& cluster_name,
                                                             const std::string& host_address,
                                                             Upstream::HostConstSharedPtr host) {
  if (config_.src_node_id.empty() || cluster_name.empty() || host_address.empty()) {
    ENVOY_LOG(error,
              "Source node ID, Host address and Cluster name are required; Source node: {} Host: {} "
              "Cluster: {}",
              config_.src_node_id, host_address, cluster_name);
    return false;
  }

  ENVOY_LOG(debug,
            "Initiating one reverse connection to host {} of cluster '{}', source node '{}'",
            host_address, cluster_name, config_.src_node_id);

  // Check circuit breaker before attempting connection
  if (!shouldAttemptConnection(cluster_name)) {
    ENVOY_LOG(warn, "Circuit breaker open for cluster: {} - skipping connection attempt",
              cluster_name);
    return false;
  }

  // Get the thread local cluster
  auto thread_local_cluster = cluster_manager_.getThreadLocalCluster(cluster_name);
  if (thread_local_cluster == nullptr) {
    ENVOY_LOG(error, "Cluster '{}' not found", cluster_name);
    return false;
  }

  try {
    // Use the new ReverseConnectionLoadBalancerContext from the header
    ReverseConnectionLoadBalancerContext lb_context(host_address);
    
    // Get connection from cluster using tcpConn()
    Upstream::Host::CreateConnectionData conn_data = thread_local_cluster->tcpConn(&lb_context);
    
    if (!conn_data.connection_) {
      ENVOY_LOG(error, "Failed to create connection to host {} in cluster {}",
                host_address, cluster_name);
      return false;
    }

    // Create wrapper to manage the connection
    auto wrapper = std::make_unique<RCConnectionWrapper>(
        *this, 
        std::move(conn_data.connection_),
        conn_data.host_description_);

    // Initiate the reverse connection handshake
    const std::string connection_key = wrapper->connect(
        config_.src_tenant_id,
        config_.src_cluster_id, 
        config_.src_node_id);

    ENVOY_LOG(debug, "Initiated reverse connection handshake for host {} with key {}",
              host_address, connection_key);

    // Track the wrapper
    {
      absl::MutexLock lock(&host_connections_mutex_);
      
      // Initialize host info if not present
      if (host_to_conn_info_map_.find(host_address) == host_to_conn_info_map_.end()) {
        host_to_conn_info_map_[host_address] = HostConnectionInfo{
            host_address,
            cluster_name,
            {},  // connection_keys - empty set initially
            0    // target_connection_count will be updated
        };
      }
      
      // Update target connection count from config
      auto cluster_config = std::find_if(
          config_.remote_clusters.begin(), config_.remote_clusters.end(),
          [&cluster_name](const auto& config) { return config.cluster_name == cluster_name; });
      
      if (cluster_config != config_.remote_clusters.end()) {
        host_to_conn_info_map_[host_address].target_connection_count = 
            cluster_config->reverse_connection_count;
      }
      
      // Store wrapper-to-host mapping
      conn_wrapper_to_host_map_[wrapper.get()] = host_address;
      
      // Store the wrapper
      connection_wrappers_.push_back(std::move(wrapper));
    }

    ENVOY_LOG(debug, "Successfully initiated reverse connection to host {} ({}:{}) in cluster {}",
              host_address,
              host->address()->ip()->addressAsString(),
              host->address()->ip()->port(),
              cluster_name);

    return true;

  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Exception creating reverse connection to host {} in cluster {}: {}",
              host_address, cluster_name, e.what());
    return false;
  }
}

/*
void ReverseConnectionIOHandle::scheduleHealthCheck(const std::string& cluster_name) {
  if (!config_.enable_metrics) {
    return;
  }

  ENVOY_LOG(debug, "Scheduling health check for cluster: {} every {}ms", cluster_name,
            config_.health_check_interval_ms);

  // Cancel existing health check timer.
  auto timer_it = health_check_timers_.find(cluster_name);
  if (timer_it != health_check_timers_.end() && timer_it->second) {
    timer_it->second->disableTimer();
  }

  // Create and schedule health check timer.
  auto timer = getThreadLocalDispatcher().createTimer([this, cluster_name]() {
    performHealthCheck(cluster_name);
    // Reschedule next health check.
    scheduleHealthCheck(cluster_name);
  });

  timer->enableTimer(std::chrono::milliseconds(config_.health_check_interval_ms));
  health_check_timers_[cluster_name] = std::move(timer);
}
*/

/*
void ReverseConnectionIOHandle::performHealthCheck(const std::string& cluster_name) {
  ENVOY_LOG(trace, "Performing health check for cluster: {}", cluster_name);

  // Check connections per host for more granular health monitoring
  {
    absl::MutexLock lock(&host_connections_mutex_);
    
    uint32_t total_active_connections = 0;
    uint32_t total_required_connections = 0;
    std::vector<std::string> unhealthy_hosts;
    
    for (auto& [host_address, host_info] : host_to_conn_info_map_) {
      if (host_info.cluster_name != cluster_name) {
        continue;
      }
      
      // Instead of checking actual connections, check wrapper count
      // Active connections are those with wrappers still in progress
      uint32_t host_active_connections = 0;
      for (const auto& [wrapper, mapped_host] : conn_wrapper_to_host_map_) {
        if (mapped_host == host_address) {
          host_active_connections++;
        }
      }
      
      total_active_connections += host_active_connections;
      total_required_connections += host_info.target_connection_count;
      
      if (host_active_connections < host_info.target_connection_count) {
        unhealthy_hosts.push_back(host_address);
        ENVOY_LOG(debug, "Host {} has {}/{} healthy connections", 
                  host_address, host_active_connections, host_info.target_connection_count);
      }
    }
    
    // Update health check status
    bool health_check_passed = unhealthy_hosts.empty();
    
    {
      absl::MutexLock metadata_lock(&metadata_mutex_);
      auto& metadata = connection_metadata_[cluster_name];
      metadata.health_check_passed = health_check_passed;
    }
    
    if (!health_check_passed) {
      ENVOY_LOG(warn, "Health check failed for cluster: {} - {}/{} connections active, {} unhealthy hosts",
                cluster_name, total_active_connections, total_required_connections, unhealthy_hosts.size());
      
      // updateConnectionMetrics(cluster_name, ReverseConnectionState::HealthCheckFailed);
      
      // Trigger targeted reconnection only for unhealthy hosts
      ENVOY_LOG(info, "Health check failure detected - re-initiating connections for cluster: {}",
                cluster_name);
      initiateReverseTcpConnections();
    } else {
      ENVOY_LOG(trace, "Health check passed for cluster: {} - all {} connections healthy",
                cluster_name, total_active_connections);
    }
  }
}
*/

bool ReverseConnectionIOHandle::shouldAttemptConnection(const std::string& cluster_name) {
  if (!config_.enable_circuit_breaker) {
    return true;
  }

  absl::MutexLock lock(&metadata_mutex_);
  const auto& metadata = connection_metadata_[cluster_name];

  // Simple circuit breaker: if we've failed too many times recently, don't attempt.
  auto now = std::chrono::steady_clock::now();
  auto time_since_last_attempt =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - metadata.last_attempt).count();

  // If we just attempted recently and failed, wait before trying again.
  if (metadata.state == ReverseConnectionState::Failed && time_since_last_attempt < 5000) {
    ENVOY_LOG(debug, "Circuit breaker: too soon since last failed attempt for cluster: {}",
              cluster_name);
    return false;
  }

  return true;
}

void ReverseConnectionIOHandle::createTriggerPipe() {
  ENVOY_LOG(debug, "Creating trigger pipe for single-byte mechanism");

  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    ENVOY_LOG(error, "Failed to create trigger pipe: {}", strerror(errno));
    trigger_pipe_read_fd_ = -1;
    trigger_pipe_write_fd_ = -1;
    return;
  }

  trigger_pipe_read_fd_ = pipe_fds[0];
  trigger_pipe_write_fd_ = pipe_fds[1];

  // Make both ends non-blocking.
  int flags = fcntl(trigger_pipe_write_fd_, F_GETFL, 0);
  if (flags != -1) {
    fcntl(trigger_pipe_write_fd_, F_SETFL, flags | O_NONBLOCK);
  }

  flags = fcntl(trigger_pipe_read_fd_, F_GETFL, 0);
  if (flags != -1) {
    fcntl(trigger_pipe_read_fd_, F_SETFL, flags | O_NONBLOCK);
  }

  ENVOY_LOG(debug, "Created trigger pipe: read_fd={}, write_fd={}", trigger_pipe_read_fd_,
            trigger_pipe_write_fd_);
}

/*
void ReverseConnectionIOHandle::updateConnectionMetrics(const std::string& cluster_name,
                                                        ReverseConnectionState new_state) {
  if (!config_.enable_metrics) {
    return;
  }

  absl::MutexLock lock(&metadata_mutex_);
  updateConnectionMetricsUnsafe(cluster_name, new_state);
}

void ReverseConnectionIOHandle::updateConnectionMetricsUnsafe(const std::string& cluster_name,
                                                              ReverseConnectionState new_state) {
  // This method assumes metadata_mutex_ is already held.
  auto& metadata = connection_metadata_[cluster_name];

  auto now = std::chrono::steady_clock::now();

  // Update state and timestamp.
  ReverseConnectionState old_state = metadata.state;
  metadata.state = new_state;
  metadata.last_attempt = now;

  if (new_state == ReverseConnectionState::Connected) {
    metadata.last_connected = now;
    metadata.connection_count++;
  }

  ENVOY_LOG(trace, "Updated metrics for cluster: {} - state: {} -> {}", cluster_name,
            static_cast<int>(old_state), static_cast<int>(new_state));
}
*/

void ReverseConnectionIOHandle::onConnectionDone(const std::string& error, 
                                                       RCConnectionWrapper* wrapper, 
                                                       bool closed) {
  ENVOY_LOG(debug, "Connection wrapper done - error: '{}', closed: {}", error, closed);
  
  // Find the host and cluster for this wrapper
  std::string host_address;
  std::string cluster_name;
  
  {
    absl::MutexLock lock(&host_connections_mutex_);
    auto wrapper_it = conn_wrapper_to_host_map_.find(wrapper);
    if (wrapper_it == conn_wrapper_to_host_map_.end()) {
      ENVOY_LOG(error, "Internal error: wrapper not found in conn_wrapper_to_host_map_");
      return;
    }
    host_address = wrapper_it->second;
    
    // Get cluster name from host info
    auto host_it = host_to_conn_info_map_.find(host_address);
    if (host_it != host_to_conn_info_map_.end()) {
      cluster_name = host_it->second.cluster_name;
    }
  }
  
  if (cluster_name.empty()) {
    ENVOY_LOG(error, "Reverse connection failed: Internal Error: host -> cluster mapping "
                     "not present. Ignoring message");
    absl::MutexLock lock(&host_connections_mutex_);
    conn_wrapper_to_host_map_.erase(wrapper);
    return;
  }
  
  ENVOY_LOG(debug, "Got response from initiated reverse connection for host '{}', "
            "cluster '{}', error '{}'", host_address, cluster_name, error);
  
  if (closed || !error.empty()) {
    // Connection failed
    if (!error.empty()) {
      ENVOY_LOG(error, "Reverse connection failed: Received error '{}' from remote envoy for host {}",
                error, host_address);
      wrapper->onFailure();
    }
    
    ENVOY_LOG(error, "Reverse connection failed: Removing connection to host {}", host_address);
    
    // Remove the wrapper and clean up connection key
    {
      absl::MutexLock lock(&host_connections_mutex_);
      
      // Clean up the connection key for failed connection
      if (wrapper->getConnection()) {
        const std::string connection_key = wrapper->getConnection()->connectionInfoProvider().localAddress()->asString();
        ENVOY_LOG(debug, "Cleaning up connection key {} for host {} after connection failure",
                  connection_key, host_address);
        auto host_it = host_to_conn_info_map_.find(host_address);
        if (host_it != host_to_conn_info_map_.end()) {
          ENVOY_LOG(debug, "Found host info for host {} in host_to_conn_info_map_", host_address);
          if (host_it->second.connection_keys.erase(connection_key) > 0) {
            ENVOY_LOG(debug, "Cleaned up connection key {} for host {} after connection failure",
                      connection_key, host_address);
          }
        }
      }
      // Remove the wrapper from the map.
      conn_wrapper_to_host_map_.erase(wrapper);
    }
    
    // Update failure metrics
    // updateConnectionMetrics(cluster_name, ReverseConnectionState::Failed);
  } else {
    // Connection succeeded
    ENVOY_LOG(debug, "Reverse connection handshake succeeded for host {}", host_address);
    
    // Get the socket from wrapper's connection
    auto* connection = wrapper->getConnection();
    if (!connection) {
      ENVOY_LOG(error, "Connection is null after successful handshake");
      return;
    }
    
    // Get connection key before releasing the connection
    const std::string connection_key = connection->connectionInfoProvider().localAddress()->asString();
    
    // Reset file events.
    connection->getSocket()->ioHandle().resetFileEvents();
    
    // Update success metrics
    // updateConnectionMetrics(cluster_name, ReverseConnectionState::Connected);
    
    // Update host connection tracking with connection key
    {
      absl::MutexLock lock(&host_connections_mutex_);
      auto host_it = host_to_conn_info_map_.find(host_address);
      if (host_it != host_to_conn_info_map_.end()) {
        // Track the connection key for stats
        host_it->second.connection_keys.insert(connection_key);
        ENVOY_LOG(debug, "Added connection key {} for host {} of cluster {}", 
                  connection_key, host_address, cluster_name);
      }
    }
    
    // we release the connection and trigger accept()
    Network::ClientConnectionPtr released_conn = wrapper->releaseConnection();
    
    if (released_conn) {
      // Move connection to established queue
      {
        absl::MutexLock lock(&connection_mutex_);
        established_connections_.push(std::move(released_conn));
      }
      
      // Trigger the accept mechanism
      if (trigger_pipe_write_fd_ != -1) {
        char trigger_byte = 1;
        ssize_t bytes_written = ::write(trigger_pipe_write_fd_, &trigger_byte, 1);
        if (bytes_written == 1) {
          ENVOY_LOG(debug, "Successfully triggered accept() for reverse connection from host {} "
                    "of cluster {}", host_address, cluster_name);
        } else {
          ENVOY_LOG(error, "Failed to write trigger byte: {}", strerror(errno));
        }
      }
    }
  }
  
  // Remove the wrapper from connection_wrappers_ vector.
  connection_wrappers_.erase(
      std::remove_if(connection_wrappers_.begin(), connection_wrappers_.end(),
                     [wrapper](const std::unique_ptr<RCConnectionWrapper>& w) {
                       return w.get() == wrapper;
                     }),
      connection_wrappers_.end());
}

void ReverseConnectionIOHandle::onConnectionWrapperClosed(RCConnectionWrapper* wrapper, 
                                                         bool remote_close) {
  ENVOY_LOG(debug, "Connection wrapper closed - remote_close: {}", remote_close);
  
  // Handle connection closure
  onConnectionDone("Connection closed", wrapper, true);
}

// DownstreamReverseSocketInterface implementation
DownstreamReverseSocketInterface::DownstreamReverseSocketInterface(
    Server::Configuration::ServerFactoryContext& context)
    : extension_(nullptr), context_(&context) {

  ENVOY_LOG(debug, "Created DownstreamReverseSocketInterface");
}

DownstreamSocketThreadLocal* DownstreamReverseSocketInterface::getLocalRegistry() const {
  if (extension_) {
    return extension_->getLocalRegistry();
  }
  return nullptr;
}

// DownstreamReverseSocketInterfaceExtension implementation
void DownstreamReverseSocketInterfaceExtension::onServerInitialized() {
  ENVOY_LOG(debug, "DownstreamReverseSocketInterfaceExtension::onServerInitialized - creating thread local slot");
  
  // Set the extension reference in the socket interface
  if (socket_interface_) {
    socket_interface_->extension_ = this;
  }
  
  // Create thread local slot to store dispatcher for each worker thread
  tls_slot_ = ThreadLocal::TypedSlot<DownstreamSocketThreadLocal>::makeUnique(
      context_.threadLocal());
  
  // Set up the thread local dispatcher for each worker thread
  tls_slot_->set([](Event::Dispatcher& dispatcher) {
    return std::make_shared<DownstreamSocketThreadLocal>(dispatcher);
  });
}

DownstreamSocketThreadLocal* DownstreamReverseSocketInterfaceExtension::getLocalRegistry() const {
  ENVOY_LOG(debug, "DownstreamReverseSocketInterfaceExtension::getLocalRegistry()");
  if (!tls_slot_) {
    ENVOY_LOG(debug, "DownstreamReverseSocketInterfaceExtension::getLocalRegistry() - no thread local slot");
    return nullptr;
  }
  
  if (auto opt = tls_slot_->get(); opt.has_value()) {
    return &opt.value().get();
  }
  
  return nullptr;
}

Envoy::Network::IoHandlePtr DownstreamReverseSocketInterface::socket(
    Envoy::Network::Socket::Type socket_type, Envoy::Network::Address::Type addr_type,
    Envoy::Network::Address::IpVersion version, bool socket_v6only,
    const Envoy::Network::SocketCreationOptions& options) const {
  (void)socket_v6only; // Mark unused
  (void)options;       // Mark unused

  ENVOY_LOG(debug, "DownstreamReverseSocketInterface::socket() - type={}, addr_type={}",
            static_cast<int>(socket_type), static_cast<int>(addr_type));

  // For stream sockets on IP addresses, create our reverse connection IOHandle.
  if (socket_type == Envoy::Network::Socket::Type::Stream &&
      addr_type == Envoy::Network::Address::Type::Ip) {

    // Create socket file descriptor using system calls.
    int domain = (version == Envoy::Network::Address::IpVersion::v4) ? AF_INET : AF_INET6;
    int sock_fd = ::socket(domain, SOCK_STREAM, 0);

    if (sock_fd == -1) {
      ENVOY_LOG(error, "Failed to create socket: {}", strerror(errno));
      return nullptr;
    }

    if (!temp_rc_config_) {
      ENVOY_LOG(error, "No reverse connection configuration available");
      ::close(sock_fd);
      return nullptr;
    }
    ENVOY_LOG(debug, "Created socket fd={}, wrapping with ReverseConnectionIOHandle", sock_fd);
    // Use the temporary config and then clear it
    auto config = std::move(*temp_rc_config_);
    temp_rc_config_.reset();
    // Create ReverseConnectionIOHandle with cluster manager from context
    return std::make_unique<ReverseConnectionIOHandle>(sock_fd, config, context_->clusterManager(),
                                                        *this);
  }

  // For all other socket types, we create a default socket handle.
  // We can't call SocketInterfaceImpl directly since we don't inherit from it
  // So we'll create a basic IoSocketHandleImpl for now.
  int domain;
  if (addr_type == Envoy::Network::Address::Type::Ip) {
    domain = (version == Envoy::Network::Address::IpVersion::v4) ? AF_INET : AF_INET6;
  } else {
    // For pipe addresses.
    domain = AF_UNIX;
  }

  int sock_type = (socket_type == Envoy::Network::Socket::Type::Stream) ? SOCK_STREAM : SOCK_DGRAM;
  int sock_fd = ::socket(domain, sock_type, 0);

  if (sock_fd == -1) {
    ENVOY_LOG(error, "Failed to create fallback socket: {}", strerror(errno));
    return nullptr;
  }

  return std::make_unique<Envoy::Network::IoSocketHandleImpl>(sock_fd);
}

Envoy::Network::IoHandlePtr DownstreamReverseSocketInterface::socket(
    Envoy::Network::Socket::Type socket_type,
    const Envoy::Network::Address::InstanceConstSharedPtr addr,
    const Envoy::Network::SocketCreationOptions& options) const {
  
  // Extract reverse connection configuration from address
  const auto* reverse_addr = dynamic_cast<const ReverseConnectionAddress*>(addr.get());
  if (reverse_addr) {
    // Get the reverse connection config from the address
    ENVOY_LOG(debug, "DownstreamReverseSocketInterface::socket() - reverse_addr: {}", reverse_addr->asString());
    const auto& config = reverse_addr->reverseConnectionConfig();
    
    // Convert ReverseConnectionAddress::ReverseConnectionConfig to ReverseConnectionSocketConfig
    ReverseConnectionSocketConfig socket_config;
    socket_config.src_node_id = config.src_node_id;
    socket_config.src_cluster_id = config.src_cluster_id;
    socket_config.src_tenant_id = config.src_tenant_id;
    
    // Add the remote cluster configuration
    RemoteClusterConnectionConfig cluster_config(config.remote_cluster, config.connection_count);
    socket_config.remote_clusters.push_back(cluster_config);
    
    // HACK: Store the reverse connection socket config temporarility for socket() to consume
    // TODO(Basu): Find a cleaner way to do this.
    temp_rc_config_ = std::make_unique<ReverseConnectionSocketConfig>(std::move(socket_config));
  }

  // Delegate to the other socket() method
  return socket(socket_type, addr->type(),
                addr->ip() ? addr->ip()->version() : Envoy::Network::Address::IpVersion::v4, false,
                options);
}

bool DownstreamReverseSocketInterface::ipFamilySupported(int domain) {
  // Support standard IP families.
  return domain == AF_INET || domain == AF_INET6;
}

Server::BootstrapExtensionPtr DownstreamReverseSocketInterface::createBootstrapExtension(
    const Protobuf::Message& config, Server::Configuration::ServerFactoryContext& context) {
  ENVOY_LOG(debug, "DownstreamReverseSocketInterface::createBootstrapExtension()");
  // Cast the config to the proper type
  const auto& message = MessageUtil::downcastAndValidate<
      const envoy::extensions::bootstrap::reverse_connection_socket_interface::v3alpha::DownstreamReverseConnectionSocketInterface&>(
      config, context.messageValidationVisitor());

  // Set the context for this socket interface instance
  context_ = &context;

  // Return a SocketInterfaceExtension that wraps this socket interface
  // The onServerInitialized() will be called automatically by the BootstrapExtension lifecycle
  return std::make_unique<DownstreamReverseSocketInterfaceExtension>(*this, context, message);
}

ProtobufTypes::MessagePtr DownstreamReverseSocketInterface::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::bootstrap::reverse_connection_socket_interface::v3alpha::DownstreamReverseConnectionSocketInterface>();
}

REGISTER_FACTORY(DownstreamReverseSocketInterface,
                 Server::Configuration::BootstrapExtensionFactory);

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy



 