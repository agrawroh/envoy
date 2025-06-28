#pragma once

#include <unistd.h>

#include <atomic>
#include <cstdint>

#include "envoy/event/timer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/server/bootstrap_extension_config.h"
#include "envoy/thread_local/thread_local.h"
#include "source/common/common/random_generator.h"

#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_interface.h"

#include "contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha/upstream_reverse_connection_socket_interface.pb.h"
#include "contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha/upstream_reverse_connection_socket_interface.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// Forward declarations
class UpstreamReverseSocketInterface;
class UpstreamReverseSocketInterfaceExtension;
class UpstreamSocketManager;

/**
 * All UpstreamSocketManager stats. @see stats_macros.h
 * This encompasses the stats for all accepted reverse connections by the responder envoy.
 */
#define ALL_USM_STATS(GAUGE)                                                                 \
  GAUGE(reverse_conn_cx_idle, NeverImport)                                                   \
  GAUGE(reverse_conn_cx_used, NeverImport)                                                   \
  GAUGE(reverse_conn_cx_total, NeverImport)

/**
 * Struct definition for all UpstreamSocketManager stats. @see stats_macros.h
 */
struct USMStats {
  ALL_USM_STATS(GENERATE_GAUGE_STRUCT)
};

using USMStatsPtr = std::unique_ptr<USMStats>;

/**
 * Custom IoHandle for upstream reverse connections that manages cached reverse TCP connections.
 */
class UpstreamReverseConnectionIOHandle : public Network::IoSocketHandleImpl {
public:
  UpstreamReverseConnectionIOHandle(os_fd_t fd, const std::string& cluster_name);

  ~UpstreamReverseConnectionIOHandle() override;

  // Network::IoHandle overrides
  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr address) override;
  Api::IoCallUint64Result close() override;

  // Add a socket to the used connections map
  void addUsedSocket(int fd, Network::ConnectionSocketPtr socket);

private:
  std::string cluster_name_;
  // Map from file descriptor to socket object to prevent sockets from going out of scope
  std::unordered_map<int, Network::ConnectionSocketPtr> used_reverse_connections_;
  mutable absl::Mutex used_sockets_mutex_;
};

/**
 * Thread local storage for UpstreamReverseSocketInterface.
 * Stores the thread-local dispatcher and socket manager for each worker thread.
 */
class UpstreamSocketThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  UpstreamSocketThreadLocal(Event::Dispatcher& dispatcher, Stats::Scope& scope) 
      : dispatcher_(dispatcher), socket_manager_(std::make_unique<UpstreamSocketManager>(dispatcher, scope)) {
      }
  
  Event::Dispatcher& dispatcher() { return dispatcher_; }
  UpstreamSocketManager* socketManager() { return socket_manager_.get(); }

private:
  Event::Dispatcher& dispatcher_;
  std::unique_ptr<UpstreamSocketManager> socket_manager_;
};

/**
 * Socket interface that creates upstream reverse connection sockets.
 */
class UpstreamReverseSocketInterface
    : public Envoy::Network::SocketInterfaceBase,
      public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  UpstreamReverseSocketInterface(Server::Configuration::ServerFactoryContext& context);
  
  // Default constructor for registry
  UpstreamReverseSocketInterface() : extension_(nullptr), context_(nullptr) {}

  // SocketInterface
  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type, Envoy::Network::Address::Type addr_type,
         Envoy::Network::Address::IpVersion version, bool socket_v6only,
         const Envoy::Network::SocketCreationOptions& options) const override;

  Envoy::Network::IoHandlePtr
  socket(Envoy::Network::Socket::Type socket_type,
         const Envoy::Network::Address::InstanceConstSharedPtr addr,
         const Envoy::Network::SocketCreationOptions& options) const override;

  bool ipFamilySupported(int domain) override;

  // Get thread local registry for the current thread
  UpstreamSocketThreadLocal* getLocalRegistry() const;

  // BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override {
    return "envoy.bootstrap.reverse_connection.upstream_reverse_connection_socket_interface";
  }

  UpstreamReverseSocketInterfaceExtension* extension_{nullptr};

private:
  Server::Configuration::ServerFactoryContext* context_;
};

/**
 * Socket interface extension for upstream reverse connections.
 */
class UpstreamReverseSocketInterfaceExtension : public Envoy::Network::SocketInterfaceExtension,
                                                public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  UpstreamReverseSocketInterfaceExtension(Envoy::Network::SocketInterface& sock_interface,
                                         Server::Configuration::ServerFactoryContext& context,
                                         const envoy::extensions::bootstrap::reverse_connection_socket_interface::v3alpha::UpstreamReverseConnectionSocketInterface& config)
      : Envoy::Network::SocketInterfaceExtension(sock_interface), context_(context),
        socket_interface_(static_cast<UpstreamReverseSocketInterface*>(&sock_interface)) {
          ENVOY_LOG(debug, "UpstreamReverseSocketInterfaceExtension: creating upstream reverse connection socket interface with stat_prefix: {}", stat_prefix_);
          stat_prefix_ = PROTOBUF_GET_STRING_OR_DEFAULT(config, stat_prefix, "upstream_reverse_connection");
        }

  // Server::BootstrapExtension (inherited from SocketInterfaceExtension)
  void onServerInitialized() override;
  void onWorkerThreadInitialized() override {}

  // Get thread local registry for the current thread
  UpstreamSocketThreadLocal* getLocalRegistry() const;

  // Get the stat prefix for stats/monitoring
  const std::string& statPrefix() const { return stat_prefix_; }

private:
  Server::Configuration::ServerFactoryContext& context_;
  std::unique_ptr<ThreadLocal::TypedSlot<UpstreamSocketThreadLocal>> tls_slot_;
  UpstreamReverseSocketInterface* socket_interface_;
  std::string stat_prefix_;
};

/**
 * Thread-local socket manager for upstream reverse connections.
 * Manages cached reverse connection sockets per cluster.
 */
class UpstreamSocketManager : public ThreadLocal::ThreadLocalObject, 
                             public Logger::Loggable<Logger::Id::filter> {
public:
  UpstreamSocketManager(Event::Dispatcher& dispatcher, Stats::Scope& scope);

  // Add a socket for a specific node and cluster
  void addConnectionSocket(const std::string& node_id, const std::string& cluster_id,
                          Network::ConnectionSocketPtr socket,
                          std::chrono::milliseconds ping_interval, bool rebalanced);

  // Get a socket for a cluster ID (returns first available socket for that cluster)
  std::pair<Network::ConnectionSocketPtr, bool> getConnectionSocket(const std::string& key, bool mark_used);

  // Get number of sockets for a cluster
  size_t getNumberOfSocketsByCluster(const std::string& cluster_id);

  // Get number of sockets for a node
  size_t getNumberOfSocketsByNode(const std::string& node_id);

  // Get socket count map (cluster -> count)
  absl::flat_hash_map<std::string, size_t> getSocketCountMap();

  // Get connection stats (node -> count)
  absl::flat_hash_map<std::string, size_t> getConnectionStats();

  // Mark socket dead and remove from internal maps
  void markSocketDead(const int fd, const bool used);

  static const std::string ping_message;

private:
  void pingConnections();
  void pingConnections(const std::string& node_id);
  void tryEnablePingTimer(const std::chrono::seconds& ping_interval);
  void cleanStaleNodeEntry(const std::string& node_id);
  void onPingResponse(Network::IoHandle& io_handle);

  // Get or create a USMStats object for the given node
  USMStats* getStatsByNode(const std::string& node_id);
  // Get or create a USMStats object for the given cluster
  USMStats* getStatsByCluster(const std::string& cluster_id);
  // Delete the USMStats object for the given node
  bool deleteStatsByNode(const std::string& node_id);
  // Delete the USMStats object for the given cluster
  bool deleteStatsByCluster(const std::string& cluster_id);

  Event::Dispatcher& dispatcher_;
  Random::RandomGeneratorPtr random_generator_;
  
  // Map from node ID to list of available sockets
  std::unordered_map<std::string, std::list<Network::ConnectionSocketPtr>> accepted_reverse_connections_;
  
  // Map from file descriptor to node ID
  std::unordered_map<int, std::string> fd_to_node_map_;
  
  // Map from node ID to cluster ID
  std::unordered_map<std::string, std::string> node_to_cluster_map_;
  
  // Map from cluster ID to list of node IDs
  std::unordered_map<std::string, std::vector<std::string>> cluster_to_node_map_;
  
  // File events and timers for ping functionality
  absl::flat_hash_map<int, Event::FileEventPtr> fd_to_event_map_;
  absl::flat_hash_map<int, Event::TimerPtr> fd_to_timer_map_;

  // Stats management
  absl::flat_hash_map<std::string, USMStatsPtr> usm_node_stats_map_;
  absl::flat_hash_map<std::string, USMStatsPtr> usm_cluster_stats_map_;
  Stats::ScopeSharedPtr usm_scope_;

  // Ping timer and interval
  Event::TimerPtr ping_timer_;
  std::chrono::seconds ping_interval_{0};
};

DECLARE_FACTORY(UpstreamReverseSocketInterface);

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
