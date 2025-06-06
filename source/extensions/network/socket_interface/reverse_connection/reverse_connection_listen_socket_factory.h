#pragma once

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/listener/v3/listener.pb.h"
#include "envoy/network/listen_socket.h"
#include "envoy/server/listener_manager.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/network/listen_socket_impl.h"
#include "source/extensions/network/socket_interface/reverse_connection/downstream_reverse_socket_interface.h"

// #include
// "source/extensions/reverse_connection/reverse_connection_listener_config/v3alpha/reverse_connection_listener_config.pb.h"
// // Temporarily removed

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Factory for creating reverse connection listen sockets.
 * This factory detects when a listener has reverse_connection_listener_config
 * and creates appropriate custom socket interfaces.
 */
class ReverseConnectionListenSocketFactory
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionListenSocketFactory(Upstream::ClusterManager& cluster_manager,
                                       Event::Dispatcher& dispatcher);

  /**
   * Create listen socket for the given listener configuration.
   * If the listener has reverse_connection_listener_config, creates custom socket.
   * Otherwise, creates standard listen socket.
   */
  Envoy::Network::SocketSharedPtr
  createListenSocket(const envoy::config::listener::v3::Listener& listener_config,
                     const Envoy::Network::Address::InstanceConstSharedPtr& address,
                     const Envoy::Network::Socket::OptionsSharedPtr& options,
                     const envoy::config::core::v3::BindConfig& bind_config);

  /**
   * Check if listener has reverse connection configuration.
   */
  static bool
  hasReverseConnectionConfig(const envoy::config::listener::v3::Listener& listener_config);

  /**
   * Extract reverse connection configuration from listener metadata.
   */
  static ReverseConnectionSocketConfig
  extractReverseConnectionConfig(const envoy::config::listener::v3::Listener& listener_config);

private:
  /**
   * Create custom socket interface for reverse connections.
   */
  std::shared_ptr<DownstreamReverseSocketInterface>
  createReverseSocketInterface(const ReverseConnectionSocketConfig& config);

  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;
};

/**
 * Custom listen socket that uses reverse connection socket interface.
 */
class ReverseConnectionListenSocket : public Envoy::Network::ListenSocketImpl,
                                      public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionListenSocket(const Envoy::Network::Address::InstanceConstSharedPtr& address,
                                const Envoy::Network::Socket::OptionsSharedPtr& options,
                                const envoy::config::core::v3::BindConfig& bind_config,
                                std::shared_ptr<DownstreamReverseSocketInterface> socket_interface);

  // Override socket interface
  const Envoy::Network::SocketInterface* socketInterface() const;

private:
  std::shared_ptr<DownstreamReverseSocketInterface> reverse_socket_interface_;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
