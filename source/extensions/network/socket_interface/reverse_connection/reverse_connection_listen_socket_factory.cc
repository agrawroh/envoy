#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_listen_socket_factory.h"

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/stats/stats.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

ReverseConnectionListenSocketFactory::ReverseConnectionListenSocketFactory(
    Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher)
    : cluster_manager_(cluster_manager), dispatcher_(dispatcher) {

  ENVOY_LOG(info, "Created ReverseConnectionListenSocketFactory");
}

Envoy::Network::SocketSharedPtr ReverseConnectionListenSocketFactory::createListenSocket(
    const envoy::config::listener::v3::Listener& listener_config,
    const Envoy::Network::Address::InstanceConstSharedPtr& address,
    const Envoy::Network::Socket::OptionsSharedPtr& options,
    const envoy::config::core::v3::BindConfig& bind_config) {

  ENVOY_LOG(debug, "Creating listen socket for listener: {}", listener_config.name());

  // Check if this listener has reverse connection configuration
  if (hasReverseConnectionConfig(listener_config)) {
    ENVOY_LOG(info, "Detected reverse connection configuration for listener: {}",
              listener_config.name());

    // Extract reverse connection configuration
    auto reverse_config = extractReverseConnectionConfig(listener_config);

    // Create custom socket interface
    auto reverse_socket_interface = createReverseSocketInterface(reverse_config);

    // Create and return custom listen socket
    return std::make_shared<ReverseConnectionListenSocket>(address, options, bind_config,
                                                           reverse_socket_interface);
  }

  // Not a reverse connection listener - return nullptr to indicate standard handling
  return nullptr;
}

bool ReverseConnectionListenSocketFactory::hasReverseConnectionConfig(
    const envoy::config::listener::v3::Listener& listener_config) {

  // Check if listener has reverse_connection_listener_config in metadata
  if (!listener_config.has_metadata()) {
    return false;
  }

  const auto& metadata = listener_config.metadata();
  if (metadata.filter_metadata().find("reverse_connection_listener_config") ==
      metadata.filter_metadata().end()) {
    return false;
  }

  return true;
}

ReverseConnectionSocketConfig ReverseConnectionListenSocketFactory::extractReverseConnectionConfig(
    const envoy::config::listener::v3::Listener& listener_config) {

  ReverseConnectionSocketConfig config;

  const auto& metadata = listener_config.metadata();
  const auto& filter_metadata = metadata.filter_metadata();

  auto it = filter_metadata.find("reverse_connection_listener_config");
  if (it != filter_metadata.end()) {
    const auto& config_struct = it->second;

    // Extract configuration from metadata fields
    const auto& fields = config_struct.fields();

    if (fields.find("src_cluster_id") != fields.end()) {
      config.src_cluster_id = fields.at("src_cluster_id").string_value();
    } else {
      config.src_cluster_id = "default_cluster";
    }

    if (fields.find("src_node_id") != fields.end()) {
      config.src_node_id = fields.at("src_node_id").string_value();
    } else {
      config.src_node_id = "default_node";
    }

    if (fields.find("src_tenant_id") != fields.end()) {
      config.src_tenant_id = fields.at("src_tenant_id").string_value();
    } else {
      config.src_tenant_id = "default_tenant";
    }

    // Extract remote clusters configuration
    if (fields.find("remote_clusters") != fields.end()) {
      const auto& clusters_list = fields.at("remote_clusters").list_value();
      for (const auto& cluster_value : clusters_list.values()) {
        if (cluster_value.has_struct_value()) {
          const auto& cluster_fields = cluster_value.struct_value().fields();

          std::string cluster_name = "upstream_cluster";
          uint32_t connection_count = 2;

          if (cluster_fields.find("cluster_name") != cluster_fields.end()) {
            cluster_name = cluster_fields.at("cluster_name").string_value();
          }

          if (cluster_fields.find("connection_count") != cluster_fields.end()) {
            connection_count =
                static_cast<uint32_t>(cluster_fields.at("connection_count").number_value());
          }

          config.remote_clusters.push_back(
              RemoteClusterConnectionConfig(cluster_name, connection_count));
        }
      }
    } else {
      // Default configuration if not specified
      config.remote_clusters.push_back(RemoteClusterConnectionConfig("upstream_cluster", 2));
    }

    ENVOY_LOG(
        debug,
        "Extracted reverse connection config - src_cluster: {}, src_node: {}, {} remote clusters",
        config.src_cluster_id, config.src_node_id, config.remote_clusters.size());
  }

  return config;
}

std::shared_ptr<DownstreamReverseSocketInterface>
ReverseConnectionListenSocketFactory::createReverseSocketInterface(
    const ReverseConnectionSocketConfig& config) {

  ENVOY_LOG(debug, "Creating reverse socket interface for {} remote clusters",
            config.remote_clusters.size());

  return std::make_shared<DownstreamReverseSocketInterface>(config, cluster_manager_, dispatcher_);
}

// ReverseConnectionListenSocket implementation
ReverseConnectionListenSocket::ReverseConnectionListenSocket(
    const Envoy::Network::Address::InstanceConstSharedPtr& address,
    const Envoy::Network::Socket::OptionsSharedPtr& options,
    const envoy::config::core::v3::BindConfig& bind_config,
    std::shared_ptr<DownstreamReverseSocketInterface> socket_interface)
    : ListenSocketImpl(socket_interface->socket(Envoy::Network::Socket::Type::Stream,
                                                Envoy::Network::Address::Type::Ip,
                                                address->ip()->version(), false, {}),
                       address),
      reverse_socket_interface_(socket_interface) {

  // Mark unused parameters to prevent warnings
  (void)options;
  (void)bind_config;

  ENVOY_LOG(info, "Created ReverseConnectionListenSocket for address: {}", address->asString());
}

const Envoy::Network::SocketInterface* ReverseConnectionListenSocket::socketInterface() const {
  return reverse_socket_interface_.get();
}

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
