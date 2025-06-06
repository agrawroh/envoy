#include "source/extensions/filters/network/reverse_connection/config.h"

#include "envoy/extensions/filters/network/reverse_connection/v3/reverse_connection.pb.h"
#include "envoy/network/connection.h"
#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/network/reverse_connection/reverse_connection_filter.h"
#include "source/extensions/filters/network/reverse_connection/reverse_connection_socket_handoff_manager.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

Envoy::Network::FilterFactoryCb ReverseConnectionConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::reverse_connection::v3::ReverseConnection&
        proto_config,
    Server::Configuration::FactoryContext& context) {

  // Extract configuration values with proper defaults
  const std::string stat_prefix = proto_config.stat_prefix();
  const std::string cluster_name = proto_config.cluster_name();
  const std::chrono::milliseconds connection_timeout =
      proto_config.has_connection_timeout() ? std::chrono::milliseconds(PROTOBUF_GET_MS_OR_DEFAULT(
                                                  proto_config, connection_timeout, 30000))
                                            : std::chrono::milliseconds(30000);
  const bool debug_logging = proto_config.debug_logging();
  const bool enable_http_pooling = proto_config.enable_http_pooling();

  // Extract socket handoff configuration
  bool enable_socket_handoff = false;
  if (proto_config.has_socket_handoff_config()) {
    enable_socket_handoff = proto_config.socket_handoff_config().enable_socket_handoff();
  }

  // Create comprehensive configuration object
  ReverseConnectionConfig config(stat_prefix, cluster_name, connection_timeout, debug_logging,
                                 enable_http_pooling, enable_socket_handoff);

  // CRITICAL FIX: Get SocketHandoffManager singleton on main thread during configuration
  // This prevents the threading assertion that was causing the crash
  std::shared_ptr<SocketHandoffManager> socket_handoff_manager = nullptr;
  if (enable_socket_handoff) {
    socket_handoff_manager =
        SocketHandoffManager::singleton(context.serverFactoryContext().singletonManager());
    ENVOY_LOG(info,
              "✅ Created SocketHandoffManager singleton during configuration for cluster: {}",
              cluster_name);
  }

  return [&context, config,
          socket_handoff_manager](Envoy::Network::FilterManager& filter_manager) -> void {
    auto filter = std::make_shared<ReverseConnectionNetworkFilter>(
        config, context.serverFactoryContext().clusterManager(), socket_handoff_manager);

    // Add as both read and write filter to make it terminal
    filter_manager.addReadFilter(filter);
    filter_manager.addWriteFilter(filter);
  };
}

/**
 * Static registration for the reverse connection filter. @see RegisterFactory.
 */
REGISTER_FACTORY(ReverseConnectionConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
