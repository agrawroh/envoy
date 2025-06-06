#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_terminal_filter_config.h"

#include "envoy/registry/registry.h"

#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_terminal_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

using TerminalFilterConfig = Envoy::Extensions::Network::SocketInterface::ReverseConnection::
    ReverseConnectionTerminalFilterConfig;
using TerminalFilter =
    Envoy::Extensions::Network::SocketInterface::ReverseConnection::ReverseConnectionTerminalFilter;

Envoy::Network::FilterFactoryCb
ReverseConnectionTerminalFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::reverse_connection::v3::ReverseConnectionConfig&
        proto_config,
    Server::Configuration::FactoryContext&) {

  ENVOY_LOG(info, "Creating ReverseConnectionTerminalFilter with cluster: {}",
            proto_config.cluster_name());

  auto filter_config = std::make_shared<TerminalFilterConfig>(
      proto_config.cluster_name(), proto_config.max_connections_per_cluster(),
      proto_config.connection_timeout_seconds(), proto_config.debug_logging());

  return [filter_config](Envoy::Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<TerminalFilter>(filter_config));
  };
}

/**
 * Static registration for the reverse connection terminal filter. @see RegisterFactory.
 */
REGISTER_FACTORY(ReverseConnectionTerminalFilterConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
