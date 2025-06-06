#pragma once

#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_config.pb.h"
#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_config.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

/**
 * Config registration for the reverse connection terminal filter.
 * @see NamedNetworkFilterConfigFactory.
 */
class ReverseConnectionTerminalFilterConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::reverse_connection::v3::ReverseConnectionConfig>,
      public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionTerminalFilterConfigFactory()
      : FactoryBase("reverse_connection.terminal", true) {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::reverse_connection::v3::ReverseConnectionConfig&
          proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
