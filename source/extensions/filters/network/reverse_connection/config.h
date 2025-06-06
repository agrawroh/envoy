#pragma once

#include "envoy/extensions/filters/network/reverse_connection/v3/reverse_connection.pb.h"
#include "envoy/extensions/filters/network/reverse_connection/v3/reverse_connection.pb.validate.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnection {

/**
 * Config registration for the reverse connection filter. @see NamedNetworkFilterConfigFactory.
 */
class ReverseConnectionConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::reverse_connection::v3::ReverseConnection>,
      public Logger::Loggable<Logger::Id::config> {
public:
  ReverseConnectionConfigFactory()
      : FactoryBase("envoy.filters.network.reverse_connection", true) {}

private:
  Envoy::Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::reverse_connection::v3::ReverseConnection&
          proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace ReverseConnection
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
