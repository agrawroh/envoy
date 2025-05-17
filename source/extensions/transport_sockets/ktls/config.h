#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Config registration for the kTLS transport socket factory.
 * @see TransportSocketConfigFactory.
 */
class KtlsSocketFactory : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.ktls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

/**
 * Config registration for the upstream kTLS transport socket factory.
 */
class UpstreamKtlsSocketFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory,
      public KtlsSocketFactory {
public:
  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
};

/**
 * Config registration for the downstream kTLS transport socket factory.
 */
class DownstreamKtlsSocketFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public KtlsSocketFactory {
public:
  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context,
      const std::vector<std::string>& server_names) override;
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 