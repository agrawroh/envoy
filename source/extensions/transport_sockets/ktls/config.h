#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

/**
 * Config registration for the kTLS transport socket factory.
 * This factory wraps an existing TLS transport socket and delegates to kTLS when appropriate.
 */
class KTlsTransportSocketConfigFactory : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.ktls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

class KTlsUpstreamTransportSocketConfigFactory
    : public KTlsTransportSocketConfigFactory,
      public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
  createTransportSocketFactory(const Protobuf::Message& config,
                              Server::Configuration::TransportSocketFactoryContext& context) override;
};

class KTlsDownstreamTransportSocketConfigFactory
    : public KTlsTransportSocketConfigFactory,
      public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
  createTransportSocketFactory(const Protobuf::Message& config,
                              Server::Configuration::TransportSocketFactoryContext& context) override;
};

DECLARE_FACTORY(KTlsUpstreamTransportSocketConfigFactory);
DECLARE_FACTORY(KTlsDownstreamTransportSocketConfigFactory);

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 