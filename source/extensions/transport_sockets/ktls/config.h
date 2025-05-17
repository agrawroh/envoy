#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Config registration for the kTLS transport socket factory for both client and server.
 * @see TransportSocketConfigFactory.
 */
class KtlsTransportSocketConfigFactory : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  ~KtlsTransportSocketConfigFactory() override = default;
  
  /**
   * @return ProtobufTypes::MessagePtr create empty config proto.
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  
  std::string name() const override { return "envoy.transport_sockets.ktls"; }
};

/**
 * Client kTLS transport socket implementation factory.
 */
class KtlsClientTransportSocketConfigFactory : public KtlsTransportSocketConfigFactory,
                                           public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& message,
      Server::Configuration::TransportSocketFactoryContext& context) override;
};

/**
 * Server kTLS transport socket implementation factory.
 */
class KtlsServerTransportSocketConfigFactory : public KtlsTransportSocketConfigFactory,
                                           public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& message,
      Server::Configuration::TransportSocketFactoryContext& context,
      const std::vector<std::string>& server_names) override;
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 