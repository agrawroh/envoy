#include "source/extensions/transport_sockets/ktls/config.h"

#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.h"
#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"
#include "source/extensions/transport_sockets/common/passthrough.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

// Note: We use the DownstreamKtlsTransportSocketFactory defined in ktls_transport_socket.h

// Helper functions to create the inner TLS transport socket factory
// We don't need the createInnerFactory helper functions since we'll implement the logic directly
// in the factory methods

ProtobufTypes::MessagePtr KtlsTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> 
KtlsClientTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& outer_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
          message, context.messageValidationVisitor());
          
  // Find inner transport socket factory by name
  auto& inner_config_factory = Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::UpstreamTransportSocketConfigFactory>(outer_config.tls_socket_config().name());
      
  // Create a ProtobufTypes::MessagePtr from the typed_config
  ProtobufTypes::MessagePtr inner_factory_config = Config::Utility::translateAnyToFactoryConfig(
      outer_config.tls_socket_config().typed_config(), context.messageValidationVisitor(), inner_config_factory);
      
  // Create the inner transport socket factory
  auto inner_factory_or = inner_config_factory.createTransportSocketFactory(*inner_factory_config, context);
  if (!inner_factory_or.ok()) {
    return inner_factory_or.status();
  }

  return std::make_unique<KtlsTransportSocketFactory>(
      std::move(inner_factory_or).value(),
      outer_config.enable_tx_zerocopy(),
      outer_config.enable_rx_no_pad());
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr> 
KtlsServerTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {
  const auto& outer_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
          message, context.messageValidationVisitor());

  // Find inner transport socket factory by name
  auto& inner_config_factory = Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::DownstreamTransportSocketConfigFactory>(outer_config.tls_socket_config().name());
      
  // Create a ProtobufTypes::MessagePtr from the typed_config
  ProtobufTypes::MessagePtr inner_factory_config = Config::Utility::translateAnyToFactoryConfig(
      outer_config.tls_socket_config().typed_config(), context.messageValidationVisitor(), inner_config_factory);

  // Create the inner transport socket factory with server names for SNI
  auto inner_factory_or = inner_config_factory.createTransportSocketFactory(
      *inner_factory_config, context, server_names);
  if (!inner_factory_or.ok()) {
    return inner_factory_or.status();
  }

  return std::make_unique<DownstreamKtlsTransportSocketFactory>(
      std::move(inner_factory_or).value(),
      outer_config.enable_tx_zerocopy(),
      outer_config.enable_rx_no_pad());
}

REGISTER_FACTORY(KtlsClientTransportSocketConfigFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);
REGISTER_FACTORY(KtlsServerTransportSocketConfigFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 