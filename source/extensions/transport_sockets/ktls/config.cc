#include "source/extensions/transport_sockets/ktls/config.h"

#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.h"
#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

// Downstream kTLS transport socket factory implementation
class KtlsDownstreamTransportSocketFactory : public TransportSockets::DownstreamPassthroughFactory {
public:
  KtlsDownstreamTransportSocketFactory(Network::DownstreamTransportSocketFactoryPtr&& transport_socket_factory,
                                     bool enable_tx_zerocopy,
                                     bool enable_rx_no_pad)
      : DownstreamPassthroughFactory(std::move(transport_socket_factory)),
        enable_tx_zerocopy_(enable_tx_zerocopy),
        enable_rx_no_pad_(enable_rx_no_pad) {}

  Network::TransportSocketPtr createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                                                   const Network::Address::InstanceConstSharedPtr& local_address,
                                                   const Network::Address::InstanceConstSharedPtr& remote_address) const override {
    auto inner_socket = transport_socket_factory_->createTransportSocket(options, local_address, remote_address);
    if (inner_socket == nullptr) {
      return nullptr;
    }
    return std::make_unique<KtlsTransportSocket>(std::move(inner_socket), 
                                               enable_tx_zerocopy_, enable_rx_no_pad_);
  }

private:
  bool enable_tx_zerocopy_;
  bool enable_rx_no_pad_;
};

// Helper functions to create the inner TLS transport socket factory
Network::TransportSocketFactoryPtr createInnerFactory(
    const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket& config,
    Server::Configuration::TransportSocketFactoryContext& context) {
  auto& inner_config = config.tls_socket_config();

  // Find inner transport socket factory, which should be TLS
  auto& config_factory = Config::Utility::getAndCheckFactory<
      Server::Configuration::UpstreamTransportSocketConfigFactory>(inner_config.name());

  // For client sockets, no server_names are passed
  return config_factory.createTransportSocketFactory(inner_config.typed_config(), context);
}

Network::TransportSocketFactoryPtr createInnerFactory(
    const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket& config,
    Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {
  auto& inner_config = config.tls_socket_config();

  // Find inner transport socket factory, which should be TLS
  auto& config_factory = Config::Utility::getAndCheckFactory<
      Server::Configuration::DownstreamTransportSocketConfigFactory>(inner_config.name());

  // For server sockets, pass SNI server_names
  return config_factory.createTransportSocketFactory(inner_config.typed_config(), context, server_names);
}

ProtobufTypes::MessagePtr KtlsTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket>();
}

Network::TransportSocketFactoryPtr KtlsClientTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& outer_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
          message, context.messageValidationVisitor());

  auto inner_factory = createInnerFactory(outer_config, context);
  if (!inner_factory) {
    return nullptr;
  }

  return std::make_unique<KtlsTransportSocketFactory>(
      std::move(Network::UpstreamTransportSocketFactoryPtr(
          dynamic_cast<Network::UpstreamTransportSocketFactory*>(inner_factory.release()))),
      outer_config.enable_tx_zerocopy(),
      outer_config.enable_rx_no_pad());
}

Network::TransportSocketFactoryPtr KtlsServerTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {
  const auto& outer_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
          message, context.messageValidationVisitor());

  auto inner_factory = createInnerFactory(outer_config, context, server_names);
  if (!inner_factory) {
    return nullptr;
  }

  return std::make_unique<KtlsDownstreamTransportSocketFactory>(
      std::move(Network::DownstreamTransportSocketFactoryPtr(
          dynamic_cast<Network::DownstreamTransportSocketFactory*>(inner_factory.release()))),
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