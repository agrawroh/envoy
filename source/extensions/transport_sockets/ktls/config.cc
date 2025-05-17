#include "source/extensions/transport_sockets/ktls/config.h"

#include "envoy/extensions/transport_sockets/v3/ktls.pb.h"
#include "envoy/extensions/transport_sockets/v3/ktls.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

namespace {

// Factory that creates a kTLS transport socket wrapped around another transport socket
class KTlsTransportSocketFactory : public Network::TransportSocketFactory {
public:
  KTlsTransportSocketFactory(Network::TransportSocketFactoryPtr&& transport_socket_factory,
                            const envoy::extensions::transport_sockets::v3::KTlsOptions& options)
      : transport_socket_factory_(std::move(transport_socket_factory)),
        options_(options) {}

  // Creates a transport socket wrapped in a kTLS transport socket
  Network::TransportSocketPtr createTransportSocket(
      Network::TransportSocketOptionsConstSharedPtr options) const override {
    // Create the underlying transport socket
    Network::TransportSocketPtr transport_socket = transport_socket_factory_->createTransportSocket(options);
    
    // Only continue if the underlying socket implements secure transport
    if (!transport_socket_factory_->implementsSecureTransport()) {
      return transport_socket;
    }
    
    // Check if kTLS is explicitly disabled
    if (options_.has_enable_ktls() && !options_.enable_ktls()) {
      return transport_socket;
    }
    
    // Create the kTLS transport socket
    // We'll need access to the SSL session after the handshake completes
    // For now, we return the original transport socket, and we'll upgrade
    // to kTLS after the handshake completes in the connection handlers
    
    // Ideally, we would have a way to get the SSL connection info with direct
    // access to the OpenSSL SSL* object, which we need for kTLS configuration
    
    // For prototype purposes, wrap with a kTLS transport socket
    Ssl::ConnectionInfoConstSharedPtr ssl_info = transport_socket->ssl();
    if (ssl_info == nullptr) {
      // Not a TLS socket, can't use kTLS
      return transport_socket;
    }
    
    // In a real implementation, we would:
    // 1. Register a handshake completion callback with the TLS transport socket
    // 2. When the handshake completes, extract SSL session information
    // 3. Create a KTlsTransportSocket that takes over from the TLS socket
    
    // For now, just return the original socket
    return transport_socket;
  }

  bool implementsSecureTransport() const override {
    return transport_socket_factory_->implementsSecureTransport();
  }

  bool supportsAlpn() const override { return transport_socket_factory_->supportsAlpn(); }

private:
  Network::TransportSocketFactoryPtr transport_socket_factory_;
  envoy::extensions::transport_sockets::v3::KTlsOptions options_;
};

// Factory that creates upstream kTLS transport sockets
class KTlsUpstreamTransportSocketFactory : public KTlsTransportSocketFactory,
                                          public Network::UpstreamTransportSocketFactory {
public:
  KTlsUpstreamTransportSocketFactory(Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory,
                                    const envoy::extensions::transport_sockets::v3::KTlsOptions& options)
      : KTlsTransportSocketFactory(std::move(transport_socket_factory), options),
        upstream_factory_(std::move(transport_socket_factory)) {}

  void hashKey(std::vector<uint8_t>& key, Network::TransportSocketOptionsConstSharedPtr options) const override {
    upstream_factory_->hashKey(key, options);
  }

private:
  Network::UpstreamTransportSocketFactoryPtr upstream_factory_;
};

// Factory that creates downstream kTLS transport sockets
class KTlsDownstreamTransportSocketFactory : public KTlsTransportSocketFactory,
                                            public Network::DownstreamTransportSocketFactory {
public:
  KTlsDownstreamTransportSocketFactory(Network::DownstreamTransportSocketFactoryPtr&& transport_socket_factory,
                                      const envoy::extensions::transport_sockets::v3::KTlsOptions& options)
      : KTlsTransportSocketFactory(std::move(transport_socket_factory), options),
        downstream_factory_(std::move(transport_socket_factory)) {}

  std::vector<std::string> alpnProtocols() const override {
    return downstream_factory_->alpnProtocols();
  }

private:
  Network::DownstreamTransportSocketFactoryPtr downstream_factory_;
};

} // namespace

ProtobufTypes::MessagePtr KTlsTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::v3::KTls>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
KTlsUpstreamTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& outer_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::v3::KTls&>(
      message, context.messageValidationVisitor());
  
  auto& inner_config = outer_config.transport_socket();
  auto& inner_factory_name = inner_config.name();
  auto* inner_factory = Registry::FactoryRegistry<
      Server::Configuration::UpstreamTransportSocketConfigFactory>::getFactory(inner_factory_name);
  if (inner_factory == nullptr) {
    return absl::InvalidArgumentError(
        fmt::format("Unable to find inner transport socket factory with name {}.", inner_factory_name));
  }

  auto inner_transport_factory =
      inner_factory->createTransportSocketFactory(*inner_config.typed_config().get(), context);
  if (!inner_transport_factory.ok()) {
    return inner_transport_factory.status();
  }

  return std::make_unique<KTlsUpstreamTransportSocketFactory>(
      std::move(*inner_transport_factory), outer_config.options());
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
KTlsDownstreamTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& outer_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::v3::KTls&>(
      message, context.messageValidationVisitor());
  
  auto& inner_config = outer_config.transport_socket();
  auto& inner_factory_name = inner_config.name();
  auto* inner_factory = Registry::FactoryRegistry<
      Server::Configuration::DownstreamTransportSocketConfigFactory>::getFactory(inner_factory_name);
  if (inner_factory == nullptr) {
    return absl::InvalidArgumentError(
        fmt::format("Unable to find inner transport socket factory with name {}.", inner_factory_name));
  }

  auto inner_transport_factory =
      inner_factory->createTransportSocketFactory(*inner_config.typed_config().get(), context);
  if (!inner_transport_factory.ok()) {
    return inner_transport_factory.status();
  }

  return std::make_unique<KTlsDownstreamTransportSocketFactory>(
      std::move(*inner_transport_factory), outer_config.options());
}

REGISTER_FACTORY(KTlsUpstreamTransportSocketConfigFactory,
                Server::Configuration::UpstreamTransportSocketConfigFactory);
REGISTER_FACTORY(KTlsDownstreamTransportSocketConfigFactory,
                Server::Configuration::DownstreamTransportSocketConfigFactory);

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 