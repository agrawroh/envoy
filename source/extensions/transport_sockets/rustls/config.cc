#include "source/extensions/transport_sockets/rustls/config.h"

#include "envoy/registry/registry.h"

#include "source/common/config/datasource.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/extensions/transport_sockets/rustls/rustls_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

// UpstreamRustlsSocketFactory implementation.

UpstreamRustlsSocketFactory::UpstreamRustlsSocketFactory(
    const envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext& config,
    Server::Configuration::TransportSocketFactoryContext& context) {
  
  // Load certificates and keys.
  const auto& common_tls_context = config.common_tls_context();
  
  std::string cert_pem;
  std::string key_pem;
  if (common_tls_context.has_tls_certificate()) {
    auto cert_or_error = Config::DataSource::read(common_tls_context.tls_certificate().certificate_chain(),
                                        true, context.serverFactoryContext().api());
    if (!cert_or_error.ok()) {
      throw EnvoyException(std::string(cert_or_error.status().message()));
    }
    cert_pem = cert_or_error.value();
    
    auto key_or_error = Config::DataSource::read(common_tls_context.tls_certificate().private_key(), true,
                                        context.serverFactoryContext().api());
    if (!key_or_error.ok()) {
      throw EnvoyException(std::string(key_or_error.status().message()));
    }
    key_pem = key_or_error.value();
  }

  std::string ca_pem;
  if (common_tls_context.has_validation_context() &&
      common_tls_context.validation_context().has_trusted_ca()) {
    auto ca_or_error = Config::DataSource::read(common_tls_context.validation_context().trusted_ca(), true,
                                       context.serverFactoryContext().api());
    if (!ca_or_error.ok()) {
      throw EnvoyException(std::string(ca_or_error.status().message()));
    }
    ca_pem = ca_or_error.value();
  }

  // Prepare ALPN protocols.
  std::vector<std::string> alpn_protocols;
  for (const auto& protocol : common_tls_context.alpn_protocols()) {
    alpn_protocols.push_back(protocol);
  }

  // Create rustls configuration.
  config_ = RustlsConfig::createClient(cert_pem, key_pem, ca_pem, alpn_protocols);
  if (config_ == nullptr) {
    throw EnvoyException("Failed to create rustls client configuration");
  }

  // Store SNI configuration.
  sni_ = config.sni();

  // Store kTLS enable flag.
  enable_ktls_ = config.has_enable_ktls() && config.enable_ktls().value();
  ktls_tx_only_ = config.ktls_tx_only();
}

Network::TransportSocketPtr UpstreamRustlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    Upstream::HostDescriptionConstSharedPtr host) const {
  
  // Determine SNI: use override from options, then config, then host name.
  std::string sni = sni_;
  if (options && options->serverNameOverride().has_value()) {
    sni = options->serverNameOverride().value();
  } else if (sni.empty() && host) {
    sni = host->hostname();
  }

  // Create rustls connection.
  // Note: File descriptor will be set when socket is connected.
  int fd = -1; // Placeholder, actual FD is set by Connection.
  auto rustls_conn = RustlsConnection::createClient(config_->handle(), fd, sni);
  
  if (rustls_conn == nullptr) {
    return nullptr;
  }

  return std::make_unique<RustlsSocket>(std::move(rustls_conn), enable_ktls_, ktls_tx_only_);
}

// DownstreamRustlsSocketFactory implementation.

DownstreamRustlsSocketFactory::DownstreamRustlsSocketFactory(
    const envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext& config,
    Server::Configuration::TransportSocketFactoryContext& context) {
  
  // Load certificates and keys.
  const auto& common_tls_context = config.common_tls_context();
  
  if (!common_tls_context.has_tls_certificate()) {
    throw EnvoyException("Server certificate is required for downstream rustls transport socket");
  }

  auto cert_or_error =
      Config::DataSource::read(common_tls_context.tls_certificate().certificate_chain(), true,
                               context.serverFactoryContext().api());
  if (!cert_or_error.ok()) {
    throw EnvoyException(std::string(cert_or_error.status().message()));
  }
  std::string cert_pem = cert_or_error.value();
  
  auto key_or_error =
      Config::DataSource::read(common_tls_context.tls_certificate().private_key(), true,
                               context.serverFactoryContext().api());
  if (!key_or_error.ok()) {
    throw EnvoyException(std::string(key_or_error.status().message()));
  }
  std::string key_pem = key_or_error.value();

  // Prepare ALPN protocols.
  std::vector<std::string> alpn_protocols;
  for (const auto& protocol : common_tls_context.alpn_protocols()) {
    alpn_protocols.push_back(protocol);
  }

  // Create rustls configuration.
  config_ = RustlsConfig::createServer(cert_pem, key_pem, alpn_protocols);
  if (config_ == nullptr) {
    throw EnvoyException("Failed to create rustls server configuration");
  }

  // Store kTLS enable flag.
  enable_ktls_ = config.has_enable_ktls() && config.enable_ktls().value();
  ktls_tx_only_ = config.ktls_tx_only();
}

Network::TransportSocketPtr DownstreamRustlsSocketFactory::createDownstreamTransportSocket() const {
  // Create rustls connection.
  // Note: File descriptor will be set when socket is accepted.
  int fd = -1; // Placeholder, actual FD is set by Connection.
  auto rustls_conn = RustlsConnection::createServer(config_->handle(), fd);
  
  if (rustls_conn == nullptr) {
    return nullptr;
  }

  return std::make_unique<RustlsSocket>(std::move(rustls_conn), enable_ktls_, ktls_tx_only_);
}

// UpstreamRustlsSocketConfigFactory implementation.

ProtobufTypes::MessagePtr UpstreamRustlsSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
UpstreamRustlsSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& config,
    Server::Configuration::TransportSocketFactoryContext& context) {
  
  const auto& upstream_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::rustls::v3::
                                           RustlsUpstreamTlsContext&>(
          config, context.messageValidationVisitor());

  std::unique_ptr<UpstreamRustlsSocketFactory> factory =
      std::make_unique<UpstreamRustlsSocketFactory>(upstream_config, context);
  return Network::UpstreamTransportSocketFactoryPtr(std::move(factory));
}

// DownstreamRustlsSocketConfigFactory implementation.

ProtobufTypes::MessagePtr DownstreamRustlsSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext>();
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
DownstreamRustlsSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& config, Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& /* server_names */) {
  
  const auto& downstream_config =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::rustls::v3::
                                           RustlsDownstreamTlsContext&>(
          config, context.messageValidationVisitor());

  std::unique_ptr<DownstreamRustlsSocketFactory> factory =
      std::make_unique<DownstreamRustlsSocketFactory>(downstream_config, context);
  return Network::DownstreamTransportSocketFactoryPtr(std::move(factory));
}

// Register factories.
REGISTER_FACTORY(UpstreamRustlsSocketConfigFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);

REGISTER_FACTORY(DownstreamRustlsSocketConfigFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

