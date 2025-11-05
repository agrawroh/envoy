#pragma once

#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.h"
#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.validate.h"
#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/common/assert.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/extensions/transport_sockets/rustls/rustls_wrapper.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

/**
 * Factory for creating rustls upstream transport sockets.
 */
class UpstreamRustlsSocketFactory : public Network::CommonUpstreamTransportSocketFactory {
public:
  UpstreamRustlsSocketFactory(
      const envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext& config,
      Server::Configuration::TransportSocketFactoryContext& context);

  // Network::UpstreamTransportSocketFactory
  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        Upstream::HostDescriptionConstSharedPtr host) const override;
  bool implementsSecureTransport() const override { return true; }
  absl::string_view defaultServerNameIndication() const override { return sni_; }

private:
  RustlsConfigPtr config_;
  std::string sni_;
  bool enable_ktls_;
  bool ktls_tx_only_{false};
};

/**
 * Factory for creating rustls downstream transport sockets.
 */
class DownstreamRustlsSocketFactory : public Network::DownstreamTransportSocketFactory {
public:
  DownstreamRustlsSocketFactory(
      const envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext& config,
      Server::Configuration::TransportSocketFactoryContext& context);

  // Network::DownstreamTransportSocketFactory
  Network::TransportSocketPtr createDownstreamTransportSocket() const override;
  bool implementsSecureTransport() const override { return true; }

private:
  RustlsConfigPtr config_;
  bool enable_ktls_;
  bool ktls_tx_only_{false};
};

/**
 * Config factory for registering upstream rustls transport socket.
 */
class UpstreamRustlsSocketConfigFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.rustls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
};

DECLARE_FACTORY(UpstreamRustlsSocketConfigFactory);

/**
 * Config factory for registering downstream rustls transport socket.
 */
class DownstreamRustlsSocketConfigFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.rustls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context,
      const std::vector<std::string>& server_names) override;
};

DECLARE_FACTORY(DownstreamRustlsSocketConfigFactory);

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

