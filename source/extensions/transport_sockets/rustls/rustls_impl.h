#pragma once

#include <memory>
#include <string>
#include <vector>

#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/upstream/host_description.h"

#include "source/common/common/logger.h"
#include "source/common/common/statusor.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/extensions/transport_sockets/dynamic_modules/transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

using DynamicModules::DynamicModuleTransportSocketConfigSharedPtr;

/**
 * Stub transport socket returned by the rustls factories when a per-connection feature is
 * requested but not yet supported (e.g. ALPN or SAN match-list override). Every I/O is `Close`;
 * `failureReason()` is a fixed human-readable string so the connection layer surfaces a clean
 * `upstream_cx_connect_fail` with operator-visible context.
 *
 * Mirrors `Tls::NotReadySslSocket` / `Tls::ErrorSslSocket` from the standard TLS transport socket.
 */
class NotReadyRustlsSocket : public Network::TransportSocket {
public:
  explicit NotReadyRustlsSocket(std::string failure_reason)
      : failure_reason_(std::move(failure_reason)) {}

  void setTransportSocketCallbacks(Network::TransportSocketCallbacks&) override {}
  std::string protocol() const override { return {}; }
  absl::string_view failureReason() const override { return failure_reason_; }
  bool canFlushClose() override { return true; }
  void closeSocket(Network::ConnectionEvent, bool) override {}
  void onConnected() override {}
  Network::IoResult doRead(Buffer::Instance&) override {
    return {Network::PostIoAction::Close, 0, false, absl::nullopt};
  }
  Network::IoResult doWrite(Buffer::Instance&, bool) override {
    return {Network::PostIoAction::Close, 0, false, absl::nullopt};
  }
  Ssl::ConnectionInfoConstSharedPtr ssl() const override { return nullptr; }
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) override {}

private:
  const std::string failure_reason_;
};

/**
 * Upstream transport socket factory for the `rustls` TLS library with optional `kTLS` offload. The
 * per-connection socket and its I/O are the shared dynamic-module transport socket; this factory
 * adds the rustls-specific pieces the generic dynamic-module factory does not: pre-screening of
 * per-connection options the rustls module cannot honor yet, the configured default SNI and ALPN
 * list, and the connection-pool hash key.
 */
class RustlsUpstreamTransportSocketFactory : public Network::CommonUpstreamTransportSocketFactory {
public:
  RustlsUpstreamTransportSocketFactory(DynamicModuleTransportSocketConfigSharedPtr config,
                                       std::string default_sni,
                                       std::vector<std::string> alpn_protocols,
                                       std::string socket_config_bytes);

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        Upstream::HostDescriptionConstSharedPtr host) const override;

  bool implementsSecureTransport() const override { return true; }
  absl::string_view defaultServerNameIndication() const override { return default_sni_; }
  bool supportsAlpn() const override { return !alpn_protocols_.empty(); }

  void hashKey(std::vector<uint8_t>& key,
               Network::TransportSocketOptionsConstSharedPtr options) const override;

private:
  DynamicModuleTransportSocketConfigSharedPtr config_;
  const std::string default_sni_;
  const std::vector<std::string> alpn_protocols_;
  const std::string socket_config_bytes_;
};

/**
 * Downstream transport socket factory for the `rustls` TLS library with optional `kTLS` offload.
 */
class RustlsDownstreamTransportSocketFactory : public Network::DownstreamTransportSocketFactory {
public:
  explicit RustlsDownstreamTransportSocketFactory(
      DynamicModuleTransportSocketConfigSharedPtr config)
      : config_(std::move(config)) {}

  Network::TransportSocketPtr createDownstreamTransportSocket() const override;
  bool implementsSecureTransport() const override { return true; }

private:
  DynamicModuleTransportSocketConfigSharedPtr config_;
};

/**
 * Config factory for upstream transport sockets using the `rustls` TLS library with optional `kTLS`
 * offload. Loads the Rust module statically by name and delegates I/O to the shared dynamic-module
 * transport socket.
 */
class RustlsUpstreamTransportSocketConfigFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.rustls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr> createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
};

/**
 * Config factory for downstream transport sockets using the `rustls` TLS library with optional
 * `kTLS` offload.
 */
class RustlsDownstreamTransportSocketConfigFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.rustls"; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;
};

DECLARE_FACTORY(RustlsUpstreamTransportSocketConfigFactory);
DECLARE_FACTORY(RustlsDownstreamTransportSocketConfigFactory);

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
