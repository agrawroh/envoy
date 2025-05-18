#pragma once

#include <memory>

#include "envoy/network/transport_socket.h"
#include "envoy/upstream/host_description.h"
#include "envoy/upstream/upstream.h"

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/common/passthrough.h"
#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Implementation of Network::TransportSocket that enables kTLS by offloading
 * TLS encryption/decryption to the kernel after handshake completion.
 */
class KtlsTransportSocket : public TransportSockets::PassthroughSocket,
                            public Logger::Loggable<Logger::Id::connection> {
public:
  KtlsTransportSocket(Network::TransportSocketPtr&& transport_socket, bool enable_tx_zerocopy,
                      bool enable_rx_no_pad);
  ~KtlsTransportSocket() override;

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  bool canFlushClose() override;
  void closeSocket(Network::ConnectionEvent event) override;
  Network::IoResult doRead(Buffer::Instance& buffer) override;
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override;
  bool startSecureTransport() override;
  void onConnected() override;

  // Not in base class, implement directly
  bool isConnectionSecure() const;

private:
  bool enableKtls();
  bool canEnableKtls() const;

  Network::TransportSocketCallbacks* callbacks_{nullptr};
  bool ktls_enabled_{false};
  bool enable_tx_zerocopy_{false};
  bool enable_rx_no_pad_{false};

  KtlsInfoConstSharedPtr ktls_info_;
  std::unique_ptr<KtlsSocketSplicing> socket_splicing_;
};

/**
 * Implementation of Network::UpstreamTransportSocketFactory for kTLS.
 */
class KtlsTransportSocketFactory : public Network::CommonUpstreamTransportSocketFactory {
public:
  KtlsTransportSocketFactory(Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory,
                             bool enable_tx_zerocopy, bool enable_rx_no_pad);

  // Network::TransportSocketFactory
  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        std::shared_ptr<const Upstream::HostDescription> host) const override;

  // Network::TransportSocketFactory
  bool implementsSecureTransport() const override {
    return inner_factory_->implementsSecureTransport();
  }

  absl::string_view defaultServerNameIndication() const override {
    return inner_factory_->defaultServerNameIndication();
  }

  // We need to correctly use the ClientContextSharedPtr return type
  Ssl::ClientContextSharedPtr sslCtx() override { return inner_factory_->sslCtx(); }

private:
  Network::UpstreamTransportSocketFactoryPtr inner_factory_;
  bool enable_tx_zerocopy_;
  bool enable_rx_no_pad_;
};

/**
 * Implementation of Network::DownstreamTransportSocketFactory for kTLS.
 * This factory wraps another TLS factory and enables kTLS on its connections.
 */
class DownstreamKtlsTransportSocketFactory : public TransportSockets::DownstreamPassthroughFactory {
public:
  DownstreamKtlsTransportSocketFactory(
      Network::DownstreamTransportSocketFactoryPtr&& transport_socket_factory,
      bool enable_tx_zerocopy, bool enable_rx_no_pad);

  // Network::DownstreamTransportSocketFactory
  Network::TransportSocketPtr createDownstreamTransportSocket() const override;

private:
  bool enable_tx_zerocopy_;
  bool enable_rx_no_pad_;
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
