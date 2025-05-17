#pragma once

#include <memory>

#include "envoy/network/transport_socket.h"

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
class KtlsTransportSocket : public TransportSockets::PassthroughSocket {
public:
  KtlsTransportSocket(Network::TransportSocketPtr&& transport_socket,
                      bool enable_tx_zerocopy, bool enable_rx_no_pad);
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

class KtlsTransportSocketFactory : public TransportSockets::PassthroughFactory {
public:
  KtlsTransportSocketFactory(Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory,
                           bool enable_tx_zerocopy,
                           bool enable_rx_no_pad);

  // Network::TransportSocketFactory
  Network::TransportSocketPtr createTransportSocket(
      Network::TransportSocketOptionsConstSharedPtr options) const override;

private:
  bool enable_tx_zerocopy_;
  bool enable_rx_no_pad_;
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 