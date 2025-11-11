#pragma once

#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/rustls/rustls_wrapper.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

/**
 * Implementation of Network::TransportSocket using rustls library with optional kTLS support.
 */
class RustlsSocket : public Network::TransportSocket,
                     protected Logger::Loggable<Logger::Id::connection> {
public:
  RustlsSocket(RustlsConnectionPtr rustls_conn, bool enable_ktls, bool ktls_tx_only = false);
  ~RustlsSocket() override;

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  absl::string_view failureReason() const override;
  bool canFlushClose() override;
  void closeSocket(Network::ConnectionEvent event) override;
  void onConnected() override;
  Network::IoResult doRead(Buffer::Instance& buffer) override;
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override;
  Ssl::ConnectionInfoConstSharedPtr ssl() const override;
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t bandwidth_bits_per_sec,
                                        std::chrono::microseconds rtt) override;

private:
  /**
   * Performs TLS handshake.
   * @return true if handshake is complete, false if more I/O is needed.
   */
  bool doHandshake();

  /**
   * Attempts to enable kTLS offload after successful handshake.
   */
  void enableKtls();
  
  /**
   * Flushes pending encrypted TLS data to the network.
   */
  void flushPendingTlsData();

  Network::TransportSocketCallbacks* callbacks_{nullptr};
  RustlsConnectionPtr rustls_conn_;
  bool enable_ktls_;
  bool ktls_tx_only_{false};
  bool ktls_tx_enabled_{false};
  bool ktls_rx_enabled_{false};
  bool handshake_complete_{false};
  std::string failure_reason_;
  std::string negotiated_protocol_;
};

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

