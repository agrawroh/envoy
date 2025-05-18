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
  bool isConnectionSecure() const;

private:
  /**
   * Try to enable kTLS on the socket.
   * @return true if kTLS was enabled, false otherwise.
   */
  bool enableKtls();

  /**
   * Check if kTLS can be enabled based on TLS parameters.
   * @return true if kTLS can be enabled, false otherwise.
   */
  bool canEnableKtls() const;

  /**
   * Try to determine if kTLS is ready or impossible, and update state accordingly.
   */
  void determineKtlsReadiness();

  /**
   * Schedule the next kTLS readiness determination with progressive delay.
   */
  void scheduleKtlsReadinessCheck();

  /**
   * Check if the SSL handshake is complete.
   * @return true if the handshake is complete, false otherwise.
   */
  bool isSslHandshakeComplete() const;

  /**
   * Process any pending operations now that kTLS readiness is determined.
   */
  void processPendingOps();
  
  /**
   * The current state of kTLS for this socket
   */
  enum class KtlsState { Unknown, Supported, Unsupported };
  
  /**
   * Set the kTLS state and mark state as determined
   */
  void setKtlsState(KtlsState state) {
    ktls_enabled_ = (state == KtlsState::Supported);
    ktls_state_determined_ = true;
    processPendingOps();
  }

  Network::TransportSocketCallbacks* callbacks_{};
  bool enable_tx_zerocopy_{false};
  bool enable_rx_no_pad_{false};
  bool ktls_enabled_{false};
  KtlsInfoConstSharedPtr ktls_info_;
  uint32_t ktls_handshake_attempts_{0};
  bool ktls_state_determined_{false};
  
  // Timer for scheduling readiness checks with progressive delays
  Event::TimerPtr readiness_timer_;
  
  // Buffered operations that should be processed after kTLS state is determined
  struct PendingReadOp {
    Buffer::Instance* buffer;
    Network::IoResult result;
    bool completed{false};
  };
  
  struct PendingWriteOp {
    Buffer::Instance* buffer;
    bool end_stream;
    Network::IoResult result;
    bool completed{false};
  };
  
  absl::optional<PendingReadOp> pending_read_;
  absl::optional<PendingWriteOp> pending_write_;
  
  // Maximum number of attempts to enable kTLS before giving up
  static constexpr uint32_t MAX_KTLS_ATTEMPTS = 5;

#ifdef HAS_SPLICE_SYSCALL  
  // Only declare splicing support if the syscall is available
  std::unique_ptr<KtlsSocketSplicing> socket_splicing_;
#endif
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
