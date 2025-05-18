#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/network/transport_socket.h"
#include "envoy/upstream/host_description.h"
#include "envoy/upstream/upstream.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/ssl/ssl_socket_state.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/common/network/io_socket_error_impl.h"
#include "source/extensions/transport_sockets/common/passthrough.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

// Include the appropriate socket splicing implementation based on platform availability
#ifdef HAS_SPLICE_SYSCALL
#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"
#else
#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing_stub.h"
#endif

// Include Linux-specific headers only in Linux builds
#ifdef __linux__
#include <linux/tls.h>
#else
// Provide a dummy definition for non-Linux platforms
using tls_crypto_info_t = void*;
#endif

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

  // Network::TransportSocketCallbacks (called by the underlying SslSocket)
  void raiseEvent(Network::ConnectionEvent event);

  /**
   * Check if kTLS is enabled for this socket.
   * @return true if kTLS is enabled, false otherwise.
   */
  bool isKtlsEnabled() const;

  // Set whether this is an upstream or downstream connection
  void setIsUpstream(bool is_upstream) { is_upstream_ = is_upstream; }

  // Methods for stack-driven resynchronization
  void scheduleResynchronization();
  bool performResynchronization();
  void resetResyncState();

private:
  /**
   * Try to enable kTLS on the socket.
   * @return true if kTLS was enabled, false otherwise.
   */
  bool enableKtls();

  /**
   * Disable kTLS with a reason, useful when errors occur.
   * @param reason The reason for disabling kTLS, for logging.
   */
  void disableKtls(const std::string& reason);

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
  uint32_t readiness_attempts_{0};
  bool ktls_state_determined_{false};

  // Timer for delayed kTLS readiness check
  Event::TimerPtr readiness_timer_;
  
  // Timer for resynchronization
  Event::TimerPtr resync_timer_;

  // Sequence numbers at time of kTLS initialization
  uint64_t saved_tx_seq_{0};
  uint64_t saved_rx_seq_{0};
  
  // Resynchronization related members
  uint32_t consecutive_decrypt_failures_{0};
  bool resync_in_progress_{false};
  uint64_t last_resync_attempt_time_ms_{0};
  absl::optional<uint64_t> next_expected_rx_seq_;
  bool resync_scheduled_{false};

  // Direction flag - whether this is upstream or downstream
  bool is_upstream_{false};

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

  // Always declare socket_splicing_ to make the code simpler
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
