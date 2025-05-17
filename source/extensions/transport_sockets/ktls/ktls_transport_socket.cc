#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"

#include <netinet/tcp.h>
#include <sys/splice.h>

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/network/io_socket_error_impl.h"

// Include OpenSSL headers for direct access to SSL objects
#include "openssl/evp.h"
#include "openssl/ssl.h"

#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

KTlsTransportSocket::KTlsTransportSocket(Ssl::ConnectionInfoConstSharedPtr ssl_info,
                                         Network::IoHandlePtr io_handle)
    : ssl_info_(ssl_info) {
  UNREFERENCED_PARAMETER(io_handle);
}

KTlsTransportSocket::KTlsTransportSocket(KTlsInfoConstSharedPtr ktls_info,
                                         Network::IoHandlePtr io_handle)
    : ktls_info_(ktls_info), ssl_info_(ktls_info) {
  UNREFERENCED_PARAMETER(io_handle);
}

KTlsTransportSocket::~KTlsTransportSocket() {
  downstream_to_upstream_splicer_.reset();
  upstream_to_downstream_splicer_.reset();
}

void KTlsTransportSocket::setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  
  // Try to set up kTLS once we have callbacks
  if (!ktls_tx_enabled_ && !ktls_rx_enabled_) {
    setupKTls();
  }
}

std::string KTlsTransportSocket::protocol() const {
  return ssl_info_ ? ssl_info_->tlsVersion() : EMPTY_STRING;
}

absl::string_view KTlsTransportSocket::failureReason() const { return failure_reason_; }

bool KTlsTransportSocket::canFlushClose() { 
  return true; // kTLS can always flush close
}

void KTlsTransportSocket::closeSocket(Network::ConnectionEvent close_type) {
  // Clean up splicing resources
  downstream_to_upstream_splicer_.reset();
  upstream_to_downstream_splicer_.reset();
  splice_enabled_ = false;
  upstream_fd_ = -1;
}

Network::IoResult KTlsTransportSocket::doRead(Buffer::Instance& read_buffer) {
  // If upstream FD is set and splice is enabled, try to splice data from downstream to upstream
  if (splice_enabled_ && upstream_fd_ >= 0) {
    ssize_t bytes_spliced = spliceData(true, 0);
    if (bytes_spliced > 0) {
      // Data was successfully spliced directly to upstream, no need to read into the buffer
      return {Network::PostIoAction::KeepOpen, bytes_spliced, false};
    }
    // Fall back to normal read if splice failed or no data was available
  }

  // When kTLS is enabled, decryption happens automatically in the kernel
  // We just need to call the regular read on the socket
  return callbacks_->ioHandle().read(read_buffer);
}

Network::IoResult KTlsTransportSocket::doWrite(Buffer::Instance& write_buffer, bool end_stream) {
  // If upstream FD is set and splice is enabled, we could try splicing data from upstream to downstream
  // This would be handled by the upstream connection's read path
  
  // When kTLS is enabled, encryption happens automatically in the kernel
  // We just need to call the regular write on the socket
  return callbacks_->ioHandle().write(write_buffer);
}

void KTlsTransportSocket::onConnected() {
  // Ensure kTLS is set up
  if (!ktls_tx_enabled_ && !ktls_rx_enabled_) {
    setupKTls();
  }
}

Ssl::ConnectionInfoConstSharedPtr KTlsTransportSocket::ssl() const { return ssl_info_; }

bool KTlsTransportSocket::setupKTls() {
  ENVOY_LOG(debug, "Setting up kTLS");
  
  // Make sure we have SSL connection info
  if (ssl_info_ == nullptr) {
    failure_reason_ = "No SSL connection info available";
    ENVOY_LOG(warn, "Failed to setup kTLS: {}", failure_reason_);
    return false;
  }
  
  // Setup TX crypto info
  tls12_crypto_info_aes_gcm_128 tx_crypto_info;
  if (!extractCryptoInfo(ssl_info_, tx_crypto_info, true)) {
    failure_reason_ = "Failed to extract TX crypto info";
    ENVOY_LOG(warn, "Failed to setup kTLS TX: {}", failure_reason_);
    return false;
  }
  
  // Enable kTLS TX
  ktls_tx_enabled_ = enableTlsTx(tx_crypto_info);
  if (!ktls_tx_enabled_) {
    failure_reason_ = "Failed to enable kTLS TX";
    ENVOY_LOG(warn, "Failed to setup kTLS TX: {}", failure_reason_);
    return false;
  }
  
  // Setup RX crypto info
  tls12_crypto_info_aes_gcm_128 rx_crypto_info;
  if (!extractCryptoInfo(ssl_info_, rx_crypto_info, false)) {
    failure_reason_ = "Failed to extract RX crypto info";
    ENVOY_LOG(warn, "Failed to setup kTLS RX: {}", failure_reason_);
    return false;
  }
  
  // Enable kTLS RX
  ktls_rx_enabled_ = enableTlsRx(rx_crypto_info);
  if (!ktls_rx_enabled_) {
    failure_reason_ = "Failed to enable kTLS RX";
    ENVOY_LOG(warn, "Failed to setup kTLS RX: {}", failure_reason_);
    return false;
  }
  
  // If both TX and RX are enabled, set up splice for zero-copy
  if (ktls_tx_enabled_ && ktls_rx_enabled_) {
    splice_enabled_ = enableSplice();
    if (splice_enabled_) {
      ENVOY_LOG(info, "Enabled zero-copy splice for kTLS");
    }
  }
  
  ENVOY_LOG(info, "Successfully set up kTLS (TX: {}, RX: {}, Splice: {})", 
           ktls_tx_enabled_, ktls_rx_enabled_, splice_enabled_);
  
  return ktls_tx_enabled_ || ktls_rx_enabled_;
}

bool KTlsTransportSocket::extractCryptoInfo(Ssl::ConnectionInfoConstSharedPtr ssl_info,
                                          tls12_crypto_info_aes_gcm_128& crypto_info,
                                          bool is_tx) {
#ifdef TLS_1_2_VERSION
  // If we have a KTlsInfo, use it directly
  if (ktls_info_) {
    return ktls_info_->extractCryptoInfo(crypto_info, is_tx);
  }
  
  // If we don't have KTlsInfo, fall back to basic checks
  
  // Only AES-GCM-128 is supported for now
  if (ssl_info->ciphersuiteId() != 0x009C) { // TLS_RSA_WITH_AES_128_GCM_SHA256
    ENVOY_LOG(warn, "Unsupported cipher suite for kTLS: {}", ssl_info->ciphersuiteString());
    return false;
  }
  
  // For now only support TLS 1.2
  if (ssl_info->tlsVersion() != "TLSv1.2") {
    ENVOY_LOG(warn, "Unsupported TLS version for kTLS: {}", ssl_info->tlsVersion());
    return false;
  }
  
  // Initialize the crypto info struct
  crypto_info.info.version = TLS_1_2_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  
  // Since we don't have KTlsInfo, we can't access the SSL* directly
  // Log this limitation and return false to prevent kTLS from being enabled
  
  ENVOY_LOG(warn, "Direct access to SSL keys not available. Implement KTlsInfo for this connection.");
  return false;
#else
  UNREFERENCED_PARAMETER(ssl_info);
  UNREFERENCED_PARAMETER(crypto_info);
  UNREFERENCED_PARAMETER(is_tx);
  return false;
#endif
}

bool KTlsTransportSocket::enableTlsTx(const tls12_crypto_info_aes_gcm_128& crypto_info) {
#ifdef TLS_TX
  // First set the TCP ULP to TLS
  static const char tls_ulp[] = "tls";
  int rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TCP, TCP_ULP, tls_ulp, sizeof(tls_ulp));
  if (rc < 0) {
    ENVOY_LOG(debug, "Failed to set TCP_ULP for kTLS: {}", strerror(errno));
    return false;
  }
  
  // Now set up the TLS TX crypto info
  rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
  if (rc < 0) {
    ENVOY_LOG(debug, "Failed to set TLS_TX for kTLS: {}", strerror(errno));
    return false;
  }

  // Optionally enable zerocopy TX if supported
#ifdef TLS_TX_ZEROCOPY_RO
  int zerocopy = 1;
  rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TLS, TLS_TX_ZEROCOPY_RO, &zerocopy, sizeof(zerocopy));
  if (rc < 0) {
    ENVOY_LOG(debug, "Failed to enable TLS_TX_ZEROCOPY_RO (not critical): {}", strerror(errno));
    // Not critical, so continue
  } else {
    ENVOY_LOG(debug, "Enabled TLS_TX_ZEROCOPY_RO for kTLS");
  }
#endif
  
  return true;
#else
  UNREFERENCED_PARAMETER(crypto_info);
  ENVOY_LOG(debug, "kTLS not supported on this platform");
  return false;
#endif
}

bool KTlsTransportSocket::enableTlsRx(const tls12_crypto_info_aes_gcm_128& crypto_info) {
#ifdef TLS_RX
  // Note: We don't need to set TCP_ULP again if TX was already enabled
  if (!ktls_tx_enabled_) {
    static const char tls_ulp[] = "tls";
    int rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TCP, TCP_ULP, tls_ulp, sizeof(tls_ulp));
    if (rc < 0) {
      ENVOY_LOG(debug, "Failed to set TCP_ULP for kTLS: {}", strerror(errno));
      return false;
    }
  }
  
  // Set up the TLS RX crypto info
  int rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
  if (rc < 0) {
    ENVOY_LOG(debug, "Failed to set TLS_RX for kTLS: {}", strerror(errno));
    return false;
  }

  // Optionally enable no-padding optimization if supported
#ifdef TLS_RX_EXPECT_NO_PAD
  int no_pad = 1;
  rc = setsockopt(callbacks_->ioHandle().fdDoNotUse(), SOL_TLS, TLS_RX_EXPECT_NO_PAD, &no_pad, sizeof(no_pad));
  if (rc < 0) {
    ENVOY_LOG(debug, "Failed to enable TLS_RX_EXPECT_NO_PAD (not critical): {}", strerror(errno));
    // Not critical, so continue
  } else {
    ENVOY_LOG(debug, "Enabled TLS_RX_EXPECT_NO_PAD for kTLS");
  }
#endif
  
  return true;
#else
  UNREFERENCED_PARAMETER(crypto_info);
  ENVOY_LOG(debug, "kTLS not supported on this platform");
  return false;
#endif
}

bool KTlsTransportSocket::enableSplice() {
#if defined(TLS_RX) && defined(TLS_TX)
  // Initialize the splicers if they don't exist
  downstream_to_upstream_splicer_ = std::make_unique<KTlsSplicer>();
  upstream_to_downstream_splicer_ = std::make_unique<KTlsSplicer>();
  
  // We'll initialize the splicers with actual FDs when upstream_fd is set
  
  ENVOY_LOG(debug, "Splice support for kTLS ready, waiting for upstream connection");
  return true;
#else
  return false;
#endif
}

bool KTlsTransportSocket::setUpstreamFileDescriptor(os_fd_t upstream_fd) {
  if (!splice_enabled_) {
    ENVOY_LOG(warn, "Cannot set upstream FD: splice not enabled");
    return false;
  }
  
  if (upstream_fd < 0) {
    ENVOY_LOG(error, "Invalid upstream file descriptor");
    return false;
  }
  
  upstream_fd_ = upstream_fd;
  
  // Initialize the splicers with the file descriptors
  os_fd_t downstream_fd = callbacks_->ioHandle().fdDoNotUse();
  
  bool downstream_to_upstream_initialized = 
      downstream_to_upstream_splicer_->initialize(downstream_fd, upstream_fd_);
  bool upstream_to_downstream_initialized = 
      upstream_to_downstream_splicer_->initialize(upstream_fd_, downstream_fd);
  
  if (!downstream_to_upstream_initialized || !upstream_to_downstream_initialized) {
    ENVOY_LOG(error, "Failed to initialize splicers");
    upstream_fd_ = -1;
    return false;
  }
  
  ENVOY_LOG(info, "Configured zero-copy splice between downstream and upstream");
  return true;
}

ssize_t KTlsTransportSocket::spliceData(bool from_downstream, size_t max_bytes) {
  if (!splice_enabled_ || upstream_fd_ < 0) {
    return -1;
  }
  
  if (from_downstream) {
    // Transfer data from downstream client to upstream server
    if (!downstream_to_upstream_splicer_->isInitialized()) {
      return -1;
    }
    return downstream_to_upstream_splicer_->splice(max_bytes);
  } else {
    // Transfer data from upstream server to downstream client
    if (!upstream_to_downstream_splicer_->isInitialized()) {
      return -1;
    }
    return upstream_to_downstream_splicer_->splice(max_bytes);
  }
}

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 