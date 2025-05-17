#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"

#include <netinet/tcp.h>
// Only include splice.h on Linux
#ifdef __linux__
#include <sys/splice.h>
#endif

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/network/io_socket_error_impl.h"

// Include OpenSSL headers for direct access to SSL objects
#include "openssl/evp.h"
#include "openssl/ssl.h"

#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

namespace {
class KtlsLogger : public Logger::Loggable<Logger::Id::connection> {};
}

KtlsTransportSocket::KtlsTransportSocket(Network::TransportSocketPtr&& transport_socket,
                                         bool enable_tx_zerocopy, bool enable_rx_no_pad)
    : PassthroughSocket(std::move(transport_socket)),
      enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad) {
  ENVOY_LOG(debug, "Creating KtlsTransportSocket with zerocopy={} no_pad={}", 
            enable_tx_zerocopy_, enable_rx_no_pad_);
}

KtlsTransportSocket::~KtlsTransportSocket() = default;

void KtlsTransportSocket::setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  PassthroughSocket::setTransportSocketCallbacks(callbacks);
}

bool KtlsTransportSocket::canFlushClose() {
  return PassthroughSocket::canFlushClose();
}

void KtlsTransportSocket::closeSocket(Network::ConnectionEvent event) {
  // Make sure we clean up any kTLS state before closing
  if (ktls_enabled_) {
    // No special cleanup needed for kTLS currently
  }
  PassthroughSocket::closeSocket(event);
}

Network::IoResult KtlsTransportSocket::doRead(Buffer::Instance& buffer) {
  if (!ktls_enabled_) {
    // Pass through to the underlying socket
    return PassthroughSocket::doRead(buffer);
  }
  
  // If kTLS is enabled, we might want to use socket splicing for zero-copy
  // But for now, we just pass through
  return PassthroughSocket::doRead(buffer);
}

Network::IoResult KtlsTransportSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (!ktls_enabled_) {
    // Pass through to the underlying socket if kTLS is not enabled
    return PassthroughSocket::doWrite(buffer, end_stream);
  }
  
  // If kTLS is enabled, we might use socket splicing for zero-copy
  // But for now, we just pass through
  return PassthroughSocket::doWrite(buffer, end_stream);
}

bool KtlsTransportSocket::startSecureTransport() {
  // This is no-op for kTLS
  return false;
}

void KtlsTransportSocket::onConnected() {
  // Delegate to the wrapped socket first
  PassthroughSocket::onConnected();
  
  // After the handshake is complete, try to enable kTLS
  enableKtls();
}

bool KtlsTransportSocket::isConnectionSecure() const {
  return transport_socket_->ssl() != nullptr;
}

bool KtlsTransportSocket::enableKtls() {
  // Check if we already enabled kTLS
  if (ktls_enabled_) {
    return true;
  }
  
  // Check if we can enable kTLS
  if (!canEnableKtls()) {
    return false;
  }
  
  // Get the SSL info from the underlying socket
  Ssl::ConnectionInfoConstSharedPtr ssl_info = transport_socket_->ssl();
  if (!ssl_info) {
    ENVOY_LOG(debug, "No SSL info available, cannot enable kTLS");
    return false;
  }
  
  // Create SSL info wrapper for kTLS
  ktls_info_ = std::make_shared<KtlsSslInfoImpl>(ssl_info);
  
#ifdef __linux__
  if (callbacks_ == nullptr) {
    ENVOY_LOG(debug, "No callbacks available, cannot enable kTLS");
    return false;
  }
  
  // Get the socket file descriptor
  int fd = callbacks_->ioHandle().fdDoNotUse();
  
  // 1. Enable kTLS ULP on the socket
  const char* tls_ulp = "tls";
  if (setsockopt(fd, SOL_TCP, TCP_ULP, tls_ulp, strlen(tls_ulp)) < 0) {
    ENVOY_LOG(debug, "Failed to set TCP_ULP for kTLS: {}", ::strerror(errno));
    return false;
  }
  
  // 2. Set up the TLS crypto state for TX (sending)
  tls_crypto_info_t crypto_info;
  if (!ktls_info_->getTxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "Failed to get TX crypto info for kTLS");
    return false;
  }
  
  if (setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
    ENVOY_LOG(debug, "Failed to set TLS_TX crypto info: {}", ::strerror(errno));
    return false;
  }
  
  // 3. Set up the TLS crypto state for RX (receiving)
  if (!ktls_info_->getRxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "Failed to get RX crypto info for kTLS");
    return false;
  }
  
  if (setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) < 0) {
    ENVOY_LOG(debug, "Failed to set TLS_RX crypto info: {}", ::strerror(errno));
    return false;
  }
  
  // 4. Enable TX zerocopy if requested
  if (enable_tx_zerocopy_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &val, sizeof(val)) < 0) {
      ENVOY_LOG(debug, "Failed to enable TX zerocopy for kTLS: {}", ::strerror(errno));
      // Not fatal, continue
    }
  }
  
  // 5. Enable RX no padding if requested
  if (enable_rx_no_pad_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &val, sizeof(val)) < 0) {
      ENVOY_LOG(debug, "Failed to set RX no padding for kTLS: {}", ::strerror(errno));
      // Not fatal, continue
    }
  }
  
  // 6. Set up socket splicing for zero-copy operations
  if (enable_tx_zerocopy_) {
    socket_splicing_ = std::make_unique<KtlsSocketSplicing>(
        callbacks_->ioHandle(), callbacks_->connection().socket().ioHandle());
  }
  
  // Mark kTLS as enabled
  ktls_enabled_ = true;
  ENVOY_LOG(info, "kTLS enabled successfully");
  return true;
#else
  // kTLS is not supported on non-Linux platforms
  ENVOY_LOG(debug, "kTLS not supported on this platform");
  return false;
#endif
}

bool KtlsTransportSocket::canEnableKtls() const {
  // Get the SSL connection
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    return false;
  }
  
  // Check if the SSL handshake is complete - this is implementation dependent
  // In a real implementation you'd need to check if the SSL session is established
  
  // Check cipher suite - for now we only support AES-GCM-128 with TLS 1.2
  std::string cipher = std::string(ssl_connection->ciphersuiteString());
  if (cipher.find("ECDHE-RSA-AES128-GCM-SHA256") == std::string::npos &&
      cipher.find("AES128-GCM-SHA256") == std::string::npos) {
    ENVOY_LOG(debug, "Unsupported cipher suite for kTLS: {}", cipher);
    return false;
  }
  
  // Check TLS version - for now we only support TLS 1.2
  std::string version = std::string(ssl_connection->tlsVersion());
  if (version != "TLSv1.2") {
    ENVOY_LOG(debug, "Unsupported TLS version for kTLS: {}", version);
    return false;
  }
  
  return true;
}

KtlsTransportSocketFactory::KtlsTransportSocketFactory(
    Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory,
    bool enable_tx_zerocopy, bool enable_rx_no_pad)
    : PassthroughFactory(std::move(transport_socket_factory)),
      enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad) {}

Network::TransportSocketPtr KtlsTransportSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options) const {
  std::shared_ptr<const Upstream::HostDescription> host; // Null host
  auto inner_socket = transport_socket_factory_->createTransportSocket(options, host);
  if (inner_socket == nullptr) {
    return nullptr;
  }
  
  return std::make_unique<KtlsTransportSocket>(std::move(inner_socket), 
                                             enable_tx_zerocopy_, enable_rx_no_pad_);
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 