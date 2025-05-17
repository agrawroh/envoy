#include "source/common/network/ktls/ktls_socket_handle_impl.h"

#include <netinet/tcp.h>

#include "envoy/common/exception.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Network {

bool KTlsSocketHandleImpl::enableTlsTx(const tls12_crypto_info_aes_gcm_128& crypto_info) {
#ifdef TLS_TX
  // First set the TCP ULP to TLS
  static const char tls_ulp[] = "tls";
  int rc = setsockopt(fd_, SOL_TCP, TCP_ULP, tls_ulp, sizeof(tls_ulp));
  if (rc < 0) {
    ENVOY_LOG_MISC(debug, "Failed to set TCP_ULP for kTLS: {}", strerror(errno));
    return false;
  }
  
  // Now set up the TLS TX crypto info
  rc = setsockopt(fd_, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
  if (rc < 0) {
    ENVOY_LOG_MISC(debug, "Failed to set TLS_TX for kTLS: {}", strerror(errno));
    return false;
  }
  
  tls_tx_enabled_ = true;
  return true;
#else
  UNREFERENCED_PARAMETER(crypto_info);
  ENVOY_LOG_MISC(debug, "kTLS not supported on this platform");
  return false;
#endif
}

bool KTlsSocketHandleImpl::enableTlsRx(const tls12_crypto_info_aes_gcm_128& crypto_info) {
#ifdef TLS_RX
  // Note: We don't need to set TCP_ULP again if TX was already enabled
  if (!tls_tx_enabled_) {
    static const char tls_ulp[] = "tls";
    int rc = setsockopt(fd_, SOL_TCP, TCP_ULP, tls_ulp, sizeof(tls_ulp));
    if (rc < 0) {
      ENVOY_LOG_MISC(debug, "Failed to set TCP_ULP for kTLS: {}", strerror(errno));
      return false;
    }
  }
  
  // Set up the TLS RX crypto info
  int rc = setsockopt(fd_, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
  if (rc < 0) {
    ENVOY_LOG_MISC(debug, "Failed to set TLS_RX for kTLS: {}", strerror(errno));
    return false;
  }
  
  tls_rx_enabled_ = true;
  return true;
#else
  UNREFERENCED_PARAMETER(crypto_info);
  ENVOY_LOG_MISC(debug, "kTLS not supported on this platform");
  return false;
#endif
}

} // namespace Network
} // namespace Envoy 