#pragma once

#include "source/extensions/transport_sockets/ktls/tls_compat.h"

#include "envoy/ssl/connection.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

/**
 * Extension for the SSL ConnectionInfo interface that provides access
 * to the TLS key material needed for kTLS.
 */
class KTlsInfo {
public:
  virtual ~KTlsInfo() = default;

  /**
   * Extract the crypto parameters needed for kTLS from the SSL session.
   * @param crypto_info The tls12_crypto_info_aes_gcm_128 structure to populate.
   * @param is_tx True for transmit direction, false for receive direction.
   * @return True if successful, false otherwise.
   */
  virtual bool extractCryptoInfo(tls12_crypto_info_aes_gcm_128& crypto_info, bool is_tx) const PURE;

  /**
   * Get access to the raw SSL object.
   * @return Pointer to the SSL object.
   */
  virtual SSL* ssl() const PURE;
};

using KTlsInfoConstSharedPtr = std::shared_ptr<const KTlsInfo>;

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 