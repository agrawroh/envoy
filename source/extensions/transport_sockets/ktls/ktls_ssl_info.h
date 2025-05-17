#pragma once

#include "envoy/ssl/connection.h"

#include "source/extensions/transport_sockets/ktls/tls_compat.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Interface for accessing SSL session data needed for kTLS configuration.
 */
class KtlsInfo {
public:
  virtual ~KtlsInfo() = default;

  /**
   * @return The TLS version used for the connection (e.g., "TLSv1.2").
   */
  virtual absl::string_view tlsVersion() const PURE;

  /**
   * @return The cipher suite used for the connection.
   */
  virtual absl::string_view cipherSuite() const PURE;

  /**
   * Gets the TLS crypto information for transmit direction (TX).
   * @param crypto_info The structure to fill with crypto parameters.
   * @return true if the parameters were successfully extracted, false otherwise.
   */
  virtual bool getTxCryptoInfo(tls_crypto_info_t& crypto_info) const PURE;

  /**
   * Gets the TLS crypto information for receive direction (RX).
   * @param crypto_info The structure to fill with crypto parameters.
   * @return true if the parameters were successfully extracted, false otherwise.
   */
  virtual bool getRxCryptoInfo(tls_crypto_info_t& crypto_info) const PURE;
};

using KtlsInfoConstSharedPtr = std::shared_ptr<const KtlsInfo>;

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 