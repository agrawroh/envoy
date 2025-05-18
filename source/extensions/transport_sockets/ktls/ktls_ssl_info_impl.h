#pragma once

#include <string>
#include <vector>

#include "envoy/ssl/connection.h"

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"

#ifdef __linux__
#include <sys/socket.h>
#include <linux/tls.h>
using tls_crypto_info_t = struct tls12_crypto_info_aes_gcm_128;
#else
using tls_crypto_info_t = void*;
#endif

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Implementation of KtlsInfo that gets TLS session data from an Ssl::ConnectionInfo.
 */
class KtlsSslInfoImpl : public KtlsInfo, public Logger::Loggable<Logger::Id::connection> {
public:
  KtlsSslInfoImpl(Ssl::ConnectionInfoConstSharedPtr ssl_info);

  // KtlsInfo
  absl::string_view tlsVersion() const override;
  absl::string_view cipherSuite() const override;
  bool getTxCryptoInfo(tls_crypto_info_t& crypto_info) const override;
  bool getRxCryptoInfo(tls_crypto_info_t& crypto_info) const override;
  
  // Override from KtlsInfo
  bool extractCryptoParams() const override;

  // Initialize sequence numbers according to kernel capabilities
  bool initializeSequenceNumbers(int ktls_mode) const override;

private:
  /**
   * Extract key material from SSL connection.
   * @return true if successful, false otherwise.
   */
  bool extractKeyMaterial() const;

  /**
   * SSL connection information.
   */
  Ssl::ConnectionInfoConstSharedPtr ssl_info_;

  /**
   * Storage for cipher suite string.
   */
  mutable std::string cipher_suite_storage_;

  /**
   * Flag indicating whether we are a client or server.
   */
  mutable bool is_client_{false};

  /**
   * Flag indicating whether crypto parameters have been extracted.
   */
  mutable bool params_extracted_{false};

  /**
   * Client write key (16 bytes for AES-128-GCM).
   */
  mutable std::vector<uint8_t> client_write_key_;

  /**
   * Server write key (16 bytes for AES-128-GCM).
   */
  mutable std::vector<uint8_t> server_write_key_;

  /**
   * Client write IV (12 bytes for AES-128-GCM, includes 4-byte salt and 8-byte nonce).
   */
  mutable std::vector<uint8_t> client_write_iv_;

  /**
   * Server write IV (12 bytes for AES-128-GCM, includes 4-byte salt and 8-byte nonce).
   */
  mutable std::vector<uint8_t> server_write_iv_;

  /**
   * Client write sequence number (8 bytes).
   */
  mutable std::vector<uint8_t> client_write_seq_;

  /**
   * Server write sequence number (8 bytes).
   */
  mutable std::vector<uint8_t> server_write_seq_;
};

using KtlsSslInfoImplConstSharedPtr = std::shared_ptr<const KtlsSslInfoImpl>;

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
