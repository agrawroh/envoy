#pragma once

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"

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

private:
  /**
   * Extract crypto parameters for both TX and RX from the SSL connection.
   * @return true if successful, false otherwise.
   */
  bool extractCryptoParams();

  /**
   * Extract key material from SSL connection.
   * @return true if successful, false otherwise.
   */
  bool extractKeyMaterial();

  Ssl::ConnectionInfoConstSharedPtr ssl_info_;

  // Storage for returned cipher suite string
  mutable std::string cipher_suite_storage_;

  // Extracted crypto parameters
  bool params_extracted_{false};
  bool is_client_{false};

  // Crypto key material
  std::vector<uint8_t> client_key_;
  std::vector<uint8_t> server_key_;
  std::vector<uint8_t> client_iv_;
  std::vector<uint8_t> server_iv_;
  std::vector<uint8_t> client_salt_;
  std::vector<uint8_t> server_salt_;
  std::vector<uint8_t> client_rec_seq_;
  std::vector<uint8_t> server_rec_seq_;
};

using KtlsSslInfoImplConstSharedPtr = std::shared_ptr<const KtlsSslInfoImpl>;

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
