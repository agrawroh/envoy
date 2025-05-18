#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

#include <netinet/tcp.h>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/network/utility.h"
#include "source/common/tls/utility.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

KtlsSslInfoImpl::KtlsSslInfoImpl(Ssl::ConnectionInfoConstSharedPtr ssl_info) : ssl_info_(ssl_info) {
  // Once created, extract the crypto parameters from the SSL connection
  extractCryptoParams();
}

absl::string_view KtlsSslInfoImpl::tlsVersion() const { return ssl_info_->tlsVersion(); }

absl::string_view KtlsSslInfoImpl::cipherSuite() const {
  std::string cipher_str = ssl_info_->ciphersuiteString();
  // Store the string so we can return a string_view to it
  cipher_suite_storage_ = cipher_str;
  return cipher_suite_storage_;
}

bool KtlsSslInfoImpl::getTxCryptoInfo(tls_crypto_info_t& crypto_info) const {
  if (!params_extracted_) {
    return false;
  }

  // Fill in common fields
  memset(&crypto_info, 0, sizeof(crypto_info));

  if (tlsVersion() == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else {
    // Only support TLS 1.2 for now
    return false;
  }

  crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;

  // Use client or server keys based on whether we're the client or server
  if (is_client_) {
    if (client_key_.size() != sizeof(crypto_info.key) ||
        client_iv_.size() != sizeof(crypto_info.iv) ||
        client_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    memcpy(crypto_info.key, client_key_.data(), sizeof(crypto_info.key));
    memcpy(crypto_info.iv, client_iv_.data(), sizeof(crypto_info.iv));
    memcpy(crypto_info.rec_seq, client_rec_seq_.data(), sizeof(crypto_info.rec_seq));
    memcpy(crypto_info.salt, client_salt_.data(), sizeof(crypto_info.salt));
  } else {
    if (server_key_.size() != sizeof(crypto_info.key) ||
        server_iv_.size() != sizeof(crypto_info.iv) ||
        server_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    memcpy(crypto_info.key, server_key_.data(), sizeof(crypto_info.key));
    memcpy(crypto_info.iv, server_iv_.data(), sizeof(crypto_info.iv));
    memcpy(crypto_info.rec_seq, server_rec_seq_.data(), sizeof(crypto_info.rec_seq));
    memcpy(crypto_info.salt, server_salt_.data(), sizeof(crypto_info.salt));
  }

  return true;
}

bool KtlsSslInfoImpl::getRxCryptoInfo(tls_crypto_info_t& crypto_info) const {
  if (!params_extracted_) {
    return false;
  }

  // Fill in common fields
  memset(&crypto_info, 0, sizeof(crypto_info));

  if (tlsVersion() == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else {
    // Only support TLS 1.2 for now
    return false;
  }

  crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;

  // For RX, use the peer's keys (opposite of TX)
  if (is_client_) {
    if (server_key_.size() != sizeof(crypto_info.key) ||
        server_iv_.size() != sizeof(crypto_info.iv) ||
        server_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    memcpy(crypto_info.key, server_key_.data(), sizeof(crypto_info.key));
    memcpy(crypto_info.iv, server_iv_.data(), sizeof(crypto_info.iv));
    memcpy(crypto_info.rec_seq, server_rec_seq_.data(), sizeof(crypto_info.rec_seq));
    memcpy(crypto_info.salt, server_salt_.data(), sizeof(crypto_info.salt));
  } else {
    if (client_key_.size() != sizeof(crypto_info.key) ||
        client_iv_.size() != sizeof(crypto_info.iv) ||
        client_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    memcpy(crypto_info.key, client_key_.data(), sizeof(crypto_info.key));
    memcpy(crypto_info.iv, client_iv_.data(), sizeof(crypto_info.iv));
    memcpy(crypto_info.rec_seq, client_rec_seq_.data(), sizeof(crypto_info.rec_seq));
    memcpy(crypto_info.salt, client_salt_.data(), sizeof(crypto_info.salt));
  }

  return true;
}

bool KtlsSslInfoImpl::extractCryptoParams() {
  // Check if we already extracted params
  if (params_extracted_) {
    return true;
  }

  // We need to check the cipher suite first
  std::string cipher = std::string(cipherSuite());
  bool is_aes_gcm = cipher.find("AES128-GCM") != std::string::npos ||
                    cipher.find("AES-128-GCM") != std::string::npos;

  if (!is_aes_gcm) {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}", cipher);
    return false;
  }

  // Check TLS version
  std::string version = std::string(tlsVersion());
  if (version != "TLSv1.2") {
    ENVOY_LOG(debug, "Unsupported TLS version for kTLS: {}", version);
    return false;
  }

  // Try to extract key material
  if (!extractKeyMaterial()) {
    ENVOY_LOG(debug, "Failed to extract key material for kTLS");
    return false;
  }

  params_extracted_ = true;
  return true;
}

bool KtlsSslInfoImpl::extractKeyMaterial() {
  // In Envoy, we don't have direct access to the SSL* structure from ConnectionInfo
  // We would need to enhance the ConnectionInfo interface to expose methods for extracting
  // key material needed for kTLS.

  // For now, simulate this with placeholder values to make it compile
  // But in a real implementation, we would get the SSL* and extract the real key material

  // Determine if we're client or server based on ConnectionInfo
  // In a real implementation, we would determine this from the SSL connection
  is_client_ = false;

  // In a real implementation based on ktls-utils, we would:
  // 1. Extract master secret using SSL_SESSION_get_master_key
  // 2. Extract client/server random values
  // 3. Derive the key material using SSL_export_keying_material or similar
  // 4. Set up proper record sequence numbers based on handshake completion

  // For now, use placeholder values for development
  client_key_.resize(16, 0x01);
  server_key_.resize(16, 0x02);
  client_iv_.resize(8, 0x03);
  server_iv_.resize(8, 0x04);
  client_salt_.resize(4, 0x05);
  server_salt_.resize(4, 0x06);
  client_rec_seq_.resize(8, 0);
  server_rec_seq_.resize(8, 0);

  return true;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
