#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

#include <netinet/tcp.h>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/network/utility.h"
#include "source/common/tls/connection_info_impl_base.h"
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

    // Copy data from vectors to crypto_info struct
    safeMemcpyUnsafeSrc(crypto_info.key, client_key_.data());
    safeMemcpyUnsafeSrc(crypto_info.iv, client_iv_.data());
    safeMemcpyUnsafeSrc(crypto_info.rec_seq, client_rec_seq_.data());
    safeMemcpyUnsafeSrc(crypto_info.salt, client_salt_.data());
  } else {
    if (server_key_.size() != sizeof(crypto_info.key) ||
        server_iv_.size() != sizeof(crypto_info.iv) ||
        server_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    // Copy data from vectors to crypto_info struct
    safeMemcpyUnsafeSrc(crypto_info.key, server_key_.data());
    safeMemcpyUnsafeSrc(crypto_info.iv, server_iv_.data());
    safeMemcpyUnsafeSrc(crypto_info.rec_seq, server_rec_seq_.data());
    safeMemcpyUnsafeSrc(crypto_info.salt, server_salt_.data());
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

    // Copy data from vectors to crypto_info struct
    safeMemcpyUnsafeSrc(crypto_info.key, server_key_.data());
    safeMemcpyUnsafeSrc(crypto_info.iv, server_iv_.data());
    safeMemcpyUnsafeSrc(crypto_info.rec_seq, server_rec_seq_.data());
    safeMemcpyUnsafeSrc(crypto_info.salt, server_salt_.data());
  } else {
    if (client_key_.size() != sizeof(crypto_info.key) ||
        client_iv_.size() != sizeof(crypto_info.iv) ||
        client_rec_seq_.size() != sizeof(crypto_info.rec_seq)) {
      return false;
    }

    // Copy data from vectors to crypto_info struct
    safeMemcpyUnsafeSrc(crypto_info.key, client_key_.data());
    safeMemcpyUnsafeSrc(crypto_info.iv, client_iv_.data());
    safeMemcpyUnsafeSrc(crypto_info.rec_seq, client_rec_seq_.data());
    safeMemcpyUnsafeSrc(crypto_info.salt, client_salt_.data());
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
  // Check if we already extracted params
  if (params_extracted_) {
    return true;
  }

  // Get the SSL object from ConnectionInfo
  // We need to cast to ConnectionInfoImplBase which provides ssl() access
  const Extensions::TransportSockets::Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Extensions::TransportSockets::Tls::ConnectionInfoImplBase*>(
          ssl_info_.get());
  if (!impl_base) {
    ENVOY_LOG(debug, "Cannot cast SSL info to ConnectionInfoImplBase");
    return false;
  }

  SSL* ssl_handle = impl_base->ssl();
  if (!ssl_handle) {
    ENVOY_LOG(debug, "Failed to get SSL handle from ConnectionInfo");
    return false;
  }

  // Get the SSL_SESSION which contains key material
  SSL_SESSION* session = SSL_get_session(ssl_handle);
  if (!session) {
    ENVOY_LOG(debug, "Failed to get SSL session, handshake may not be complete");
    return false;
  }

  // Determine if this is a client or server
  is_client_ = SSL_is_server(ssl_handle) == 0;
  ENVOY_LOG(debug, "This endpoint is acting as {}", is_client_ ? "client" : "server");

  // Check if the TLS version is supported
  const char* version_str = SSL_get_version(ssl_handle);
  if (version_str == nullptr || std::string(version_str) != "TLSv1.2") {
    ENVOY_LOG(debug, "Unsupported TLS version for kTLS: {}",
              version_str != nullptr ? version_str : "null");
    return false;
  }

  // Check if the cipher suite is supported (AES128-GCM)
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_handle);
  if (cipher == nullptr) {
    ENVOY_LOG(debug, "Failed to get current cipher");
    return false;
  }

  // Get cipher name directly from SSL_CIPHER_get_name
  const char* cipher_name = SSL_CIPHER_get_name(cipher);
  if (!cipher_name || strstr(cipher_name, "AES128-GCM") == nullptr) {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}", cipher_name ? cipher_name : "unknown");
    return false;
  }
  ENVOY_LOG(debug, "Using cipher: {}", cipher_name);

  // Get client and server random values
  uint8_t client_random[SSL3_RANDOM_SIZE];
  uint8_t server_random[SSL3_RANDOM_SIZE];
  memset(client_random, 0, SSL3_RANDOM_SIZE);
  memset(server_random, 0, SSL3_RANDOM_SIZE);

  if (SSL_get_client_random(ssl_handle, client_random, SSL3_RANDOM_SIZE) != SSL3_RANDOM_SIZE) {
    ENVOY_LOG(debug, "Failed to get client random");
    return false;
  }

  if (SSL_get_server_random(ssl_handle, server_random, SSL3_RANDOM_SIZE) != SSL3_RANDOM_SIZE) {
    ENVOY_LOG(debug, "Failed to get server random");
    return false;
  }

  // Get master key
  uint8_t master_key[SSL_MAX_MASTER_KEY_LENGTH];
  memset(master_key, 0, SSL_MAX_MASTER_KEY_LENGTH);
  size_t master_key_length =
      SSL_SESSION_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
  if (master_key_length == 0) {
    ENVOY_LOG(debug, "Failed to get master key");
    return false;
  }
  ENVOY_LOG(debug, "Master key length: {}", master_key_length);

  // TLS 1.2 key derivation (RFC 5246)
  // For TLS 1.2, we need to derive:
  // 1. Client write key and IV (for encryption when we're client, decryption when server)
  // 2. Server write key and IV (for encryption when we're server, decryption when client)

  // Allocate memory for keys and IVs
  client_key_.resize(16);       // AES-128-GCM key is 16 bytes
  server_key_.resize(16);       // AES-128-GCM key is 16 bytes
  client_salt_.resize(4);       // Salt is first 4 bytes of IV
  server_salt_.resize(4);       // Salt is first 4 bytes of IV
  client_iv_.resize(8);         // Explicit nonce is 8 bytes
  server_iv_.resize(8);         // Explicit nonce is 8 bytes
  client_rec_seq_.resize(8, 0); // Start with sequence 0
  server_rec_seq_.resize(8, 0); // Start with sequence 0

  // Use OpenSSL's key expansion function to derive key material
  // We need 2 keys (client, server) of 16 bytes each, and 2 IVs (client, server) of 12 bytes each
  uint8_t key_block[64]; // Plenty of space for key material
  memset(key_block, 0, sizeof(key_block));

  // Define key expansion label and seed
  const char* label = "key expansion";
  uint8_t seed[SSL3_RANDOM_SIZE * 2];
  memcpy(seed, server_random, SSL3_RANDOM_SIZE);
  memcpy(seed + SSL3_RANDOM_SIZE, client_random, SSL3_RANDOM_SIZE);

  // Use TLS PRF to derive key material
  if (!SSL_export_keying_material(ssl_handle, key_block, sizeof(key_block), label, strlen(label),
                                  seed, sizeof(seed), 0)) {
    ENVOY_LOG(debug, "Failed to export keying material");
    return false;
  }

  // Parse key block according to TLS 1.2 with AES-128-GCM
  // Key block format (in bytes):
  // [client write key(16)][server write key(16)][client write IV(12)][server write IV(12)]
  memcpy(client_key_.data(), key_block, 16);
  memcpy(server_key_.data(), key_block + 16, 16);

  // For kTLS with AES-GCM, IV is split into salt (first 4 bytes) and explicit nonce (8 bytes)
  memcpy(client_salt_.data(), key_block + 32, 4);
  memcpy(client_iv_.data(), key_block + 36, 8);
  memcpy(server_salt_.data(), key_block + 44, 4);
  memcpy(server_iv_.data(), key_block + 48, 8);

  // Record sequence numbers start at 0
  memset(client_rec_seq_.data(), 0, client_rec_seq_.size());
  memset(server_rec_seq_.data(), 0, server_rec_seq_.size());

  ENVOY_LOG(debug, "Successfully extracted key material for kTLS");
  params_extracted_ = true;
  return true;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
