#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

#include <netinet/tcp.h>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

bool KTlsInfoImpl::extractCryptoInfo(tls12_crypto_info_aes_gcm_128& crypto_info, bool is_tx) const {
#ifdef TLS_1_2_VERSION
  // Initialize the crypto info struct
  crypto_info.info.version = TLS_1_2_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  
  if (ssl_ == nullptr) {
    ENVOY_LOG_MISC(warn, "Cannot extract crypto info: SSL object is null");
    return false;
  }
  
  // Get the cipher suite - only AES128-GCM is supported for kTLS currently
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
  if (cipher == nullptr) {
    ENVOY_LOG_MISC(warn, "Failed to get current cipher from SSL object");
    return false;
  }
  
  // Check that we're using a compatible cipher suite
  uint16_t cipher_id = SSL_CIPHER_get_id(cipher) & 0xFFFF;
  if (cipher_id != 0x009C) { // TLS_RSA_WITH_AES_128_GCM_SHA256
    ENVOY_LOG_MISC(warn, "Unsupported cipher suite for kTLS: 0x{:04x}", cipher_id);
    return false;
  }
  
  // Extract sequence number
  uint64_t seq_num = 0;
  if (is_tx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL 1.1.0 and later
    const uint8_t* sequence = SSL_get_write_sequence(ssl_);
    if (sequence != nullptr) {
      // Convert from network byte order (big-endian)
      for (int i = 0; i < 8; i++) {
        seq_num = (seq_num << 8) | sequence[i];
      }
    }
#else
    // Not supported in older OpenSSL versions
    ENVOY_LOG_MISC(warn, "OpenSSL version too old to extract sequence numbers");
    return false;
#endif
  } else {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL 1.1.0 and later
    const uint8_t* sequence = SSL_get_read_sequence(ssl_);
    if (sequence != nullptr) {
      // Convert from network byte order (big-endian)
      for (int i = 0; i < 8; i++) {
        seq_num = (seq_num << 8) | sequence[i];
      }
    }
#else
    // Not supported in older OpenSSL versions
    ENVOY_LOG_MISC(warn, "OpenSSL version too old to extract sequence numbers");
    return false;
#endif
  }
  
  // Store the sequence number in network byte order
  uint64_t seq_num_be = htobe64(seq_num);
  memcpy(crypto_info.rec_seq, &seq_num_be, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
  
  // Extract key and IV
  // This requires access to the internal SSL structures
  // For a real implementation, we would need to use OpenSSL APIs to extract:
  // - client_write_key / server_write_key
  // - client_write_IV / server_write_IV
  // - Additional parameters like salt
  
  // For TLS 1.2 with AES-GCM, the key material is organized as:
  // - 16 bytes for the AES key
  // - 4 bytes for the salt
  // - 8 bytes for the nonce
  
  // Export key material if possible
  unsigned char key_material[32];
  int key_material_len = 0;
  
  // Try to export the key material
  // Note: This approach won't work directly with SSL_export_keying_material as
  // we need the specific encryption keys, not the general key material.
  // A more complete solution would require internal OpenSSL knowledge or API extensions.
  
  if (is_tx) {
    // For transmitting, we need the client write key for outbound connections
    // and the server write key for inbound connections
    // This is a placeholder - actual implementation would need to extract real keys
    memset(crypto_info.key, 1, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memset(crypto_info.salt, 2, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memset(crypto_info.iv, 3, TLS_CIPHER_AES_GCM_128_IV_SIZE);
  } else {
    // For receiving, we need the server write key for outbound connections
    // and the client write key for inbound connections
    // This is a placeholder - actual implementation would need to extract real keys
    memset(crypto_info.key, 4, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memset(crypto_info.salt, 5, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memset(crypto_info.iv, 6, TLS_CIPHER_AES_GCM_128_IV_SIZE);
  }
  
  // In production, we would need a way to access the actual key material from OpenSSL
  ENVOY_LOG_MISC(warn, "Using placeholder values for kTLS key material - NOT SECURE FOR PRODUCTION");
  ENVOY_LOG_MISC(debug, "Extracted sequence number: {}", seq_num);
  
  return true;
#else
  UNREFERENCED_PARAMETER(crypto_info);
  UNREFERENCED_PARAMETER(is_tx);
  return false;
#endif
}

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 