#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

#include <algorithm>
#include <random>

#include "source/common/common/assert.h"
#include "source/common/common/byte_order.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/network/utility.h"
#include "source/common/tls/connection_info_impl_base.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

KtlsSslInfoImpl::KtlsSslInfoImpl(Network::TransportSocketPtr&& ssl_socket)
    : ssl_socket_(std::move(ssl_socket)), is_client_(false), params_extracted_(false) {
  // Attempt to extract parameters immediately, but don't fail if they're not ready yet
  extractCryptoParams();
}

const std::string& KtlsSslInfoImpl::tlsVersion() const {
  if (ssl_socket_ && ssl_socket_->ssl()) {
    tls_version_storage_ = ssl_socket_->ssl()->tlsVersion();
    return tls_version_storage_;
  }
  static const std::string empty_string;
  return empty_string;
}

const std::string& KtlsSslInfoImpl::ciphersuiteString() const {
  if (ssl_socket_ && ssl_socket_->ssl()) {
    cipher_suite_storage_ = ssl_socket_->ssl()->ciphersuiteString();
    return cipher_suite_storage_;
  }
  static const std::string empty_string;
  return empty_string;
}

const std::string& KtlsSslInfoImpl::sessionId() const {
  if (ssl_socket_ && ssl_socket_->ssl()) {
    session_id_storage_ = ssl_socket_->ssl()->sessionId();
    return session_id_storage_;
  }
  static const std::string empty_string;
  return empty_string;
}

bool KtlsSslInfoImpl::peerCertificatePresented() const {
  if (ssl_socket_ && ssl_socket_->ssl()) {
    return ssl_socket_->ssl()->peerCertificatePresented();
  }
  return false;
}

bool KtlsSslInfoImpl::peerCertificateValidated() const {
  if (ssl_socket_ && ssl_socket_->ssl()) {
    return ssl_socket_->ssl()->peerCertificateValidated();
  }
  return false;
}

Ssl::ConnectionInfoConstSharedPtr KtlsSslInfoImpl::ssl() const {
  return ssl_socket_ ? ssl_socket_->ssl() : nullptr;
}

bool KtlsSslInfoImpl::getTxCryptoInfo(tls_crypto_info_t& crypto_info) {
  // Try to extract params if not already done
  if (!params_extracted_) {
    if (!extractCryptoParams()) {
      ENVOY_LOG(debug, "Cannot get TX crypto info: failed to extract parameters");
      return false;
    }
  }

  if (!params_extracted_) {
    ENVOY_LOG(debug, "Cannot get TX crypto info: parameters not extracted yet");
    return false;
  }

  // Fill in common fields - zero initialize the structure
  memset(&crypto_info, 0, sizeof(crypto_info));

  std::string tls_version_str = tlsVersion();
  if (tls_version_str == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else if (tls_version_str == "TLSv1.3") {
    // TLS 1.3 is also supported by kTLS since kernel 5.1
    crypto_info.version = TLS_1_3_VERSION;
  } else {
    ENVOY_LOG(debug, "Cannot get TX crypto info: unsupported TLS version: '{}'",
              tls_version_str);
    return false;
  }

  // Get cipher name to determine the cipher type for kTLS
  std::string cipher = ciphersuiteString();
  ENVOY_LOG(debug, "Using cipher for TX crypto: '{}'", cipher);

  // Determine cipher type
  if (cipher.find("AES128-GCM") != std::string::npos ||
      cipher.find("AES-128-GCM") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;
  } else if (cipher.find("AES256-GCM") != std::string::npos ||
             cipher.find("AES-256-GCM") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_AES_GCM_256;
  } else if (cipher.find("CHACHA20") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
    ENVOY_LOG(warn, "CHACHA20-POLY1305 support in kTLS may not be complete");
  } else {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: '{}'", cipher);
    return false;
  }

  // Use client or server keys based on whether we're the client or server
  if (is_client_) {
    // Client endpoint sending data - use client_write_key/iv
    if (client_write_key_.size() != 16 || client_write_iv_.size() < 12) {
      ENVOY_LOG(debug, "Invalid client TX crypto material sizes: key={}, iv={}",
                client_write_key_.size(), client_write_iv_.size());
      return false;
    }

    // Copy the key
    memcpy(crypto_info.key, client_write_key_.data(), 16);

    // Copy the salt (first 4 bytes of IV)
    memcpy(crypto_info.salt, client_write_iv_.data(), 4);

    // Copy the IV (next 8 bytes)
    memcpy(crypto_info.iv, client_write_iv_.data() + 4, 8);

    // Copy the record sequence number
    memcpy(crypto_info.rec_seq, client_write_seq_.data(), 8);

    ENVOY_LOG(debug, "Using client write key/IV for TX (we are client)");
  } else {
    // Server endpoint sending data - use server_write_key/iv
    if (server_write_key_.size() != 16 || server_write_iv_.size() < 12) {
      ENVOY_LOG(debug, "Invalid server TX crypto material sizes: key={}, iv={}",
                server_write_key_.size(), server_write_iv_.size());
      return false;
    }

    // Copy the key
    memcpy(crypto_info.key, server_write_key_.data(), 16);

    // Copy the salt (first 4 bytes of IV)
    memcpy(crypto_info.salt, server_write_iv_.data(), 4);

    // Copy the IV (next 8 bytes)
    memcpy(crypto_info.iv, server_write_iv_.data() + 4, 8);

    // Copy the record sequence number
    memcpy(crypto_info.rec_seq, server_write_seq_.data(), 8);

    ENVOY_LOG(debug, "Using server write key/IV for TX (we are server)");
  }

  // Dump some debug info about the TX crypto
  uint64_t seq_num;
  memcpy(&seq_num, crypto_info.rec_seq, sizeof(seq_num));
  ENVOY_LOG(debug, "TX rec_seq (big-endian): {:#016x}, decoded: {}", seq_num, be64toh(seq_num));

  return true;
}

bool KtlsSslInfoImpl::getRxCryptoInfo(tls_crypto_info_t& crypto_info) {
  // Try to extract params if not already done
  if (!params_extracted_) {
    if (!extractCryptoParams()) {
      ENVOY_LOG(debug, "Cannot get RX crypto info: failed to extract parameters");
      return false;
    }
  }

  if (!params_extracted_) {
    ENVOY_LOG(debug, "Cannot get RX crypto info: parameters not extracted yet");
    return false;
  }

  // Fill in common fields - zero initialize the structure
  memset(&crypto_info, 0, sizeof(crypto_info));

  std::string tls_version_str = tlsVersion();
  if (tls_version_str == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else if (tls_version_str == "TLSv1.3") {
    // TLS 1.3 is also supported by kTLS since kernel 5.1
    crypto_info.version = TLS_1_3_VERSION;
  } else {
    ENVOY_LOG(debug, "Cannot get RX crypto info: unsupported TLS version: '{}'",
              tls_version_str);
    return false;
  }

  // Get cipher name to determine the cipher type for kTLS
  std::string cipher = ciphersuiteString();
  ENVOY_LOG(debug, "Using cipher for RX crypto: '{}'", cipher);

  // Determine cipher type
  if (cipher.find("AES128-GCM") != std::string::npos ||
      cipher.find("AES-128-GCM") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;
  } else if (cipher.find("AES256-GCM") != std::string::npos ||
             cipher.find("AES-256-GCM") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_AES_GCM_256;
  } else if (cipher.find("CHACHA20") != std::string::npos) {
    crypto_info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
    ENVOY_LOG(warn, "CHACHA20-POLY1305 support in kTLS may not be complete");
  } else {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: '{}'", cipher);
    return false;
  }

  // For receiving, use the opposite keys from transmitting
  if (is_client_) {
    // Client endpoint receiving data - use server_write_key/iv
    if (server_write_key_.size() != 16 || server_write_iv_.size() < 12) {
      ENVOY_LOG(debug, "Invalid server RX crypto material sizes: key={}, iv={}",
                server_write_key_.size(), server_write_iv_.size());
      return false;
    }

    // Copy the key
    memcpy(crypto_info.key, server_write_key_.data(), 16);

    // Copy the salt (first 4 bytes of IV)
    memcpy(crypto_info.salt, server_write_iv_.data(), 4);

    // Copy the IV (next 8 bytes)
    memcpy(crypto_info.iv, server_write_iv_.data() + 4, 8);

    // Copy the record sequence number
    memcpy(crypto_info.rec_seq, server_write_seq_.data(), 8);

    ENVOY_LOG(debug, "Using server write key/IV for RX (we are client)");
  } else {
    // Server endpoint receiving data - use client_write_key/iv
    if (client_write_key_.size() != 16 || client_write_iv_.size() < 12) {
      ENVOY_LOG(debug, "Invalid client RX crypto material sizes: key={}, iv={}",
                client_write_key_.size(), client_write_iv_.size());
      return false;
    }

    // Copy the key
    memcpy(crypto_info.key, client_write_key_.data(), 16);

    // Copy the salt (first 4 bytes of IV)
    memcpy(crypto_info.salt, client_write_iv_.data(), 4);

    // Copy the IV (next 8 bytes)
    memcpy(crypto_info.iv, client_write_iv_.data() + 4, 8);

    // Copy the record sequence number
    memcpy(crypto_info.rec_seq, client_write_seq_.data(), 8);

    ENVOY_LOG(debug, "Using client write key/IV for RX (we are server)");
  }

  // Dump some debug info about the RX crypto
  uint64_t seq_num;
  memcpy(&seq_num, crypto_info.rec_seq, sizeof(seq_num));
  ENVOY_LOG(debug, "RX rec_seq (big-endian): {:#016x}, decoded: {}", seq_num, be64toh(seq_num));

  return true;
}

bool KtlsSslInfoImpl::extractCryptoParams() {
  // Check if we already extracted
  if (params_extracted_) {
    ENVOY_LOG(debug, "Crypto parameters already extracted");
    return true;
  }

  ENVOY_LOG(debug, "Extracting crypto parameters for kTLS");

  // First, make sure we have a valid SSL connection
  if (!ssl_socket_ || !ssl_socket_->ssl()) {
    ENVOY_LOG(debug, "Cannot extract crypto params: no SSL connection");
    return false;
  }

  // Get the SSL handle to access the SSL object directly
  const Extensions::TransportSockets::Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Extensions::TransportSockets::Tls::ConnectionInfoImplBase*>(
          ssl_socket_->ssl().get());
  if (!impl_base) {
    ENVOY_LOG(debug, "Cannot cast SSL connection to ConnectionInfoImplBase");
    return false;
  }

  SSL* ssl_handle = impl_base->ssl();
  if (!ssl_handle) {
    ENVOY_LOG(debug, "Failed to get SSL handle");
    return false;
  }

  // Check if handshake is complete - no point extracting if not
  if (SSL_in_init(ssl_handle) != 0) {
    ENVOY_LOG(debug, "Handshake not complete, deferring key material extraction");
    return false;
  }

  // Check if the connection is a client or server
  is_client_ = (SSL_is_server(ssl_handle) == 0);
  ENVOY_LOG(debug, "SSL connection is {} side", is_client_ ? "client" : "server");

  // Get the underlying cipher suite
  std::string cipher = ciphersuiteString();
  if (cipher.empty()) {
    ENVOY_LOG(debug, "Cannot get cipher suite");
    return false;
  }
  ENVOY_LOG(debug, "Cipher suite: {}", cipher);

  // Currently, only AES-GCM is well supported in kTLS
  bool supports_cipher = false;
  if (cipher.find("AES128-GCM") != std::string::npos ||
      cipher.find("AES-128-GCM") != std::string::npos) {
    supports_cipher = true;
  } else if (cipher.find("AES256-GCM") != std::string::npos ||
             cipher.find("AES-256-GCM") != std::string::npos) {
    supports_cipher = true;
  } else if (cipher.find("CHACHA20") != std::string::npos) {
    // CHACHA20-POLY1305 is supported in newer kernels
    supports_cipher = true;
  }

  if (!supports_cipher) {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}. Only AES-GCM and CHACHA20-POLY1305 are supported.", cipher);
    return false;
  }

  // Now extract the actual key material
  if (!extractKeyMaterial(ssl_handle)) {
    ENVOY_LOG(debug, "Failed to extract key material");
    return false;
  }

  // Now that we've extracted keys, we need to initialize sequence numbers
  if (!initializeSequenceNumbers(2)) { // Use mode 2 for modern kernels
    ENVOY_LOG(debug, "Failed to initialize sequence numbers");
    params_extracted_ = false;
    return false;
  }

  ENVOY_LOG(debug, "Successfully extracted crypto parameters for kTLS");
  return true;
}

bool KtlsSslInfoImpl::extractKeyMaterial(SSL* ssl_handle) {
  // Check if we already extracted keys
  if (params_extracted_) {
    return true;
  }

  if (!ssl_handle) {
    ENVOY_LOG(debug, "Cannot extract key material: no SSL handle");
    return false;
  }

  ENVOY_LOG(debug, "Starting key material extraction for kTLS");

  if (SSL_in_init(ssl_handle) != 0) {
    ENVOY_LOG(debug, "Handshake not complete, cannot extract key material for kTLS yet.");
    return false;
  }

  SSL_SESSION* session = SSL_get_session(ssl_handle);
  if (!session) {
    ENVOY_LOG(debug, "Failed to get SSL session");
    return false;
  }

  const SSL_CIPHER* cipher = SSL_SESSION_get0_cipher(session);
  if (!cipher) {
    ENVOY_LOG(debug, "Failed to get cipher from SSL session");
    return false;
  }

  const EVP_CIPHER* evp_cipher = nullptr;
  const char* cipher_name = SSL_CIPHER_get_name(cipher);
  ENVOY_LOG(debug, "Cipher name from SSL: {}", cipher_name ? cipher_name : "null");

  // Determine the cipher parameters
  if (cipher_name && (strstr(cipher_name, "AES128-GCM") || strstr(cipher_name, "AES-128-GCM"))) {
    evp_cipher = EVP_aes_128_gcm();
    ENVOY_LOG(debug, "Using AES-128-GCM for key extraction");
  } else if (cipher_name && (strstr(cipher_name, "AES256-GCM") || strstr(cipher_name, "AES-256-GCM"))) {
    evp_cipher = EVP_aes_256_gcm();
    ENVOY_LOG(debug, "Using AES-256-GCM for key extraction");
  } else if (cipher_name && strstr(cipher_name, "CHACHA20")) {
    // Use a placeholder for CHACHA20
#ifdef EVP_CIPHER_CTX_FLAG_WRAP_ALLOW
    evp_cipher = EVP_chacha20_poly1305();
#else
    ENVOY_LOG(warn, "CHACHA20-POLY1305 not available in this OpenSSL version");
    return false;
#endif
    ENVOY_LOG(debug, "Using CHACHA20-POLY1305 for key extraction");
  } else {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}", cipher_name ? cipher_name : "unknown");
    return false;
  }

  if (!evp_cipher) {
    ENVOY_LOG(debug, "Failed to get EVP cipher");
    return false;
  }

  int key_len = EVP_CIPHER_key_length(evp_cipher);
  int expected_iv_len = 12; // GCM/CCM always uses 12 bytes in TLS
  ENVOY_LOG(debug, "Cipher key length: {}, Expected IV length for kTLS: {}", key_len,
            expected_iv_len);

  // Resize our vectors to hold the key material
  client_write_key_.resize(key_len);
  server_write_key_.resize(key_len);
  client_write_iv_.resize(expected_iv_len);
  server_write_iv_.resize(expected_iv_len);
  client_write_seq_.resize(8, 0); // 8-byte sequence number
  server_write_seq_.resize(8, 0);

  // Define the labels for exporting key material
  const char* client_key_label = "EXPORTER_CLIENT_WRITE_KEY";
  const char* server_key_label = "EXPORTER_SERVER_WRITE_KEY";
  const char* client_iv_label = "EXPORTER_CLIENT_WRITE_IV";
  const char* server_iv_label = "EXPORTER_SERVER_WRITE_IV";
  const uint8_t context[] = {}; // No context

  // Export the key material using TLS exporters
  // TLS 1.2 and TLS 1.3 both support these exporters
  if (SSL_export_keying_material(ssl_handle, client_write_key_.data(), key_len, client_key_label,
                                 strlen(client_key_label), context, 0, 0) != 1) {
    ENVOY_LOG(debug, "Failed to export client write key: {}",
              ERR_reason_error_string(ERR_get_error()));
    return false;
  }
  if (SSL_export_keying_material(ssl_handle, server_write_key_.data(), key_len, server_key_label,
                                 strlen(server_key_label), context, 0, 0) != 1) {
    ENVOY_LOG(debug, "Failed to export server write key: {}",
              ERR_reason_error_string(ERR_get_error()));
    return false;
  }
  if (SSL_export_keying_material(ssl_handle, client_write_iv_.data(), expected_iv_len,
                                 client_iv_label, strlen(client_iv_label), context, 0, 0) != 1) {
    ENVOY_LOG(debug, "Failed to export client write IV: {}",
              ERR_reason_error_string(ERR_get_error()));
    return false;
  }
  if (SSL_export_keying_material(ssl_handle, server_write_iv_.data(), expected_iv_len,
                                 server_iv_label, strlen(server_iv_label), context, 0, 0) != 1) {
    ENVOY_LOG(debug, "Failed to export server write IV: {}",
              ERR_reason_error_string(ERR_get_error()));
    return false;
  }

  // Sequence numbers will be initialized later in initializeSequenceNumbers
  ENVOY_LOG(debug, "Successfully extracted TLS key material");

  // Log the sizes of our exported keys (not the content, for security)
  ENVOY_LOG(debug, "Client write key size: {}", client_write_key_.size());
  ENVOY_LOG(debug, "Server write key size: {}", server_write_key_.size());
  ENVOY_LOG(debug, "Client write IV size: {}", client_write_iv_.size());
  ENVOY_LOG(debug, "Server write IV size: {}", server_write_iv_.size());
  ENVOY_LOG(debug, "Client write SEQ size: {}", client_write_seq_.size());
  ENVOY_LOG(debug, "Server write SEQ size: {}", server_write_seq_.size());

  params_extracted_ = true;
  return true;
}

bool KtlsSslInfoImpl::initializeSequenceNumbers(int ktls_mode) {
  // Make sure we have extracted parameters first
  if (!params_extracted_) {
    ENVOY_LOG(debug, "Cannot initialize sequence numbers: parameters not extracted");
    return false;
  }

  // Get the SSL handle to access current sequence numbers
  SSL* ssl_handle = nullptr;
  const Extensions::TransportSockets::Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Extensions::TransportSockets::Tls::ConnectionInfoImplBase*>(
          ssl_socket_->ssl().get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
  }

  if (!ssl_handle) {
    ENVOY_LOG(debug, "Cannot initialize sequence numbers: no SSL handle");
    return false;
  }

  // Get current sequence numbers from SSL
  uint64_t current_tx_seq = SSL_get_write_sequence(ssl_handle);
  uint64_t current_rx_seq = SSL_get_read_sequence(ssl_handle);

  ENVOY_LOG(debug, "Current SSL sequence numbers - TX: {}, RX: {}", current_tx_seq, current_rx_seq);

  // Handle sequence numbers based on kernel mode:
  // ktls_mode = 0: Basic kTLS (4.13-4.16) - requires zero sequence numbers
  // ktls_mode = 1: Partial support (4.17-5.14) - can handle non-zero but with limitations
  // ktls_mode = 2: Full support (5.15+) - fully supports non-zero sequence numbers
  uint64_t tx_seq_to_use, rx_seq_to_use;

  if (ktls_mode >= 2) {
    // Full non-zero sequence number support (5.15+)
    ENVOY_LOG(debug, "Using full non-zero sequence number support (kernel 5.15+)");
    tx_seq_to_use = current_tx_seq;
    rx_seq_to_use = current_rx_seq;
  } else if (ktls_mode == 1) {
    // Partial non-zero sequence number support (4.17-5.14)
    // Use sequence numbers if they're both small, otherwise zero them
    if (current_tx_seq < 1000 && current_rx_seq < 1000) {
      ENVOY_LOG(debug, "Using non-zero sequence numbers with partial support (kernel 4.17-5.14)");
      tx_seq_to_use = current_tx_seq;
      rx_seq_to_use = current_rx_seq;
    } else {
      ENVOY_LOG(warn,
                "Sequence numbers too large for partial support kernel: TX={}, RX={}. "
                "Falling back to zeroed sequence numbers.",
                current_tx_seq, current_rx_seq);
      tx_seq_to_use = 0;
      rx_seq_to_use = 0;
    }
  } else {
    // Basic support - must use zero sequence numbers (4.13-4.16)
    ENVOY_LOG(debug, "Using zeroed sequence numbers for basic kTLS support (kernel 4.13-4.16)");
    tx_seq_to_use = 0;
    rx_seq_to_use = 0;
  }

  ENVOY_LOG(debug, "Using sequence numbers for kTLS: TX={}, RX={}", tx_seq_to_use, rx_seq_to_use);

  // Convert to network byte order (big-endian)
  uint64_t tx_seq_be = htobe64(tx_seq_to_use);
  uint64_t rx_seq_be = htobe64(rx_seq_to_use);

  // Store in appropriate sequence vectors based on client/server role
  if (is_client_) {
    // CLIENT SIDE HANDLING
    // Client TX = client_write_seq_
    memcpy(client_write_seq_.data(), &tx_seq_be, sizeof(tx_seq_be));
    // Client RX = server_write_seq_
    memcpy(server_write_seq_.data(), &rx_seq_be, sizeof(rx_seq_be));
  } else {
    // SERVER SIDE HANDLING
    // Server TX = server_write_seq_
    memcpy(server_write_seq_.data(), &tx_seq_be, sizeof(tx_seq_be));
    // Server RX = client_write_seq_
    memcpy(client_write_seq_.data(), &rx_seq_be, sizeof(rx_seq_be));
  }

  // Verify the sequence numbers were properly stored in big endian
  uint64_t client_verify = 0, server_verify = 0;
  memcpy(&client_verify, client_write_seq_.data(), 8);
  memcpy(&server_verify, server_write_seq_.data(), 8);

  ENVOY_LOG(debug, "Client write seq stored as big-endian={:#016x}, decoded={}", client_verify,
            be64toh(client_verify));
  ENVOY_LOG(debug, "Server write seq stored as big-endian={:#016x}, decoded={}", server_verify,
            be64toh(server_verify));

  return true;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
