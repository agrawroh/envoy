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
#include "source/common/tls/utility.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

KtlsSslInfoImpl::KtlsSslInfoImpl(Ssl::ConnectionInfoConstSharedPtr ssl_info)
    : ssl_info_(ssl_info), is_client_(false), params_extracted_(false) {}

absl::string_view KtlsSslInfoImpl::tlsVersion() const { return ssl_info_->tlsVersion(); }

absl::string_view KtlsSslInfoImpl::cipherSuite() const {
  std::string cipher_str = ssl_info_->ciphersuiteString();
  // Store the string so we can return a string_view to it
  cipher_suite_storage_ = cipher_str;
  return cipher_suite_storage_;
}

bool KtlsSslInfoImpl::getTxCryptoInfo(tls_crypto_info_t& crypto_info) const {
  if (!params_extracted_) {
    ENVOY_LOG(debug, "Cannot get TX crypto info: parameters not extracted yet");
    return false;
  }

  // Fill in common fields - zero initialize the structure
  tls_crypto_info_t zeroed_info = {};
  crypto_info = zeroed_info;

  if (tlsVersion() == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else {
    // Only support TLS 1.2 for now
    ENVOY_LOG(debug, "Cannot get TX crypto info: unsupported TLS version: {}",
              !tlsVersion().empty() ? std::string(tlsVersion()) : "empty");
    return false;
  }

  crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;

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

  return true;
}

bool KtlsSslInfoImpl::getRxCryptoInfo(tls_crypto_info_t& crypto_info) const {
  if (!params_extracted_) {
    ENVOY_LOG(debug, "Cannot get RX crypto info: parameters not extracted yet");
    return false;
  }

  // Fill in common fields - zero initialize the structure
  tls_crypto_info_t zeroed_info = {};
  crypto_info = zeroed_info;

  if (tlsVersion() == "TLSv1.2") {
    crypto_info.version = TLS_1_2_VERSION;
  } else {
    // Only support TLS 1.2 for now
    ENVOY_LOG(debug, "Cannot get RX crypto info: unsupported TLS version: {}",
              !tlsVersion().empty() ? std::string(tlsVersion()) : "empty");
    return false;
  }

  crypto_info.cipher_type = TLS_CIPHER_AES_GCM_128;

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

  return true;
}

bool KtlsSslInfoImpl::extractCryptoParams() const {
  ENVOY_LOG(debug, "Extracting crypto parameters for kTLS");

  // Get the underlying cipher suite
  std::string cipher = std::string(cipherSuite());
  ENVOY_LOG(debug, "Cipher suite: {}", cipher);

  // For TLS 1.2, we need to ensure we use an AES-GCM-128 cipher
  if (cipher.find("AES128-GCM") == std::string::npos &&
      cipher.find("AES-128-GCM") == std::string::npos) {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}. Only AES-GCM-128 is supported.", cipher);
    return false;
  }

  // Check if we successfully extracted the key material
  if (!extractKeyMaterial()) {
    ENVOY_LOG(debug, "Failed to extract key material");
    return false;
  }

  // Validate the extracted parameters
  if (params_extracted_) {
    ENVOY_LOG(debug, "Crypto params extraction successful");

    // Debug log the parameter lengths (not the actual contents for security)
    ENVOY_LOG(debug, "Client key size: {}, Server key size: {}", client_write_key_.size(),
              server_write_key_.size());
    ENVOY_LOG(debug, "Client IV size: {}, Server IV size: {}", client_write_iv_.size(),
              server_write_iv_.size());
    ENVOY_LOG(debug, "Client salt size: {}, Server salt size: {}",
              client_write_iv_.size() >= 4 ? 4 : 0, server_write_iv_.size() >= 4 ? 4 : 0);

    // Validate key size - must be 16 bytes for AES-128-GCM
    if (client_write_key_.size() != 16 || server_write_key_.size() != 16) {
      ENVOY_LOG(debug, "Invalid key size for AES-128-GCM (expected 16 bytes)");
      params_extracted_ = false;
      return false;
    }

    // Validate IV size - must be at least 12 bytes for GCM (should be 12 exactly in TLS 1.2)
    if (client_write_iv_.size() < 12 || server_write_iv_.size() < 12) {
      ENVOY_LOG(debug, "Invalid IV size for GCM (expected at least 12 bytes)");
      params_extracted_ = false;
      return false;
    }

    // Ensure sequence numbers are initialized
    if (client_write_seq_.size() != 8 || server_write_seq_.size() != 8) {
      ENVOY_LOG(debug, "Invalid sequence number size (expected 8 bytes)");
      params_extracted_ = false;
      return false;
    }
  } else {
    ENVOY_LOG(debug, "Parameter extraction reported false");
    return false;
  }

  return params_extracted_;
}

bool KtlsSslInfoImpl::extractKeyMaterial() const {
  // Check if we already extracted params
  if (params_extracted_) {
    return true;
  }

  ENVOY_LOG(debug, "Starting key material extraction for kTLS");

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

  if (SSL_in_init(ssl_handle) != 0) {
    ENVOY_LOG(debug, "Handshake not complete, cannot extract key material for kTLS yet.");
    return false;
  }

  SSL_SESSION* session = SSL_get_session(ssl_handle);
  if (!session) {
    ENVOY_LOG(debug, "Failed to get SSL session");
    return false;
  }

  is_client_ = (SSL_is_server(ssl_handle) == 0);
  ENVOY_LOG(debug, "SSL connection is {}", is_client_ ? "client" : "server");

  const SSL_CIPHER* cipher = SSL_SESSION_get0_cipher(session);
  if (!cipher) {
    ENVOY_LOG(debug, "Failed to get cipher from SSL session");
    return false;
  }

  const EVP_CIPHER* evp_cipher = nullptr;
  const char* cipher_name = SSL_CIPHER_get_name(cipher);
  ENVOY_LOG(debug, "Cipher name from SSL: {}", cipher_name ? cipher_name : "null");

  if (cipher_name && (strstr(cipher_name, "AES128-GCM") || strstr(cipher_name, "AES-128-GCM"))) {
    evp_cipher = EVP_aes_128_gcm();
    ENVOY_LOG(debug, "Using AES-128-GCM for key extraction");
  } else {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}", cipher_name ? cipher_name : "unknown");
    return false;
  }

  if (!evp_cipher) {
    ENVOY_LOG(debug, "Failed to get EVP cipher");
    return false;
  }

  int key_len = EVP_CIPHER_key_length(evp_cipher);
  int expected_iv_len = 12;
  ENVOY_LOG(debug, "Cipher key length: {}, Expected IV length for kTLS: {}", key_len,
            expected_iv_len);

  client_write_key_.resize(key_len);
  server_write_key_.resize(key_len);
  client_write_iv_.resize(expected_iv_len);
  server_write_iv_.resize(expected_iv_len);
  client_write_seq_.resize(8);
  server_write_seq_.resize(8);

  const char* client_key_label = "EXPORTER_CLIENT_WRITE_KEY";
  const char* server_key_label = "EXPORTER_SERVER_WRITE_KEY";
  const char* client_iv_label = "EXPORTER_CLIENT_WRITE_IV";
  const char* server_iv_label = "EXPORTER_SERVER_WRITE_IV";
  const uint8_t context[] = {};

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

  // Initialize sequence number vectors with zeros
  // The actual sequence numbers will be set in initializeSequenceNumbers
  // based on kernel version capabilities
  memset(client_write_seq_.data(), 0, 8);
  memset(server_write_seq_.data(), 0, 8);

  ENVOY_LOG(debug, "Successfully extracted TLS key material");

  ENVOY_LOG(debug, "Client write key size: {}", client_write_key_.size());
  ENVOY_LOG(debug, "Server write key size: {}", server_write_key_.size());
  ENVOY_LOG(debug, "Client write IV size: {}", client_write_iv_.size());
  ENVOY_LOG(debug, "Server write IV size: {}", server_write_iv_.size());
  ENVOY_LOG(debug, "Client write SEQ size: {}", client_write_seq_.size());
  ENVOY_LOG(debug, "Server write SEQ size: {}", server_write_seq_.size());

  params_extracted_ = true;
  return true;
}

bool KtlsSslInfoImpl::initializeSequenceNumbers(int ktls_mode) const {
  // Make sure we have extracted parameters first
  if (!params_extracted_ || !extractCryptoParams()) {
    ENVOY_LOG(debug, "Cannot initialize sequence numbers: parameters not extracted");
    return false;
  }

  // Get the SSL handle to access current sequence numbers
  SSL* ssl_handle = nullptr;
  const Extensions::TransportSockets::Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Extensions::TransportSockets::Tls::ConnectionInfoImplBase*>(
          ssl_info_.get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
  }

  if (!ssl_handle) {
    ENVOY_LOG(debug, "Cannot initialize sequence numbers: no SSL handle");
    return false;
  }

  // Get current sequence numbers - FIXED: The order of these is switched on server side
  // For client: TX = write, RX = read
  // For server: TX = read, RX = write  <-- This was incorrect
  // Correct mapping: For both client and server, TX = write_sequence, RX = read_sequence
  uint64_t current_tx_seq = SSL_get_write_sequence(ssl_handle);
  uint64_t current_rx_seq = SSL_get_read_sequence(ssl_handle);

  ENVOY_LOG(debug, "Current SSL sequence numbers - TX: {}, RX: {}", current_tx_seq, current_rx_seq);

  // Handle sequence numbers based on kernel mode:
  // ktls_mode = 0: Basic kTLS (4.13-4.16) - requires zero sequence numbers
  // ktls_mode = 1: Partial support (4.17-5.14) - can handle non-zero but with limitations
  // ktls_mode = 2: Full support (5.15+) - fully supports non-zero sequence numbers

  uint64_t tx_seq_to_use, rx_seq_to_use;

  if (ktls_mode >= 2) {
    // Full non-zero sequence number support
    ENVOY_LOG(debug, "Using full non-zero sequence number support (kernel 5.15+)");
    tx_seq_to_use = current_tx_seq;
    rx_seq_to_use = current_rx_seq;
  } else if (ktls_mode == 1) {
    // Partial non-zero sequence number support
    // Use sequence numbers if they're both small (< 1000), otherwise zero them
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
    // Basic support - must use zero sequence numbers
    ENVOY_LOG(debug, "Using zeroed sequence numbers for basic kTLS support (kernel 4.13-4.16)");
    tx_seq_to_use = 0;
    rx_seq_to_use = 0;
  }

  // Update the sequence numbers in our buffers
  uint64_t seq_num_hton;

  // Always initialize sequence number vectors first
  client_write_seq_.resize(8, 0);
  server_write_seq_.resize(8, 0);

  ENVOY_LOG(debug, "Using sequence numbers for kTLS: TX={}, RX={}", tx_seq_to_use, rx_seq_to_use);

  if (is_client_) {
    // CLIENT SIDE HANDLING
    // Write to client_write_seq_ (client sending direction)
    seq_num_hton = htobe64(tx_seq_to_use);
    memcpy(client_write_seq_.data(), &seq_num_hton, sizeof(seq_num_hton));

    // Write to server_write_seq_ (server sending to client direction)
    seq_num_hton = htobe64(rx_seq_to_use);
    memcpy(server_write_seq_.data(), &seq_num_hton, sizeof(seq_num_hton));
  } else {
    // SERVER SIDE HANDLING
    // Write to server_write_seq_ (server sending direction)
    seq_num_hton = htobe64(tx_seq_to_use);
    memcpy(server_write_seq_.data(), &seq_num_hton, sizeof(seq_num_hton));

    // Write to client_write_seq_ (client sending to server direction)
    seq_num_hton = htobe64(rx_seq_to_use);
    memcpy(client_write_seq_.data(), &seq_num_hton, sizeof(seq_num_hton));
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
