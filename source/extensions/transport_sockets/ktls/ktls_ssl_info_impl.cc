#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"

#include <algorithm>
#include <random>

#include "source/common/common/assert.h"
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
    ENVOY_LOG(debug, "Client key size: {}, Server key size: {}", 
              client_write_key_.size(), server_write_key_.size());
    ENVOY_LOG(debug, "Client IV size: {}, Server IV size: {}", 
              client_write_iv_.size(), server_write_iv_.size());
    ENVOY_LOG(debug, "Client salt size: {}, Server salt size: {}", 
              client_write_iv_.size() >= 4 ? 4 : 0, 
              server_write_iv_.size() >= 4 ? 4 : 0);
              
    // Validate key size - must be 16 bytes for AES-128-GCM
    if (client_write_key_.size() != 16 || server_write_key_.size() != 16) {
      ENVOY_LOG(debug, "Invalid key size for AES-128-GCM (expected 16 bytes)");
      params_extracted_ = false;
    }
    
    // Validate IV size - must be at least 8 bytes for GCM
    if (client_write_iv_.size() < 8 || server_write_iv_.size() < 8) {
      ENVOY_LOG(debug, "Invalid IV size for GCM (expected at least 8 bytes)");
      params_extracted_ = false;
    }
  }
  
  return params_extracted_;
}

bool KtlsSslInfoImpl::extractKeyMaterial() const {
  // Check if we already extracted params
  if (params_extracted_) {
    return true;
  }

  ENVOY_LOG(debug, "Starting key material extraction for kTLS");
  
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
    ENVOY_LOG(debug, "Failed to get SSL session");
    return false;
  }

  // Determine if we're the client or server
  int is_server = SSL_is_server(ssl_handle);
  is_client_ = !is_server;
  ENVOY_LOG(debug, "SSL connection is {}", is_client_ ? "client" : "server");

  // Get the master key
  const SSL_CIPHER* cipher = SSL_SESSION_get0_cipher(session);
  if (!cipher) {
    ENVOY_LOG(debug, "Failed to get cipher from SSL session");
    return false;
  }

  // Determine the key size based on the cipher
  const EVP_CIPHER* evp_cipher = NULL;
  
  // For AES-128-GCM
  const char* cipher_name = SSL_CIPHER_get_name(cipher);
  ENVOY_LOG(debug, "Cipher name from SSL: {}", cipher_name ? cipher_name : "null");
  
  if (cipher_name && (strstr(cipher_name, "AES128-GCM") || strstr(cipher_name, "AES-128-GCM"))) {
    evp_cipher = EVP_aes_128_gcm();
    ENVOY_LOG(debug, "Using AES-128-GCM for key extraction");
  } else {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS");
    return false;
  }

  if (!evp_cipher) {
    ENVOY_LOG(debug, "Failed to get EVP cipher");
    return false;
  }

  // Get the key length
  int key_len = EVP_CIPHER_key_length(evp_cipher);
  int iv_len = EVP_CIPHER_iv_length(evp_cipher);
  ENVOY_LOG(debug, "Cipher key length: {}, IV length: {}", key_len, iv_len);

  // Buffer for key material
  client_write_key_.resize(key_len);
  server_write_key_.resize(key_len);
  
  // For TLS 1.2 GCM, the IV is 4 byte salt + 8 byte nonce
  // The kernel expects the full 12 bytes
  client_write_iv_.resize(12);
  server_write_iv_.resize(12);
  
  // Resize sequence numbers (8 bytes per TLS spec)
  client_write_seq_.resize(8, 0);
  server_write_seq_.resize(8, 0);

  // Extract key material using OpenSSL's exporters
  const char* client_key_label = "EXPORTER_CLIENT_WRITE_KEY";
  const char* server_key_label = "EXPORTER_SERVER_WRITE_KEY";
  const char* client_iv_label = "EXPORTER_CLIENT_WRITE_IV";
  const char* server_iv_label = "EXPORTER_SERVER_WRITE_IV";
  
  // Empty context for TLS 1.2
  const uint8_t context[] = {};
  
  // Extract client write key
  if (SSL_export_keying_material(ssl_handle, 
                                client_write_key_.data(), key_len,
                                client_key_label, strlen(client_key_label),
                                context, 0, 0) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ENVOY_LOG(debug, "Failed to export client write key: {}", err_buf);
    return false;
  }
  
  // Extract server write key
  if (SSL_export_keying_material(ssl_handle, 
                                server_write_key_.data(), key_len,
                                server_key_label, strlen(server_key_label),
                                context, 0, 0) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ENVOY_LOG(debug, "Failed to export server write key: {}", err_buf);
    return false;
  }
  
  // Extract client write IV
  if (SSL_export_keying_material(ssl_handle, 
                                client_write_iv_.data(), 12,
                                client_iv_label, strlen(client_iv_label),
                                context, 0, 0) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ENVOY_LOG(debug, "Failed to export client write IV: {}", err_buf);
    return false;
  }
  
  // Extract server write IV
  if (SSL_export_keying_material(ssl_handle, 
                                server_write_iv_.data(), 12,
                                server_iv_label, strlen(server_iv_label),
                                context, 0, 0) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ENVOY_LOG(debug, "Failed to export server write IV: {}", err_buf);
    return false;
  }

  ENVOY_LOG(debug, "Successfully extracted TLS key material");
  
  // Log key material sizes for debugging
  ENVOY_LOG(debug, "Client write key size: {}", client_write_key_.size());
  ENVOY_LOG(debug, "Server write key size: {}", server_write_key_.size());
  ENVOY_LOG(debug, "Client write IV size: {}", client_write_iv_.size());
  ENVOY_LOG(debug, "Server write IV size: {}", server_write_iv_.size());

  // Set the flag indicating we've extracted the parameters
  params_extracted_ = true;
  return true;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
