#include "source/extensions/transport_sockets/rustls/rustls_wrapper.h"

#include <cstring>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

// External C functions from rustls FFI library.
extern "C" {

struct rustls_connection_handle;
struct rustls_config_handle;

rustls_config_handle* rustls_client_config_new(const char* cert_pem, size_t cert_len,
                                                const char* key_pem, size_t key_len,
                                                const char* ca_pem, size_t ca_len,
                                                const char** alpn_protocols, size_t alpn_count);

rustls_config_handle* rustls_server_config_new(const char* cert_pem, size_t cert_len,
                                                const char* key_pem, size_t key_len,
                                                const char** alpn_protocols, size_t alpn_count);

void rustls_config_free(rustls_config_handle* config);

rustls_connection_handle* rustls_client_connection_new(const rustls_config_handle* config, int fd,
                                                        const char* server_name);

rustls_connection_handle* rustls_server_connection_new(const rustls_config_handle* config, int fd);

void rustls_connection_free(rustls_connection_handle* conn);

int rustls_connection_handshake(rustls_connection_handle* conn);

bool rustls_connection_is_handshaking(const rustls_connection_handle* conn);

ssize_t rustls_connection_read(rustls_connection_handle* conn, uint8_t* buf, size_t len);

ssize_t rustls_connection_write(rustls_connection_handle* conn, const uint8_t* buf, size_t len);

ssize_t rustls_connection_read_tls(rustls_connection_handle* conn, const uint8_t* buf, size_t len);

ssize_t rustls_connection_write_tls(rustls_connection_handle* conn, uint8_t* buf, size_t len);

bool rustls_connection_wants_write(const rustls_connection_handle* conn);

bool rustls_connection_wants_read(const rustls_connection_handle* conn);

void rustls_connection_set_fd(rustls_connection_handle* conn, int fd);

int rustls_enable_ktls_tx(rustls_connection_handle* conn);

int rustls_enable_ktls_rx(rustls_connection_handle* conn);

const uint8_t* rustls_connection_get_alpn_protocol(const rustls_connection_handle* conn,
                                                    size_t* len);

} // extern "C"

// RustlsConnection implementation.

std::unique_ptr<RustlsConnection> RustlsConnection::createClient(rustls_config_handle* config,
                                                                  int fd,
                                                                  const std::string& server_name) {
  rustls_connection_handle* handle =
      rustls_client_connection_new(config, fd, server_name.c_str());
  
  if (handle == nullptr) {
    return nullptr;
  }

  return std::unique_ptr<RustlsConnection>(new RustlsConnection(handle));
}

std::unique_ptr<RustlsConnection> RustlsConnection::createServer(rustls_config_handle* config,
                                                                  int fd) {
  rustls_connection_handle* handle = rustls_server_connection_new(config, fd);
  
  if (handle == nullptr) {
    return nullptr;
  }

  return std::unique_ptr<RustlsConnection>(new RustlsConnection(handle));
}

RustlsConnection::RustlsConnection(rustls_connection_handle* handle) : handle_(handle) {}

RustlsConnection::~RustlsConnection() {
  if (handle_ != nullptr) {
    rustls_connection_free(handle_);
  }
}

int RustlsConnection::handshake() {
  return rustls_connection_handshake(handle_);
}

bool RustlsConnection::isHandshaking() const {
  return rustls_connection_is_handshaking(handle_);
}

ssize_t RustlsConnection::read(uint8_t* buf, size_t len) {
  return rustls_connection_read(handle_, buf, len);
}

ssize_t RustlsConnection::write(const uint8_t* buf, size_t len) {
  return rustls_connection_write(handle_, buf, len);
}

ssize_t RustlsConnection::readTls(const uint8_t* buf, size_t len) {
  return rustls_connection_read_tls(handle_, buf, len);
}

ssize_t RustlsConnection::writeTls(uint8_t* buf, size_t len) {
  return rustls_connection_write_tls(handle_, buf, len);
}

bool RustlsConnection::wantsWrite() const {
  return rustls_connection_wants_write(handle_);
}

bool RustlsConnection::wantsRead() const {
  return rustls_connection_wants_read(handle_);
}

void RustlsConnection::setFileDescriptor(int fd) {
  rustls_connection_set_fd(handle_, fd);
}

bool RustlsConnection::enableKtlsTx() {
  return rustls_enable_ktls_tx(handle_) == OK;
}

bool RustlsConnection::enableKtlsRx() {
  return rustls_enable_ktls_rx(handle_) == OK;
}

std::string RustlsConnection::getAlpnProtocol() const {
  size_t len = 0;
  const uint8_t* protocol = rustls_connection_get_alpn_protocol(handle_, &len);
  
  if (protocol != nullptr && len > 0) {
    return std::string(reinterpret_cast<const char*>(protocol), len);
  }
  
  return "";
}

// RustlsConfig implementation.

std::unique_ptr<RustlsConfig> RustlsConfig::createClient(
    const std::string& cert_pem, const std::string& key_pem, const std::string& ca_pem,
    const std::vector<std::string>& alpn_protocols) {
  
  // Prepare ALPN protocols as C strings.
  std::vector<const char*> alpn_c_strs;
  for (const auto& protocol : alpn_protocols) {
    alpn_c_strs.push_back(protocol.c_str());
  }

  const char* cert_ptr = cert_pem.empty() ? nullptr : cert_pem.c_str();
  const char* key_ptr = key_pem.empty() ? nullptr : key_pem.c_str();
  const char* ca_ptr = ca_pem.empty() ? nullptr : ca_pem.c_str();

  rustls_config_handle* handle = rustls_client_config_new(
      cert_ptr, cert_pem.size(), key_ptr, key_pem.size(), ca_ptr, ca_pem.size(),
      alpn_c_strs.empty() ? nullptr : alpn_c_strs.data(), alpn_c_strs.size());

  if (handle == nullptr) {
    return nullptr;
  }

  return std::unique_ptr<RustlsConfig>(new RustlsConfig(handle));
}

std::unique_ptr<RustlsConfig> RustlsConfig::createServer(
    const std::string& cert_pem, const std::string& key_pem,
    const std::vector<std::string>& alpn_protocols) {
  
  // Prepare ALPN protocols as C strings.
  std::vector<const char*> alpn_c_strs;
  for (const auto& protocol : alpn_protocols) {
    alpn_c_strs.push_back(protocol.c_str());
  }

  rustls_config_handle* handle = rustls_server_config_new(
      cert_pem.c_str(), cert_pem.size(), key_pem.c_str(), key_pem.size(),
      alpn_c_strs.empty() ? nullptr : alpn_c_strs.data(), alpn_c_strs.size());

  if (handle == nullptr) {
    return nullptr;
  }

  return std::unique_ptr<RustlsConfig>(new RustlsConfig(handle));
}

RustlsConfig::RustlsConfig(rustls_config_handle* handle) : handle_(handle) {}

RustlsConfig::~RustlsConfig() {
  if (handle_ != nullptr) {
    rustls_config_free(handle_);
  }
}

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
