#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

// Forward declarations for rustls FFI types.
struct rustls_connection_handle;
struct rustls_config_handle;

/**
 * C++ wrapper around rustls FFI connection handle.
 */
class RustlsConnection {
public:
  // Result codes matching Rust FFI.
  static constexpr int OK = 0;
  static constexpr int ERR_INVALID_PARAM = -1;
  static constexpr int ERR_IO = -2;
  static constexpr int ERR_HANDSHAKE = -3;
  static constexpr int ERR_CERTIFICATE = -4;
  static constexpr int ERR_KTLS_NOT_SUPPORTED = -5;

  /**
   * Creates a client TLS connection.
   * @param config rustls configuration handle.
   * @param fd file descriptor for the connection.
   * @param server_name SNI server name.
   * @return unique pointer to RustlsConnection or nullptr on failure.
   */
  static std::unique_ptr<RustlsConnection> createClient(rustls_config_handle* config, int fd,
                                                         const std::string& server_name);

  /**
   * Creates a server TLS connection.
   * @param config rustls configuration handle.
   * @param fd file descriptor for the connection.
   * @return unique pointer to RustlsConnection or nullptr on failure.
   */
  static std::unique_ptr<RustlsConnection> createServer(rustls_config_handle* config, int fd);

  ~RustlsConnection();

  /**
   * Performs TLS handshake I/O.
   * @return OK if successful, error code otherwise.
   */
  int handshake();

  /**
   * Checks if handshake is still in progress.
   * @return true if handshaking, false if complete.
   */
  bool isHandshaking() const;

  /**
   * Reads decrypted application data.
   * @param buf buffer to read into.
   * @param len maximum bytes to read.
   * @return number of bytes read, or negative error code.
   */
  ssize_t read(uint8_t* buf, size_t len);

  /**
   * Writes application data to be encrypted.
   * @param buf buffer to write from.
   * @param len number of bytes to write.
   * @return number of bytes written, or negative error code.
   */
  ssize_t write(const uint8_t* buf, size_t len);

  /**
   * Updates the file descriptor for kTLS offload.
   * Must be called after the socket is connected.
   * @param fd the real socket file descriptor.
   */
  void setFileDescriptor(int fd);

  /**
   * Reads encrypted TLS data from buffer and feeds it to rustls.
   * @param buf buffer containing encrypted TLS data.
   * @param len length of data in buffer.
   * @return number of bytes consumed, or negative error code.
   */
  ssize_t readTls(const uint8_t* buf, size_t len);

  /**
   * Writes pending encrypted TLS data from rustls to buffer.
   * @param buf buffer to write encrypted TLS data to.
   * @param len capacity of buffer.
   * @return number of bytes written, or negative error code.
   */
  ssize_t writeTls(uint8_t* buf, size_t len);

  /**
   * Checks if rustls wants to write encrypted TLS data.
   * @return true if rustls has pending TLS data to write.
   */
  bool wantsWrite() const;

  /**
   * Checks if rustls wants to read encrypted TLS data.
   * @return true if rustls is waiting for TLS data.
   */
  bool wantsRead() const;

  /**
   * Enables kernel TLS (kTLS) for transmission.
   * @return true if successful, false otherwise.
   */
  bool enableKtlsTx();

  /**
   * Enables kernel TLS (kTLS) for reception.
   * @return true if successful, false otherwise.
   */
  bool enableKtlsRx();

  /**
   * Gets the negotiated ALPN protocol.
   * @return protocol name, or empty string if none.
   */
  std::string getAlpnProtocol() const;

private:
  explicit RustlsConnection(rustls_connection_handle* handle);

  rustls_connection_handle* handle_;
};

using RustlsConnectionPtr = std::unique_ptr<RustlsConnection>;

/**
 * C++ wrapper around rustls FFI config handle.
 */
class RustlsConfig {
public:
  /**
   * Creates a client TLS configuration.
   * @param cert_pem client certificate in PEM format (optional for client).
   * @param key_pem private key in PEM format (optional for client).
   * @param ca_pem CA certificates in PEM format (optional, uses system defaults if not provided).
   * @param alpn_protocols list of ALPN protocols to advertise.
   * @return unique pointer to RustlsConfig or nullptr on failure.
   */
  static std::unique_ptr<RustlsConfig> createClient(const std::string& cert_pem,
                                                     const std::string& key_pem,
                                                     const std::string& ca_pem,
                                                     const std::vector<std::string>& alpn_protocols);

  /**
   * Creates a server TLS configuration.
   * @param cert_pem server certificate in PEM format (required).
   * @param key_pem private key in PEM format (required).
   * @param alpn_protocols list of ALPN protocols to advertise.
   * @return unique pointer to RustlsConfig or nullptr on failure.
   */
  static std::unique_ptr<RustlsConfig> createServer(const std::string& cert_pem,
                                                     const std::string& key_pem,
                                                     const std::vector<std::string>& alpn_protocols);

  ~RustlsConfig();

  rustls_config_handle* handle() const { return handle_; }

private:
  explicit RustlsConfig(rustls_config_handle* handle);

  rustls_config_handle* handle_;
};

using RustlsConfigPtr = std::unique_ptr<RustlsConfig>;

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

