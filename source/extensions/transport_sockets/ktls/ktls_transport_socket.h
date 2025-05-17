#pragma once

#include "source/extensions/transport_sockets/ktls/tls_compat.h"

#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/ssl_socket_state.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/common/logger.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"
#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

/**
 * Implementation of Network::TransportSocket for kTLS.
 */
class KTlsTransportSocket : public Network::TransportSocket, Logger::Loggable<Logger::Id::connection> {
public:
  KTlsTransportSocket(Ssl::ConnectionInfoConstSharedPtr ssl_info, Network::IoHandlePtr io_handle);
  KTlsTransportSocket(KTlsInfoConstSharedPtr ktls_info, Network::IoHandlePtr io_handle);
  ~KTlsTransportSocket() override;
  
  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  absl::string_view failureReason() const override;
  bool canFlushClose() override;
  void closeSocket(Network::ConnectionEvent close_type) override;
  Network::IoResult doRead(Buffer::Instance& read_buffer) override;
  Network::IoResult doWrite(Buffer::Instance& write_buffer, bool end_stream) override;
  void onConnected() override;
  Ssl::ConnectionInfoConstSharedPtr ssl() const override;
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) override {}

  /**
   * Set the upstream file descriptor for splice operations.
   * This allows zero-copy data transfer between the client and upstream connection.
   * @param upstream_fd The upstream socket file descriptor.
   * @return true if splice setup was successful, false otherwise.
   */
  bool setUpstreamFileDescriptor(os_fd_t upstream_fd);

private:
  /**
   * Setup kTLS for the socket based on the SSL connection info.
   * @return true if kTLS was successfully enabled, false otherwise.
   */
  bool setupKTls();

  /**
   * Extract kTLS crypto parameters from the SSL connection.
   * @param ssl_info SSL connection info
   * @param crypto_info [out] structure to populate with crypto parameters
   * @param is_tx true for transmit direction, false for receive
   * @return true if parameters were successfully extracted, false otherwise
   */
  bool extractCryptoInfo(Ssl::ConnectionInfoConstSharedPtr ssl_info,
                        tls12_crypto_info_aes_gcm_128& crypto_info,
                        bool is_tx);

  /**
   * Enable kTLS for TX direction.
   * @param crypto_info the TLS crypto parameters
   * @return true if kTLS was successfully enabled, false otherwise
   */
  bool enableTlsTx(const tls12_crypto_info_aes_gcm_128& crypto_info);

  /**
   * Enable kTLS for RX direction.
   * @param crypto_info the TLS crypto parameters
   * @return true if kTLS was successfully enabled, false otherwise
   */
  bool enableTlsRx(const tls12_crypto_info_aes_gcm_128& crypto_info);  

  /**
   * Enable use of splice() for zero-copy data transfer with kTLS
   * This is used when both RX and TX are enabled.
   * @return true if splice was successfully enabled, false otherwise
   */
  bool enableSplice();

  /**
   * Transfer data using splice if possible.
   * @param from_downstream true to transfer data from downstream to upstream,
   *                       false for upstream to downstream.
   * @param max_bytes maximum number of bytes to transfer.
   * @return The number of bytes transferred, or -1 on error.
   */
  ssize_t spliceData(bool from_downstream, size_t max_bytes);

  Network::TransportSocketCallbacks* callbacks_{nullptr};
  KTlsInfoConstSharedPtr ktls_info_;
  Ssl::ConnectionInfoConstSharedPtr ssl_info_;
  std::string failure_reason_;
  bool ktls_tx_enabled_{false};
  bool ktls_rx_enabled_{false};
  bool splice_enabled_{false};
  
  // For splice operations
  os_fd_t upstream_fd_{-1};
  std::unique_ptr<KTlsSplicer> downstream_to_upstream_splicer_;
  std::unique_ptr<KTlsSplicer> upstream_to_downstream_splicer_;
};

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 