#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tls.h>

#include "envoy/network/io_handle.h"

#include "source/common/network/io_socket_handle_impl.h"

namespace Envoy {
namespace Network {

/**
 * Implementation of IoHandle for kTLS sockets.
 */
class KTlsSocketHandleImpl : public IoSocketHandleImpl {
public:
  /**
   * Construct a new instance from an existing socket.
   * @param fd supplies the socket.
   * @param socket_v6only specifies whether the socket is IPv6 only.
   */
  KTlsSocketHandleImpl(os_fd_t fd, bool socket_v6only)
      : IoSocketHandleImpl(fd, socket_v6only) {}

  /**
   * Enables kTLS encryption for the transmit direction (TX).
   * @param crypto_info the TLS crypto parameters.
   * @return true if kTLS was successfully enabled, false otherwise.
   */
  bool enableTlsTx(const tls12_crypto_info_aes_gcm_128& crypto_info);

  /**
   * Enables kTLS decryption for the receive direction (RX).
   * @param crypto_info the TLS crypto parameters.
   * @return true if kTLS was successfully enabled, false otherwise.
   */
  bool enableTlsRx(const tls12_crypto_info_aes_gcm_128& crypto_info);

  /**
   * Check if kTLS is enabled for transmit.
   */
  bool isTlsTxEnabled() const { return tls_tx_enabled_; }

  /**
   * Check if kTLS is enabled for receive.
   */
  bool isTlsRxEnabled() const { return tls_rx_enabled_; }

  /**
   * @return true if the socket supports TLS.
   */
  bool supportsTls() const override { return true; }

private:
  bool tls_tx_enabled_{false};
  bool tls_rx_enabled_{false};
};

using KTlsSocketHandleImplSharedPtr = std::shared_ptr<KTlsSocketHandleImpl>;

} // namespace Network
} // namespace Envoy 