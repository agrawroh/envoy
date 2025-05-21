#include <string>
#include <utility>
#include <vector>
#include <fstream>

// Standard C/C++ headers available on all platforms
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <errno.h>

// Non-Linux system headers that are safe to include globally
#include <unistd.h>
#include <fcntl.h>

// Platform-specific includes
#ifdef __linux__
// Include Linux system headers globally since macros can't be namespaced
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <endian.h>
#include <poll.h>
#include <netinet/in.h>

// Be careful with TCP headers - netinet/tcp.h and linux/tcp.h have conflicts
// Include only netinet/tcp.h and define missing constants ourselves
#include <netinet/tcp.h>

// Define missing TCP constants that might be needed from linux/tcp.h
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef TCP_AVAILABLE_ULPS
#define TCP_AVAILABLE_ULPS 20
#endif

// We need TLS definitions which might be in linux/tls.h
#if __has_include(<linux/tls.h>)
#include <linux/tls.h>
#endif

#if __has_include(<sys/splice.h>)
#include <sys/splice.h>
#endif
#if __has_include(<sys/capability.h>)
#include <sys/capability.h>
#endif
#endif // __linux__

// Include Envoy headers
#include "envoy/event/dispatcher.h"
#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/common/thread.h"
#include "source/common/network/io_socket_error_impl.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/network/utility.h"
#include "source/common/tls/connection_info_impl_base.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"
#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

// Include OpenSSL headers
#include "openssl/evp.h"
#include "openssl/ssl.h"

// Include SSL socket header using correct path
#include "source/common/tls/ssl_socket.h"

// Create platform-agnostic utility namespace
namespace platform_util {

// Macro to mark parameters as unused to avoid compiler warnings
#define UNUSED_PARAMETER(param) ((void)(param))

#ifdef __linux__
// Linux-specific platform utilities

// Endian conversion wrappers
inline uint64_t be64toh_fn(uint64_t value) {
  return be64toh(value);
}

inline uint64_t htobe64_fn(uint64_t value) {
  return htobe64(value);
}

// System call wrappers
inline int ioctl_fn(int fd, unsigned long request, void* argp) {
  return ::ioctl(fd, request, argp);
}

inline int poll_fn(pollfd* fds, nfds_t nfds, int timeout) {
  return ::poll(fds, nfds, timeout);
}

// Use native socket poll structures
using pollfd = ::pollfd;

// Define system capability macros
#if __has_include(<sys/capability.h>)
#define HAS_CAPABILITY_SUPPORT 1
#endif

// Define splice syscall availability
#if defined(splice) || defined(__NR_splice)
#define HAS_SPLICE_SYSCALL 1
#endif

#else // Not Linux

// Define byte order conversion for non-Linux systems
#if defined(__APPLE__)
// macOS (Darwin) has different byte order functions
#include <libkern/OSByteOrder.h>
inline uint64_t be64toh_fn(uint64_t value) {
  return OSSwapBigToHostInt64(value);
}
#elif defined(_WIN32)
// Windows implementation
#include <stdlib.h>
inline uint64_t be64toh_fn(uint64_t value) {
  return _byteswap_uint64(value);
}
#else
// Generic BSD-like systems
#include <endian.h>
inline uint64_t be64toh_fn(uint64_t value) {
  return be64toh(value);
}
#endif

// Define our own pollfd structure for non-Linux systems
struct pollfd {
  int fd;
  short events;
  short revents;
};

// Placeholder implementations for non-Linux systems
inline int ioctl_fn(int fd, unsigned long request, void* argp) {
  // Mark parameters as unused to avoid compiler warnings
  UNUSED_PARAMETER(fd);
  UNUSED_PARAMETER(request);
  UNUSED_PARAMETER(argp);
  errno = ENOSYS;
  return -1;
}

inline int poll_fn(pollfd* fds, size_t nfds, int timeout) {
  // Mark parameters as unused to avoid compiler warnings
  UNUSED_PARAMETER(fds);
  UNUSED_PARAMETER(nfds);
  UNUSED_PARAMETER(timeout);
  errno = ENOSYS;
  return -1;
}

#endif // __linux__

} // namespace platform_util

// Define TLS constants for non-Linux platforms
#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef TLS_TX
#define TLS_TX 1
#endif

#ifndef TLS_RX
#define TLS_RX 2
#endif

#ifndef TLS_TX_ZEROCOPY_RO
#define TLS_TX_ZEROCOPY_RO 3
#endif

#ifndef TLS_RX_EXPECT_NO_PAD
#define TLS_RX_EXPECT_NO_PAD 4
#endif

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef TCP_INFO
#define TCP_INFO 11
#endif

#ifndef TCP_AVAILABLE_ULPS
#define TCP_AVAILABLE_ULPS 20
#endif

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

namespace {
class KtlsLogger : public Logger::Loggable<Logger::Id::connection> {};
} // namespace

KtlsTransportSocket::KtlsTransportSocket(Network::TransportSocketPtr&& transport_socket,
                                         bool enable_tx_zerocopy, bool enable_rx_no_pad)
    : PassthroughSocket(std::move(transport_socket)), 
      callbacks_(nullptr),
      enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad),
      ktls_enabled_(false),
      ktls_handshake_attempts_(0),
      readiness_attempts_(0),
      ktls_state_determined_(false),
      saved_tx_seq_(0),
      saved_rx_seq_(0),
      safe_seq_threshold_(10),
      retry_on_failure_(true),
      max_retry_attempts_(5),
      try_loading_module_(true),
      error_handling_mode_(1),
      consecutive_decrypt_failures_(0),
      resync_in_progress_(false),
      last_resync_attempt_time_ms_(0),
      resync_scheduled_(false),
      is_upstream_(false) {
  ENVOY_LOG(debug, "Creating KtlsTransportSocket with zerocopy={} no_pad={}", enable_tx_zerocopy_,
            enable_rx_no_pad_);
}

KtlsTransportSocket::~KtlsTransportSocket() = default;

void KtlsTransportSocket::setTransportSocketCallbacks(
    Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  PassthroughSocket::setTransportSocketCallbacks(callbacks);
}

bool KtlsTransportSocket::canFlushClose() { return PassthroughSocket::canFlushClose(); }

void KtlsTransportSocket::closeSocket(Network::ConnectionEvent event) {
  // Cancel any pending timers
  if (readiness_timer_) {
    readiness_timer_->disableTimer();
    readiness_timer_.reset();
  }

  // Make sure we clean up any kTLS state before closing
  if (ktls_enabled_) {
    // No special cleanup needed for kTLS currently
  }
  PassthroughSocket::closeSocket(event);
}

bool KtlsTransportSocket::isKtlsEnabled() const { return ktls_enabled_; }

Network::IoResult KtlsTransportSocket::doRead(Buffer::Instance& buffer) {
  if (!isKtlsEnabled()) {
    return transport_socket_->doRead(buffer);
  }

  // Create a temporary buffer to read data
  const uint64_t max_read_size = buffer.highWatermark() - buffer.length();
  if (max_read_size == 0) {
    return {Network::PostIoAction::KeepOpen, 0, false};
  }

  // Use the buffer's reservation mechanism for reading
  auto reservation = buffer.reserveSingleSlice(max_read_size);

  // Get a non-temporary copy of the slice
  Buffer::RawSlice slice = reservation.slice();

  // Perform the read directly using the slice
  auto result = callbacks_->ioHandle().readv(max_read_size, &slice, 1);
  ENVOY_LOG(trace, "kTLS read result: {}", result.return_value_);

  if (result.err_) {
    // Check if this is an EBADMSG error (Bad message, which is common with kTLS sequence issues)
    if (result.err_->getSystemErrorCode() == EBADMSG) {
      ENVOY_LOG(debug,
                "kTLS read failed with EBADMSG (Bad message) - sequence number mismatch detected");

      // ENHANCED: Capture detailed error metrics and state
      auto ssl_connection = transport_socket_->ssl();
      int fd = callbacks_->ioHandle().fdDoNotUse();
      bool sequence_mismatch_confirmed = false;
      uint64_t current_tx_seq = 0;
      uint64_t current_rx_seq = 0;
      uint64_t kernel_rx_seq = 0;
      bool have_kernel_seq = false;

      // ENHANCED: Capture connection info for diagnostics
      std::string remote_address = "unknown";
      std::string local_address = "unknown";

      if (callbacks_) {
        auto& conn = callbacks_->connection();
        auto remote = conn.connectionInfoProvider().remoteAddress();
        auto local = conn.connectionInfoProvider().localAddress();
        if (remote) {
          remote_address = remote->asString();
        }
        if (local) {
          local_address = local->asString();
        }
      }

      // Extract sequence numbers for diagnosis
      if (ssl_connection) {
        const Tls::ConnectionInfoImplBase* impl_base =
            dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
        if (impl_base) {
          SSL* ssl_handle = impl_base->ssl();
          if (ssl_handle) {
            current_tx_seq = SSL_get_write_sequence(ssl_handle);
            current_rx_seq = SSL_get_read_sequence(ssl_handle);

            // Get the file descriptor to query kernel's sequence number
            ENVOY_LOG(info,
                      "EBADMSG Diagnostic: Connection {} -> {}, Current SSL seq TX={}, RX={}, "
                      "saved seq TX={}, RX={}, fd={}",
                      local_address, remote_address, current_tx_seq, current_rx_seq, saved_tx_seq_,
                      saved_rx_seq_, fd);

            // Calculate what the expected sequence numbers would be in the kernel
            if (ktls_info_) {
              tls_crypto_info_t rx_info = {};
              if (ktls_info_->getRxCryptoInfo(rx_info)) {
                memcpy(&kernel_rx_seq, rx_info.rec_seq, 8);
                kernel_rx_seq = platform_util::be64toh_fn(kernel_rx_seq);
                have_kernel_seq = true;

                // Check if there's actually a sequence mismatch
                sequence_mismatch_confirmed = (kernel_rx_seq != current_rx_seq);

                ENVOY_LOG(info,
                          "Expected kernel RX seq={} (converted from big-endian), "
                          "current SSL RX seq={}, mismatch={}",
                          kernel_rx_seq, current_rx_seq,
                          sequence_mismatch_confirmed ? "YES" : "NO");
              }
            }

            // ENHANCED: Try to diagnose the exact type of sequence error
            int64_t seq_diff = 0;
            std::string error_type = "unknown";

            if (have_kernel_seq) {
              seq_diff = static_cast<int64_t>(kernel_rx_seq) - static_cast<int64_t>(current_rx_seq);

              if (seq_diff > 0) {
                error_type = "SSL_BEHIND_KERNEL";
                ENVOY_LOG(
                    info,
                    "Sequence error type: SSL sequence number is behind kernel by {} records");
              } else if (seq_diff < 0) {
                error_type = "KERNEL_BEHIND_SSL";
                ENVOY_LOG(
                    info,
                    "Sequence error type: Kernel sequence number is behind SSL by {} records");
              } else {
                error_type = "MATCHING_BUT_DECRYPT_FAILED";
                ENVOY_LOG(info,
                          "Sequence error type: Sequence numbers match but decryption failed");
              }
            }
          }
        }
      }

      // CRITICAL FIX: Handle sequence number mismatch based on whether it's actually confirmed
      // and attempt recovery using progressively more aggressive strategies

      // Try to drain any bad data that might be in the socket buffer
      if (fd >= 0) {
        // Find out how much data is available
        int available = 0;
        if (platform_util::ioctl_fn(fd, FIONREAD, &available) == 0 && available > 0) {
          ENVOY_LOG(debug, "Draining {} bytes from socket with sequence error", available);
          
          // Allocate a temporary buffer for draining (up to 8KB at a time)
          const int drain_size = std::min(available, 8192);
          std::vector<uint8_t> drain_buffer(drain_size);
          
          // Try to drain data using a non-blocking recv
          ssize_t drained = ::recv(fd, drain_buffer.data(), drain_buffer.size(), MSG_DONTWAIT);
          if (drained > 0) {
            ENVOY_LOG(debug, "Successfully drained {} bytes from socket", drained);
            
            // If the buffer contains enough bytes to be a TLS record, try to analyze it
            if (drained >= 5) {
              // TLS record header is 5 bytes: type(1) + version(2) + length(2)
              uint8_t record_type = drain_buffer[0];
              uint16_t tls_version = (static_cast<uint16_t>(drain_buffer[1]) << 8) | drain_buffer[2];
              uint16_t record_len = (static_cast<uint16_t>(drain_buffer[3]) << 8) | drain_buffer[4];
              
              // Convert record type to string for better logging
              std::string record_type_str;
              switch (record_type) {
              case 20: record_type_str = "ChangeCipherSpec"; break;
              case 21: record_type_str = "Alert"; break;
              case 22: record_type_str = "Handshake"; break;
              case 23: record_type_str = "Application"; break;
              default: record_type_str = "Unknown"; break;
              }
              
              ENVOY_LOG(debug, "Drained TLS record: type={} ({}), version=0x{:04x}, length={}",
                        record_type, record_type_str, tls_version, record_len);
              
              // Provide details for alert records to aid debugging
              if (record_type == 21 && drained >= 7) { // Alert record (5+2 bytes)
                uint8_t alert_level = drain_buffer[5];
                uint8_t alert_code = drain_buffer[6];
                ENVOY_LOG(debug, "TLS Alert: level={}, code={}", alert_level, alert_code);
              }
            }
          }
        }
      }

      // Different recovery approaches based on failure count
      consecutive_decrypt_failures_++;

      if (consecutive_decrypt_failures_ == 1) {
        // On first failure, just try again with software TLS
        ENVOY_LOG(info, "First kTLS decrypt failure. Using software TLS fallback this time.");
      } else if (consecutive_decrypt_failures_ <= 3) {
        // On subsequent failures, attempt resynchronization
        ENVOY_LOG(warn, "Multiple kTLS failures (count={}). Attempting to resynchronize.",
                  consecutive_decrypt_failures_);
        scheduleResynchronization();
      } else {
        // After too many failures, permanently disable kTLS
        ENVOY_LOG(error, 
                  "Too many kTLS decrypt failures ({}), permanently falling back to software TLS",
                  consecutive_decrypt_failures_);
        disableKtls("Multiple EBADMSG errors during read - sequence mismatch detected");
      }

      // Fall back to software TLS for this read
      ENVOY_LOG(debug, "Using software TLS fallback for read operation");
      Network::IoResult fallback_result = transport_socket_->doRead(buffer);

      // Check if the software fallback succeeded 
      if (fallback_result.bytes_processed_ > 0) {
        // Successfully read data - reset consecutive failure count
        ENVOY_LOG(debug, "Software TLS read succeeded, resetting consecutive failure counter");
        consecutive_decrypt_failures_ = 0;
      } else if (fallback_result.err_code_ && fallback_result.action_ == Network::PostIoAction::Close) {
        // Both kTLS and software TLS fallback failed - likely a corrupted TLS state
        ENVOY_LOG(error, "Software TLS fallback also failed after kTLS error - "
                         "connection state may be corrupted, initiating close");
      }

      return fallback_result;
    } else if (result.err_->getSystemErrorCode() == EINVAL) {
      // EINVAL can occur if the kTLS state is invalid, also fall back
      ENVOY_LOG(debug, "kTLS read failed with EINVAL - kernel state may be corrupted");
      disableKtls("EINVAL error during read");
      return transport_socket_->doRead(buffer);
    } else {
      // For other errors, maintain standard behavior
      return {Network::PostIoAction::Close, 0,
              result.err_->getErrorCode() == Network::IoSocketError::IoErrorCode::Again};
    }
  }

  uint64_t bytes_read = result.return_value_;
  if (bytes_read == 0) {
    // Remote close
    return {Network::PostIoAction::Close, 0, false};
  }

  // Commit the successful read into the buffer and clean up the reservation
  reservation.commit(bytes_read);

  // If we successfully read data, reset error counters
  if (consecutive_decrypt_failures_ > 0) {
    ENVOY_LOG(debug, "Successful kTLS read after {} previous failures - resetting error counters",
              consecutive_decrypt_failures_);
    consecutive_decrypt_failures_ = 0;
  }

  // Also reset any resync state
  resetResyncState();

  return {Network::PostIoAction::KeepOpen, bytes_read, false};
}

Network::IoResult KtlsTransportSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (!isKtlsEnabled()) {
    return PassthroughSocket::doWrite(buffer, end_stream);
  }

  ENVOY_LOG(trace, "kTLS write buffer size: {}, end_stream: {}", buffer.length(), end_stream);

  // Track the original buffer length before write
  const uint64_t bytes_to_write = buffer.length();

  // Perform the write using IoHandle's writev directly
  Buffer::RawSliceVector slices = buffer.getRawSlices();
  Api::IoCallUint64Result result = callbacks_->ioHandle().writev(slices.data(), slices.size());

  if (result.err_) {
    const int err_code = result.err_->getSystemErrorCode();
    ENVOY_LOG(debug, "kTLS write error: {} (code={})", result.err_->getErrorDetails(), err_code);

    // Handle kTLS-specific write errors (EBADMSG, EPROTO, EINVAL often indicate crypto issues)
    if (err_code == EBADMSG || err_code == EPROTO || err_code == EINVAL) {
      ENVOY_LOG(debug, "kTLS write had protocol error (code={})", err_code);

      // CRITICAL FIX: Immediately fall back to software TLS on first protocol error
      // This is more reliable than trying to recover with kTLS
      ENVOY_LOG(warn, "kTLS write error (code={}) - immediately falling back to software TLS",
                err_code);
      disableKtls("Protocol error during write - immediate fallback to software TLS");

      // Retry with software path immediately
      return PassthroughSocket::doWrite(buffer, end_stream);
    } else if (err_code == EAGAIN || err_code == EWOULDBLOCK) {
      // Normal EAGAIN handling - don't count as an error
      ENVOY_LOG(trace, "kTLS write would block");
      return {Network::PostIoAction::KeepOpen, 0, true};
    } else {
      // For other errors, return normal error result
      ENVOY_LOG(debug, "kTLS write had non-protocol error: {} (code={})",
                result.err_->getErrorDetails(), err_code);
      return {Network::PostIoAction::Close, 0, false};
    }
  }

  uint64_t bytes_written = result.return_value_;

  // If we wrote everything successfully, drain the buffer
  if (bytes_written == bytes_to_write) {
    buffer.drain(bytes_written);
  } else if (bytes_written > 0) {
    // Partial write - drain what was written
    buffer.drain(bytes_written);
  }

  return {Network::PostIoAction::KeepOpen, bytes_written, false};
}

bool KtlsTransportSocket::startSecureTransport() {
  // This is no-op for kTLS
  return false;
}

void KtlsTransportSocket::onConnected() {
  // Delegate to the wrapped socket first
  PassthroughSocket::onConnected();

  // CRITICAL FIX: Immediately attempt to evaluate kTLS readiness on connection
  // This is the best time - right at handshake completion when sequence numbers are lowest
  ENVOY_LOG(info, "{} connection established, determining kTLS readiness",
            is_upstream_ ? "Upstream" : "Downstream");

  // This is a better place to enable kTLS - immediately after handshake completion
  // when sequence numbers are likely to be at their minimum
  if (callbacks_) {
    // Cancel any pending readiness timer to avoid race conditions
    if (readiness_timer_) {
      readiness_timer_->disableTimer();
      readiness_timer_.reset();
    }

    // CRITICAL FIX: For upstream connections, add a graduated delay strategy
    // to ensure the handshake is absolutely complete before trying to enable kTLS
    if (is_upstream_) {
      ENVOY_LOG(info, "Using adaptive delay for upstream connection before enabling kTLS");

      // CRITICAL FIX: Check if TLS handshake appears to be complete before scheduling
      // This helps us determine the appropriate delay strategy
      bool ssl_initialized = false;
      bool has_session_id = false;
      bool has_peer_cert = false;
      bool cipher_available = false;
      bool is_handshake_done = false;

      auto ssl_connection = transport_socket_->ssl();
      if (ssl_connection) {
        std::string session_id = std::string(ssl_connection->sessionId());
        has_session_id = !session_id.empty();
        has_peer_cert = ssl_connection->peerCertificatePresented();
        std::string cipher = std::string(ssl_connection->ciphersuiteString());
        cipher_available = !cipher.empty();

        // Also check if SSL_in_init returns 0 (handshake complete)
        const Tls::ConnectionInfoImplBase* impl_base =
            dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
        if (impl_base && impl_base->ssl()) {
          is_handshake_done = (SSL_in_init(impl_base->ssl()) == 0);
          ssl_initialized = true;
        }
      }

      // Log detailed handshake state
      ENVOY_LOG(debug,
                "Upstream handshake state: ssl_init={}, handshake_done={}, session_id={}, "
                "peer_cert={}, cipher={}",
                ssl_initialized, is_handshake_done, has_session_id, has_peer_cert,
                cipher_available);

      // Use a variable delay based on connection state and attempt number
      // Increase delay for subsequent attempts using exponential backoff
      uint64_t attempt_factor = std::min(1UL << readiness_attempts_, 16UL);

      // Adjust base delay based on multiple handshake indicators
      uint64_t base_delay = 0;
      if (is_handshake_done && (has_session_id || has_peer_cert)) {
        // Handshake appears complete - use short delay
        base_delay = 5;
      } else if (is_handshake_done || cipher_available || has_peer_cert) {
        // Handshake may be partially complete - use medium delay
        base_delay = 15;
      } else {
        // Handshake likely incomplete - use long delay
        base_delay = 25;
      }

      uint64_t delay_ms = base_delay * attempt_factor;

      ENVOY_LOG(info,
                "Using {}ms delay for upstream kTLS (attempt={}, handshake_done={}, session_id={}, "
                "peer_cert={})",
                delay_ms, readiness_attempts_, is_handshake_done,
                has_session_id ? "present" : "missing", has_peer_cert ? "present" : "missing");

      Event::Dispatcher& dispatcher = callbacks_->connection().dispatcher();
      readiness_timer_ = dispatcher.createTimer([this]() {
        ENVOY_LOG(info, "Delayed upstream kTLS readiness check now running");
        determineKtlsReadiness();
      });

      // Use the calculated delay to ensure the connection is fully established
      readiness_timer_->enableTimer(std::chrono::milliseconds(delay_ms));
    } else {
      // For downstream connections, proceed immediately
      determineKtlsReadiness();
    }
  } else {
    ENVOY_LOG(debug, "No callbacks available, cannot determine kTLS readiness");
  }
}

bool KtlsTransportSocket::isSslHandshakeComplete() const {
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    return false;
  }

  // Get SSL handle for low-level checks
  SSL* ssl_handle = nullptr;
  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
  }

  // Multiple methods to detect handshake completion
  
  // Method 1: Check if SSL_in_init returns 0 (most reliable indicator)
  bool is_handshake_done = false;
  if (ssl_handle) {
    // SSL_in_init() returns 0 when handshake is complete
    is_handshake_done = (SSL_in_init(ssl_handle) == 0);
    
    // Double check with alternate approach if we have the function
#ifdef SSL_is_init_finished
    if (!is_handshake_done) {
      is_handshake_done = SSL_is_init_finished(ssl_handle);
    }
#endif
  }

  // Method 2: Check connection info attributes
  std::string cipher = std::string(ssl_connection->ciphersuiteString());
  std::string version = std::string(ssl_connection->tlsVersion());
  bool has_crypto_info = !cipher.empty() && !version.empty();
  bool has_peer_cert = ssl_connection->peerCertificatePresented();
  bool has_session_id = !std::string(ssl_connection->sessionId()).empty();
  bool has_security = ssl_connection->peerCertificateValidated();

  // Log the detailed state for debugging
  ENVOY_LOG(debug, "SSL handshake check - has_crypto_info: {}, has_peer_cert: {}, "
            "has_security: {}, has_session_id: {}, is_handshake_done: {}",
            has_crypto_info, has_peer_cert, has_security, has_session_id, is_handshake_done);

  // For upstream connections, be more cautious (but less restrictive than before)
  if (is_upstream_) {
    // Reliable handshake completion = handshake done OR (crypto info AND peer cert/session ID)
    bool result = is_handshake_done || (has_crypto_info && (has_peer_cert || has_session_id));
    
    ENVOY_LOG(debug, "Upstream SSL handshake completion: {}", result);
    return result;
  }

  // For downstream, any strong indicator is acceptable
  return is_handshake_done || has_crypto_info || has_peer_cert || has_session_id;
}

void KtlsTransportSocket::determineKtlsReadiness() {
  if (ktls_state_determined_) {
    return;
  }

  // Only try to determine kTLS readiness if the SSL socket has a valid SSL object
  if (!transport_socket_->ssl()) {
    ENVOY_LOG(debug, "No SSL connection found for {} connection, cannot determine kTLS readiness",
              is_upstream_ ? "upstream" : "downstream");
    ktls_state_determined_ = true;
    ktls_enabled_ = false;
    processPendingOps();
    return;
  }

  ENVOY_LOG(info, "Checking SSL handshake completion for {} kTLS readiness",
            is_upstream_ ? "upstream" : "downstream");

  // Make an immediate check for handshake completion
  bool handshake_complete = isSslHandshakeComplete();

  if (!handshake_complete) {
    ENVOY_LOG(info, "SSL handshake not yet complete for {} connection, cannot enable kTLS",
              is_upstream_ ? "upstream" : "downstream");

    // CRITICAL FIX: For upstream connections, try many more attempts with longer delays
    // as upstream handshakes typically take longer and we need all indicators to be set
    uint32_t max_attempts = is_upstream_ ? 20 : 5;

    // If we've already tried several times, give up
    if (readiness_attempts_ >= max_attempts) {
      ENVOY_LOG(info,
                "Maximum kTLS readiness attempts reached ({}/{}) for {} connection, giving up.",
                readiness_attempts_, max_attempts, is_upstream_ ? "upstream" : "downstream");
      ktls_state_determined_ = true;
      ktls_enabled_ = false;
      // Process any pending operations that were waiting
      processPendingOps();
      return;
    }

    // Calculate a reasonable delay with a maximum cap to avoid extreme delays
    uint64_t base_delay_ms = 10;
    uint64_t max_delay_ms = 160; // Cap max delay to avoid extremely long waits
    
    // Use exponential backoff but cap at maximum delay
    uint64_t delay_ms = std::min(
      base_delay_ms * (1 << std::min(readiness_attempts_, uint32_t(4))), 
      max_delay_ms
    );

    ENVOY_LOG(debug, "Scheduling kTLS readiness check in {}ms (attempt {}/{})",
              delay_ms, readiness_attempts_ + 1, max_attempts);

    readiness_attempts_++;

    // Schedule next check with increasing delay
    Event::Dispatcher& dispatcher = callbacks_->connection().dispatcher();
    readiness_timer_ = dispatcher.createTimer([this, max_attempts]() {
      ENVOY_LOG(debug, "Running scheduled kTLS readiness check (attempt {}/{})", 
                readiness_attempts_, max_attempts);
      determineKtlsReadiness();
    });
    readiness_timer_->enableTimer(std::chrono::milliseconds(delay_ms));

    return;
  }

  ENVOY_LOG(info,
            "SSL handshake complete for {} connection, checking kTLS enablement prerequisites",
            is_upstream_ ? "upstream" : "downstream");

  // CRITICAL FIX: Add special upstream handling with extra sequence number safety
  if (is_upstream_) {
    ENVOY_LOG(info, "This is an upstream connection, applying stricter kTLS readiness checks");
  }

  // SAFETY CHECK: Only enable kTLS if we're immediately after handshake
  // Get the SSL object to check sequence numbers
  SSL* ssl_handle = nullptr;
  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(transport_socket_->ssl().get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
  }

  // Check if we've already sent/received significant data
  // If sequence numbers are high, kTLS enablement is risky
  bool is_safe_to_enable = true;
  if (ssl_handle) {
    uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
    uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);

    ENVOY_LOG(debug, "Current SSL sequence numbers - TX: {}, RX: {}", tx_seq, rx_seq);

    // Use the member variable safe_seq_threshold_ instead of hardcoded values
    // On Linux 5.15, we can be more permissive as it supports non-zero sequence numbers properly
    // This was a major improvement in 5.11+ kernels
    uint64_t active_safe_seq_threshold = safe_seq_threshold_;

    // For older kernels (detected by poor kTLS support), be more conservative
    ENVOY_LOG(debug, "Using safe sequence threshold {} for {} connection.",
              active_safe_seq_threshold, is_upstream_ ? "upstream" : "downstream");

    if (tx_seq + rx_seq > active_safe_seq_threshold) {
      ENVOY_LOG(warn,
                "Connection has already exchanged {} records (TX={}, RX={}), "
                "which exceeds threshold of {}. Skipping kTLS enablement for safety.",
                tx_seq + rx_seq, tx_seq, rx_seq, active_safe_seq_threshold);
      is_safe_to_enable = false;
    }
  }

  // Handshake is complete, determine if we can use kTLS
  if (canEnableKtls() && is_safe_to_enable) {
    ENVOY_LOG(info, "Attempting to enable kTLS for {}", is_upstream_ ? "upstream" : "downstream");

    // Get the cipher to log some details
    std::string cipher = std::string(transport_socket_->ssl()->ciphersuiteString());
    std::string version = std::string(transport_socket_->ssl()->tlsVersion());

    ENVOY_LOG(info, "Try to enable kernel TLS {} for {}", cipher, version);

    // Try enabling kTLS for this connection
    if (enableKtls()) {
      ENVOY_LOG(info, "Successfully enabled kTLS");
      ktls_enabled_ = true;
    } else {
      ENVOY_LOG(warn, "Failed to enable kTLS, falling back to software TLS");
      ktls_enabled_ = false;
    }
  } else {
    if (!is_safe_to_enable) {
      ENVOY_LOG(debug, "kTLS not enabled because too many records already exchanged");
    } else {
      ENVOY_LOG(debug, "kTLS cannot be enabled for this connection, using software TLS");
    }
    ktls_enabled_ = false;
  }

  // Mark as determined regardless of success, to avoid retrying
  ktls_state_determined_ = true;

  // Now that kTLS state is determined, handle any pending operations
  processPendingOps();
}

void KtlsTransportSocket::scheduleKtlsReadinessCheck() {
  if (!callbacks_) {
    ENVOY_LOG(debug, "No callbacks available, cannot schedule kTLS readiness check");
    return;
  }

  // Calculate delay based on attempt number and connection state
  uint64_t delay_ms = 0;

  // Base exponential backoff starting at 10ms and doubling with each attempt
  delay_ms =
      10 * (1 << std::min(ktls_handshake_attempts_, uint32_t(4))); // Cap at reasonable max (160ms)

  // For long-lived connections, we can be more patient
  // For short-lived connections, we should be more aggressive
  if (callbacks_->connection().state() != Network::Connection::State::Open) {
    // Connection is not fully open, be more aggressive
    delay_ms = std::min(delay_ms, static_cast<uint64_t>(20));
  }

  // If we're on the last attempt, make one final aggressive check
  if (ktls_handshake_attempts_ + 1 >= MAX_KTLS_ATTEMPTS) {
    delay_ms = 5; // Final quick check
  }

  ENVOY_LOG(debug, "Scheduling kTLS readiness check in {}ms (attempt {}/{})", delay_ms,
            ktls_handshake_attempts_ + 1, MAX_KTLS_ATTEMPTS);

  // Clear any existing timer
  if (readiness_timer_) {
    readiness_timer_->disableTimer();
  }

  // Create and enable timer
  if (!readiness_timer_) {
    readiness_timer_ = callbacks_->connection().dispatcher().createTimer([this]() {
      // Verify connection is still active before proceeding
      if (callbacks_ && callbacks_->connection().state() == Network::Connection::State::Open) {
        determineKtlsReadiness();
      } else {
        ENVOY_LOG(debug, "Connection no longer active, abandoning kTLS readiness check");
        ktls_state_determined_ = true; // Mark as determined to avoid further attempts
      }
    });
  }

  readiness_timer_->enableTimer(std::chrono::milliseconds(delay_ms));
}

void KtlsTransportSocket::scheduleResynchronization() {
  if (resync_scheduled_) {
    ENVOY_LOG(debug, "Resynchronization already scheduled, not scheduling again");
    return;
  }

  if (!callbacks_) {
    ENVOY_LOG(debug, "No callbacks available, cannot schedule resynchronization");
    return;
  }

  // Set flag to avoid multiple concurrent resync attempts
  resync_scheduled_ = true;
  resync_in_progress_ = false;

  // Get current time to calculate delay
  uint64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count();

  // If we've attempted a resync recently, use exponential backoff
  uint64_t delay_ms = 10; // Default initial delay

  if (last_resync_attempt_time_ms_ > 0) {
    uint64_t time_since_last_ms = now_ms - last_resync_attempt_time_ms_;
    if (time_since_last_ms < 1000) {
      // Less than 1 second since last attempt, use exponential backoff
      // Each consecutive failure doubles the delay, starting at 10ms up to 160ms
      delay_ms = 10 * (1 << std::min(consecutive_decrypt_failures_, 4U));
    }
  }

  ENVOY_LOG(debug, "Scheduling kTLS resynchronization in {}ms", delay_ms);

  // Create and enable timer
  Event::Dispatcher& dispatcher = callbacks_->connection().dispatcher();
  if (!resync_timer_) {
    resync_timer_ = dispatcher.createTimer([this]() {
      // Verify connection is still active before proceeding
      if (callbacks_ && callbacks_->connection().state() == Network::Connection::State::Open) {
        performResynchronization();
      } else {
        ENVOY_LOG(debug, "Connection no longer active, abandoning kTLS resynchronization");
        resync_scheduled_ = false;
      }
    });
  }

  resync_timer_->enableTimer(std::chrono::milliseconds(delay_ms));
}

void KtlsTransportSocket::processPendingOps() {
  // Early return if no pending operations
  if (!pending_read_ && !pending_write_) {
    return;
  }

  ENVOY_LOG(
      debug,
      "Processing pending operations, read={}, write={}, kTLS state determined={}, kTLS enabled={}",
      pending_read_.has_value(), pending_write_.has_value(), ktls_state_determined_, ktls_enabled_);

  // Process pending operations only if kTLS state is determined
  if (!ktls_state_determined_) {
    ENVOY_LOG(debug, "Cannot process pending operations yet, kTLS state not determined");

    // Check if we've been waiting too long (more than 100ms) and force processing
    // This is a safety mechanism to prevent hanging if kTLS state can't be determined
    if (ktls_handshake_attempts_ >= MAX_KTLS_ATTEMPTS) {
      ENVOY_LOG(debug, "Max attempts reached, forcing kTLS state to determined with kTLS disabled");
      ktls_state_determined_ = true;
      ktls_enabled_ = false;
      // Continue processing below since we've now set ktls_state_determined_ = true
    } else {
      return;
    }
  }

  // Create temporary copies of our pending operations and reset the originals
  // This prevents recursive calls back into processPendingOps() during doRead/doWrite
  absl::optional<PendingReadOp> pending_read_copy;
  absl::optional<PendingWriteOp> pending_write_copy;

  if (pending_read_ && !pending_read_->completed) {
    pending_read_copy = std::move(pending_read_);
    pending_read_.reset();
  }

  if (pending_write_ && !pending_write_->completed) {
    pending_write_copy = std::move(pending_write_);
    pending_write_.reset();
  }

  // Process pending read if any
  if (pending_read_copy && !pending_read_copy->completed) {
    ENVOY_LOG(debug, "Processing pending read operation");

    // Check if the buffer is still valid
    if (pending_read_copy->buffer != nullptr) {
      // Choose whether to use kTLS-enabled or passthrough read
      // Never use kTLS doRead for the first pass, to avoid recursive buffering
      if (ktls_enabled_) {
        pending_read_copy->result = this->doRead(*pending_read_copy->buffer);
      } else {
        pending_read_copy->result = PassthroughSocket::doRead(*pending_read_copy->buffer);
      }
      pending_read_copy->completed = true;

      ENVOY_LOG(debug, "Completed pending read with result: bytes={}, end_stream={}, action={}",
                pending_read_copy->result.bytes_processed_,
                pending_read_copy->result.end_stream_read_,
                pending_read_copy->result.action_ == Network::PostIoAction::KeepOpen ? "KeepOpen"
                                                                                     : "Close");
    } else {
      // Buffer is no longer valid, mark as completed with empty result
      ENVOY_LOG(debug, "Pending read buffer is no longer valid");
      pending_read_copy->completed = true;
      pending_read_copy->result = {Network::PostIoAction::KeepOpen, 0, false};
    }

    // Store the result back in the main object
    pending_read_ = std::move(pending_read_copy);
  }

  // Process pending write if any
  if (pending_write_copy && !pending_write_copy->completed) {
    ENVOY_LOG(debug, "Processing pending write operation");

    // Check if the buffer is still valid
    if (pending_write_copy->buffer != nullptr) {
      // Choose whether to use kTLS-enabled or passthrough write
      // Never use kTLS doWrite for the first pass, to avoid recursive buffering
      if (ktls_enabled_) {
        pending_write_copy->result =
            this->doWrite(*pending_write_copy->buffer, pending_write_copy->end_stream);
      } else {
        pending_write_copy->result =
            PassthroughSocket::doWrite(*pending_write_copy->buffer, pending_write_copy->end_stream);
      }
      pending_write_copy->completed = true;

      ENVOY_LOG(debug, "Completed pending write with result: bytes={}, action={}",
                pending_write_copy->result.bytes_processed_,
                pending_write_copy->result.action_ == Network::PostIoAction::KeepOpen ? "KeepOpen"
                                                                                      : "Close");
    } else {
      // Buffer is no longer valid, mark as completed with empty result
      ENVOY_LOG(debug, "Pending write buffer is no longer valid");
      pending_write_copy->completed = true;
      pending_write_copy->result = {Network::PostIoAction::KeepOpen, 0, false};
    }

    // Store the result back in the main object
    pending_write_ = std::move(pending_write_copy);
  }

  // Clear completed operations
  if (pending_read_ && pending_read_->completed) {
    pending_read_.reset();
  }

  if (pending_write_ && pending_write_->completed) {
    pending_write_.reset();
  }
}

bool KtlsTransportSocket::isConnectionSecure() const { return transport_socket_->ssl() != nullptr; }

void KtlsTransportSocket::raiseEvent(Network::ConnectionEvent event) {
  // Check if this is the Connected event signifying SSL handshake completion
  // and if we haven't tried to determine kTLS state from this path yet.
  // SslSocket raises Connected only upon successful handshake.
  if (event == Network::ConnectionEvent::Connected && !ktls_state_determined_ &&
      transport_socket_->ssl() != nullptr) {
    ENVOY_LOG(debug,
              "KtlsTransportSocket: SSL handshake complete (via Connected event). Triggering kTLS "
              "readiness check immediately.");

    // Cancel any pending readiness timer, as we are acting on a definitive event.
    if (readiness_timer_) {
      readiness_timer_->disableTimer();
    }

    // Get and log sequence numbers, but don't restrict kTLS based on them
    // since Linux 5.15+ supports non-zero sequence numbers
    SSL* ssl_handle = nullptr;
    const Tls::ConnectionInfoImplBase* impl_base =
        dynamic_cast<const Tls::ConnectionInfoImplBase*>(transport_socket_->ssl().get());
    if (impl_base) {
      ssl_handle = impl_base->ssl();
      if (ssl_handle) {
        uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
        uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
        ENVOY_LOG(debug, "Sequence numbers at Connected event - TX: {}, RX: {}", tx_seq, rx_seq);
      }
    }

    // Directly determine kTLS readiness.
    // This will call isSslHandshakeComplete (should be true), then enableKtls(),
    // then extractCryptoParams().
    determineKtlsReadiness();
  }

  // Always forward the event to the actual connection manager etc.
  // This uses the 'callbacks_' member which PassthroughSocket::setTransportSocketCallbacks
  // would have set to the ConnectionImpl.
  if (callbacks_) {
    callbacks_->raiseEvent(event);
  }
}

void KtlsTransportSocket::disableKtls(const std::string& reason) {
  if (ktls_enabled_) {
    ENVOY_LOG(info, "Disabling kTLS: {}", reason);

    // First, mark as disabled to prevent further kTLS calls
    ktls_enabled_ = false;

    // Clear any associated resources
    ktls_info_.reset();

    // Clean up socket splicing regardless of availability
    if (socket_splicing_) {
      socket_splicing_.reset();
    }

    // Reset any error tracking counters
    consecutive_decrypt_failures_ = 0;
    resync_in_progress_ = false;
    resync_scheduled_ = false;
    next_expected_rx_seq_.reset();

    // Reset timer if any
    if (resync_timer_) {
      resync_timer_->disableTimer();
      resync_timer_.reset();
    }

    // ADDED: Try to reset the socket's TLS configuration to minimize buffer issues
    // This is platform-specific and we make a best effort
    if (callbacks_) {
      int fd = callbacks_->ioHandle().fdDoNotUse();
      if (fd >= 0) {
        // Try to clear the kTLS state (this may not work on all kernels, but worth trying)
        // Using null pointers and zero-length for the TLS options should disable them
#ifdef __linux__
        // Note: Some kernels don't support clearing TLS_RX, which is fine
        setsockopt(fd, SOL_TLS, TLS_TX, nullptr, 0);
        setsockopt(fd, SOL_TLS, TLS_RX, nullptr, 0);

        // Drain any pending data from the socket buffer
        // This prevents corrupted/partial TLS records from being passed to software TLS
        char drain_buffer[4096];

        // Check if data is available using a non-blocking call
        int readable = 0;
        platform_util::ioctl_fn(fd, FIONREAD, &readable);

        if (readable > 0) {
          ENVOY_LOG(debug, "Draining socket buffer during kTLS disable ({} bytes available)",
                    readable);
          ssize_t drained = 0;
          int drain_attempts = 0;

          // Try to drain any pending data (maximum 3 attempts)
          while (drain_attempts < 3) {
            ssize_t result = recv(fd, drain_buffer, sizeof(drain_buffer), MSG_DONTWAIT);
            if (result <= 0) {
              break; // No more data or error
            }

            drained += result;
            drain_attempts++;
          }

          if (drained > 0) {
            ENVOY_LOG(debug, "Drained {} bytes from socket during kTLS disable", drained);
          }
        }
#endif
      }
    }

    // Don't attempt to call setsockopt as it's unreliable and often fails
    // The best approach is to simply let future operations use the software TLS path
    // via the transport_socket_ without trying to reset the socket state

    // Log this decision for clarity
    ENVOY_LOG(
        debug,
        "Leaving kTLS socket in current state but redirecting all traffic through software TLS");
  }
}

bool KtlsTransportSocket::enableKtls() {
  ENVOY_LOG(info, "Starting kTLS enablement process");
  
  // STEP 1: Validate basic preconditions
  if (!callbacks_) {
    ENVOY_LOG(debug, "Cannot enable kTLS: No callbacks available");
    return false;
  }
  
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: Invalid file descriptor");
    return false;
  }
  
  // STEP 2: Check SSL connection and get the SSL handle
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(warn, "Cannot enable kTLS: No SSL connection available");
    return false;
  }

  const Tls::ConnectionInfoImplBase* impl_base = 
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (!impl_base || !impl_base->ssl()) {
    ENVOY_LOG(warn, "Cannot enable kTLS: Invalid SSL connection state");
    return false;
  }

  SSL* ssl_handle = impl_base->ssl();
  
  // STEP 3: Check if handshake is complete and log sequence numbers
  if (SSL_in_init(ssl_handle) != 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: SSL handshake still in progress");
    return false;
  }
  
  uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
  uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
  ENVOY_LOG(info, "SSL sequence numbers at kTLS enablement - TX: {}, RX: {}", tx_seq, rx_seq);
  
  // Save sequence numbers for diagnostics
  saved_tx_seq_ = tx_seq;
  saved_rx_seq_ = rx_seq;
  
  // STEP 4: Ensure no pending data in SSL or socket buffers
  if (BIO_flush(SSL_get_wbio(ssl_handle)) <= 0) {
    if (BIO_should_retry(SSL_get_wbio(ssl_handle))) {
      ENVOY_LOG(debug, "Cannot enable kTLS: BIO_flush would block");
      return false;
    }
    ENVOY_LOG(debug, "BIO_flush error: {}, continuing anyway", 
              ERR_reason_error_string(ERR_get_error()));
  }
  
  if (BIO_ctrl_pending(SSL_get_wbio(ssl_handle)) > 0) {
    ENVOY_LOG(warn, "Cannot enable kTLS: Write BIO has pending data ({} bytes)", 
              BIO_ctrl_pending(SSL_get_wbio(ssl_handle)));
    return false;
  }
  
  if (SSL_pending(ssl_handle) > 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: SSL has {} bytes of pending data", 
              SSL_pending(ssl_handle));
    return false;
  }
  
  int socket_pending = 0;
  if (platform_util::ioctl_fn(fd, FIONREAD, &socket_pending) == 0 && socket_pending > 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: Socket has {} bytes pending", socket_pending);
    return false;
  }
  
  // STEP 5: Create kTLS connection info
  auto ktls_info = std::make_shared<KtlsSslInfoImpl>(std::move(ssl_connection));
  
  // STEP 6: Check if ULP is already set
  std::string ulp_buf(16, '\0');
  socklen_t ulp_len = ulp_buf.size();
  bool ulp_already_set = false;
  
  int gso_ret = getsockopt(fd, SOL_TCP, TCP_ULP, ulp_buf.data(), &ulp_len);
  if (gso_ret == 0 && ulp_len > 0) {
    // Trim to actual length and handle null characters
    ulp_buf.resize(ulp_len);
    size_t null_pos = ulp_buf.find('\0');
    if (null_pos != std::string::npos) {
      ulp_buf.resize(null_pos);
    }
    
    ENVOY_LOG(debug, "Current socket ULP: '{}'", ulp_buf);
    
    if (ulp_buf == "tls") {
      ENVOY_LOG(info, "kTLS ULP already enabled for this socket");
      ulp_already_set = true;
    } else if (!ulp_buf.empty()) {
      ENVOY_LOG(warn, "Socket has non-TLS ULP '{}', cannot enable kTLS", ulp_buf);
      return false;
    }
  } else if (gso_ret != 0) {
    // Not fatal, we'll try to set it below
    ENVOY_LOG(debug, "Failed to get current ULP: {} (errno={})", 
              Envoy::errorDetails(errno), errno);
  }
  
  // STEP 7: Set the TLS ULP if not already set
  if (!ulp_already_set) {
    // Use static array with trailing null to ensure proper string length
    static constexpr char TLS_ULP_NAME[] = "tls";
    
    // Try setting the ULP with proper length including null
    int ulp_result = setsockopt(fd, SOL_TCP, TCP_ULP, TLS_ULP_NAME, sizeof(TLS_ULP_NAME) - 1);
    
    if (ulp_result != 0) {
      int err = errno;
      if (err == EEXIST) {
        // ULP already exists, this is fine
        ENVOY_LOG(debug, "kTLS ULP already exists (EEXIST), continuing");
      } else {
        ENVOY_LOG(warn, "Failed to set TLS ULP: {} (errno={})", 
                  Envoy::errorDetails(err), err);
        
        // Try to load the module for certain error types
        if ((err == ENOPROTOOPT || err == EOPNOTSUPP || err == EPERM) && try_loading_module_) {
          ENVOY_LOG(info, "Attempting to load tls kernel module");
          int ret = system("modprobe tls >/dev/null 2>&1");
          if (ret != 0) {
            ENVOY_LOG(warn, "Failed to load tls module (ret={})", ret);
            return false;
          }
          
          // Retry setting ULP after loading module
          ulp_result = setsockopt(fd, SOL_TCP, TCP_ULP, TLS_ULP_NAME, sizeof(TLS_ULP_NAME) - 1);
          if (ulp_result != 0) {
            err = errno;
            ENVOY_LOG(warn, "Failed to set TLS ULP after loading module: {} (errno={})", 
                      Envoy::errorDetails(err), err);
            
            // Special handling for permissions issues
            if (err == EPERM) {
              ENVOY_LOG(error, "Permission denied setting TLS ULP even after module load. "
                           "Ensure process has CAP_NET_ADMIN capability.");
            }
            return false;
          }
          
          ENVOY_LOG(info, "Successfully loaded tls module and set ULP");
        } else {
          // Special handling for permissions issues
          if (err == EPERM) {
            ENVOY_LOG(error, "Permission denied setting TLS ULP. Ensure process has "
                         "CAP_NET_ADMIN capability or run with sudo.");
          }
          return false;
        }
      }
    } else {
      ENVOY_LOG(debug, "Successfully set TLS ULP");
    }
    
    // Verify ULP was set correctly
    ulp_buf.assign(16, '\0');
    ulp_len = ulp_buf.size();
    
    if (getsockopt(fd, SOL_TCP, TCP_ULP, ulp_buf.data(), &ulp_len) == 0 && ulp_len > 0) {
      ulp_buf.resize(ulp_len);
      size_t null_pos = ulp_buf.find('\0');
      if (null_pos != std::string::npos) {
        ulp_buf.resize(null_pos);
      }
      
      ENVOY_LOG(debug, "Verified socket ULP after setting: '{}'", ulp_buf);
      
      if (ulp_buf != "tls") {
        ENVOY_LOG(warn, "Expected ULP 'tls' but got '{}' after setting", ulp_buf);
      }
    }
  }
  
  // STEP 8: Get crypto info from SSL
  tls_crypto_info_t tx_crypto_info = {};
  tls_crypto_info_t rx_crypto_info = {};
  
  if (!ktls_info->getTxCryptoInfo(tx_crypto_info)) {
    ENVOY_LOG(warn, "Failed to get TX crypto info for kTLS");
    return false;
  }
  
  if (!ktls_info->getRxCryptoInfo(rx_crypto_info)) {
    ENVOY_LOG(warn, "Failed to get RX crypto info for kTLS");
    return false;
  }
  
  // STEP 9: Apply TX crypto settings to socket
  bool tx_success = false;
  if (setsockopt(fd, SOL_TLS, TLS_TX, &tx_crypto_info, sizeof(tx_crypto_info)) != 0) {
    int err = errno;
    if (err == EBUSY) {
      ENVOY_LOG(debug, "TX crypto context already exists (EBUSY), considering successful");
      tx_success = true;
    } else {
      ENVOY_LOG(warn, "Failed to set TLS_TX crypto: {} (errno={})", 
                Envoy::errorDetails(err), err);
                
      // Special log for common errors
      if (err == EINVAL) {
        ENVOY_LOG(warn, "Invalid TX crypto parameters - possibly wrong version or cipher type");
      } else if (err == ENOMEM) {
        ENVOY_LOG(warn, "Not enough memory for TX crypto context");
      } else if (err == EBADMSG) {
        ENVOY_LOG(warn, "TX crypto message verification failed");
      } else if (err == EPERM) {
        ENVOY_LOG(error, "Permission denied setting TX crypto. Ensure process has "
                      "CAP_NET_ADMIN capability or run with sudo.");
      }
    }
  } else {
    ENVOY_LOG(debug, "Successfully set TX crypto parameters");
    tx_success = true;
  }
  
  // STEP 10: Set TX zerocopy if requested and TX was successful
  if (tx_success && enable_tx_zerocopy_) {
    int zerocopy_val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &zerocopy_val, sizeof(zerocopy_val)) != 0) {
      ENVOY_LOG(debug, "Failed to set TLS_TX_ZEROCOPY_RO: {} (errno={})", 
                Envoy::errorDetails(errno), errno);
      // Not fatal, continue
    } else {
      ENVOY_LOG(debug, "Successfully enabled TX zerocopy");
    }
  }
  
  // STEP 11: Apply RX crypto settings to socket
  bool rx_success = false;
  if (setsockopt(fd, SOL_TLS, TLS_RX, &rx_crypto_info, sizeof(rx_crypto_info)) != 0) {
    int err = errno;
    if (err == EBUSY) {
      ENVOY_LOG(debug, "RX crypto context already exists (EBUSY), considering successful");
      rx_success = true;
    } else {
      ENVOY_LOG(warn, "Failed to set TLS_RX crypto: {} (errno={})", 
                Envoy::errorDetails(err), err);
                
      // Special log for common errors
      if (err == EINVAL) {
        ENVOY_LOG(warn, "Invalid RX crypto parameters - possibly wrong version or cipher type");
      } else if (err == ENOMEM) {
        ENVOY_LOG(warn, "Not enough memory for RX crypto context");
      } else if (err == EBADMSG) {
        ENVOY_LOG(warn, "RX crypto message verification failed");
      } else if (err == EPERM) {
        ENVOY_LOG(error, "Permission denied setting RX crypto. Ensure process has "
                      "CAP_NET_ADMIN capability or run with sudo.");
      }
    }
  } else {
    ENVOY_LOG(debug, "Successfully set RX crypto parameters");
    rx_success = true;
  }
  
  // STEP 12: Set RX no-padding if requested and RX was successful
  if (rx_success && enable_rx_no_pad_) {
    int no_pad_val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &no_pad_val, sizeof(no_pad_val)) != 0) {
      ENVOY_LOG(debug, "Failed to set TLS_RX_EXPECT_NO_PAD: {} (errno={})", 
                Envoy::errorDetails(errno), errno);
      // Not fatal, continue
    } else {
      ENVOY_LOG(debug, "Successfully enabled RX no-padding");
    }
  }
  
  // STEP 13: Determine overall success and complete setup
  // Some implementations only need TX to work, based on error_handling_mode
  if ((tx_success && rx_success) || (tx_success && error_handling_mode_ == 1)) {
    ENVOY_LOG(info, "Successfully enabled kTLS with TX={}, RX={}, zerocopy={}, no_pad={}", 
              tx_success, rx_success, enable_tx_zerocopy_, enable_rx_no_pad_);
    
    // Store the kTLS info and mark as enabled
    ktls_info_ = ktls_info;
    ktls_enabled_ = true;
    return true;
  }
  
  ENVOY_LOG(warn, "Failed to fully enable kTLS (TX={}, RX={})", tx_success, rx_success);
  return false;
}

// Method to reset resync state after successful read
void KtlsTransportSocket::resetResyncState() {
  if (consecutive_decrypt_failures_ > 0) {
    ENVOY_LOG(debug, "Resetting kTLS resync state after successful read");
    consecutive_decrypt_failures_ = 0;
    next_expected_rx_seq_.reset();
  }
}

bool KtlsTransportSocket::performResynchronization() {
  if (!ktls_enabled_ || !callbacks_) {
    ENVOY_LOG(debug, "Cannot resynchronize: kTLS not enabled or callbacks not available");
    resync_scheduled_ = false;
    return false;
  }

  resync_scheduled_ = false;
  resync_in_progress_ = true;

  // Save current time as the last attempt time
  last_resync_attempt_time_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count();

  ENVOY_LOG(info, "Performing kTLS resynchronization attempt");

  // Get current sequence numbers from SSL
  bool have_current_seq = false;
  uint64_t current_rx_seq = 0;
  uint64_t current_tx_seq = 0;

  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(warn, "Cannot resynchronize: SSL connection not available");
    return false;
  }

  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (!impl_base || !impl_base->ssl()) {
    ENVOY_LOG(warn, "Cannot resynchronize: Invalid SSL connection");
    return false;
  }

  SSL* ssl_handle = impl_base->ssl();
  current_rx_seq = SSL_get_read_sequence(ssl_handle);
  current_tx_seq = SSL_get_write_sequence(ssl_handle);
  have_current_seq = true;

  ENVOY_LOG(debug, "Resynchronizing kTLS with current RX seq={}, TX seq={}", 
            current_rx_seq, current_tx_seq);

  // Track sequence number updates for diagnostics
  if (!next_expected_rx_seq_.has_value()) {
    // First resync attempt - store the expected next sequence number
    next_expected_rx_seq_ = current_rx_seq + 1;
    ENVOY_LOG(debug, "Initial resync: Current RX seq={}, next expected={}", current_rx_seq,
              *next_expected_rx_seq_);
  } else {
    // Update the expected sequence if it appears we've progressed
    if (current_rx_seq >= *next_expected_rx_seq_) {
      ENVOY_LOG(debug, "Updating next_expected_rx_seq from {} to {} based on current state",
                *next_expected_rx_seq_, current_rx_seq + 1);
      next_expected_rx_seq_ = current_rx_seq + 1;
    }
  }

  // Get the underlying file descriptor
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(warn, "Cannot resynchronize: Invalid file descriptor");
    return false;
  }

  if (!have_current_seq) {
    ENVOY_LOG(warn, "Cannot resynchronize: Failed to get current sequence numbers");
    return false;
  }

#ifdef __linux__
  // First, try disabling and re-enabling kTLS completely if this is a later resync attempt
  if (consecutive_decrypt_failures_ >= 3) {
    ENVOY_LOG(info, "Multiple failures ({}), attempting full kTLS reset", 
              consecutive_decrypt_failures_);

    // Try to clear the kTLS state by disabling it first
    // Using null pointers and zero-length for the TLS options should disable them
    setsockopt(fd, SOL_TLS, TLS_TX, nullptr, 0);
    setsockopt(fd, SOL_TLS, TLS_RX, nullptr, 0);

    // Drain any pending data from socket buffer
    char drain_buffer[4096];
    int readable = 0;
    platform_util::ioctl_fn(fd, FIONREAD, &readable);
    if (readable > 0) {
      ENVOY_LOG(debug, "Draining {} bytes during kTLS reset", readable);
      ssize_t drained = recv(fd, drain_buffer, sizeof(drain_buffer), MSG_DONTWAIT);
      if (drained > 0) {
        ENVOY_LOG(debug, "Drained {} bytes during kTLS reset", drained);
      }
    }

    // Wait a tiny bit to allow any kernel cleanup (non-blocking)
    usleep(1000); // 1ms sleep

    // Now try to re-enable kTLS completely
    if (enableKtls()) {
      ENVOY_LOG(info, "Successfully reset and re-enabled kTLS");
      resync_in_progress_ = false;
      return true;
    }

    ENVOY_LOG(warn, "Failed to re-enable kTLS during full reset");
    disableKtls("Failed to re-enable kTLS during resync");
    return false;
  }

  // For lighter resync attempts, just update the sequence numbers
  if (ktls_info_ && ktls_info_->initializeSequenceNumbers(/* ktls_mode */ 0)) {
    ENVOY_LOG(info, "Successfully reinitialized kTLS sequence numbers");

    // Get fresh crypto info for RX with updated sequence numbers
    tls_crypto_info_t rx_info = {};
    if (ktls_info_->getRxCryptoInfo(rx_info)) {
      ENVOY_LOG(debug, "Updating kTLS RX crypto state after resync");

      // Attempt to reset the RX state with updated sequence numbers
      if (setsockopt(fd, SOL_TLS, TLS_RX, &rx_info, sizeof(rx_info)) != 0) {
        int err = errno;
        ENVOY_LOG(warn, "Failed to resynchronize kTLS RX state: {} (errno={})",
                  Envoy::errorDetails(err), err);
        
        if (err == EINVAL) {
          // EINVAL often means the new sequence number wasn't accepted
          ENVOY_LOG(warn, "Kernel rejected sequence number update (EINVAL), "
                         "this might indicate Linux kernel version < 5.11");
        }
        
        return false;
      }

      // Try also updating TX crypto info for good measure
      tls_crypto_info_t tx_info = {};
      if (ktls_info_->getTxCryptoInfo(tx_info)) {
        if (setsockopt(fd, SOL_TLS, TLS_TX, &tx_info, sizeof(tx_info)) != 0) {
          // This isn't fatal, just log it
          ENVOY_LOG(debug, "Non-critical: Failed to update kTLS TX state: {}",
                    Envoy::errorDetails(errno));
        } else {
          ENVOY_LOG(debug, "Successfully updated kTLS TX state");
        }
      }
      
      ENVOY_LOG(info, "kTLS RX state successfully resynchronized");
      resync_in_progress_ = false;
      return true;
    }
  }
#else
  // Non-Linux platforms: just disable and re-enable kTLS
  ENVOY_LOG(info, "Platform doesn't support fine-grained kTLS control, using full reset");
  
  // Simply try to re-enable kTLS completely
  if (enableKtls()) {
    ENVOY_LOG(info, "Successfully reset kTLS");
    resync_in_progress_ = false;
    return true;
  }
#endif

  ENVOY_LOG(warn, "Failed to resynchronize kTLS state");
  return false;
}

KtlsTransportSocketFactory::KtlsTransportSocketFactory(
    Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory, bool enable_tx_zerocopy,
    bool enable_rx_no_pad, uint64_t safe_seq_threshold)
    : inner_factory_(std::move(transport_socket_factory)), enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad), safe_seq_threshold_(safe_seq_threshold) {}

Network::TransportSocketPtr KtlsTransportSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    std::shared_ptr<const Upstream::HostDescription> host) const {
  Network::TransportSocketPtr inner_socket = inner_factory_->createTransportSocket(options, host);
  if (inner_socket == nullptr) {
    return nullptr;
  }

  auto ktls_socket = std::make_unique<KtlsTransportSocket>(std::move(inner_socket),
                                                           enable_tx_zerocopy_, enable_rx_no_pad_);
  ktls_socket->setIsUpstream(true);
  ktls_socket->setSafeSeqThreshold(safe_seq_threshold_);

  // Set enhanced parameters
  ktls_socket->setRetryOnFailure(retry_on_failure_);
  ktls_socket->setMaxRetryAttempts(max_retry_attempts_);
  ktls_socket->setTryLoadingModule(try_loading_module_);
  ktls_socket->setErrorHandlingMode(error_handling_mode_);

  return ktls_socket;
}

DownstreamKtlsTransportSocketFactory::DownstreamKtlsTransportSocketFactory(
    Network::DownstreamTransportSocketFactoryPtr&& transport_socket_factory,
    bool enable_tx_zerocopy, bool enable_rx_no_pad, uint64_t safe_seq_threshold)
    : DownstreamPassthroughFactory(std::move(transport_socket_factory)),
      enable_tx_zerocopy_(enable_tx_zerocopy), enable_rx_no_pad_(enable_rx_no_pad),
      safe_seq_threshold_(safe_seq_threshold) {}

Network::TransportSocketPtr
DownstreamKtlsTransportSocketFactory::createDownstreamTransportSocket() const {
  Network::TransportSocketPtr inner_socket =
      transport_socket_factory_->createDownstreamTransportSocket();
  if (inner_socket == nullptr) {
    return nullptr;
  }

  auto ktls_socket = std::make_unique<KtlsTransportSocket>(std::move(inner_socket),
                                                           enable_tx_zerocopy_, enable_rx_no_pad_);
  ktls_socket->setIsUpstream(false);
  ktls_socket->setSafeSeqThreshold(safe_seq_threshold_);

  // Set enhanced parameters
  ktls_socket->setRetryOnFailure(retry_on_failure_);
  ktls_socket->setMaxRetryAttempts(max_retry_attempts_);
  ktls_socket->setTryLoadingModule(try_loading_module_);
  ktls_socket->setErrorHandlingMode(error_handling_mode_);

  return ktls_socket;
}

bool KtlsTransportSocket::enableKtls() {
  ENVOY_LOG(info, "Starting kTLS enablement process");
  
  // STEP 1: Validate basic preconditions
  if (!callbacks_) {
    ENVOY_LOG(debug, "Cannot enable kTLS: No callbacks available");
    return false;
  }
  
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: Invalid file descriptor");
    return false;
  }
  
  // STEP 2: Check SSL connection and get the SSL handle
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(warn, "Cannot enable kTLS: No SSL connection available");
    return false;
  }

  const Tls::ConnectionInfoImplBase* impl_base = 
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (!impl_base || !impl_base->ssl()) {
    ENVOY_LOG(warn, "Cannot enable kTLS: Invalid SSL connection state");
    return false;
  }

  SSL* ssl_handle = impl_base->ssl();
  
  // STEP 3: Check if handshake is complete and log sequence numbers
  if (SSL_in_init(ssl_handle) != 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: SSL handshake still in progress");
    return false;
  }
  
  uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
  uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
  ENVOY_LOG(info, "SSL sequence numbers at kTLS enablement - TX: {}, RX: {}", tx_seq, rx_seq);
  
  // Save sequence numbers for diagnostics
  saved_tx_seq_ = tx_seq;
  saved_rx_seq_ = rx_seq;
  
  // STEP 4: Ensure no pending data in SSL or socket buffers
  if (BIO_flush(SSL_get_wbio(ssl_handle)) <= 0) {
    if (BIO_should_retry(SSL_get_wbio(ssl_handle))) {
      ENVOY_LOG(debug, "Cannot enable kTLS: BIO_flush would block");
      return false;
    }
    ENVOY_LOG(debug, "BIO_flush error: {}, continuing anyway", 
              ERR_reason_error_string(ERR_get_error()));
  }
  
  if (BIO_ctrl_pending(SSL_get_wbio(ssl_handle)) > 0) {
    ENVOY_LOG(warn, "Cannot enable kTLS: Write BIO has pending data ({} bytes)", 
              BIO_ctrl_pending(SSL_get_wbio(ssl_handle)));
    return false;
  }
  
  if (SSL_pending(ssl_handle) > 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: SSL has {} bytes of pending data", 
              SSL_pending(ssl_handle));
    return false;
  }
  
  int socket_pending = 0;
  if (platform_util::ioctl_fn(fd, FIONREAD, &socket_pending) == 0 && socket_pending > 0) {
    ENVOY_LOG(debug, "Cannot enable kTLS: Socket has {} bytes pending", socket_pending);
    return false;
  }
  
  // STEP 5: Create kTLS connection info and extract crypto params
  auto ktls_info = std::make_shared<KtlsSslInfoImpl>(std::move(ssl_connection));
  
  // Explicitly trigger parameter extraction before proceeding
  // This should populate the crypto info structures
  if (!ktls_info->extractCryptoParams()) {
    ENVOY_LOG(warn, "Failed to extract crypto parameters, will retry on next readiness check");
    return false;
  }
  
  // STEP 6: Check if ULP is already set
  std::string ulp_buf(16, '\0');
  socklen_t ulp_len = ulp_buf.size();
  bool ulp_already_set = false;
  
  int gso_ret = getsockopt(fd, SOL_TCP, TCP_ULP, ulp_buf.data(), &ulp_len);
  if (gso_ret == 0 && ulp_len > 0) {
    // Trim to actual length and handle null characters
    ulp_buf.resize(ulp_len);
    size_t null_pos = ulp_buf.find('\0');
    if (null_pos != std::string::npos) {
      ulp_buf.resize(null_pos);
    }
    
    ENVOY_LOG(debug, "Current socket ULP: '{}'", ulp_buf);
    
    if (ulp_buf == "tls") {
      ENVOY_LOG(info, "kTLS ULP already enabled for this socket");
      ulp_already_set = true;
    } else if (!ulp_buf.empty()) {
      ENVOY_LOG(warn, "Socket has non-TLS ULP '{}', cannot enable kTLS", ulp_buf);
      return false;
    }
  } else if (gso_ret != 0) {
    // Not fatal, we'll try to set it below
    ENVOY_LOG(debug, "Failed to get current ULP: {} (errno={})", 
              Envoy::errorDetails(errno), errno);
  }
  
  // STEP 7: Set the TLS ULP if not already set
  if (!ulp_already_set) {
    // Use static array with trailing null to ensure proper string length
    static constexpr char TLS_ULP_NAME[] = "tls";
    
    // Try setting the ULP with proper length
    int ulp_result = setsockopt(fd, SOL_TCP, TCP_ULP, TLS_ULP_NAME, strlen(TLS_ULP_NAME));
    
    if (ulp_result != 0) {
      int err = errno;
      if (err == EEXIST) {
        // ULP already exists, this is fine
        ENVOY_LOG(debug, "kTLS ULP already exists (EEXIST), continuing");
      } else {
        ENVOY_LOG(warn, "Failed to set TLS ULP: {} (errno={})", 
                  Envoy::errorDetails(err), err);
        
        // Try to load the module for certain error types
        if ((err == ENOPROTOOPT || err == EOPNOTSUPP || err == EPERM) && try_loading_module_) {
          ENVOY_LOG(info, "Attempting to load tls kernel module");
          int ret = system("modprobe tls >/dev/null 2>&1");
          if (ret != 0) {
            ENVOY_LOG(warn, "Failed to load tls module (ret={})", ret);
            return false;
          }
          
          // Retry setting ULP after loading module
          ulp_result = setsockopt(fd, SOL_TCP, TCP_ULP, TLS_ULP_NAME, strlen(TLS_ULP_NAME));
          if (ulp_result != 0) {
            err = errno;
            ENVOY_LOG(warn, "Failed to set TLS ULP after loading module: {} (errno={})", 
                      Envoy::errorDetails(err), err);
            
            // Special handling for permissions issues
            if (err == EPERM) {
              ENVOY_LOG(error, "Permission denied setting TLS ULP even after module load. "
                           "Ensure process has CAP_NET_ADMIN capability.");
            }
            return false;
          }
          
          ENVOY_LOG(info, "Successfully loaded tls module and set ULP");
        } else {
          // Special handling for permissions issues
          if (err == EPERM) {
            ENVOY_LOG(error, "Permission denied setting TLS ULP. Ensure process has "
                         "CAP_NET_ADMIN capability or run with sudo.");
          }
          return false;
        }
      }
    } else {
      ENVOY_LOG(debug, "Successfully set TLS ULP");
    }
    
    // Verify ULP was set correctly
    ulp_buf.assign(16, '\0');
    ulp_len = ulp_buf.size();
    
    if (getsockopt(fd, SOL_TCP, TCP_ULP, ulp_buf.data(), &ulp_len) == 0 && ulp_len > 0) {
      ulp_buf.resize(ulp_len);
      size_t null_pos = ulp_buf.find('\0');
      if (null_pos != std::string::npos) {
        ulp_buf.resize(null_pos);
      }
      
      ENVOY_LOG(debug, "Verified socket ULP after setting: '{}'", ulp_buf);
      
      if (ulp_buf != "tls") {
        ENVOY_LOG(warn, "Expected ULP 'tls' but got '{}' after setting", ulp_buf);
      }
    }
  }
  
  // STEP 8: Get crypto info from SSL
  tls_crypto_info_t tx_crypto_info = {};
  tls_crypto_info_t rx_crypto_info = {};
  
  if (!ktls_info->getTxCryptoInfo(tx_crypto_info)) {
    ENVOY_LOG(warn, "Failed to get TX crypto info for kTLS");
    return false;
  }
  
  if (!ktls_info->getRxCryptoInfo(rx_crypto_info)) {
    ENVOY_LOG(warn, "Failed to get RX crypto info for kTLS");
    return false;
  }
  
  // STEP 9: Apply TX crypto settings to socket
  bool tx_success = false;
  if (setsockopt(fd, SOL_TLS, TLS_TX, &tx_crypto_info, sizeof(tx_crypto_info)) != 0) {
    int err = errno;
    if (err == EBUSY) {
      ENVOY_LOG(debug, "TX crypto context already exists (EBUSY), considering successful");
      tx_success = true;
    } else {
      ENVOY_LOG(warn, "Failed to set TLS_TX crypto: {} (errno={})", 
                Envoy::errorDetails(err), err);
                
      // Special log for common errors
      if (err == EINVAL) {
        ENVOY_LOG(warn, "Invalid TX crypto parameters - possibly wrong version or cipher type");
      } else if (err == ENOMEM) {
        ENVOY_LOG(warn, "Not enough memory for TX crypto context");
      } else if (err == EBADMSG) {
        ENVOY_LOG(warn, "TX crypto message verification failed");
      } else if (err == EPERM) {
        ENVOY_LOG(error, "Permission denied setting TX crypto. Ensure process has "
                      "CAP_NET_ADMIN capability or run with sudo.");
      }
    }
  } else {
    ENVOY_LOG(debug, "Successfully set TX crypto parameters");
    tx_success = true;
  }
  
  // STEP 10: Set TX zerocopy if requested and TX was successful
  if (tx_success && enable_tx_zerocopy_) {
    int zerocopy_val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &zerocopy_val, sizeof(zerocopy_val)) != 0) {
      ENVOY_LOG(debug, "Failed to set TLS_TX_ZEROCOPY_RO: {} (errno={})", 
                Envoy::errorDetails(errno), errno);
      // Not fatal, continue
    } else {
      ENVOY_LOG(debug, "Successfully enabled TX zerocopy");
    }
  }
  
  // STEP 11: Apply RX crypto settings to socket
  bool rx_success = false;
  if (setsockopt(fd, SOL_TLS, TLS_RX, &rx_crypto_info, sizeof(rx_crypto_info)) != 0) {
    int err = errno;
    if (err == EBUSY) {
      ENVOY_LOG(debug, "RX crypto context already exists (EBUSY), considering successful");
      rx_success = true;
    } else {
      ENVOY_LOG(warn, "Failed to set TLS_RX crypto: {} (errno={})", 
                Envoy::errorDetails(err), err);
                
      // Special log for common errors
      if (err == EINVAL) {
        ENVOY_LOG(warn, "Invalid RX crypto parameters - possibly wrong version or cipher type");
      } else if (err == ENOMEM) {
        ENVOY_LOG(warn, "Not enough memory for RX crypto context");
      } else if (err == EBADMSG) {
        ENVOY_LOG(warn, "RX crypto message verification failed");
      } else if (err == EPERM) {
        ENVOY_LOG(error, "Permission denied setting RX crypto. Ensure process has "
                      "CAP_NET_ADMIN capability or run with sudo.");
      }
    }
  } else {
    ENVOY_LOG(debug, "Successfully set RX crypto parameters");
    rx_success = true;
  }
  
  // STEP 12: Set RX no-padding if requested and RX was successful
  if (rx_success && enable_rx_no_pad_) {
    int no_pad_val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &no_pad_val, sizeof(no_pad_val)) != 0) {
      ENVOY_LOG(debug, "Failed to set TLS_RX_EXPECT_NO_PAD: {} (errno={})", 
                Envoy::errorDetails(errno), errno);
      // Not fatal, continue
    } else {
      ENVOY_LOG(debug, "Successfully enabled RX no-padding");
    }
  }
  
  // STEP 13: Determine overall success and complete setup
  // Some implementations only need TX to work, based on error_handling_mode
  if ((tx_success && rx_success) || (tx_success && error_handling_mode_ == 1)) {
    ENVOY_LOG(info, "Successfully enabled kTLS with TX={}, RX={}, zerocopy={}, no_pad={}", 
              tx_success, rx_success, enable_tx_zerocopy_, enable_rx_no_pad_);
    
    // Store the kTLS info and mark as enabled
    ktls_info_ = ktls_info;
    ktls_enabled_ = true;
    return true;
  }
  
  ENVOY_LOG(warn, "Failed to fully enable kTLS (TX={}, RX={})", tx_success, rx_success);
  return false;
}

// Define helper function for ioctl calls
inline int ioctl_wrap(int fd, unsigned long request, void* argp) {
  return platform_util::ioctl_fn(fd, request, argp);
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
