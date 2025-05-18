#include <string>
#include <utility>
#include <vector>

// Include system headers only once and in a specific order to avoid conflicts
#ifdef __linux__
// Include Linux-specific headers
#include <sys/socket.h>
#include <sys/utsname.h>

// Only use linux/tcp.h for the specific kTLS definitions we need
// Include it in a namespace to avoid polluting global namespace
namespace {
#include <linux/tcp.h>
}  // namespace

// Include capability support if available
#if __has_include(<sys/capability.h>)
#include <sys/capability.h>
#define HAS_CAPABILITY_SUPPORT 1
#endif

// More reliable check for splice availability
#if __has_include(<sys/splice.h>) || defined(splice)
#include <sys/splice.h>
#define HAS_SPLICE_SYSCALL 1
#else
// Try to detect if we have splice function available even without the header
#include <unistd.h>
#include <fcntl.h>
#ifdef __NR_splice
#define HAS_SPLICE_SYSCALL 1
#endif
#endif
#endif

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
#include "source/common/tls/connection_info_impl_base.h"
#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"
#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

// Include OpenSSL headers
#include "openssl/evp.h"
#include "openssl/ssl.h"

// Include SSL socket header using correct path
#include "source/common/tls/ssl_socket.h"

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

// Define linux/tcp.h constants needed for kTLS
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef TCP_INFO
#define TCP_INFO 11
#endif

// Define tls_crypto_info_t type if not defined
#ifndef __linux__
using tls_crypto_info_t = void*;
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
    : PassthroughSocket(std::move(transport_socket)), enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad) {
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

bool KtlsTransportSocket::isKtlsEnabled() const {
  return ktls_enabled_;
}

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

  if (!result.ok()) {
    // Check for EBADMSG (74) or other TLS-related errors
    int sys_err_code = result.err_->getSystemErrorCode();
    if (sys_err_code == EBADMSG || 
        sys_err_code == ECONNRESET || 
        sys_err_code == EPROTO) {
      ENVOY_LOG(warn, "kTLS read error: {} (errno={})", 
                result.err_->getErrorDetails(), sys_err_code);
      
      // Disable kTLS for this connection due to error and fall back to SSL
      disableKtls("TLS protocol error during read");
      
      // Try again without kTLS, but if this also fails, we'll return the original error
      auto fallback_result = transport_socket_->doRead(buffer);
      if (fallback_result.bytes_processed_ > 0 || 
          fallback_result.action_ != Network::PostIoAction::Close) {
        return fallback_result;
      }
    }
    
    // If we get here, either it wasn't a TLS error or the fallback also failed
    return {Network::PostIoAction::Close, 0, false};
  }

  uint64_t bytes_read = result.return_value_;
  
  if (bytes_read == 0) {
    // Connection closed
    return {Network::PostIoAction::Close, 0, true};
  }

  // Commit the read data to the buffer - we only use a portion of the reserved slice
  reservation.commit(bytes_read);
  
  return {Network::PostIoAction::KeepOpen, bytes_read, false};
}

Network::IoResult KtlsTransportSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  // Check if we need to determine kTLS readiness
  if (!ktls_state_determined_) {
    // First, check if the handshake is complete - it might be by now since we're about to write
    if (isSslHandshakeComplete()) {
      ENVOY_LOG(debug, "Detected completed handshake during write operation");
      determineKtlsReadiness();
    } else if (!pending_write_) {
      // If handshake is not complete, buffer the operation
      ENVOY_LOG(debug, "Buffering write operation until kTLS state is determined");
      pending_write_ =
          PendingWriteOp{&buffer, end_stream, {Network::PostIoAction::KeepOpen, 0, false}, false};

      // For write operations, we need to trigger the SSL handshake since it's lazy
      // This call might actually complete the handshake
      Network::IoResult handshake_result = PassthroughSocket::doWrite(buffer, end_stream);

      // If the handshake completed during this write, process pending ops immediately
      if (isSslHandshakeComplete()) {
        ENVOY_LOG(debug, "Handshake completed during buffered write");
        determineKtlsReadiness();
        // Check if this write operation was processed as a pending operation
        if (pending_write_ && pending_write_->completed) {
          Network::IoResult result = pending_write_->result;
          pending_write_.reset();
          return result;
        }
      }

      return handshake_result;
    } else {
      // We already have a pending write operation, just trigger the SSL handshake
      Network::IoResult handshake_result = PassthroughSocket::doWrite(buffer, end_stream);
      if (isSslHandshakeComplete()) {
        ENVOY_LOG(debug, "Handshake completed during write operation with existing pending write");
        determineKtlsReadiness();
      }
      return handshake_result;
    }
  }

  // Process any pending operations first, but prevent recursive processing
  static thread_local bool processing_pending_ops = false;
  if ((pending_read_ || pending_write_) && !processing_pending_ops) {
    processing_pending_ops = true;
    processPendingOps();
    processing_pending_ops = false;

    // Check if this write operation was processed as a pending operation
    if (pending_write_ && pending_write_->completed && pending_write_->buffer == &buffer &&
        pending_write_->end_stream == end_stream) {
      Network::IoResult result = pending_write_->result;
      pending_write_.reset();
      return result;
    }
  }

  // If kTLS is enabled, only use direct socket operations, never fall back to SSL
  if (ktls_enabled_) {
    // Get file descriptor for direct socket operations
    int fd = callbacks_->ioHandle().fdDoNotUse();
    if (fd < 0) {
      ENVOY_LOG(error, "Invalid file descriptor for kTLS write: {}", fd);
      return {Network::PostIoAction::Close, 0, false};
    }

    // Try socket splicing for zero-copy writes if available
    if (socket_splicing_ && enable_tx_zerocopy_ && buffer.length() > 0) {
      // Try to write using socket splicing for zero-copy
      auto result = socket_splicing_->writeFromBuffer(buffer);

      if (!result.ok()) {
        if (result.err_->getErrorCode() == Api::IoError::IoErrorCode::Again) {
          // EAGAIN, resource temporarily unavailable
          return {Network::PostIoAction::KeepOpen, 0, false};
        } else if (result.err_->getSystemErrorCode() == ENOSYS) {
          // ENOSYS means socket splicing is not supported - fall through to direct write
          ENVOY_LOG(debug, "Socket splicing not supported, falling back to direct write");
        } else {
          // Real error
          ENVOY_LOG(debug, "kTLS zero-copy write error: {}", result.err_->getErrorDetails());
          
          // For critical TLS errors, we should disable kTLS and fall back
          if (result.err_->getSystemErrorCode() == EBADMSG || 
              result.err_->getSystemErrorCode() == EPROTO) {
            disableKtls("TLS protocol error during zero-copy write");
            return transport_socket_->doWrite(buffer, end_stream);
          }
          
          return {Network::PostIoAction::Close, 0, false};
        }
      } else {
        // If splicing worked, drain the buffer and continue
        if (result.return_value_ > 0) {
          buffer.drain(result.return_value_);

          // Check if we've written everything (accounting for end_stream)
          if (buffer.length() == 0) {
            return {Network::PostIoAction::KeepOpen, result.return_value_, end_stream};
          }
        }

        // If we still have data to write, it will be handled in the next write event
        // or fall through to direct write below
        if (buffer.length() > 0) {
          // Only exit early if we actually wrote something
          if (result.return_value_ > 0) {
            return {Network::PostIoAction::KeepOpen, result.return_value_, false};
          }
          // Otherwise fall through to direct write
        } else {
          return {Network::PostIoAction::KeepOpen, result.return_value_, end_stream};
        }
      }
    }

    // Direct socket write if splicing not available or failed
    if (buffer.length() > 0) {
      // Get all raw slices from the buffer for direct writing
      Buffer::RawSliceVector slices = buffer.getRawSlices();
      if (!slices.empty()) {
        // Create an iovec array from the buffer slices
        std::vector<struct iovec> iov(slices.size());
        size_t total_size = 0;

        for (size_t i = 0; i < slices.size(); i++) {
          if (slices[i].len_ == 0) {
            continue;
          }
          iov[i].iov_base = slices[i].mem_;
          iov[i].iov_len = slices[i].len_;
          total_size += slices[i].len_;
        }

        if (total_size > 0) {
          // Try writing using writev directly to the socket
          ssize_t bytes_written = ::writev(fd, iov.data(), iov.size());

          if (bytes_written > 0) {
            // Direct write succeeded
            buffer.drain(bytes_written);
            return {Network::PostIoAction::KeepOpen, static_cast<uint64_t>(bytes_written),
                    end_stream && buffer.length() == 0};
          } else if (bytes_written == 0) {
            // Connection may be closing
            return {Network::PostIoAction::Close, 0, false};
          } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Would block, try again later
            return {Network::PostIoAction::KeepOpen, 0, false};
          } else if (errno == EBADMSG || errno == EPROTO) {
            // This is an expected error with some kernel kTLS implementations
            // Disable kTLS and fall back to standard SSL
            ENVOY_LOG(warn, "kTLS received protocol error during write, disabling kTLS and "
                            "falling back to SSL");
            disableKtls("Protocol error during direct write");
            return transport_socket_->doWrite(buffer, end_stream);
          } else {
            // Real error occurred
            ENVOY_LOG(error, "Direct write to kTLS socket failed with error: {} (errno={})",
                      Envoy::errorDetails(errno), errno);
            return {Network::PostIoAction::Close, 0, false};
          }
        }
      }
    }

    // If we've written everything or there's nothing to write
    return {Network::PostIoAction::KeepOpen, 0, end_stream && buffer.length() == 0};
  }

  // If kTLS is not enabled, use the standard SSL path
  return transport_socket_->doWrite(buffer, end_stream);
}

bool KtlsTransportSocket::startSecureTransport() {
  // This is no-op for kTLS
  return false;
}

void KtlsTransportSocket::onConnected() {
  // Delegate to the wrapped socket first
  PassthroughSocket::onConnected();

  // Don't try to enable kTLS immediately, we'll check during data operations
  ENVOY_LOG(debug, "Connection established, will determine kTLS readiness during data operations");

  // Schedule a delayed attempt to determine kTLS state with initial delay
  if (callbacks_) {
    scheduleKtlsReadinessCheck();
  }
}

bool KtlsTransportSocket::isSslHandshakeComplete() const {
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    return false;
  }

  // Use multiple indicators to determine if handshake is truly complete

  // Method 1: Check if connection info is valid and has cipher info
  std::string cipher = std::string(ssl_connection->ciphersuiteString());
  std::string version = std::string(ssl_connection->tlsVersion());
  bool has_crypto_info = !cipher.empty() && !version.empty();

  // Method 2: Check if we have peer certificate (may not be present for all connections)
  bool has_peer_cert = ssl_connection->peerCertificatePresented();

  // Method 3: Check for TLS handshake completion indicators
  // Note: Using simpler checks as validationStatus is not available
  bool has_security = ssl_connection->peerCertificateValidated();

  // Method 4: Check if we have a session ID, which is set once handshake completes
  std::string session_id = ssl_connection->sessionId();
  bool has_session_id = !session_id.empty();

  // Method 5: Get SSL state from the underlying SSL connection
  SSL* ssl_handle = nullptr;
  bool is_handshake_done = false;

  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());

  if (impl_base) {
    ssl_handle = impl_base->ssl();
    // Check if handshake is done using SSL_in_init
    // When SSL_in_init returns 0, the handshake is complete
    is_handshake_done = ssl_handle && SSL_in_init(ssl_handle) == 0;
  }

  // Log the detailed state for debugging
  ENVOY_LOG(debug,
            "SSL handshake state - has_crypto_info: {}, has_peer_cert: {}, has_security: {}, "
            "has_session_id: {}, is_handshake_done: {}, cipher: {}, version: {}",
            has_crypto_info, has_peer_cert, has_security, has_session_id, is_handshake_done, cipher,
            version);

  // Return true if we have good indicators that handshake is complete
  // Different connections may have different indicators, so we use a combination
  // Order the checks from most reliable to least reliable
  return is_handshake_done || has_session_id || (has_crypto_info && has_peer_cert) ||
         (has_crypto_info && has_security);
}

void KtlsTransportSocket::determineKtlsReadiness() {
  // Check if we already determined the state
  if (ktls_state_determined_) {
    return;
  }

  // Increment attempt counter
  ktls_handshake_attempts_++;

  // Check if handshake is complete first
  bool handshake_complete = isSslHandshakeComplete();

  // If handshake is not complete, we can't determine kTLS status yet
  if (!handshake_complete) {
    // Log with appropriate level based on attempt number to avoid log spam
    if (ktls_handshake_attempts_ == 1 || ktls_handshake_attempts_ % 3 == 0) {
      ENVOY_LOG(debug, "SSL handshake not complete yet, attempt {}/{}", ktls_handshake_attempts_,
                MAX_KTLS_ATTEMPTS);
    } else {
      ENVOY_LOG(trace, "SSL handshake not complete yet, attempt {}/{}", ktls_handshake_attempts_,
                MAX_KTLS_ATTEMPTS);
    }

    // Schedule next attempt if not at limit
    if (ktls_handshake_attempts_ < MAX_KTLS_ATTEMPTS) {
      scheduleKtlsReadinessCheck();
    } else {
      // Max attempts reached, mark as determined and unable to use kTLS
      ENVOY_LOG(info, "Maximum kTLS determination attempts reached, proceeding without kTLS");
      ktls_state_determined_ = true;
      processPendingOps();
    }
    return;
  }

  // If handshake is complete, try to enable kTLS
  ENVOY_CONN_LOG(debug, "SSL handshake is complete, attempting to enable kTLS",
                 callbacks_->connection());

  // Try to enable kTLS - this will check platform support and other requirements
  bool ktls_enabled = enableKtls();

  // Mark kTLS state as determined regardless of enablement result
  ktls_state_determined_ = true;

  if (ktls_enabled) {
    ENVOY_LOG(info, "kTLS enabled successfully");
  } else {
    ENVOY_LOG(debug, "kTLS could not be enabled, using standard TLS");
  }

  // Process any pending operations
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
      pending_read_copy->result =
          ktls_enabled_ ?
                        // Use direct PassthroughSocket instead of our own doRead to avoid recursion
              PassthroughSocket::doRead(*pending_read_copy->buffer)
                        : PassthroughSocket::doRead(*pending_read_copy->buffer);
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
      pending_write_copy->result =
          ktls_enabled_
              ?
              // Use direct PassthroughSocket instead of our own doWrite to avoid recursion
              PassthroughSocket::doWrite(*pending_write_copy->buffer,
                                         pending_write_copy->end_stream)
              : PassthroughSocket::doWrite(*pending_write_copy->buffer,
                                           pending_write_copy->end_stream);
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

void KtlsTransportSocket::disableKtls(const std::string& reason) {
  if (ktls_enabled_) {
    ENVOY_LOG(info, "Disabling kTLS: {}", reason);
    
    // Try to clean up the kernel TLS state
    int fd = callbacks_->ioHandle().fdDoNotUse();
    if (fd >= 0) {
      // Attempt to disable TX first
      if (setsockopt(fd, SOL_TLS, TLS_TX, NULL, 0) < 0) {
        ENVOY_LOG(debug, "Failed to disable TLS_TX: {}", Envoy::errorDetails(errno));
      }
      
      // Attempt to disable RX 
      if (setsockopt(fd, SOL_TLS, TLS_RX, NULL, 0) < 0) {
        ENVOY_LOG(debug, "Failed to disable TLS_RX: {}", Envoy::errorDetails(errno));
      }
    }
    
    ktls_enabled_ = false;

    // Clear any associated resources
    ktls_info_.reset();

    // Clean up socket splicing regardless of availability
    if (socket_splicing_) {
      socket_splicing_.reset();
    }
  }
}

bool KtlsTransportSocket::enableKtls() {
#ifdef __linux__
  // Only attempt to enable kTLS if the socket is valid
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(debug, "Invalid file descriptor for kTLS: {}", fd);
    ktls_enabled_ = false;
    return false;
  }

  // Check if syscalls are successful by checking that the TLS kernel module is loaded
  if (access("/proc/sys/net/ipv4/tcp_available_ulp", R_OK) != 0) {
    ENVOY_LOG(debug, "TCP ULP file is not accessible, kTLS module may not be loaded");
    ktls_enabled_ = false;
    return false;
  }

  // Check kernel version - kTLS requires at least 4.13
  struct utsname kernel_info;
  if (uname(&kernel_info) == 0) {
    ENVOY_LOG(debug, "Attempting kTLS on Linux kernel {}", kernel_info.release);
    
    // Simple version check - just ensure we're on 4.13 or higher
    int major = 0, minor = 0;
    if (sscanf(kernel_info.release, "%d.%d", &major, &minor) == 2) {
      if (major < 4 || (major == 4 && minor < 13)) {
        ENVOY_LOG(warn, "Kernel version {}.{} doesn't support kTLS (requires at least 4.13)",
                  major, minor);
        ktls_enabled_ = false;
        return false;
      }
    }
  }

  // 1. Set TLS ULP
  // Query and log socket state for debugging - using TCP info instead of TCP_STATE
  // Use anonymous namespace to avoid ambiguity with tcp_info struct name
  struct ::tcp_info tcp_state;
  socklen_t info_len = sizeof(tcp_state);
  if (getsockopt(fd, SOL_TCP, TCP_INFO, &tcp_state, &info_len) < 0) {
    ENVOY_LOG(debug, "Failed to query TCP socket info: {}", Envoy::errorDetails(errno));
  } else {
    ENVOY_LOG(debug, "TCP socket state: {}", tcp_state.tcpi_state);
  }

  // Make sure TCP is in established state - can't set ULP otherwise
  // TCP_ESTABLISHED is state 1
  if (info_len >= sizeof(tcp_state) && tcp_state.tcpi_state != 1) {
    ENVOY_LOG(debug, "TCP socket not in established state (got state {})", tcp_state.tcpi_state);
    ktls_enabled_ = false;
    return false;
  }

  // Set TCP ULP to TLS
  ENVOY_LOG(debug, "Attempting to set TCP_ULP for kTLS on socket fd={}", fd);
  const char ulp_name[] = "tls";
  if (setsockopt(fd, SOL_TCP, TCP_ULP, ulp_name, sizeof(ulp_name)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TCP_ULP=tls on fd={}: {} (errno={})", fd,
              Envoy::errorDetails(err), err);
    ktls_enabled_ = false;
    return false;
  }
  ENVOY_LOG(debug, "Successfully set TCP_ULP=tls on fd={}", fd);

  // Get crypto info for kTLS
  if (!ktls_info_) {
    // Create SSL info wrapper for kTLS
    auto ssl_info = transport_socket_->ssl();
    if (!ssl_info) {
      ENVOY_LOG(debug, "No SSL info available, cannot enable kTLS");
      ktls_enabled_ = false;
      return false;
    }
    ktls_info_ = std::make_shared<KtlsSslInfoImpl>(ssl_info);
    
    // Explicitly extract crypto parameters
    if (!ktls_info_->extractCryptoParams()) {
      ENVOY_LOG(debug, "Failed to extract crypto parameters for kTLS");
      ktls_enabled_ = false;
      return false;
    }
  }

  // 2. Set TX key material
  tls_crypto_info_t crypto_info;
  if (!ktls_info_->getTxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "Failed to get TX crypto info for kTLS");
    ktls_enabled_ = false;
    return false;
  }
  
  // Log details about the crypto info for debugging (but not the actual key material)
  ENVOY_LOG(debug, "TX crypto_info: version={}, cipher_type={}", crypto_info.version, 
            crypto_info.cipher_type);

  // Set TX crypto info
  if (setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TLS_TX on fd={}: {} (errno={})", fd,
              Envoy::errorDetails(err), err);
    
    // Commonly seen errors and their meaning
    if (err == EINVAL) {
      ENVOY_LOG(debug, "Invalid TX parameters - possibly wrong version or cipher type");
    } else if (err == EBUSY) {
      ENVOY_LOG(debug, "TX context already exists");
    } else if (err == ENOMEM) {
      ENVOY_LOG(debug, "Not enough memory for TX crypto context");
    } else if (err == EBADMSG) {
      ENVOY_LOG(debug, "Bad message format for TX crypto info");
    }
    
    ktls_enabled_ = false;
    return false;
  }

  // Try to enable RX too - but don't fail if this doesn't work
  bool rx_enabled = false;
  if (ktls_info_->getRxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "RX crypto_info: version={}, cipher_type={}", crypto_info.version, 
              crypto_info.cipher_type);

    if (setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) == 0) {
      ENVOY_LOG(debug, "Successfully set TLS_RX on fd={}", fd);
      rx_enabled = true;
    } else {
      int err = errno;
      ENVOY_LOG(debug, "Failed to set TLS_RX on fd={}: {} (errno={})", fd,
                Envoy::errorDetails(err), err);
      // RX setup failed, but we'll continue with TX-only if allowed
    }
  } else {
    ENVOY_LOG(debug, "Failed to get RX crypto info for kTLS");
  }

  // 4. Enable TX zerocopy if requested
  if (enable_tx_zerocopy_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &val, sizeof(val)) < 0) {
      int err = errno;
      ENVOY_LOG(debug, "Failed to enable TX zerocopy for kTLS: {} (errno={})",
              Envoy::errorDetails(err), err);
      // Don't report this as an error that affects functionality
      ENVOY_LOG(info, "Socket splicing not available, zero-copy disabled");
      // Proceed without zerocopy - not fatal
    }
  }

  // 5. Enable RX no padding if requested and RX is enabled
  if (rx_enabled && enable_rx_no_pad_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &val, sizeof(val)) < 0) {
      int err = errno;
      ENVOY_LOG(debug, "Failed to enable RX no padding for kTLS: {} (errno={})",
              Envoy::errorDetails(err), err);
      // Not fatal, continue
    }
  }

  // Check if RX failed but we still want to enable TX
  if (!rx_enabled) {
    // In production environments, we need to ensure consistent state
    // If RX failed, we should disable TX too to avoid decryption errors
    ENVOY_LOG(warn, "kTLS RX setup failed. Disabling kTLS completely for consistent state.");
    
    // Disable kTLS entirely - we can't have TX without RX
    if (setsockopt(fd, SOL_TLS, TLS_TX, NULL, 0) < 0) {
      ENVOY_LOG(debug, "Failed to disable TLS_TX: {}", Envoy::errorDetails(errno));
    }
    
    ktls_enabled_ = false;
    return false;
  }

  ktls_enabled_ = true;
  ENVOY_LOG(info, "kTLS fully enabled (TX and RX) successfully");
  
  // Set up socket splicing for zero-copy operations if requested
  if (enable_tx_zerocopy_ && ktls_enabled_) {
#ifdef HAS_SPLICE_SYSCALL
    TRY_ASSERT_MAIN_THREAD {
      socket_splicing_ =
          std::make_unique<KtlsSocketSplicing>(callbacks_->ioHandle(), callbacks_->ioHandle());
      ENVOY_LOG(debug, "kTLS socket splicing set up successfully");
    }
    END_TRY
    CATCH(EnvoyException & e, {
      ENVOY_LOG(debug, "Failed to set up kTLS socket splicing: {}", e.what());
      // Not fatal, continue without splicing
    });
#else
    ENVOY_LOG(info, "Socket splicing not available on this platform, zero-copy disabled");
#endif
  }

  return true;

#endif
  // kTLS is not supported on non-Linux platforms
  ENVOY_LOG(debug, "kTLS not supported on this platform");
  ktls_enabled_ = false;
  return false;
}

bool KtlsTransportSocket::canEnableKtls() const {
  // Get the SSL connection
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(debug, "SSL connection is null in canEnableKtls()");
    return false;
  }

  // SSL handshake must be complete before we can enable kTLS
  if (!isSslHandshakeComplete()) {
    ENVOY_LOG(debug, "SSL handshake not complete in canEnableKtls()");
    return false;
  }

  // Check cipher suite - for now we only support AES-GCM-128 with TLS 1.2
  std::string cipher = std::string(ssl_connection->ciphersuiteString());

  // Always log the negotiated cipher for debugging
  ENVOY_LOG(debug, "Negotiated cipher for kTLS: {}", cipher);

  if (cipher.empty()) {
    ENVOY_LOG(debug, "Cipher information not available");
    return false;
  }

  // Check if cipher is supported
  bool is_aes_gcm_128 = cipher.find("AES128-GCM") != std::string::npos ||
                     cipher.find("AES-128-GCM") != std::string::npos;
  if (!is_aes_gcm_128) {
    ENVOY_LOG(debug, "Unsupported cipher for kTLS: {}. Only AES-128-GCM is supported.", cipher);
    return false;
  }

  // Check TLS version - only TLS 1.2 is supported
  std::string version = std::string(ssl_connection->tlsVersion());
  ENVOY_LOG(debug, "TLS version: {}", version);

  if (version != "TLSv1.2") {
    ENVOY_LOG(debug, "Unsupported TLS version for kTLS: {}. Only TLSv1.2 is supported.", version);
    return false;
  }

  // Check if CAP_NET_ADMIN capability is available
  // This is a Linux-specific capability check
#ifdef __linux__
#ifdef HAS_CAPABILITY_SUPPORT
  if (geteuid() != 0) {  // Not running as root
    // Check if process has the capability
    cap_t caps = cap_get_proc();
    if (caps) {
      cap_flag_value_t has_net_admin;
      if (cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &has_net_admin) == 0) {
        if (has_net_admin != CAP_SET) {
          ENVOY_LOG(debug, "CAP_NET_ADMIN capability is missing, needed for kTLS");
          cap_free(caps);
          return false;
        }
      }
      cap_free(caps);
    }
  }
#else
  // If we're on Linux but don't have capability support, log a warning
  ENVOY_LOG(debug, "Running on Linux without capability support. CAP_NET_ADMIN may be required for kTLS.");
#endif
#endif

  // All checks passed
  ENVOY_LOG(debug, "All checks passed: connection can enable kTLS");
  return true;
}

KtlsTransportSocketFactory::KtlsTransportSocketFactory(
    Network::UpstreamTransportSocketFactoryPtr&& transport_socket_factory, bool enable_tx_zerocopy,
    bool enable_rx_no_pad)
    : inner_factory_(std::move(transport_socket_factory)), enable_tx_zerocopy_(enable_tx_zerocopy),
      enable_rx_no_pad_(enable_rx_no_pad) {}

Network::TransportSocketPtr KtlsTransportSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    std::shared_ptr<const Upstream::HostDescription> host) const {
  auto inner_socket = inner_factory_->createTransportSocket(options, host);
  if (inner_socket == nullptr) {
    return nullptr;
  }

  return std::make_unique<KtlsTransportSocket>(std::move(inner_socket), enable_tx_zerocopy_,
                                               enable_rx_no_pad_);
}

DownstreamKtlsTransportSocketFactory::DownstreamKtlsTransportSocketFactory(
    Network::DownstreamTransportSocketFactoryPtr&& transport_socket_factory,
    bool enable_tx_zerocopy, bool enable_rx_no_pad)
    : DownstreamPassthroughFactory(std::move(transport_socket_factory)),
      enable_tx_zerocopy_(enable_tx_zerocopy), enable_rx_no_pad_(enable_rx_no_pad) {}

Network::TransportSocketPtr
DownstreamKtlsTransportSocketFactory::createDownstreamTransportSocket() const {
  auto inner_socket = transport_socket_factory_->createDownstreamTransportSocket();
  if (inner_socket == nullptr) {
    return nullptr;
  }

  return std::make_unique<KtlsTransportSocket>(std::move(inner_socket), enable_tx_zerocopy_,
                                               enable_rx_no_pad_);
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
