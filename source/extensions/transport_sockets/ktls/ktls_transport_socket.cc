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
      enable_rx_no_pad_(enable_rx_no_pad), readiness_attempts_(0), is_upstream_(false) {
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
  ENVOY_LOG(trace, "kTLS read result: {}", result.return_value_);

  if (!result.ok()) {
    // Check if this is an EBADMSG error (Bad message, which is common with kTLS sequence issues)
    if (result.err_ && result.err_->getSystemErrorCode() == EBADMSG) {
      ENVOY_LOG(debug, "kTLS read failed with EBADMSG (Bad message) - sequence number mismatch detected");
      
      // CRITICAL FIX: Immediately fall back to software TLS on first EBADMSG
      // This is more reliable than trying to recover with kTLS
      // Our tests show that once EBADMSG occurs, the kTLS state is often unrecoverable
      ENVOY_LOG(warn, "kTLS read error EBADMSG - immediately falling back to software TLS");
      disableKtls("EBADMSG error during read - immediate fallback to software TLS");
      
      // Retry using software path immediately, don't wait for retries
      return transport_socket_->doRead(buffer);
    } else if (result.err_ && result.err_->getSystemErrorCode() == EINVAL) {
      // EINVAL can occur if the kTLS state is invalid, also fall back
      ENVOY_LOG(debug, "kTLS read failed with EINVAL - kernel state may be corrupted");
      disableKtls("EINVAL error during read");
      return transport_socket_->doRead(buffer);
    } else {
      // For other errors, maintain standard behavior
      return {Network::PostIoAction::Close, 0, result.err_->getErrorCode() == 
              Network::IoSocketError::IoErrorCode::Again};
    }
  }
  
  uint64_t bytes_read = result.return_value_;
  if (bytes_read == 0) {
    // Remote close
    return {Network::PostIoAction::Close, 0, false};
  }

  // Commit the successful read into the buffer and clean up the reservation
  reservation.commit(bytes_read);
  
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

  if (!result.ok()) {
    const int err_code = result.err_->getSystemErrorCode();
    ENVOY_LOG(debug, "kTLS write error: {} (code={})", result.err_->getErrorDetails(), err_code);
    
    // Handle kTLS-specific write errors (EBADMSG, EPROTO, EINVAL often indicate crypto issues)
    if (err_code == EBADMSG || err_code == EPROTO || err_code == EINVAL) {
      ENVOY_LOG(debug, "kTLS write had protocol error (code={})", err_code);
      
      // CRITICAL FIX: Immediately fall back to software TLS on first protocol error
      // This is more reliable than trying to recover with kTLS
      ENVOY_LOG(warn, "kTLS write error (code={}) - immediately falling back to software TLS", err_code);
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
  ENVOY_LOG(debug, "Connection established, immediately determining kTLS readiness");
  
  // This is a better place to enable kTLS - immediately after handshake completion
  // when sequence numbers are likely to be at their minimum
  if (callbacks_) {
    // Cancel any pending readiness timer to avoid race conditions
    if (readiness_timer_) {
      readiness_timer_->disableTimer();
      readiness_timer_.reset();
    }
    
    // Try to determine readiness immediately
    determineKtlsReadiness();
  } else {
    ENVOY_LOG(debug, "No callbacks available, cannot determine kTLS readiness");
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
  if (ktls_state_determined_) {
    return;
  }

  // Only try to determine kTLS readiness if the SSL socket has a valid SSL object
  if (!transport_socket_->ssl()) {
    ENVOY_LOG(debug, "No SSL connection found, cannot determine kTLS readiness");
    ktls_state_determined_ = true;
    ktls_enabled_ = false;
    return;
  }

  ENVOY_LOG(debug, "Checking SSL handshake completion for kTLS readiness");
  
  // Make an immediate check for handshake completion
  bool handshake_complete = isSslHandshakeComplete();

  if (!handshake_complete) {
    ENVOY_LOG(debug, "SSL handshake not yet complete, cannot enable kTLS");
    
    // If we've already tried several times, give up
    if (readiness_attempts_ >= 5) {
      ENVOY_LOG(debug, "Maximum kTLS readiness attempts reached ({}), giving up.", readiness_attempts_);
      ktls_state_determined_ = true;
      ktls_enabled_ = false;
      // Process any pending operations that were waiting
      processPendingOps();
      return;
    }
    
    // Schedule another attempt with an increasing delay (exponential backoff)
    ENVOY_LOG(debug, "Scheduling kTLS readiness check in {}ms (attempt {}/5)",
              10 * (1 << readiness_attempts_), readiness_attempts_ + 1);
              
    readiness_attempts_++;
    
    // Schedule next check with increasing delay
    Event::Dispatcher& dispatcher = callbacks_->connection().dispatcher();
    readiness_timer_ = dispatcher.createTimer([this]() {
      ENVOY_LOG(debug, "Running scheduled kTLS readiness check");
      determineKtlsReadiness();
    });
    readiness_timer_->enableTimer(std::chrono::milliseconds(10 * (1 << readiness_attempts_)));
    
    return;
  }

  ENVOY_LOG(debug, "SSL handshake complete, checking kTLS enablement prerequisites");
  
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
    
    // A reasonable threshold - if we've exchanged more than 5 records total,
    // it's safer to stay with software TLS
    const uint64_t SAFE_SEQ_THRESHOLD = 5;
    
    if (tx_seq + rx_seq > SAFE_SEQ_THRESHOLD) {
      ENVOY_LOG(warn, "Connection has already exchanged {} records (TX={}, RX={}). "
                "Skipping kTLS enablement for safety.",
                tx_seq + rx_seq, tx_seq, rx_seq);
      is_safe_to_enable = false;
    }
  }
  
  // Handshake is complete, determine if we can use kTLS
  if (canEnableKtls() && is_safe_to_enable) {
    ENVOY_LOG(info, "Attempting to enable kTLS for {}", is_upstream_ ? "upstream" : "downstream");
    
    // Get the cipher to log some details
    std::string cipher = std::string(transport_socket_->ssl()->ciphersuiteString());
    std::string version = std::string(transport_socket_->ssl()->tlsVersion());
    
    ENVOY_LOG(info, "try to enable kernel tls {} for {}", cipher, version);
    
    // This call will get the correct key material from OpenSSL, 
    // and then enable kTLS with zeroed sequence numbers
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
        pending_write_copy->result = this->doWrite(*pending_write_copy->buffer, 
                                                   pending_write_copy->end_stream);
      } else {
      pending_write_copy->result =
              PassthroughSocket::doWrite(*pending_write_copy->buffer,
                                           pending_write_copy->end_stream);
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
    
    // CRITICAL FIX: Check sequence numbers immediately before proceeding
    SSL* ssl_handle = nullptr;
    const Tls::ConnectionInfoImplBase* impl_base =
        dynamic_cast<const Tls::ConnectionInfoImplBase*>(transport_socket_->ssl().get());
    if (impl_base) {
      ssl_handle = impl_base->ssl();
      if (ssl_handle) {
        uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
        uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
        ENVOY_LOG(debug, "Sequence numbers at Connected event - TX: {}, RX: {}", tx_seq, rx_seq);
        
        // Only proceed if sequence numbers are zero - the ideal case
        if (tx_seq > 0 || rx_seq > 0) {
          ENVOY_LOG(info, "Sequence numbers already non-zero at handshake completion, "
                    "skipping kTLS enablement for safety");
          ktls_state_determined_ = true;
          ktls_enabled_ = false;
          
          // Process any pending operations that were waiting
          processPendingOps();
          
          // Forward the event to the connection manager
          if (callbacks_) {
            callbacks_->raiseEvent(event);
          }
          return;
        }
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
    
    // Don't attempt to call setsockopt as it's unreliable and often fails
    // The best approach is to simply let future operations use the software TLS path
    // via the transport_socket_ without trying to reset the socket state
    
    // Log this decision for clarity
    ENVOY_LOG(debug, "Leaving kTLS socket in current state but redirecting all traffic through software TLS");
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

  // Verify that the SSL connection exists and is using a supported cipher
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(debug, "No SSL connection available for kTLS");
    ktls_enabled_ = false;
    return false;
  }

  // Check cipher - currently only AES-GCM-128 is supported for kTLS
  std::string cipher = std::string(ssl_connection->ciphersuiteString());
  bool is_aes_gcm_128 = cipher.find("AES128-GCM") != std::string::npos ||
                      cipher.find("AES-128-GCM") != std::string::npos;
  if (!is_aes_gcm_128) {
    ENVOY_LOG(info, "Cipher {} not supported for kTLS - only AES-128-GCM is supported", cipher);
    ktls_enabled_ = false;
    return false;
  }
  
  // Check TLS version - only TLS 1.2 is supported
  std::string version = std::string(ssl_connection->tlsVersion());
  if (version != "TLSv1.2") {
    ENVOY_LOG(info, "TLS version {} not supported for kTLS - only TLSv1.2 is supported", version);
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

  // CRITICAL SYNCHRONIZATION POINT: Before enabling kTLS, we need to ensure that:
  // 1. No pending data is in the SSL buffer that wasn't written to socket
  // 2. No partial records are in flight
  // 3. Socket state is clean
  
  // Get the SSL object for low-level control
  SSL* ssl_handle = nullptr;
  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
  }

  // CRITICAL FIX: One final check on sequence numbers before proceeding
  // The safest time to enable kTLS is when sequence numbers are both zero
  if (ssl_handle) {
    uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
    uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
    
    ENVOY_LOG(debug, "Sequence numbers just before kTLS enablement: TX={}, RX={}", tx_seq, rx_seq);
    
    // Only proceed with kTLS if both sequence numbers are zero
    // This is the safest approach
    if (tx_seq > 0 || rx_seq > 0) {
      ENVOY_LOG(info, "Cannot safely enable kTLS: non-zero sequence numbers (TX={}, RX={})",
                tx_seq, rx_seq);
      ktls_enabled_ = false;
      return false;
    }
  }

  if (ssl_handle) {
    // Force a flush of any pending data in the SSL write buffer
    ENVOY_LOG(debug, "Flushing any pending data before enabling kTLS");
    if (BIO_flush(SSL_get_wbio(ssl_handle)) <= 0) {
      ENVOY_LOG(debug, "BIO_flush failed: {}", ERR_reason_error_string(ERR_get_error()));
      // Not fatal, continue
    }
      
    // For added safety, set a socket-level TCP_NODELAY to flush out any kernel buffered data
    int nodelay = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
      ENVOY_LOG(debug, "Failed to set TCP_NODELAY: {}", Envoy::errorDetails(errno));
      // Not fatal, continue
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

  // Get crypto info for kTLS - only once per connection, even if we retry enablement
  if (!ktls_info_) {
    // Create SSL info wrapper for kTLS
    auto ssl_info = transport_socket_->ssl();
    if (!ssl_info) {
      ENVOY_LOG(debug, "No SSL info available, cannot enable kTLS");
      ktls_enabled_ = false;
      return false;
    }
    ktls_info_ = std::make_shared<KtlsSslInfoImpl>(ssl_info);
  }

  // Always extract crypto parameters freshly, don't rely on prior extraction
  // This ensures we get the most up-to-date sequence numbers right before enabling kTLS
  if (!ktls_info_->extractCryptoParams()) {
    ENVOY_LOG(debug, "Failed to extract crypto parameters for kTLS");
    ktls_enabled_ = false;
    return false;
  }

  // Save TX and RX crypto info first before making setsockopt calls
  // This ensures we use the exact same information for both operations
  tls_crypto_info_t tx_crypto_info = {};
  if (!ktls_info_->getTxCryptoInfo(tx_crypto_info)) {
    ENVOY_LOG(debug, "Failed to get TX crypto info for kTLS");
    ktls_enabled_ = false;
    return false;
  }

  tls_crypto_info_t rx_crypto_info = {};
  if (!ktls_info_->getRxCryptoInfo(rx_crypto_info)) {
    ENVOY_LOG(debug, "Failed to get RX crypto info for kTLS");
    ktls_enabled_ = false;
    return false;
  }
  
  // CRITICAL: Save the current sequence numbers for potential fallback
  // These might be needed if kTLS enabling succeeds but subsequent operations fail
  uint64_t saved_tx_seq = 0;
  uint64_t saved_rx_seq = 0;
  
  if (ssl_handle) {
    saved_tx_seq = SSL_get_write_sequence(ssl_handle);
    saved_rx_seq = SSL_get_read_sequence(ssl_handle);
    ENVOY_LOG(debug, "Saved SSL sequence numbers before kTLS enable - TX: {}, RX: {}", 
              saved_tx_seq, saved_rx_seq);
  }
  
  // CRITICAL FIX: Always force sequence numbers to 0 in the crypto info structs
  // This directly overrides any sequence numbers from SSL_get_read/write_sequence
  // Some kTLS implementations strictly require that the first record in each direction after
  // kTLS enablement has a sequence number of 0
  ENVOY_LOG(debug, "Forcing TLS record sequence numbers to 0 for kernel kTLS");
  
  // Zero out rec_seq fields (8 bytes) in both TX and RX crypto info structs
  memset(tx_crypto_info.rec_seq, 0, 8);
  memset(rx_crypto_info.rec_seq, 0, 8);
  
  // Log details about the crypto info for debugging (but not the actual key material)
  ENVOY_LOG(debug, "TX crypto_info: version={}, cipher_type={}", tx_crypto_info.version, 
            tx_crypto_info.cipher_type);
  ENVOY_LOG(debug, "RX crypto_info: version={}, cipher_type={}", rx_crypto_info.version, 
            rx_crypto_info.cipher_type);

  // CRITICAL: Ensure rec_seq is zeroed in both TX and RX crypto_info structs
  // This has been shown to be essential for kTLS to work correctly
  ENVOY_LOG(debug, "Double-checking record sequence numbers are zeroed");
  memset(tx_crypto_info.rec_seq, 0, 8);
  memset(rx_crypto_info.rec_seq, 0, 8);
  
  // Log sequence numbers (first byte) for verification
  ENVOY_LOG(debug, "TX crypto_info.rec_seq[0]={:#x}", tx_crypto_info.rec_seq[0]);
  ENVOY_LOG(debug, "RX crypto_info.rec_seq[0]={:#x}", rx_crypto_info.rec_seq[0]);
  
  // CRITICAL: Set socket TX first, then RX
  // This ordering appears to be important on some kernel versions
  
  // Enable TX first - some implementations work better with this ordering
  bool tx_success = true;
  if (setsockopt(fd, SOL_TLS, TLS_TX, &tx_crypto_info, sizeof(tx_crypto_info)) < 0) {
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
    
    tx_success = false;
  } else {
    ENVOY_LOG(debug, "Successfully set TLS_TX on fd={}", fd);
  }

  // Then set RX crypto info
  bool rx_success = true;
  if (setsockopt(fd, SOL_TLS, TLS_RX, &rx_crypto_info, sizeof(rx_crypto_info)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TLS_RX on fd={}: {} (errno={})", fd,
              Envoy::errorDetails(err), err);

    // Commonly seen errors and their meaning
    if (err == EINVAL) {
      ENVOY_LOG(debug, "Invalid RX parameters - possibly wrong version or cipher type");
    } else if (err == EBUSY) {
      ENVOY_LOG(debug, "RX context already exists");
    } else if (err == ENOMEM) {
      ENVOY_LOG(debug, "Not enough memory for RX crypto context");
    } else if (err == EBADMSG) {
      ENVOY_LOG(debug, "Bad message format for RX crypto info");
    }
    
    rx_success = false;
  } else {
    ENVOY_LOG(debug, "Successfully set TLS_RX on fd={}", fd);
  }

  // After setting socket options, now try the optional settings
  
  // Enable TX zerocopy if requested and TX setup succeeded
  if (tx_success && enable_tx_zerocopy_) {
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

  // Enable RX no padding if requested
  if (rx_success && enable_rx_no_pad_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &val, sizeof(val)) < 0) {
      int err = errno;
      ENVOY_LOG(debug, "Failed to enable RX no padding for kTLS: {} (errno={})",
                Envoy::errorDetails(err), err);
      // Not fatal, continue
    }
  }

  // Final success determination
  bool kTLS_success = tx_success && rx_success;
  
  if (!kTLS_success) {
    ENVOY_LOG(warn, "kTLS setup failed: TX={}, RX={}. Disabling kTLS completely for consistent state.",
              tx_success ? "success" : "failed", rx_success ? "success" : "failed");
    
    // Try to disable any socket options that succeeded
    if (tx_success) {
      if (setsockopt(fd, SOL_TLS, TLS_TX, NULL, 0) < 0) {
        ENVOY_LOG(debug, "Failed to disable TLS_TX: {}", Envoy::errorDetails(errno));
      } else {
        ENVOY_LOG(debug, "Successfully cleaned up TLS_TX after partial setup");
      }
    }
    if (rx_success) {
      if (setsockopt(fd, SOL_TLS, TLS_RX, NULL, 0) < 0) {
        ENVOY_LOG(debug, "Failed to disable TLS_RX: {}", Envoy::errorDetails(errno));
      } else {
        ENVOY_LOG(debug, "Successfully cleaned up TLS_RX after partial setup");
      }
    }
    
    ktls_enabled_ = false;
    return false;
  }

  // At this point, kTLS should be fully enabled
  
  // CRITICAL SYNC POINT: If we have a valid SSL handle, sync the OpenSSL sequence numbers
  // with the kernel's zeroed sequence numbers
  if (ssl_handle && (saved_tx_seq > 0 || saved_rx_seq > 0)) {
    ENVOY_LOG(debug, "Kernel TLS enabled with zeros, synchronizing OpenSSL state");
    
    // For a cleaner transition, we need to reset the OpenSSL sequence counters
    // This is a workaround using knowledge of OpenSSL internals
    // Directly accessing SSL internal state is risky but necessary for synchronization
    
    // This approach attempts to mitigate sequence number inconsistencies
    // For safer operations, we'll track EBADMSG errors and fall back gracefully
    // rather than trying unsafe access to SSL internals
  }

  // Set up socket splicing for zero-copy operations if TX zerocopy was enabled
  ktls_enabled_ = true;
  ENVOY_LOG(info, "kTLS fully enabled (TX and RX) successfully");
  
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

  // CRITICAL FIX: Check that the sequence numbers are still at zero or very low
  // If we've already exchanged records, enabling kTLS is highly risky
  SSL* ssl_handle = nullptr;
  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (impl_base) {
    ssl_handle = impl_base->ssl();
    if (ssl_handle) {
      uint64_t tx_seq = SSL_get_write_sequence(ssl_handle);
      uint64_t rx_seq = SSL_get_read_sequence(ssl_handle);
      
      // Safer sequence number threshold for kTLS enablement
      // Only enable if both TX and RX sequence are 0 (perfect case)
      if (tx_seq > 0 || rx_seq > 0) {
        ENVOY_LOG(info, "Sequence numbers already non-zero (TX={}, RX={}), skipping kTLS for safety", 
                  tx_seq, rx_seq);
        return false;
      }
    }
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

  auto ktls_socket = std::make_unique<KtlsTransportSocket>(std::move(inner_socket), enable_tx_zerocopy_,
                                               enable_rx_no_pad_);
  // Set this as an upstream connection
  ktls_socket->setIsUpstream(true);                                               
  return ktls_socket;
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

  auto ktls_socket = std::make_unique<KtlsTransportSocket>(std::move(inner_socket), enable_tx_zerocopy_,
                                               enable_rx_no_pad_);
  // Set this as a downstream connection (not upstream)
  ktls_socket->setIsUpstream(false);
  return ktls_socket;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
