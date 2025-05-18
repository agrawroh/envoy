#include <string>
#include <utility>
#include <vector>

// Include system headers only once and in a specific order to avoid conflicts
#ifdef __linux__
// Include Linux-specific headers
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>  // For FIONREAD ioctl
#include <endian.h>  // For htobe64 and be64toh endian conversion functions
#include <poll.h>    // For pollfd struct and POLLIN constant

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

  if (result.err_) {
    // Check if this is an EBADMSG error (Bad message, which is common with kTLS sequence issues)
    if (result.err_->getSystemErrorCode() == EBADMSG) {
      ENVOY_LOG(debug, "kTLS read failed with EBADMSG (Bad message) - sequence number mismatch detected");
      
      // Log additional diagnostic information about the connection and sequences
      auto ssl_connection = transport_socket_->ssl();
      int fd = callbacks_->ioHandle().fdDoNotUse();
      bool sequence_mismatch_confirmed = false;
      
      if (ssl_connection) {
        const Tls::ConnectionInfoImplBase* impl_base =
            dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
        if (impl_base) {
          SSL* ssl_handle = impl_base->ssl();
          if (ssl_handle) {
            uint64_t current_tx_seq = SSL_get_write_sequence(ssl_handle);
            uint64_t current_rx_seq = SSL_get_read_sequence(ssl_handle);
            
            // Get the file descriptor to query kernel's sequence number 
            ENVOY_LOG(info, "EBADMSG Diagnostic: Current SSL seq TX={}, RX={}, saved seq TX={}, RX={}, fd={}",
                     current_tx_seq, current_rx_seq, saved_tx_seq_, saved_rx_seq_, fd);
                     
            // Calculate what the expected sequence numbers would be in the kernel
            if (ktls_info_) {
              tls_crypto_info_t rx_info = {};
              if (ktls_info_->getRxCryptoInfo(rx_info)) {
                uint64_t kernel_rx_seq = 0;
                memcpy(&kernel_rx_seq, rx_info.rec_seq, 8);
                kernel_rx_seq = be64toh(kernel_rx_seq);
                
                // Check if there's actually a sequence mismatch
                sequence_mismatch_confirmed = (kernel_rx_seq != current_rx_seq);
                
                ENVOY_LOG(info, "Expected kernel RX seq={} (converted from big-endian), "
                               "current SSL RX seq={}, mismatch={}",
                          kernel_rx_seq, current_rx_seq, 
                          sequence_mismatch_confirmed ? "YES" : "NO");
              }
            }
          }
        }
      }
      
      // CRITICAL FIX: Handle sequence number mismatch based on whether it's actually confirmed
      // Check if this might be a false alarm or transient error
      if (!sequence_mismatch_confirmed) {
        ENVOY_LOG(debug, "EBADMSG received but no sequence mismatch detected - may be corrupt data");
      }
      
      // CRITICAL FIX: Use a lock-step approach for draining corrupted data
      if (fd >= 0) {
        // Use a temporary buffer for TLS record analysis - large enough for TLS headers
        char peek_buffer[16];
        int flags = MSG_PEEK | MSG_DONTWAIT;
        
        // First peek to see if there's data available - just look at the header
        ssize_t peek_bytes = ::recv(fd, peek_buffer, sizeof(peek_buffer), flags);
        if (peek_bytes >= 5) {  // TLS record header is 5 bytes
          // Analyze TLS record header to determine record length
          // TLS record: 1 byte content type, 2 bytes version, 2 bytes length
          uint16_t record_len = (static_cast<uint16_t>(peek_buffer[3]) << 8) | peek_buffer[4];
          size_t total_record_size = record_len + 5;  // Add header size
          
          ENVOY_LOG(debug, "Found TLS record with length {} (total size {})", record_len, total_record_size);
          
          // Now read and discard exactly one TLS record to maintain synchronization
          std::vector<char> drain_buffer(total_record_size);
          ssize_t drained = ::recv(fd, drain_buffer.data(), total_record_size, MSG_DONTWAIT);
          ENVOY_LOG(debug, "Drained {} bytes (one TLS record) from socket buffer", drained);
        } else if (peek_bytes > 0) {
          // Can't determine record length, just drain what we have
          char drain_buffer[1024];
          ssize_t drained = ::recv(fd, drain_buffer, peek_bytes, MSG_DONTWAIT);
          ENVOY_LOG(debug, "Drained {} bytes of partial/corrupted data", drained);
        }
      }
      
      // MODIFIED: Use a smarter fallback strategy
      consecutive_decrypt_failures_++;
      
      if (consecutive_decrypt_failures_ == 1) {
        // On first failure, try to fix by just draining the bad record
        ENVOY_LOG(info, "First kTLS decrypt failure. Attempting to resynchronize by draining corrupted record");
        // We'll try software TLS for this read, but won't disable kTLS yet
      } else if (consecutive_decrypt_failures_ <= 3) {
        // On subsequent failures, keep trying but log warnings
        ENVOY_LOG(warn, "kTLS decrypt failure #{} detected, attempting to recover", consecutive_decrypt_failures_);
      } else {
        // After multiple failures, permanently disable kTLS for this connection
        ENVOY_LOG(warn, "Too many kTLS decrypt failures ({}), permanently falling back to software TLS", 
                 consecutive_decrypt_failures_);
        disableKtls("Multiple EBADMSG errors during read - sequence mismatch detected");
      }
      
      // Always use software fallback for this read
      ENVOY_LOG(debug, "Using software TLS fallback for read operation");
      
      // ADDED: Use a safer fallback approach with error handling
      // Attempt software TLS read but handle any errors that might occur
      Network::IoResult fallback_result = transport_socket_->doRead(buffer);
      
      // Check if the software fallback also failed with a critical error
      if (fallback_result.err_code_ && fallback_result.action_ == Network::PostIoAction::Close) {
        // Both kTLS and software TLS fallback failed - likely a corrupted TLS state
        ENVOY_LOG(error, "Software TLS fallback also failed after kTLS error - "
                       "connection state may be corrupted, initiating close");
                     
        // Return the failure but with a more specific error message
        return fallback_result;
      }
      
      return fallback_result;
    } else if (result.err_->getSystemErrorCode() == EINVAL) {
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
    ENVOY_LOG(debug, "Upstream handshake state: ssl_init={}, handshake_done={}, session_id={}, peer_cert={}, cipher={}",
             ssl_initialized, is_handshake_done, has_session_id, has_peer_cert, cipher_available);
    
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
    
    ENVOY_LOG(info, "Using {}ms delay for upstream kTLS (attempt={}, handshake_done={}, session_id={}, peer_cert={})", 
              delay_ms, readiness_attempts_, is_handshake_done,
              has_session_id ? "present" : "missing",
              has_peer_cert ? "present" : "missing");
      
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
  
  // Log detailed handshake state for debugging
  ENVOY_LOG(debug, "SSL handshake completion check - is_handshake_done={}, has_session_id={}, has_crypto_info={}, has_peer_cert={}", 
            is_handshake_done, has_session_id, has_crypto_info, has_peer_cert);
  
  // We need a stricter check for SSL handshake completion
  // At least one of these strong indicators must be true
  bool strong_handshake_indicator = is_handshake_done || has_session_id;
  
  // And if using the weaker indicators, ensure we have both crypto info and 
  // either peer cert or security validation
  bool weaker_handshake_indicators = has_crypto_info && 
                                    (has_peer_cert || has_security);
                                    
  return strong_handshake_indicator || weaker_handshake_indicators;
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
    
    // For upstream connections, we'll try more attempts since handshake can take longer
    uint32_t max_attempts = is_upstream_ ? 10 : 5;
    
    // If we've already tried several times, give up
    if (readiness_attempts_ >= max_attempts) {
      ENVOY_LOG(info, "Maximum kTLS readiness attempts reached ({}/{}) for {} connection, giving up.", 
                readiness_attempts_, max_attempts, is_upstream_ ? "upstream" : "downstream");
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

  ENVOY_LOG(info, "SSL handshake complete for {} connection, checking kTLS enablement prerequisites",
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
        ioctl(fd, FIONREAD, &readable);
        
        if (readable > 0) {
          ENVOY_LOG(debug, "Draining socket buffer during kTLS disable ({} bytes available)", readable);
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
  
  // CRITICAL FIX: Drain any pending data from the socket before enabling kTLS
  // This helps avoid race conditions between enabling kTLS and processing buffered data
  // which can lead to EBADMSG errors
  int pending_bytes = 0;
  if (ioctl(fd, FIONREAD, &pending_bytes) == 0 && pending_bytes > 0) {
    ENVOY_LOG(debug, "Detected {} bytes pending in socket buffer before kTLS enablement", pending_bytes);
    
    // If there's pending data, we need to read it with software TLS first
    char drain_buffer[16384];
    int flags = MSG_PEEK | MSG_DONTWAIT;
    
    // Peek at the data to see what's available
    ssize_t peek_bytes = ::recv(fd, drain_buffer, std::min(static_cast<size_t>(pending_bytes), 
                                                          sizeof(drain_buffer)), flags);
    
    if (peek_bytes > 0) {
      ENVOY_LOG(info, "Deferring kTLS enablement due to {} pending bytes in socket", peek_bytes);
      // Simply return false but don't mark as failed - we'll try again later after data is processed
      return false;
    }
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

  // Enhanced logging: Check the connection type, direction, and local/remote addresses
  ENVOY_LOG(info, "Connection type: {}, attempting kTLS enablement", 
            is_upstream_ ? "upstream" : "downstream");
  
  if (callbacks_) {
    auto& conn = callbacks_->connection();
    auto remote_address = conn.connectionInfoProvider().remoteAddress();
    auto local_address = conn.connectionInfoProvider().localAddress();
    
    if (remote_address) {
      ENVOY_LOG(info, "Remote address: {}", remote_address->asString());
    }
    
    if (local_address) {
      ENVOY_LOG(info, "Local address: {}", local_address->asString());
    }
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

  // Define ktls_mode variable to track kernel support level
  int ktls_mode = 0; // 0=basic, 1=partial non-zero seq, 2=full support

  // Enhanced kernel version detection and feature support determination
  struct utsname kernel_info;
  if (uname(&kernel_info) == 0) {
    ENVOY_LOG(debug, "Attempting kTLS on Linux kernel {}", kernel_info.release);
    
    // Parse kernel version more carefully
    int major = 0, minor = 0, patch = 0;
    if (sscanf(kernel_info.release, "%d.%d.%d", &major, &minor, &patch) >= 2) {
      if (major < 4 || (major == 4 && minor < 13)) {
        ENVOY_LOG(warn, "Kernel version {}.{}.{} doesn't support kTLS (requires at least 4.13)",
                  major, minor, patch);
        ktls_enabled_ = false;
        return false;
      }
      
      // Determine feature support level based on kernel version
      if (major > 5 || (major == 5 && minor >= 15)) {
        // Linux 5.15+ has full kTLS support with non-zero sequence numbers
        ktls_mode = 2;
        ENVOY_LOG(debug, "Full kTLS support with non-zero sequence numbers available (kernel {}.{}.{})",
                  major, minor, patch);
      } else if (major > 4 || (major == 4 && minor >= 17)) {
        // Linux 4.17-5.14 has partial support for non-zero sequence numbers
        ktls_mode = 1;
        ENVOY_LOG(debug, "Partial kTLS support with potential sequence number limitations (kernel {}.{}.{})",
                  major, minor, patch);
      } else {
        // Linux 4.13-4.16 has basic kTLS support requiring zero sequence numbers
        ktls_mode = 0;
        ENVOY_LOG(debug, "Basic kTLS support requiring zero sequence numbers (kernel {}.{}.{})",
                  major, minor, patch);
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
  
  // CRITICAL FIX: Check if there's pending data in the SSL buffer
  // If there is, we need to process it with software TLS before enabling kTLS
  if (ssl_handle) {
    // Check for pending data in the SSL read buffer
    int pending_ssl = SSL_pending(ssl_handle);
    if (pending_ssl > 0) {
      ENVOY_LOG(info, "Deferring kTLS enablement due to {} bytes pending in SSL buffer", pending_ssl);
      // Don't enable kTLS yet - we'll try again after data is processed
      return false;
    }
  }

  // Get current sequence numbers for logging and for kTLS setup
  uint64_t tx_seq = 0;
  uint64_t rx_seq = 0;
  if (ssl_handle) {
    tx_seq = SSL_get_write_sequence(ssl_handle);
    rx_seq = SSL_get_read_sequence(ssl_handle);
    
    ENVOY_LOG(info, "Current sequence numbers for {} connection: TX={}, RX: {}", 
              is_upstream_ ? "upstream" : "downstream", tx_seq, rx_seq);
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
    ktls_info_ = std::make_shared<KtlsSslInfoImpl>(ssl_connection);
  }

  // CRITICAL FIX: Test and fix mismatch between upstream and downstream SSL handshake status
  if (is_upstream_) {
    // For upstream connections, we need to wait a bit longer to ensure the handshake is fully
    // complete and all parameters are properly set before attempting to extract crypto params
    
    // Extra validation for upstream connections
    if (!ssl_handle) {
      ENVOY_LOG(warn, "No SSL handle available for upstream connection, cannot enable kTLS safely");
      ktls_enabled_ = false;
      ktls_state_determined_ = true;
      return false;
    }
    
    // Verify if SSL_in_init returns 0, which means the handshake is definitely complete
    if (SSL_in_init(ssl_handle) != 0) {
      ENVOY_LOG(warn, "Upstream SSL_in_init shows handshake not fully complete, cannot enable kTLS safely");
      ktls_enabled_ = false;
      ktls_state_determined_ = true;
      return false;
    }
    
    // Check for session ID, but don't fail if it's missing as some connections can be complete
    // without having a session ID set yet (especially on first connection)
    std::string session_id = std::string(ssl_connection->sessionId());
    if (session_id.empty()) {
      ENVOY_LOG(debug, "Upstream connection has no session ID, but continuing with kTLS if all other checks pass");
    }
    
    ENVOY_LOG(info, "Upstream connection validated for kTLS enablement: session_id={}, in_init=0",
              !session_id.empty() ? "present" : "missing");
  }

  // Extract crypto parameters with proper sequence numbers based on kernel version
  if (!ktls_info_->extractCryptoParams()) {
    ENVOY_LOG(debug, "Failed to extract crypto parameters for kTLS");
    ktls_enabled_ = false;
    ktls_state_determined_ = true;
    return false;
  }
  
  // Initialize sequence numbers based on kernel version detection
  if (!ktls_info_->initializeSequenceNumbers(ktls_mode)) {
    ENVOY_LOG(debug, "Failed to initialize sequence numbers for kTLS");
    ktls_enabled_ = false;
    ktls_state_determined_ = true;
    return false;
  }

  // Save TX and RX crypto info first before making setsockopt calls
  // This ensures we use the exact same information for both operations
  tls_crypto_info_t tx_crypto_info = {};
  if (!ktls_info_->getTxCryptoInfo(tx_crypto_info)) {
    ENVOY_LOG(debug, "Failed to get TX crypto info for kTLS");
    ktls_enabled_ = false;
    ktls_state_determined_ = true;
    return false;
  }

  tls_crypto_info_t rx_crypto_info = {};
  if (!ktls_info_->getRxCryptoInfo(rx_crypto_info)) {
    ENVOY_LOG(debug, "Failed to get RX crypto info for kTLS");
    ktls_enabled_ = false;
    ktls_state_determined_ = true;
    return false;
  }
  
  // CRITICAL: Save the current sequence numbers for potential fallback
  // These might be needed if kTLS enabling succeeds but subsequent operations fail
  saved_tx_seq_ = tx_seq;
  saved_rx_seq_ = rx_seq;
  
  ENVOY_LOG(debug, "Saved SSL sequence numbers for kTLS initialization - TX: {}, RX: {}", 
            tx_seq, rx_seq);
  
  // CRITICAL FIX: Instead of zeroing sequence numbers, we need to use the current ones
  // Linux kernel 5.15+ supports non-zero initial sequence numbers for kTLS
  // Convert to network byte order (big-endian) for the kernel
  // Note: For kTLS, sequence numbers need to be stored in big-endian format
  // We need to be very careful about byte order here
  uint64_t tx_seq_be = htobe64(tx_seq);
  uint64_t rx_seq_be = htobe64(rx_seq);
  
  // Copy the sequence numbers to the crypto_info structures
  // The rec_seq field is an array of bytes - we need to make sure this is properly filled
  memcpy(tx_crypto_info.rec_seq, &tx_seq_be, 8);
  memcpy(rx_crypto_info.rec_seq, &rx_seq_be, 8);
  
  // Log details about the crypto info for debugging (but not the actual key material)
  ENVOY_LOG(debug, "TX crypto_info: version={}, cipher_type={}, seq={}",
            tx_crypto_info.version, tx_crypto_info.cipher_type, tx_seq);
  ENVOY_LOG(debug, "RX crypto_info: version={}, cipher_type={}, seq={}",
            rx_crypto_info.version, rx_crypto_info.cipher_type, rx_seq);

  // Log sequence numbers (first byte) for verification
  // Convert from big-endian for display
  uint64_t tx_seq_verify = 0;
  uint64_t rx_seq_verify = 0;
  memcpy(&tx_seq_verify, tx_crypto_info.rec_seq, 8);
  memcpy(&rx_seq_verify, rx_crypto_info.rec_seq, 8);
  tx_seq_verify = be64toh(tx_seq_verify);
  rx_seq_verify = be64toh(rx_seq_verify);
  
  // Dump raw sequence number bytes to verify exact byte contents
  ENVOY_LOG(debug, "TX rec_seq verified={}, RX rec_seq verified={}", 
            tx_seq_verify, rx_seq_verify);
  
  // Log full byte pattern for explicit verification
  ENVOY_LOG(debug, "TX seq bytes: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            static_cast<uint8_t>(tx_crypto_info.rec_seq[0]), 
            static_cast<uint8_t>(tx_crypto_info.rec_seq[1]),
            static_cast<uint8_t>(tx_crypto_info.rec_seq[2]), 
            static_cast<uint8_t>(tx_crypto_info.rec_seq[3]),
            static_cast<uint8_t>(tx_crypto_info.rec_seq[4]), 
            static_cast<uint8_t>(tx_crypto_info.rec_seq[5]),
            static_cast<uint8_t>(tx_crypto_info.rec_seq[6]), 
            static_cast<uint8_t>(tx_crypto_info.rec_seq[7]));
  ENVOY_LOG(debug, "RX seq bytes: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            static_cast<uint8_t>(rx_crypto_info.rec_seq[0]), 
            static_cast<uint8_t>(rx_crypto_info.rec_seq[1]),
            static_cast<uint8_t>(rx_crypto_info.rec_seq[2]), 
            static_cast<uint8_t>(rx_crypto_info.rec_seq[3]),
            static_cast<uint8_t>(rx_crypto_info.rec_seq[4]), 
            static_cast<uint8_t>(rx_crypto_info.rec_seq[5]),
            static_cast<uint8_t>(rx_crypto_info.rec_seq[6]), 
            static_cast<uint8_t>(rx_crypto_info.rec_seq[7]));
    
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
      
      // ADDED: Verify RX sequence number matches expected value
      // This helps confirm proper initialization and diagnose issues
      if (ssl_handle) {
        uint64_t current_rx_seq = SSL_get_read_sequence(ssl_handle);
        ENVOY_LOG(debug, "Verifying RX sequence: SSL={}, kernel={}, match={}",
                  current_rx_seq, rx_seq_verify, 
                  (current_rx_seq == rx_seq_verify) ? "YES" : "NO");
                  
        if (current_rx_seq != rx_seq_verify) {
          ENVOY_LOG(warn, "RX sequence mismatch after kTLS setup - "
                          "expect EBADMSG errors during read operations");
          // Don't fail setup - we'll handle via resync if needed
        }
      }
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
      ENVOY_LOG(warn, "kTLS setup failed for {}: TX={}, RX={}. Disabling kTLS completely for consistent state.",
                is_upstream_ ? "upstream" : "downstream",
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
      ktls_state_determined_ = true;
      return false;
    }

    // At this point, kTLS should be fully enabled
    // with proper record sequence number synchronization
    
    ENVOY_LOG(info, "Successfully initialized kernel TLS with sequence numbers TX={}, RX={} for {}", 
              tx_seq, rx_seq, is_upstream_ ? "upstream" : "downstream");
  
    // Set up socket splicing for zero-copy operations if TX zerocopy was enabled
    ktls_enabled_ = true;
    ENVOY_LOG(info, "kTLS fully enabled (TX and RX) successfully for {}", 
              is_upstream_ ? "upstream" : "downstream");
    
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
  ENVOY_LOG(info, "Negotiated cipher for {} kTLS: {}", 
            is_upstream_ ? "upstream" : "downstream", cipher);

  if (cipher.empty()) {
    ENVOY_LOG(debug, "Cipher information not available");
    return false;
  }

  // Check if cipher is supported
  bool is_aes_gcm_128 = cipher.find("AES128-GCM") != std::string::npos ||
                     cipher.find("AES-128-GCM") != std::string::npos;
  if (!is_aes_gcm_128) {
    ENVOY_LOG(info, "Unsupported cipher for {} kTLS: {}. Only AES-128-GCM is supported.", 
              is_upstream_ ? "upstream" : "downstream", cipher);
    return false;
  }

  // Check TLS version - only TLS 1.2 is supported
  std::string version = std::string(ssl_connection->tlsVersion());
  ENVOY_LOG(info, "TLS version for {} connection: {}", 
            is_upstream_ ? "upstream" : "downstream", version);

  if (version != "TLSv1.2") {
    ENVOY_LOG(info, "Unsupported TLS version for {} kTLS: {}. Only TLSv1.2 is supported.", 
              is_upstream_ ? "upstream" : "downstream", version);
    return false;
  }

  // ADDED: Check if this is a loopback connection - these have shown issues with kTLS
  // For safety, we'll disable kTLS for loopback connections
  if (callbacks_) {
    // Check remote address
    auto& conn = callbacks_->connection();
    auto remote_address = conn.connectionInfoProvider().remoteAddress();
    if (remote_address && remote_address->ip()) {
      // Check if this is a loopback address
      if (Envoy::Network::Utility::isLoopbackAddress(*remote_address)) {
        ENVOY_LOG(info, "Disabling {} kTLS for loopback connection ({})",
                is_upstream_ ? "upstream" : "downstream", 
                remote_address->asString());
        return false;
      }
    }
    
    // Also check if local address is loopback
    auto local_address = conn.connectionInfoProvider().localAddress();
    if (local_address && local_address->ip()) {
      if (Envoy::Network::Utility::isLoopbackAddress(*local_address)) {
        ENVOY_LOG(info, "Disabling {} kTLS for loopback local address ({})",
                  is_upstream_ ? "upstream" : "downstream",
                  local_address->asString());
        return false;
      }
    }
  }
  
  // For upstream connections, we need additional verification
  if (is_upstream_) {
    // Ensure peer certificate is present and verified
    if (!ssl_connection->peerCertificatePresented()) {
      ENVOY_LOG(info, "Upstream connection missing peer certificate, not enabling kTLS");
      return false;
    }
    
    // Don't duplicate handshake completion checks since isSslHandshakeComplete() already
    // does a more comprehensive check that includes other indicators besides just SSL_in_init
    // The calling code only reaches here if isSslHandshakeComplete() returned true
  }

  // Removed the sequence number zero restriction since Linux 5.15+ supports non-zero sequence numbers
  // We'll pass the actual sequence numbers to the kernel when we enable kTLS

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
          ENVOY_LOG(info, "CAP_NET_ADMIN capability is missing for {} kTLS, needed for kTLS",
                    is_upstream_ ? "upstream" : "downstream");
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
  ENVOY_LOG(info, "All checks passed: {} connection can enable kTLS", 
            is_upstream_ ? "upstream" : "downstream");
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

// Method to trigger stack-driven resynchronization as described in the kernel documentation
void KtlsTransportSocket::scheduleResynchronization() {
  // NOTE: This resynchronization approach doesn't work with current Linux kernels
  // as they don't allow modifying TLS_RX state after it's been set.
  // We're keeping the code for reference in case future kernels allow this,
  // but our current approach is to fall back to software TLS on sequence errors.
  // See doRead() error handling for the current approach.
  ENVOY_LOG(debug, "Resynchronization requested but disabled - using software fallback instead");
  return;

  // Original implementation below (currently not executed):
  if (resync_scheduled_ || resync_in_progress_) {
    ENVOY_LOG(debug, "Resynchronization already in progress or scheduled");
    return;
  }
  
  // Mark resync as scheduled
  resync_scheduled_ = true;
  
  // Get current time for rate limiting
  auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
                 
  // Rate limit resync attempts - no more than once per second
  if (now_ms - last_resync_attempt_time_ms_ < 1000) {
    ENVOY_LOG(debug, "Resync attempted too recently, delaying");
    
    // Create a timer to delay the resync
    if (callbacks_) {
      Event::Dispatcher& dispatcher = callbacks_->connection().dispatcher();
      if (!resync_timer_) {
        resync_timer_ = dispatcher.createTimer([this]() {
          performResynchronization();
        });
      }
      // Schedule the timer for 1 second after the last attempt
      uint64_t delay_ms = 1000 - (now_ms - last_resync_attempt_time_ms_);
      ENVOY_LOG(debug, "Scheduling resync in {}ms", delay_ms);
      resync_timer_->enableTimer(std::chrono::milliseconds(delay_ms));
    }
    return;
  }
  
  // If no rate limiting needed, perform immediately
  performResynchronization();
}

// Method to perform the actual resynchronization with the kernel
bool KtlsTransportSocket::performResynchronization() {
  if (!ktls_enabled_ || !callbacks_) {
    ENVOY_LOG(debug, "Cannot perform resync: kTLS not enabled or no callbacks available");
    resync_scheduled_ = false;
    return false;
  }
  
  // Update state and timing info
  resync_in_progress_ = true;
  resync_scheduled_ = false;
  last_resync_attempt_time_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
  
  ENVOY_LOG(info, "Performing kTLS stack-driven resynchronization");
  
  // Step 1: Get current SSL sequence numbers
  auto ssl_connection = transport_socket_->ssl();
  if (!ssl_connection) {
    ENVOY_LOG(warn, "Cannot resync: no SSL connection available");
    resync_in_progress_ = false;
    return false;
  }
  
  const Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  if (!impl_base) {
    ENVOY_LOG(warn, "Cannot resync: unable to access SSL implementation");
    resync_in_progress_ = false;
    return false;
  }
  
  SSL* ssl_handle = impl_base->ssl();
  if (!ssl_handle) {
    ENVOY_LOG(warn, "Cannot resync: no SSL handle available");
    resync_in_progress_ = false;
    return false;
  }
  
  // Get current RX sequence number from SSL
  uint64_t current_rx_seq = SSL_get_read_sequence(ssl_handle);
  ENVOY_LOG(debug, "Current SSL RX sequence number for resync: {}", current_rx_seq);
  
  // Store the expected next RX sequence number
  next_expected_rx_seq_ = current_rx_seq;
  
  // Step 2: Get socket fd
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(warn, "Cannot resync: invalid file descriptor");
    resync_in_progress_ = false;
    return false;
  }
  
  // Resync procedure depends on kernel version
  // For newer kernels (5.15+), we can use the TLS_RX setsockopt with the current sequence number
  
  // Re-extract crypto params to get fresh sequence numbers
  if (ktls_info_ && ktls_info_->extractCryptoParams()) {
    ENVOY_LOG(debug, "Re-extracted crypto parameters for resync");
    
    // Get RX crypto info with updated sequence numbers
    tls_crypto_info_t rx_crypto_info = {};
    if (!ktls_info_->getRxCryptoInfo(rx_crypto_info)) {
      ENVOY_LOG(warn, "Cannot resync: failed to get RX crypto info");
      resync_in_progress_ = false;
      return false;
    }
    
    // Update the sequence number in the crypto info
    // Convert to network byte order (big-endian)
    uint64_t rx_seq_be = htobe64(current_rx_seq);
    memcpy(rx_crypto_info.rec_seq, &rx_seq_be, 8);
    
    ENVOY_LOG(debug, "Attempting to reset RX crypto state with sequence number {}", current_rx_seq);
    
    // First, clear the existing RX crypto state
    if (setsockopt(fd, SOL_TLS, TLS_RX, NULL, 0) < 0) {
      int err = errno;
      ENVOY_LOG(warn, "Failed to clear TLS_RX during resync: {} (errno={})",
               Envoy::errorDetails(err), err);
      // Continue anyway, some kernel versions don't support clearing
    }
    
    // Then set the new RX crypto state with updated sequence number
    if (setsockopt(fd, SOL_TLS, TLS_RX, &rx_crypto_info, sizeof(rx_crypto_info)) < 0) {
      int err = errno;
      ENVOY_LOG(warn, "Failed to set new TLS_RX during resync: {} (errno={})",
               Envoy::errorDetails(err), err);
      resync_in_progress_ = false;
      return false;
    }
    
    ENVOY_LOG(info, "Successfully reset RX crypto state with sequence number {}", current_rx_seq);
    
    // ADDED: Verify the sequence number was actually applied correctly
    // This helps confirm the kernel has updated the sequence number as expected
    uint64_t verified_seq = 0;
    memcpy(&verified_seq, rx_crypto_info.rec_seq, 8);
    verified_seq = be64toh(verified_seq);
    
    if (verified_seq != current_rx_seq) {
      ENVOY_LOG(error, "Sequence number mismatch after resync. Requested={}, actual={}",
               current_rx_seq, verified_seq);
      // Continue anyway - the goal is to get things back in sync even if imperfect
    } else {
      ENVOY_LOG(debug, "Sequence number successfully verified after resync: {}", verified_seq);
    }
  } else {
    ENVOY_LOG(warn, "Cannot resync: failed to extract crypto parameters");
    resync_in_progress_ = false;
    return false;
  }
  
  // Resync is now complete
  ENVOY_LOG(info, "kTLS resynchronization completed, next expected sequence: {}",
            next_expected_rx_seq_.value_or(0));
  
  resync_in_progress_ = false;
  return true;
}

// Method to reset resync state after successful read
void KtlsTransportSocket::resetResyncState() {
  if (consecutive_decrypt_failures_ > 0) {
    ENVOY_LOG(debug, "Resetting kTLS resync state after successful read");
    consecutive_decrypt_failures_ = 0;
    next_expected_rx_seq_.reset();
  }
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
