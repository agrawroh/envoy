#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"

#include <netinet/tcp.h>

// Only include Linux-specific headers when compiling on Linux
#ifdef __linux__
#include <sys/utsname.h>
#if __has_include(<sys/splice.h>)
#include <sys/splice.h>
#define HAS_SPLICE_SYSCALL 1
#endif
#endif

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/network/io_socket_error_impl.h"
#include "source/common/tls/connection_info_impl_base.h"

// Include OpenSSL headers for direct access to SSL objects
#include "openssl/evp.h"
#include "openssl/ssl.h"

#include "source/extensions/transport_sockets/ktls/ktls_ssl_info_impl.h"
// Add ktls socket splicing header
#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"

// Define TLS constants for non-Linux platforms
#ifndef SOL_TLS
#define SOL_TLS 282
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

Network::IoResult KtlsTransportSocket::doRead(Buffer::Instance& buffer) {
  // Check if we need to determine kTLS readiness
  if (!ktls_state_determined_) {
    // First, check if the handshake is complete - it might be by now
    if (isSslHandshakeComplete()) {
      ENVOY_LOG(debug, "Detected completed handshake during read operation");
      determineKtlsReadiness();
    } else if (!pending_read_) {
      // If handshake is not complete, buffer the operation
      ENVOY_LOG(debug, "Buffering read operation until kTLS state is determined");
      pending_read_ = PendingReadOp{&buffer, {Network::PostIoAction::KeepOpen, 0, false}, false};
      
      // For read operations, we need to trigger the SSL handshake since it's lazy
      // This call might actually complete the handshake
      Network::IoResult handshake_result = PassthroughSocket::doRead(buffer);
      
      // If the handshake completed during this read, process pending ops immediately
      if (isSslHandshakeComplete()) {
        ENVOY_LOG(debug, "Handshake completed during buffered read");
        determineKtlsReadiness();
        // If state is now determined, processing pending ops should have handled them
        // Check if we have pending operations that need to be processed again
        if (pending_read_ && pending_read_->completed) {
          Network::IoResult result = pending_read_->result;
          pending_read_.reset();
          return result;
        }
      }
      
      return handshake_result;
    } else {
      // We already have a pending read operation, just trigger the SSL handshake
      Network::IoResult handshake_result = PassthroughSocket::doRead(buffer);
      if (isSslHandshakeComplete()) {
        ENVOY_LOG(debug, "Handshake completed during read operation with existing pending read");
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
    
    // Check if this read operation was processed as a pending operation
    if (pending_read_ && pending_read_->completed && pending_read_->buffer == &buffer) {
      Network::IoResult result = pending_read_->result;
      pending_read_.reset();
      return result;
    }
  }

  // If kTLS is enabled, only use direct socket operations, never fall back to SSL
  if (ktls_enabled_) {
    // Get file descriptor for direct socket operations
    int fd = callbacks_->ioHandle().fdDoNotUse();
    if (fd < 0) {
      // Invalid file descriptor, return error
      ENVOY_LOG(error, "Invalid file descriptor for kTLS read: {}", fd);
      return {Network::PostIoAction::Close, 0, false};
    }

    // Try zero-copy read with socket splicing if available
#ifdef HAS_SPLICE_SYSCALL
    if (socket_splicing_ && enable_rx_no_pad_) {
      // Get a reasonable read chunk size
      uint64_t max_bytes =
          std::min(buffer.highWatermark() - buffer.length(), static_cast<uint64_t>(16384));
      if (max_bytes == 0) {
        // No capacity to read into
        return {Network::PostIoAction::KeepOpen, 0, false};
      }

      // Try to read using socket splicing
      auto result = socket_splicing_->readToBuffer(buffer, max_bytes);

      if (!result.ok() && result.err_->getErrorCode() == Api::IoError::IoErrorCode::Again) {
        // EAGAIN, nothing to read
        return {Network::PostIoAction::KeepOpen, 0, false};
      } else if (!result.ok()) {
        // Real error
        ENVOY_LOG(debug, "kTLS zero-copy read error: {}", result.err_->getErrorDetails());
        return {Network::PostIoAction::Close, 0, false};
      }

      // If we read some data, return it
      if (result.return_value_ > 0) {
        return {Network::PostIoAction::KeepOpen, result.return_value_, false};
      }
    }
#endif

    // Direct socket read if splicing not available or failed
    char read_buffer[16384];
    const size_t read_size = std::min(buffer.highWatermark() - buffer.length(), 
                                     static_cast<size_t>(16384));
    
    // Only try direct read if there's space in the buffer
    if (read_size > 0) {
      ssize_t bytes_read = ::recv(fd, read_buffer, read_size, MSG_DONTWAIT);
      if (bytes_read > 0) {
        // Direct read succeeded
        buffer.add(read_buffer, bytes_read);
        return {Network::PostIoAction::KeepOpen, static_cast<uint64_t>(bytes_read), false};
      } else if (bytes_read == 0) {
        // Connection closed
        return {Network::PostIoAction::Close, 0, true};
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // No data available right now
        return {Network::PostIoAction::KeepOpen, 0, false};
      } else {
        // Real error occurred
        ENVOY_LOG(error, "Direct read from kTLS socket failed with error: {} (errno={})",
                  Envoy::errorDetails(errno), errno);
        return {Network::PostIoAction::Close, 0, false};
      }
    }
    
    // No capacity to read into
    return {Network::PostIoAction::KeepOpen, 0, false};
  }

  // If kTLS is not enabled, use the standard SSL path
  return PassthroughSocket::doRead(buffer);
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
      pending_write_ = PendingWriteOp{&buffer, end_stream, 
                                      {Network::PostIoAction::KeepOpen, 0, false}, false};
      
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
    if (pending_write_ && pending_write_->completed && 
        pending_write_->buffer == &buffer && 
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
#ifdef HAS_SPLICE_SYSCALL
    if (socket_splicing_ && enable_tx_zerocopy_ && buffer.length() > 0) {
      // Try to write using socket splicing for zero-copy
      auto result = socket_splicing_->writeFromBuffer(buffer);

      if (!result.ok() && result.err_->getErrorCode() == Api::IoError::IoErrorCode::Again) {
        // EAGAIN, resource temporarily unavailable
        return {Network::PostIoAction::KeepOpen, 0, false};
      } else if (!result.ok()) {
        // Real error
        ENVOY_LOG(debug, "kTLS zero-copy write error: {}", result.err_->getErrorDetails());
        return {Network::PostIoAction::Close, 0, false};
      }

      // If we wrote some data, drain it from the buffer
      if (result.return_value_ > 0) {
        buffer.drain(result.return_value_);

        // Check if we've written everything (accounting for end_stream)
        if (buffer.length() == 0) {
          return {Network::PostIoAction::KeepOpen, result.return_value_, end_stream};
        }
      }

      // If we still have data to write, it will be handled in the next write event
      if (buffer.length() > 0) {
        return {Network::PostIoAction::KeepOpen, result.ok() ? result.return_value_ : 0, false};
      }
    }
#endif

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
  return PassthroughSocket::doWrite(buffer, end_stream);
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
  
  const Envoy::Extensions::TransportSockets::Tls::ConnectionInfoImplBase* impl_base =
      dynamic_cast<const Envoy::Extensions::TransportSockets::Tls::ConnectionInfoImplBase*>(ssl_connection.get());
  
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
            has_crypto_info, has_peer_cert, has_security, has_session_id, is_handshake_done,
            cipher, version);

  // Return true if we have good indicators that handshake is complete
  // Different connections may have different indicators, so we use a combination
  // Order the checks from most reliable to least reliable
  return is_handshake_done || 
         has_session_id || 
         (has_crypto_info && has_peer_cert) ||
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
      ENVOY_LOG(debug, "SSL handshake not complete yet, attempt {}/{}", 
                ktls_handshake_attempts_, MAX_KTLS_ATTEMPTS);
    } else {
      ENVOY_LOG(trace, "SSL handshake not complete yet, attempt {}/{}", 
                ktls_handshake_attempts_, MAX_KTLS_ATTEMPTS);
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
  ENVOY_CONN_LOG(debug, "SSL handshake is complete, attempting to enable kTLS", callbacks_->connection());
  
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
  delay_ms = 10 * (1 << std::min(ktls_handshake_attempts_, uint32_t(4))); // Cap at reasonable max (160ms)
  
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
  
  ENVOY_LOG(debug, "Scheduling kTLS readiness check in {}ms (attempt {}/{})", 
            delay_ms, ktls_handshake_attempts_ + 1, MAX_KTLS_ATTEMPTS);
            
  // Clear any existing timer
  if (readiness_timer_) {
    readiness_timer_->disableTimer();
  }
  
  // Create and enable timer
  if (!readiness_timer_) {
    readiness_timer_ = callbacks_->connection().dispatcher().createTimer(
      [this]() { 
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
  
  ENVOY_LOG(debug, "Processing pending operations, read={}, write={}, kTLS state determined={}, kTLS enabled={}",
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
  std::optional<PendingReadOp> pending_read_copy;
  std::optional<PendingWriteOp> pending_write_copy;
  
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
      pending_read_copy->result = ktls_enabled_ ? 
        // Use direct PassthroughSocket instead of our own doRead to avoid recursion
        PassthroughSocket::doRead(*pending_read_copy->buffer) : 
        PassthroughSocket::doRead(*pending_read_copy->buffer);
      pending_read_copy->completed = true;
      
      ENVOY_LOG(debug, "Completed pending read with result: bytes={}, end_stream={}, action={}",
                pending_read_copy->result.bytes_processed_, pending_read_copy->result.end_stream_read_,
                pending_read_copy->result.action_ == Network::PostIoAction::KeepOpen ? "KeepOpen" : "Close");
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
      pending_write_copy->result = ktls_enabled_ ? 
        // Use direct PassthroughSocket instead of our own doWrite to avoid recursion
        PassthroughSocket::doWrite(*pending_write_copy->buffer, pending_write_copy->end_stream) : 
        PassthroughSocket::doWrite(*pending_write_copy->buffer, pending_write_copy->end_stream);
      pending_write_copy->completed = true;
      
      ENVOY_LOG(debug, "Completed pending write with result: bytes={}, action={}",
                pending_write_copy->result.bytes_processed_,
                pending_write_copy->result.action_ == Network::PostIoAction::KeepOpen ? "KeepOpen" : "Close");
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

bool KtlsTransportSocket::isConnectionSecure() const {
  return transport_socket_->ssl() != nullptr;
}

void KtlsTransportSocket::disableKtls(const std::string& reason) {
  if (ktls_enabled_) {
    ENVOY_LOG(info, "Disabling kTLS: {}", reason);
    ktls_enabled_ = false;
    
    // Clear any associated resources
    ktls_info_.reset();
    
#ifdef HAS_SPLICE_SYSCALL
    socket_splicing_.reset();
#endif
  }
}

bool KtlsTransportSocket::enableKtls() {
  // Check if we already enabled kTLS
  if (ktls_enabled_) {
    return true;
  }

  // Check if we can enable kTLS
  if (!canEnableKtls()) {
    return false;
  }

  // Get the SSL info from the underlying socket
  Ssl::ConnectionInfoConstSharedPtr ssl_info = transport_socket_->ssl();
  if (!ssl_info) {
    ENVOY_LOG(debug, "No SSL info available, cannot enable kTLS");
    return false;
  }

  // Create SSL info wrapper for kTLS
  ktls_info_ = std::make_shared<KtlsSslInfoImpl>(ssl_info);

#ifdef __linux__
  // Add additional runtime checks to make sure we're actually on Linux
  #ifdef __APPLE__
    ENVOY_LOG(debug, "kTLS not supported on macOS/Darwin");
    ktls_enabled_ = false;
    return false;
  #endif

  // Check for common Linux environment variables to verify we're on Linux
  struct utsname buffer;
  if (uname(&buffer) == 0) {
    std::string sysname(buffer.sysname);
    if (sysname != "Linux") {
      ENVOY_LOG(debug, "kTLS only supported on Linux, current OS: {}", sysname);
      ktls_enabled_ = false;
      return false;
    }
    
    // Log Linux kernel version for debugging
    ENVOY_LOG(debug, "Attempting kTLS on Linux kernel {}", buffer.release);
  }

  if (callbacks_ == nullptr) {
    ENVOY_LOG(debug, "No callbacks available, cannot enable kTLS");
    return false;
  }

  // Get the socket file descriptor
  int fd = callbacks_->ioHandle().fdDoNotUse();
  if (fd < 0) {
    ENVOY_LOG(debug, "Invalid file descriptor for kTLS: {}", fd);
    return false;
  }

  // 1. Enable kTLS ULP on the socket
  const char* tls_ulp = "tls";
  if (setsockopt(fd, SOL_TCP, TCP_ULP, tls_ulp, strlen(tls_ulp)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TCP_ULP for kTLS: {} (errno={})", Envoy::errorDetails(err), err);
    
    // Special handling for common errors
    if (err == ENOENT) {
      ENVOY_LOG(debug, "kTLS ULP module not found - kernel may not support kTLS or module not loaded");
    } else if (err == EPERM) {
      ENVOY_LOG(debug, "Permission denied for kTLS ULP - check CAP_NET_ADMIN capability");
    } else if (err == ENOPROTOOPT) {
      ENVOY_LOG(debug, "Protocol option TCP_ULP not available - kernel may be too old for kTLS");
    }
    
    return false;
  }

  // 2. Set up the TLS crypto state for TX (sending)
  tls_crypto_info_t crypto_info;
  if (!ktls_info_->getTxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "Failed to get TX crypto info for kTLS");
    return false;
  }

  if (setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TLS_TX crypto info: {} (errno={})", Envoy::errorDetails(err), err);
    
    // Special handling for common errors
    if (err == EINVAL) {
      ENVOY_LOG(debug, "Invalid TLS crypto info - cipher/key may not be supported by kernel kTLS");
    } else if (err == ENOPROTOOPT) {
      ENVOY_LOG(debug, "SOL_TLS protocol option not supported - kernel may be too old for kTLS");
    }
    
    return false;
  }

  // 3. Set up the TLS crypto state for RX (receiving)
  if (!ktls_info_->getRxCryptoInfo(crypto_info)) {
    ENVOY_LOG(debug, "Failed to get RX crypto info for kTLS");
    return false;
  }

  if (setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "Failed to set TLS_RX crypto info: {} (errno={})", Envoy::errorDetails(err), err);
    return false;
  }

  // 4. Enable TX zerocopy if requested
  if (enable_tx_zerocopy_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &val, sizeof(val)) < 0) {
      int err = errno;
      ENVOY_LOG(debug, "Failed to enable TX zerocopy for kTLS: {} (errno={})", 
                Envoy::errorDetails(err), err);
      // Not fatal, continue
    }
  }

  // 5. Enable RX no padding if requested
  if (enable_rx_no_pad_) {
    int val = 1;
    if (setsockopt(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &val, sizeof(val)) < 0) {
      int err = errno;
      ENVOY_LOG(debug, "Failed to set RX no padding for kTLS: {} (errno={})", 
                Envoy::errorDetails(err), err);
      // Not fatal, continue
    }
  }

  // 6. Set up socket splicing for zero-copy operations
  if (enable_tx_zerocopy_) {
#ifdef HAS_SPLICE_SYSCALL
    try {
      socket_splicing_ = std::make_unique<KtlsSocketSplicing>(
          callbacks_->ioHandle(), callbacks_->connection().socket().ioHandle());
      ENVOY_LOG(debug, "kTLS socket splicing set up successfully");
    } catch (const EnvoyException& e) {
      ENVOY_LOG(debug, "Failed to set up kTLS socket splicing: {}", e.what());
      // Not fatal, continue without splicing
    }
#else
    ENVOY_LOG(info, "Socket splicing not available on this platform, zero-copy disabled");
#endif
  }

  // Verify kTLS is actually working by reading socket options
  int verify_val = 0;
  socklen_t verify_len = sizeof(verify_val);
  if (getsockopt(fd, SOL_TLS, TLS_TX, &verify_val, &verify_len) < 0) {
    int err = errno;
    ENVOY_LOG(debug, "kTLS verification failed on TLS_TX: {} (errno={})", 
              Envoy::errorDetails(err), err);
    ENVOY_LOG(debug, "Continuing with standard TLS as kTLS may not be properly enabled");
    // Mark kTLS as not enabled since verification failed
    ktls_enabled_ = false;
    return false;
  }

  // Perform a test write/read to ensure kTLS is working properly
  // This helps catch compatibility issues before we start using kTLS for real traffic
  char test_data[] = "kTLS-test";
  ssize_t test_write = ::send(fd, test_data, 0, MSG_DONTWAIT); // 0-byte probe
  if (test_write < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    int err = errno;
    ENVOY_LOG(debug, "kTLS test write failed: {} (errno={})", Envoy::errorDetails(err), err);
    ENVOY_LOG(debug, "Continuing with standard TLS as kTLS may not be properly enabled");
    ktls_enabled_ = false;
    return false;
  }

  // Mark kTLS as enabled
  ktls_enabled_ = true;
  ENVOY_LOG(info, "kTLS enabled successfully");
  return true;
#else
  // kTLS is not supported on non-Linux platforms
  ENVOY_LOG(debug, "kTLS not supported on this platform");
  ktls_enabled_ = false;
  return false;
#endif
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
    ENVOY_LOG(debug, "Cipher information not yet available, handshake may not be complete");
    return false;
  }

  // Check for supported ciphers
  const std::vector<std::string> supported_ciphers = {
    "ECDHE-RSA-AES128-GCM-SHA256",
    "AES128-GCM-SHA256"
  };
  
  bool cipher_supported = false;
  for (const auto& supported_cipher : supported_ciphers) {
    if (cipher.find(supported_cipher) != std::string::npos) {
      cipher_supported = true;
      break;
    }
  }
  
  if (!cipher_supported) {
    ENVOY_LOG(debug, "Unsupported cipher suite for kTLS: {}", cipher);
    ENVOY_LOG(debug, "kTLS currently only supports AES128-GCM ciphers");
    return false;
  }

  // Check TLS version - for now we only support TLS 1.2
  std::string version = std::string(ssl_connection->tlsVersion());

  // Always log the TLS version for debugging
  ENVOY_LOG(debug, "Negotiated TLS version for kTLS: {}", version);
  
  if (version.empty()) {
    ENVOY_LOG(debug, "TLS version info not yet available, handshake may not be complete");
    return false;
  }

  if (version != "TLSv1.2") {
    ENVOY_LOG(debug, "Unsupported TLS version for kTLS: {}", version);
    ENVOY_LOG(debug, "kTLS currently only supports TLS 1.2");
    return false;
  }

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
