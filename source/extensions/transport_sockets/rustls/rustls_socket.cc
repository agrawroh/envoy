#include "source/extensions/transport_sockets/rustls/rustls_socket.h"

#include <errno.h>

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

RustlsSocket::RustlsSocket(RustlsConnectionPtr rustls_conn, bool enable_ktls, bool ktls_tx_only)
    : rustls_conn_(std::move(rustls_conn)), enable_ktls_(enable_ktls), ktls_tx_only_(ktls_tx_only) {
  ASSERT(rustls_conn_ != nullptr);
}

RustlsSocket::~RustlsSocket() {
  ENVOY_CONN_LOG(debug, "rustls: destroying socket", callbacks_->connection());
}

void RustlsSocket::setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  ENVOY_CONN_LOG(info, "rustls: 🔵 V2_BUFFERED_READ_FIX socket callbacks set", callbacks_->connection());
}

std::string RustlsSocket::protocol() const {
  return negotiated_protocol_;
}

absl::string_view RustlsSocket::failureReason() const {
  return failure_reason_;
}

bool RustlsSocket::canFlushClose() {
  return handshake_complete_;
}

void RustlsSocket::closeSocket(Network::ConnectionEvent) {
  ENVOY_CONN_LOG(debug, "rustls: closing socket", callbacks_->connection());
  // Rustls connection cleanup happens in destructor.
}

void RustlsSocket::onConnected() {
  ENVOY_CONN_LOG(debug, "rustls: connection established, starting TLS handshake",
                 callbacks_->connection());
  
  // Update the file descriptor for kTLS (now that socket is connected).
  int fd = callbacks_->ioHandle().fdDoNotUse();
  ENVOY_CONN_LOG(debug, "rustls: setting file descriptor for kTLS: fd={}",
                 callbacks_->connection(), fd);
  rustls_conn_->setFileDescriptor(fd);
  
  // For server connections, we need to wait for client data.
  // For client connections, we might need to send ClientHello.
  if (rustls_conn_->wantsWrite()) {
    ENVOY_CONN_LOG(debug, "rustls: connection wants to write initial handshake data",
                   callbacks_->connection());
    flushPendingTlsData();
  }
  
  ENVOY_CONN_LOG(debug, "rustls: onConnected complete, waiting for network I/O",
                 callbacks_->connection());
}

bool RustlsSocket::doHandshake() {
  if (handshake_complete_) {
    return true;
  }

  ENVOY_CONN_LOG(debug, "rustls: performing handshake (isHandshaking: {})", 
                 callbacks_->connection(), rustls_conn_->isHandshaking());

  int result = rustls_conn_->handshake();
  if (result != RustlsConnection::OK) {
    failure_reason_ = "TLS handshake failed";
    ENVOY_CONN_LOG(error, "rustls: handshake failed with error code {}", 
                   callbacks_->connection(), result);
    callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    return false;
  }

  ENVOY_CONN_LOG(debug, "rustls: handshake() returned OK, checking if still handshaking", 
                 callbacks_->connection());

  if (!rustls_conn_->isHandshaking()) {
    handshake_complete_ = true;
    ENVOY_CONN_LOG(info, "rustls: ✅ TLS handshake complete!", callbacks_->connection());

    // Get negotiated ALPN protocol.
    negotiated_protocol_ = rustls_conn_->getAlpnProtocol();
    if (!negotiated_protocol_.empty()) {
      ENVOY_CONN_LOG(debug, "rustls: negotiated ALPN protocol: {}", 
                     callbacks_->connection(), negotiated_protocol_);
    }

    // CRITICAL: Always flush ALL pending TLS data BEFORE attempting kTLS.
    // Rustls generates the final handshake message (TLS Finished) during the handshake,
    // and won't allow secret extraction if there are buffered TLS records to send.
    // We MUST flush unconditionally to ensure all handshake data is sent.
    bool wants_write_before = rustls_conn_->wantsWrite();
    ENVOY_CONN_LOG(info, "rustls: 🔍 wants_write={} BEFORE flush", 
                   callbacks_->connection(), wants_write_before);
    
    // Always flush, even if wants_write is currently false, because the state might change.
    ENVOY_CONN_LOG(info, "rustls: 📤 UNCONDITIONALLY flushing pending TLS data before kTLS",
                   callbacks_->connection());
    flushPendingTlsData();
    
    bool wants_write_after = rustls_conn_->wantsWrite();
    ENVOY_CONN_LOG(info, "rustls: 🔍 wants_write={} AFTER flush", 
                   callbacks_->connection(), wants_write_after);

    // Enable kTLS if requested and supported.
    if (enable_ktls_) {
      enableKtls();
    }

    // Raise connected event.
    callbacks_->raiseEvent(Network::ConnectionEvent::Connected);
  }

  // Handshake still in progress or just completed - both are success cases.
  ENVOY_CONN_LOG(debug, "rustls: doHandshake() returning true (complete: {})", 
                 callbacks_->connection(), handshake_complete_);
  return true;
}

void RustlsSocket::enableKtls() {
  ENVOY_CONN_LOG(debug, "rustls: attempting to enable kTLS offload{}", callbacks_->connection(),
                ktls_tx_only_ ? " (TX only)" : "");

  ktls_tx_enabled_ = rustls_conn_->enableKtlsTx();
  
  if (!ktls_tx_only_) {
    ktls_rx_enabled_ = rustls_conn_->enableKtlsRx();
  }

  if (ktls_tx_enabled_ && (ktls_tx_only_ || ktls_rx_enabled_)) {
    if (ktls_tx_only_) {
      ENVOY_CONN_LOG(info, "rustls: kTLS offload enabled (TX only, RX using userspace)", 
                     callbacks_->connection());
    } else {
      ENVOY_CONN_LOG(info, "rustls: kTLS offload enabled (TX and RX)", callbacks_->connection());
    }
  } else if (ktls_tx_enabled_ || ktls_rx_enabled_) {
    ENVOY_CONN_LOG(warn, "rustls: partial kTLS offload (TX: {}, RX: {})", 
                   callbacks_->connection(), ktls_tx_enabled_, ktls_rx_enabled_);
  } else {
    ENVOY_CONN_LOG(warn, "rustls: kTLS offload not available on this system",
                   callbacks_->connection());
  }
}

Network::IoResult RustlsSocket::doRead(Buffer::Instance& buffer) {
  ENVOY_CONN_LOG(info, "rustls: 🔵 V2_BUFFERED_READ_FIX doRead() called (handshake_complete: {})",
                 callbacks_->connection(), handshake_complete_);
  
  Network::PostIoAction action = Network::PostIoAction::KeepOpen;
  uint64_t bytes_read = 0;
  bool end_stream = false;

  // IMPORTANT: If handshake is complete AND kTLS RX is enabled, read directly using
  // rustls_conn_->read() which will use kernel I/O. Don't do the encrypted data flow.
  if (handshake_complete_ && ktls_rx_enabled_) {
    ENVOY_CONN_LOG(trace, "rustls: kTLS RX enabled - reading decrypted data directly from kernel",
                   callbacks_->connection());
    
    const uint64_t max_read_size = 16384;
    uint8_t app_buffer[max_read_size];
    ssize_t app_bytes = rustls_conn_->read(app_buffer, max_read_size);
    
    if (app_bytes > 0) {
      bytes_read = static_cast<uint64_t>(app_bytes);
      buffer.add(app_buffer, bytes_read);
      ENVOY_CONN_LOG(trace, "rustls: 📖 kTLS RX read {} decrypted bytes", 
                     callbacks_->connection(), bytes_read);
      return {action, bytes_read, end_stream};
    } else if (app_bytes == 0) {
      // Connection closed.
      end_stream = true;
      return {Network::PostIoAction::Close, 0, end_stream};
    } else {
      // Error or EAGAIN.
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return {Network::PostIoAction::KeepOpen, 0, false};
      }
      ENVOY_CONN_LOG(error, "rustls: kTLS RX read error: errno={}", callbacks_->connection(), errno);
      return {Network::PostIoAction::Close, 0, false};
    }
  }
  
  // For userspace TLS: If handshake is complete, first try to read any buffered application data
  // that rustls has already decrypted. Rustls will refuse to accept more encrypted data
  // if it has unconsumed decrypted data in its internal buffer.
  if (handshake_complete_) {
    ENVOY_CONN_LOG(info, "rustls: 🔵 V2_FIX: Checking for buffered application data BEFORE network read",
                   callbacks_->connection());
    
    const uint64_t max_read_size = 16384;
    uint8_t app_buffer[max_read_size];
    ssize_t app_bytes = rustls_conn_->read(app_buffer, max_read_size);
    
    ENVOY_CONN_LOG(info, "rustls: 🔵 V2_FIX: rustls_conn_->read() returned {} bytes",
                   callbacks_->connection(), app_bytes);
    
    if (app_bytes > 0) {
      bytes_read = static_cast<uint64_t>(app_bytes);
      buffer.add(app_buffer, bytes_read);
      ENVOY_CONN_LOG(info, "rustls: 📖 V2_FIX SUCCESS: read {} buffered application bytes (before network read)", 
                     callbacks_->connection(), bytes_read);
      return {action, bytes_read, end_stream};
    } else {
      ENVOY_CONN_LOG(info, "rustls: 🔵 V2_FIX: No buffered data, proceeding to network read",
                     callbacks_->connection());
    }
  }

  // Read raw encrypted TLS data from network into a buffer.
  Buffer::OwnedImpl network_buffer;
  Api::IoCallUint64Result result = callbacks_->ioHandle().read(network_buffer, 16384);
  
  if (!result.ok()) {
    if (result.err_->getErrorCode() == Api::IoError::IoErrorCode::Again) {
      // No data available right now, this is normal.
      ENVOY_CONN_LOG(trace, "rustls: no data available (EAGAIN)", callbacks_->connection());
      return {Network::PostIoAction::KeepOpen, 0, false};
    }
    // Real error occurred.
    ENVOY_CONN_LOG(error, "rustls: network read error: {}", callbacks_->connection(), 
                   result.err_->getErrorDetails());
    return {Network::PostIoAction::Close, 0, false};
  }
  
  uint64_t network_bytes_read = result.return_value_;
  if (network_bytes_read == 0) {
    // Connection closed by peer.
    ENVOY_CONN_LOG(info, "rustls: peer closed connection (read 0 bytes)", callbacks_->connection());
    return {Network::PostIoAction::Close, 0, true};
  }

  ENVOY_CONN_LOG(info, "rustls: 📥 read {} encrypted bytes from network", 
                 callbacks_->connection(), network_bytes_read);

  // Feed encrypted TLS data to rustls.
  // We need to copy the data out of the buffer into a contiguous array for rustls.
  const auto slices = network_buffer.getRawSlices();
  size_t total_consumed = 0;
  for (const auto& slice : slices) {
    if (slice.len_ == 0) continue;
    
    ssize_t consumed = rustls_conn_->readTls(static_cast<const uint8_t*>(slice.mem_), slice.len_);
    if (consumed < 0) {
      ENVOY_CONN_LOG(error, "rustls: readTls() failed with code {}", 
                     callbacks_->connection(), consumed);
      return {Network::PostIoAction::Close, 0, false};
    }
    total_consumed += consumed;
    ENVOY_CONN_LOG(debug, "rustls: readTls() consumed {} bytes from slice (len: {})",
                   callbacks_->connection(), consumed, slice.len_);
  }
  
  ENVOY_CONN_LOG(info, "rustls: 🔄 fed {} bytes to rustls (total_consumed: {})", 
                 callbacks_->connection(), network_bytes_read, total_consumed);

  // Process TLS packets (handshake or application data).
  ENVOY_CONN_LOG(debug, "rustls: calling handshake to process packets", callbacks_->connection());
  if (!doHandshake()) {
    // Handshake failed.
    ENVOY_CONN_LOG(error, "rustls: handshake processing failed", callbacks_->connection());
    return {Network::PostIoAction::Close, 0, false};
  }

  // If still handshaking, flush any pending TLS responses.
  if (!handshake_complete_) {
    ENVOY_CONN_LOG(info, "rustls: still handshaking, flushing TLS responses", 
                   callbacks_->connection());
    flushPendingTlsData();
    return {Network::PostIoAction::KeepOpen, 0, false};
  }
  
  // Handshake just completed in this doRead() call.
  // If kTLS RX was enabled, the rustls connection is now consumed. Do NOT try to read from it.
  // Instead, return and let the next doRead() call use the kTLS RX fast path.
  // If only kTLS TX was enabled, we can still read from rustls using userspace decryption.
  if (ktls_rx_enabled_) {
    ENVOY_CONN_LOG(trace, "rustls: handshake complete with kTLS RX - returning to use kTLS RX path next", 
                   callbacks_->connection());
    return {Network::PostIoAction::KeepOpen, 0, false};
  }
  
  // Userspace TLS: handshake complete, read any buffered decrypted application data from rustls.
  ENVOY_CONN_LOG(info, "rustls: handshake complete (userspace TLS), reading application data", 
                 callbacks_->connection());

  const uint64_t max_read_size = 16384;
  uint8_t app_buffer[max_read_size];
  ssize_t app_bytes = rustls_conn_->read(app_buffer, max_read_size);
  
  if (app_bytes > 0) {
    bytes_read = static_cast<uint64_t>(app_bytes);
    buffer.add(app_buffer, bytes_read);
    ENVOY_CONN_LOG(info, "rustls: 📖 read {} decrypted application bytes", 
                   callbacks_->connection(), bytes_read);
  } else {
    ENVOY_CONN_LOG(trace, "rustls: rustls_conn_->read() returned {} (no application data available)", 
                   callbacks_->connection(), app_bytes);
  }

  return {action, bytes_read, end_stream};
}

Network::IoResult RustlsSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (!handshake_complete_) {
    if (!doHandshake()) {
      // Handshake still in progress or failed.
      return {Network::PostIoAction::KeepOpen, 0, false};
    }
  }

  Network::PostIoAction action = Network::PostIoAction::KeepOpen;
  uint64_t bytes_written = 0;

  // Write application data to be encrypted by rustls.
  const auto slices = buffer.getRawSlices();

  for (const auto& slice : slices) {
    if (slice.len_ == 0) {
      continue;
    }

    ssize_t result = rustls_conn_->write(static_cast<const uint8_t*>(slice.mem_), slice.len_);

    if (result > 0) {
      bytes_written += result;
      ENVOY_CONN_LOG(trace, "rustls: wrote {} encrypted bytes",
                     callbacks_->connection(), result);
    } else {
      // Error occurred.
      ENVOY_CONN_LOG(debug, "rustls: write error", callbacks_->connection());
      action = Network::PostIoAction::Close;
      break;
    }
  }

  // Drain written bytes from buffer.
  buffer.drain(bytes_written);

  if (end_stream && bytes_written == buffer.length()) {
    action = Network::PostIoAction::Close;
  }

  return {action, bytes_written, false};
}

Ssl::ConnectionInfoConstSharedPtr RustlsSocket::ssl() const {
  // TODO: Implement SSL connection info for rustls.
  // This would include peer certificate, cipher suite, etc.
  return nullptr;
}

void RustlsSocket::configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) {
  // Not implemented for rustls transport socket.
}

void RustlsSocket::flushPendingTlsData() {
  ENVOY_CONN_LOG(info, "rustls: 📤 flushPendingTlsData() called", callbacks_->connection());
  
  if (!rustls_conn_->wantsWrite()) {
    ENVOY_CONN_LOG(info, "rustls: 📭 no pending TLS data to flush (wants_write=false)", 
                   callbacks_->connection());
    return;
  }

  ENVOY_CONN_LOG(info, "rustls: 📤 flushing pending TLS data (wants_write=true)...", 
                 callbacks_->connection());

  const uint64_t max_write_size = 16384;
  std::vector<uint8_t> tls_buffer(max_write_size);
  size_t total_written = 0;
  int iteration = 0;

  while (rustls_conn_->wantsWrite()) {
    iteration++;
    ENVOY_CONN_LOG(info, "rustls: 🔄 flush iteration {} (wants_write=true)", 
                   callbacks_->connection(), iteration);
    
    ssize_t written = rustls_conn_->writeTls(tls_buffer.data(), max_write_size);
    if (written <= 0) {
      ENVOY_CONN_LOG(warn, "rustls: writeTls() returned {} on iteration {}", 
                     callbacks_->connection(), written, iteration);
      break;
    }

    ENVOY_CONN_LOG(info, "rustls: 📤 writeTls() extracted {} encrypted bytes",
                   callbacks_->connection(), written);

    // Write encrypted TLS data directly to network.
    Buffer::OwnedImpl tls_data(tls_buffer.data(), written);
    Api::IoCallUint64Result result = callbacks_->ioHandle().write(tls_data);
    
    if (!result.ok()) {
      ENVOY_CONN_LOG(error, "rustls: ❌ failed to write {} bytes to network: {}",
                     callbacks_->connection(), written, result.err_->getErrorDetails());
      break;
    }
    
    total_written += written;
    ENVOY_CONN_LOG(info, "rustls: ✅ wrote {} bytes to network (total so far: {})",
                   callbacks_->connection(), written, total_written);
  }
  
  ENVOY_CONN_LOG(info, "rustls: 🏁 flush complete: {} iterations, {} total bytes, wants_write={}",
                 callbacks_->connection(), iteration, total_written, rustls_conn_->wantsWrite());
}

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

