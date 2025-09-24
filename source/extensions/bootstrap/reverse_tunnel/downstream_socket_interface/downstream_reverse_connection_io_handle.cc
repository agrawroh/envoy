#include "source/extensions/bootstrap/reverse_tunnel/downstream_socket_interface/downstream_reverse_connection_io_handle.h"

#include "source/common/common/logger.h"
#include "source/extensions/bootstrap/reverse_tunnel/common/reverse_connection_utility.h"
#include "source/extensions/bootstrap/reverse_tunnel/downstream_socket_interface/reverse_connection_io_handle.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

// DownstreamReverseConnectionIOHandle constructor implementation
DownstreamReverseConnectionIOHandle::DownstreamReverseConnectionIOHandle(
    Network::ConnectionSocketPtr socket, ReverseConnectionIOHandle* parent,
    const std::string& connection_key)
    : IoSocketHandleImpl(socket->ioHandle().fdDoNotUse()), owned_socket_(std::move(socket)),
      parent_(parent), connection_key_(connection_key) {
  ENVOY_LOG(debug,
            "DownstreamReverseConnectionIOHandle: taking ownership of socket with FD: {} for "
            "connection key: {}",
            fd_, connection_key_);
}

// DownstreamReverseConnectionIOHandle destructor implementation
DownstreamReverseConnectionIOHandle::~DownstreamReverseConnectionIOHandle() {
  ENVOY_LOG(
      debug,
      "DownstreamReverseConnectionIOHandle: destroying handle for FD: {} with connection key: {}",
      fd_, connection_key_);
}

Api::IoCallUint64Result
DownstreamReverseConnectionIOHandle::read(Buffer::Instance& buffer,
                                          absl::optional<uint64_t> max_length) {
  // Perform the actual read first.
  Api::IoCallUint64Result result = IoSocketHandleImpl::read(buffer, max_length);

  // If ping echoing is still active, inspect incoming data for RPING and echo back.
  if (ping_echo_active_ && result.err_ == nullptr && result.return_value_ > 0) {
    const uint64_t expected =
        ::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::PING_MESSAGE
            .size();

    // Copy out up to expected bytes to check for RPING without destroying app payload semantics.
    const uint64_t len = std::min<uint64_t>(buffer.length(), expected);
    std::string peek;
    peek.resize(static_cast<size_t>(len));
    buffer.copyOut(0, len, peek.data());

    // If we have at least expected bytes, check direct match.
    if (len == expected &&
        ::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::isPingMessage(
            peek)) {
      buffer.drain(expected);
      auto echo_rc = ::Envoy::Extensions::Bootstrap::ReverseConnection::ReverseConnectionUtility::
          sendPingResponse(*this);
      if (!echo_rc.ok()) {
        ENVOY_LOG(trace, "DownstreamReverseConnectionIOHandle: failed to send RPING echo on FD: {}",
                  fd_);
      } else {
        ENVOY_LOG(trace, "DownstreamReverseConnectionIOHandle: echoed RPING on FD: {}", fd_);
      }
      // If buffer now only contained RPING, suppress delivery to upper layers.
      if (buffer.length() == 0) {
        return Api::IoCallUint64Result{0, Api::IoError::none()};
      }
      // There is remaining data beyond RPING; continue returning remaining data this call.
      // Report number of bytes excluding the drained ping.
      const uint64_t adjusted =
          (result.return_value_ >= expected) ? (result.return_value_ - expected) : 0;
      return Api::IoCallUint64Result{adjusted, Api::IoError::none()};
    }

    // If fewer than expected bytes, we cannot conclusively detect ping yet; wait for more bytes.
    if (len < expected) {
      // Do nothing; a subsequent read will deliver more bytes.
    } else {
      // We had expected bytes but not RPING; disable echo permanently.
      ping_echo_active_ = false;
    }
  }

  return result;
}

// DownstreamReverseConnectionIOHandle close() implementation.
Api::IoCallUint64Result DownstreamReverseConnectionIOHandle::close() {
  ENVOY_LOG(
      debug,
      "DownstreamReverseConnectionIOHandle: closing handle for FD: {} with connection key: {}", fd_,
      connection_key_);

  // If we're ignoring close calls during socket hand-off, just return success.
  if (ignore_close_and_shutdown_) {
    ENVOY_LOG(
        debug,
        "DownstreamReverseConnectionIOHandle: ignoring close() call during socket hand-off for "
        "connection key: {}",
        connection_key_);
    return Api::ioCallUint64ResultNoError();
  }

  // Prevent double-closing by checking if already closed
  if (fd_ < 0) {
    ENVOY_LOG(debug,
              "DownstreamReverseConnectionIOHandle: handle already closed for connection key: {}",
              connection_key_);
    return Api::ioCallUint64ResultNoError();
  }

  // Notify parent that this downstream connection has been closed
  // This will trigger re-initiation of the reverse connection if needed.
  if (parent_) {
    parent_->onDownstreamConnectionClosed(connection_key_);
    ENVOY_LOG(
        debug,
        "DownstreamReverseConnectionIOHandle: notified parent of connection closure for key: {}",
        connection_key_);
  }

  // Reset the owned socket to properly close the connection.
  if (owned_socket_) {
    owned_socket_.reset();
  }
  return IoSocketHandleImpl::close();
}

// DownstreamReverseConnectionIOHandle shutdown() implementation.
Api::SysCallIntResult DownstreamReverseConnectionIOHandle::shutdown(int how) {
  ENVOY_LOG(trace,
            "DownstreamReverseConnectionIOHandle: shutdown({}) called for FD: {} with connection "
            "key: {}",
            how, fd_, connection_key_);

  // If we're ignoring shutdown calls during socket hand-off, just return success.
  if (ignore_close_and_shutdown_) {
    ENVOY_LOG(
        debug,
        "DownstreamReverseConnectionIOHandle: ignoring shutdown() call during socket hand-off "
        "for connection key: {}",
        connection_key_);
    return Api::SysCallIntResult{0, 0};
  }

  return IoSocketHandleImpl::shutdown(how);
}

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
