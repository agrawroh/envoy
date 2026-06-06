#include "source/common/tcp_proxy/splice_pump.h"

#include <cerrno>
#include <cstdint>
#include <cstring>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace Envoy {
namespace TcpProxy {

namespace {
// TLS record-type bytes for the kTLS control-message dispatch (RFC 5246 6.2.1, RFC 8446).
constexpr uint8_t kTlsRecordChangeCipherSpec = 20;
constexpr uint8_t kTlsRecordAlert = 21;
constexpr uint8_t kTlsRecordHandshake = 22;
constexpr uint8_t kTlsHandshakeNewSessionTicket = 4;
constexpr uint8_t kTlsAlertCloseNotify = 0;
} // namespace

ControlAction classifyKtlsControlRecord(uint8_t record_type, const uint8_t* data, size_t len) {
  switch (record_type) {
  case kTlsRecordAlert:
    if (len >= 2 && data[1] == kTlsAlertCloseNotify) {
      return ControlAction::Eof;
    }
    return ControlAction::Close;
  case kTlsRecordHandshake: {
    // Walk the coalesced handshake messages, each a 1-byte type then a 3-byte length. Tolerate
    // NewSessionTicket and close on any rekey or renegotiation the consumed rustls cannot service.
    size_t pos = 0;
    while (pos < len) {
      if (data[pos] != kTlsHandshakeNewSessionTicket) {
        return ControlAction::Close;
      }
      if (pos + 4 > len) {
        break;
      }
      const size_t msg_len = (static_cast<size_t>(data[pos + 1]) << 16) |
                             (static_cast<size_t>(data[pos + 2]) << 8) |
                             static_cast<size_t>(data[pos + 3]);
      pos += 4 + msg_len;
    }
    return ControlAction::Retry;
  }
  case kTlsRecordChangeCipherSpec:
    return ControlAction::Retry; // TLS 1.3 middlebox-compat record
  default:
    return ControlAction::Close;
  }
}

#if defined(__linux__)

namespace {
// Pipe capacity (1 MiB), matching OSD's zerocopy-proxy. The kernel clamps to
// /proc/sys/fs/pipe-max-size. The pre-engage chunk goes straight to the downstream socket, so the
// pipe size does not bound it.
constexpr size_t kPipeCapacity = 1024 * 1024;
// Userspace relay chunk for the downstream-to-upstream direction. The request direction is small,
// so a modest buffer keeps the copy cheap. A larger request or upload is relayed in chunks.
constexpr size_t kD2uChunk = 64 * 1024;
// Upper bound on non-DATA kTLS control records drained in one pump pass. A trusted upstream sends
// a handful of NewSessionTickets, so a large run signals a misbehaving peer and we close.
constexpr int kMaxControlRecordsPerPass = 1024;
} // namespace

SplicePump::SplicePump(os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls,
                       Event::Dispatcher& dispatcher, CompletionCb on_complete,
                       BytesCb on_upstream_to_downstream, BytesCb on_downstream_to_upstream)
    : down_fd_(down_fd), up_fd_(up_fd), up_is_ktls_(up_is_ktls), dispatcher_(dispatcher),
      on_complete_(std::move(on_complete)), on_u2d_bytes_(std::move(on_upstream_to_downstream)),
      on_d2u_bytes_(std::move(on_downstream_to_upstream)) {}

SplicePump::~SplicePump() {
  // Close only our own pipe fds. The socket fds are borrowed and stay owned by their
  // ConnectionImpls, which close them in their own teardown.
  for (int fd : {u2d_.read_fd, u2d_.write_fd}) {
    if (fd >= 0) {
      ::close(fd);
    }
  }
}

bool SplicePump::prepare(std::string initial_downstream_data) {
  int u2d[2];
  if (::pipe2(u2d, O_NONBLOCK | O_CLOEXEC) != 0) {
    ENVOY_LOG(warn, "splice pump pipe2 failed, {}", std::strerror(errno));
    return false;
  }
  u2d_.read_fd = u2d[0];
  u2d_.write_fd = u2d[1];
  d2u_buf_.resize(kD2uChunk);

  // Write the pre-engage decrypted chunk straight to the downstream socket so it precedes any
  // spliced bytes and ordering is preserved. It can exceed the pipe capacity, so it goes to the
  // socket rather than the bounded pipe. Whatever the send buffer cannot take now is stashed and
  // flushed by the pump.
  if (!initial_downstream_data.empty()) {
    size_t off = 0;
    while (off < initial_downstream_data.size()) {
      const ssize_t w = ::write(down_fd_, initial_downstream_data.data() + off,
                                initial_downstream_data.size() - off);
      if (w > 0) {
        off += static_cast<size_t>(w);
        on_u2d_bytes_(static_cast<uint64_t>(w));
      } else if (w < 0 && errno == EINTR) {
        continue;
      } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break; // socket full, stash the rest below
      } else {
        ENVOY_LOG(warn, "splice pump initial downstream write error, {}", std::strerror(errno));
        if (off == 0) {
          return false; // nothing delivered yet, let the buffered path handle the broken socket
        }
        break; // some bytes already delivered, stash the rest and let the pump surface the error
      }
    }
    if (off < initial_downstream_data.size()) {
      pending_down_ = std::move(initial_downstream_data);
      pending_down_off_ = off;
    }
  }
  return true;
}

void SplicePump::arm() {
  // Best-effort enlarge the u2d pipe. On failure the kernel keeps the default size.
  ::fcntl(u2d_.write_fd, F_SETPIPE_SZ, static_cast<int>(kPipeCapacity));
  u2d_.capacity = kPipeCapacity;

  up_file_event_ = dispatcher_.createFileEvent(
      up_fd_, [this](uint32_t events) { return onUpReady(events); }, Event::FileTriggerType::Edge,
      Event::FileReadyType::Read | Event::FileReadyType::Write | Event::FileReadyType::Closed);
  down_file_event_ = dispatcher_.createFileEvent(
      down_fd_, [this](uint32_t events) { return onDownReady(events); },
      Event::FileTriggerType::Edge,
      Event::FileReadyType::Read | Event::FileReadyType::Write | Event::FileReadyType::Closed);

  // We don't know the current readiness, and the sockets may already hold buffered data at engage
  // time. Assume ready in all directions and let the first splices clear the latches on EAGAIN.
  up_readable_ = up_writable_ = down_readable_ = down_writable_ = true;
  ENVOY_LOG(debug, "splice pump armed down_fd={} up_fd={} kTLS={} pending={}", down_fd_, up_fd_,
            up_is_ktls_, pending_down_.size() - pending_down_off_);
  pump();
}

absl::Status SplicePump::onUpReady(uint32_t events) {
  if (completed_) {
    return absl::OkStatus();
  }
  if (events & (Event::FileReadyType::Read | Event::FileReadyType::Closed)) {
    up_readable_ = true;
  }
  if (events & Event::FileReadyType::Write) {
    up_writable_ = true;
  }
  pump();
  return absl::OkStatus();
}

absl::Status SplicePump::onDownReady(uint32_t events) {
  if (completed_) {
    return absl::OkStatus();
  }
  if (events & (Event::FileReadyType::Read | Event::FileReadyType::Closed)) {
    down_readable_ = true;
  }
  if (events & Event::FileReadyType::Write) {
    down_writable_ = true;
  }
  pump();
  return absl::OkStatus();
}

void SplicePump::pump() {
  if (completed_) {
    return;
  }
  // SPLICE_F_MOVE is advisory. SPLICE_F_MORE is not set so the downstream write is not corked.
  const unsigned flags = SPLICE_F_NONBLOCK | SPLICE_F_MOVE;
  int control_records = 0;
  bool progress = true;
  while (progress) {
    progress = false;

    // (1a) Flush any stashed pre-engage chunk to downstream FIRST (ordering: it precedes u2d).
    while (down_writable_ && pending_down_off_ < pending_down_.size()) {
      const ssize_t w = ::write(down_fd_, pending_down_.data() + pending_down_off_,
                                pending_down_.size() - pending_down_off_);
      if (w > 0) {
        pending_down_off_ += static_cast<size_t>(w);
        on_u2d_bytes_(static_cast<uint64_t>(w));
        progress = true;
      } else if (w == 0) {
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        down_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      }
    }

    // (1b) Drain u2d pipe -> downstream socket (only after the stashed chunk is fully delivered).
    while (down_writable_ && u2d_.in_pipe > 0 && pending_down_off_ >= pending_down_.size()) {
      const ssize_t n = ::splice(u2d_.read_fd, nullptr, down_fd_, nullptr, u2d_.in_pipe, flags);
      if (n > 0) {
        u2d_.in_pipe -= static_cast<size_t>(n);
        on_u2d_bytes_(static_cast<uint64_t>(n));
        progress = true;
      } else if (n == 0) {
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        down_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump u2d downstream write error, {}", std::strerror(errno));
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      }
    }

    // (2) Fill u2d pipe <- upstream kTLS socket (read the decrypted download body).
    while (up_readable_ && !up_read_eof_ && u2d_.in_pipe < u2d_.capacity) {
      const ssize_t n =
          ::splice(up_fd_, nullptr, u2d_.write_fd, nullptr, u2d_.capacity - u2d_.in_pipe, flags);
      if (n > 0) {
        u2d_.in_pipe += static_cast<size_t>(n);
        progress = true;
      } else if (n == 0) {
        up_read_eof_ = true;
        break;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        up_readable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else if (errno == EINVAL && up_is_ktls_) {
        if (drainUpstreamControlMessage()) {
          if (++control_records > kMaxControlRecordsPerPass) {
            ENVOY_LOG(debug, "splice pump too many kTLS control records, closing");
            complete(Network::ConnectionEvent::RemoteClose);
            return;
          }
          progress = true;
          continue; // benign control record consumed, retry the upstream splice
        }
        if (completed_) {
          return; // a fatal record or error closed the pump
        }
        break; // EAGAIN or close_notify, stop reading upstream but keep draining the d2u direction
      } else {
        ENVOY_LOG(debug, "splice pump u2d upstream read error, {}", std::strerror(errno));
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      }
    }

    // (3) Write buffered d2u bytes to the upstream socket. kTLS TX encrypts them through the
    // kernel sendmsg path. This carries the request and any upload.
    while (up_writable_ && d2u_off_ < d2u_len_) {
      const ssize_t n = ::write(up_fd_, d2u_buf_.data() + d2u_off_, d2u_len_ - d2u_off_);
      if (n > 0) {
        d2u_off_ += static_cast<size_t>(n);
        on_d2u_bytes_(static_cast<uint64_t>(n));
        progress = true;
      } else if (n == 0) {
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        up_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump d2u upstream write error, {}", std::strerror(errno));
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      }
    }
    if (d2u_off_ >= d2u_len_) {
      d2u_len_ = d2u_off_ = 0;
    }

    // (4) Read more d2u bytes from the downstream socket once the buffer is fully drained, so
    // bytes leave in order.
    while (down_readable_ && !down_read_eof_ && d2u_len_ == 0) {
      const ssize_t n = ::read(down_fd_, d2u_buf_.data(), d2u_buf_.size());
      if (n > 0) {
        d2u_len_ = static_cast<size_t>(n);
        d2u_off_ = 0;
        progress = true;
      } else if (n == 0) {
        down_read_eof_ = true;
        break;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        down_readable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump d2u downstream read error, {}", std::strerror(errno));
        complete(Network::ConnectionEvent::RemoteClose);
        return;
      }
    }
  }
  maybeHalfCloseOrComplete();
}

bool SplicePump::drainUpstreamControlMessage() {
  // splice() cannot deliver a non-DATA TLS record into a pipe, so consume it with recvmsg() and
  // read its type from the TLS_GET_RECORD_TYPE control message.
  uint8_t buf[16640];
  alignas(struct cmsghdr) char cmsg_space[CMSG_SPACE(sizeof(uint8_t))];
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  struct msghdr msg;
  std::memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_space;
  msg.msg_controllen = sizeof(cmsg_space);

  ssize_t n;
  do {
    n = ::recvmsg(up_fd_, &msg, MSG_DONTWAIT);
  } while (n < 0 && errno == EINTR);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      up_readable_ = false;
      return false;
    }
    ENVOY_LOG(debug, "splice pump kTLS control recvmsg error, {}", std::strerror(errno));
    complete(Network::ConnectionEvent::RemoteClose);
    return false;
  }
  if (n == 0) {
    // Upstream closed the read side, mirror the splice n==0 EOF arm.
    up_read_eof_ = true;
    maybeHalfCloseOrComplete();
    return false;
  }
  // A record larger than the buffer (record body or control data truncated) cannot be classified
  // safely, so close.
  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
    ENVOY_LOG(debug, "splice pump kTLS control record truncated");
    complete(Network::ConnectionEvent::RemoteClose);
    return false;
  }

  uint8_t record_type = 0;
  for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_TLS && cmsg->cmsg_type == TLS_GET_RECORD_TYPE &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(uint8_t))) {
      record_type = *reinterpret_cast<uint8_t*>(CMSG_DATA(cmsg));
    }
  }

  switch (classifyKtlsControlRecord(record_type, buf, static_cast<size_t>(n))) {
  case ControlAction::Retry:
    return true;
  case ControlAction::Eof:
    ENVOY_LOG(debug, "splice pump upstream close_notify");
    up_read_eof_ = true;
    maybeHalfCloseOrComplete();
    return false;
  case ControlAction::Close:
    if (record_type == kTlsRecordAlert) {
      ENVOY_LOG(debug, "splice pump upstream fatal TLS alert level {} desc {}",
                n >= 1 ? buf[0] : 0xFF, n >= 2 ? buf[1] : 0xFF);
    } else {
      ENVOY_LOG(debug, "splice pump closing on TLS record type {}", record_type);
    }
    complete(Network::ConnectionEvent::RemoteClose);
    return false;
  }
  return false; // all ControlActions are handled above
}

void SplicePump::sendUpstreamCloseNotify() {
  // Emit a TLS close_notify alert on the kTLS TX socket via the TLS_SET_RECORD_TYPE control
  // message before the FIN, so a strict peer does not treat the request or upload as truncated.
  // This mirrors the userspace rustls close path. Best-effort, the FIN follows regardless.
  uint8_t alert[2] = {1, kTlsAlertCloseNotify}; // warning level, close_notify description
  alignas(struct cmsghdr) char cmsg_space[CMSG_SPACE(sizeof(uint8_t))];
  struct iovec iov;
  iov.iov_base = alert;
  iov.iov_len = sizeof(alert);
  struct msghdr msg;
  std::memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_space;
  msg.msg_controllen = sizeof(cmsg_space);
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == nullptr) {
    return;
  }
  cmsg->cmsg_level = SOL_TLS;
  cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint8_t));
  *CMSG_DATA(cmsg) = kTlsRecordAlert;
  ssize_t rc;
  do {
    rc = ::sendmsg(up_fd_, &msg, MSG_DONTWAIT);
  } while (rc < 0 && errno == EINTR);
  if (rc < 0) {
    ENVOY_LOG(debug, "splice pump close_notify sendmsg failed, {}", std::strerror(errno));
  }
}

void SplicePump::maybeHalfCloseOrComplete() {
  if (completed_) {
    return;
  }
  const bool u2d_drained =
      up_read_eof_ && u2d_.in_pipe == 0 && pending_down_off_ >= pending_down_.size();
  const bool d2u_drained = down_read_eof_ && d2u_off_ >= d2u_len_;
  // Half-close the downstream write once the upstream is done and everything is flushed, which
  // gives the client its EOF.
  if (u2d_drained && !down_write_shutdown_) {
    ::shutdown(down_fd_, SHUT_WR);
    down_write_shutdown_ = true;
  }
  if (d2u_drained && !up_write_shutdown_) {
    if (up_is_ktls_) {
      sendUpstreamCloseNotify();
    }
    ::shutdown(up_fd_, SHUT_WR);
    up_write_shutdown_ = true;
  }
  if (u2d_drained && d2u_drained) {
    complete(Network::ConnectionEvent::RemoteClose);
  }
}

void SplicePump::complete(Network::ConnectionEvent event) {
  if (completed_) {
    return;
  }
  completed_ = true;
  ENVOY_LOG(debug, "splice pump complete");
  // Disable rather than destroy the FileEvents. We may be inside one of their callbacks, and the
  // pump is destroyed later by the owning Filter's deferred teardown.
  if (up_file_event_ != nullptr) {
    up_file_event_->setEnabled(0);
  }
  if (down_file_event_ != nullptr) {
    down_file_event_->setEnabled(0);
  }
  // The owning Filter is alive here because it owns this pump. Its callback must not destroy the
  // pump synchronously and defers teardown through its own SchedulableCallback.
  on_complete_(event);
}

#else // !defined(__linux__)

// kTLS and splice() are Linux-only. On other platforms the pump never engages because prepare()
// fails, so tcp_proxy stays on the buffered path and every other method is an unused no-op.
SplicePump::SplicePump(os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls,
                       Event::Dispatcher& dispatcher, CompletionCb on_complete,
                       BytesCb on_upstream_to_downstream, BytesCb on_downstream_to_upstream)
    : down_fd_(down_fd), up_fd_(up_fd), up_is_ktls_(up_is_ktls), dispatcher_(dispatcher),
      on_complete_(std::move(on_complete)), on_u2d_bytes_(std::move(on_upstream_to_downstream)),
      on_d2u_bytes_(std::move(on_downstream_to_upstream)) {}

SplicePump::~SplicePump() = default;
bool SplicePump::prepare(std::string) { return false; }
void SplicePump::arm() {}
absl::Status SplicePump::onUpReady(uint32_t) { return absl::OkStatus(); }
absl::Status SplicePump::onDownReady(uint32_t) { return absl::OkStatus(); }
void SplicePump::pump() {}
bool SplicePump::drainUpstreamControlMessage() { return false; }
void SplicePump::sendUpstreamCloseNotify() {}
void SplicePump::maybeHalfCloseOrComplete() {}
void SplicePump::complete(Network::ConnectionEvent) {}

#endif

} // namespace TcpProxy
} // namespace Envoy
