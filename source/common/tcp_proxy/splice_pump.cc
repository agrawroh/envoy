#include "source/common/tcp_proxy/splice_pump.h"

#include <algorithm>
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
      // A handshake message whose 4-byte header is split across two TLS records would need
      // cross-record reassembly, which this classifier does not do (it inspects one record at a
      // time). Treat a truncated header as fatal rather than silently discarding it. This is
      // intentionally STRICTER than the rustls userspace fallback's classifier, which tolerates the
      // split and continues: on the splice path there is no userspace TLS state machine to resume a
      // reassembled message, so a fragmented post-handshake message we cannot fully classify is
      // closed rather than risk misframing. S3/s2n sends small, unfragmented NewSessionTickets, so
      // this is not reached in practice.
      if (pos + 4 > len) {
        return ControlAction::Close;
      }
      const size_t msg_len = (static_cast<size_t>(data[pos + 1]) << 16) |
                             (static_cast<size_t>(data[pos + 2]) << 8) |
                             static_cast<size_t>(data[pos + 3]);
      if (msg_len > len - pos - 4) {
        return ControlAction::Close; // declared length overruns the record
      }
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
// Floor used only if both F_SETPIPE_SZ and F_GETPIPE_SZ fail to report a size. The kernel's
// default pipe is 16 pages (64 KiB); assume that minimum so accounting never overstates capacity.
constexpr size_t kFallbackPipeCapacity = 64 * 1024;
// Upper bound on non-DATA kTLS control records drained in one pump pass. A trusted upstream sends
// a handful of NewSessionTickets, so a large run signals a misbehaving peer and we close.
constexpr int kMaxControlRecordsPerPass = 1024;
// TLS 1.3 max record, 16384 plaintext plus AEAD and header overhead.
constexpr size_t kMaxTlsRecordSize = 16640;
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
  for (int fd : {u2d_.read_fd, u2d_.write_fd, d2u_.read_fd, d2u_.write_fd}) {
    if (fd >= 0) {
      ::close(fd);
    }
  }
}

bool SplicePump::createPipes(bool need_u2d, bool need_d2u) {
  // Allocate only the directions the caller will actually use. The bounded HTTP body-splice runs a
  // single direction per engage, so creating only that pipe halves the per-message fd cost (2 fds
  // and one F_SETPIPE_SZ instead of 4 and two) and the pipe-page footprint that, under load, drives
  // the per-user pipe-pages accounting. The L4 path and tests need both.
  if (need_u2d && u2d_.read_fd < 0) {
    int u2d[2];
    if (::pipe2(u2d, O_NONBLOCK | O_CLOEXEC) != 0) {
      ENVOY_LOG(warn, "splice pump u2d pipe2 failed, {}", std::strerror(errno));
      return false;
    }
    u2d_.read_fd = u2d[0];
    u2d_.write_fd = u2d[1];
  }
  if (need_d2u && d2u_.read_fd < 0) {
    int d2u[2];
    if (::pipe2(d2u, O_NONBLOCK | O_CLOEXEC) != 0) {
      ENVOY_LOG(warn, "splice pump d2u pipe2 failed, {}", std::strerror(errno));
      return false;
    }
    d2u_.read_fd = d2u[0];
    d2u_.write_fd = d2u[1];
  }
  return true;
}

bool SplicePump::prepare(std::string initial_u2d, std::string initial_d2u) {
  // Lazily create both pipes when the caller did not pre-create them (the L4 path and unit tests
  // call prepare() directly). The L7 coordinator instead calls createPipes() first, before it
  // irreversibly extracts the sink's pending write, so a pipe-creation failure there falls back to
  // the buffered path rather than corrupting an already-drained connection.
  if (u2d_.read_fd < 0 && d2u_.read_fd < 0) {
    if (!createPipes(/*need_u2d=*/true, /*need_d2u=*/true)) {
      return false;
    }
  }

  // Write the pre-engage decrypted upstream chunk straight to the downstream socket so it precedes
  // any spliced u2d bytes and ordering is preserved. It can exceed the pipe capacity, so it goes to
  // the socket rather than the bounded pipe. Whatever the send buffer cannot take now is stashed
  // and flushed by the pump.
  if (!initial_u2d.empty()) {
    size_t off = 0;
    while (off < initial_u2d.size()) {
      const ssize_t w = ::write(down_fd_, initial_u2d.data() + off, initial_u2d.size() - off);
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
    if (off < initial_u2d.size()) {
      pending_down_ = std::move(initial_u2d);
      pending_down_off_ = off;
    }
  }

  // Symmetric for the upload direction. Write the pre-engage downstream chunk straight to the
  // upstream socket so it precedes any spliced d2u bytes. On a kTLS-TX socket write() frames TLS
  // records correctly. Stash whatever the send buffer cannot take for the pump to flush.
  if (!initial_d2u.empty()) {
    size_t off = 0;
    while (off < initial_d2u.size()) {
      const ssize_t w = ::write(up_fd_, initial_d2u.data() + off, initial_d2u.size() - off);
      if (w > 0) {
        off += static_cast<size_t>(w);
        on_d2u_bytes_(static_cast<uint64_t>(w));
      } else if (w < 0 && errno == EINTR) {
        continue;
      } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break; // socket full, stash the rest below
      } else {
        ENVOY_LOG(warn, "splice pump initial upstream write error, {}", std::strerror(errno));
        if (off == 0) {
          return false; // nothing delivered yet, let the buffered path handle the broken socket
        }
        break;
      }
    }
    if (off < initial_d2u.size()) {
      pending_up_ = std::move(initial_d2u);
      pending_up_off_ = off;
    }
  }
  return true;
}

void SplicePump::setBounds(absl::optional<uint64_t> u2d_limit, absl::optional<uint64_t> d2u_limit) {
  bounded_ = true;
  u2d_limit_ = u2d_limit;
  d2u_limit_ = d2u_limit;
}

void SplicePump::arm() {
  // Enlarge each created pipe and record the capacity the kernel ACTUALLY gave us, not the size we
  // asked for. F_SETPIPE_SZ returns the (page-rounded) size on success; if it fails, EPERM past
  // fs.pipe-user-pages-soft for an unprivileged process, or a clamp to fs.pipe-max-size, the pipe
  // keeps a smaller size and F_GETPIPE_SZ reports it. Trusting the requested 1 MiB while the real
  // pipe is a few pages makes the section-(2)/(4) `in_pipe < capacity` guard splice into a full
  // pipe, get EAGAIN, and misattribute it to the source socket, a stall or false-EOF truncation.
  // Mirrors OSD's zerocopy proxy, which accounts the real F_GETPIPE_SZ size.
  auto size_pipe = [](Pipe& pipe) {
    if (pipe.write_fd < 0) {
      return;
    }
    const int set = ::fcntl(pipe.write_fd, F_SETPIPE_SZ, static_cast<int>(kPipeCapacity));
    if (set > 0) {
      pipe.capacity = static_cast<size_t>(set);
      return;
    }
    const int got = ::fcntl(pipe.write_fd, F_GETPIPE_SZ);
    pipe.capacity = got > 0 ? static_cast<size_t>(got) : kFallbackPipeCapacity;
  };
  size_pipe(u2d_);
  size_pipe(d2u_);

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
  if (events & Event::FileReadyType::Closed) {
    up_closed_ = true;
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
  if (events & Event::FileReadyType::Closed) {
    down_closed_ = true;
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
  // Reset each pass. Set true only by a real upstream EAGAIN below, so completion can tell "the
  // upstream is drained right now" from a stale cross-pass readiness latch.
  up_eagain_this_pass_ = false;
  // Assume both sockets are writable at the start of every pass and let an actual splice/write
  // EAGAIN re-clear the latch within the pass. The cross-pass writable latches otherwise sit
  // stale-false after a transient EAGAIN while the socket is in fact writable (Send-Q drained to
  // empty), with no further EPOLLOUT edge to re-arm them because the socket never went un-writable
  // at the epoll level. That deadlocks a pump that still has buffered upload to push to the
  // upstream (and the symmetric download case): d2u stays full, the downstream read stalls, and the
  // peer close is never seen. Re-testing each pass costs at most one extra EAGAIN syscall under
  // genuine backpressure.
  up_writable_ = true;
  down_writable_ = true;
  // SPLICE_F_MOVE is advisory. SPLICE_F_MORE is added per direction on the pipe->socket drains when
  // more bytes are still expected from that direction's source, so the kernel keeps the open TCP
  // segment (plaintext downstream) or the open TLS record (kTLS-TX upstream) un-flushed and
  // coalesces up to a full segment / 16 KiB record instead of emitting a runt at every pipe-drain
  // boundary. It is cleared on the final drains (source exhausted or byte budget met) so the tail
  // flushes immediately with no cork latency. Refills (socket->pipe) never set it. Mirrors OSD's
  // `will_transfer_more`.
  const unsigned base_flags = SPLICE_F_NONBLOCK | SPLICE_F_MOVE;
  int control_records = 0;
  bool progress = true;
  while (progress) {
    progress = false;

    // More body still expected toward each sink, used to drive SPLICE_F_MORE on this pass's drains.
    // SPLICE_F_MORE is set ONLY in bounded mode (the L7 body-splice), where the Content-Length
    // budget makes "more is coming" exact and the final drain provably clears it. The unbounded L4
    // pass-through has no end-of-message signal (a keep-alive upstream never EOFs), so leaving MORE
    // set would cork every response's final segment for ~200 ms (a latency regression for tunneled
    // request/response protocols), there it stays unset, exactly as before this fast path.
    const bool u2d_more_expected =
        bounded_ && u2d_limit_.has_value() && u2d_read_ < u2d_limit_.value();
    const bool d2u_more_expected =
        bounded_ && d2u_limit_.has_value() && d2u_read_ < d2u_limit_.value();
    const unsigned u2d_out_flags = base_flags | (u2d_more_expected ? SPLICE_F_MORE : 0u);
    const unsigned d2u_out_flags = base_flags | (d2u_more_expected ? SPLICE_F_MORE : 0u);

    // (1a) Flush any stashed pre-engage chunk to downstream FIRST (ordering: it precedes u2d).
    while (down_writable_ && pending_down_off_ < pending_down_.size()) {
      const ssize_t w = ::write(down_fd_, pending_down_.data() + pending_down_off_,
                                pending_down_.size() - pending_down_off_);
      if (w > 0) {
        pending_down_off_ += static_cast<size_t>(w);
        on_u2d_bytes_(static_cast<uint64_t>(w));
        progress = true;
      } else if (w == 0) {
        complete(SpliceCompletion::Closed);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        down_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        complete(SpliceCompletion::Closed);
        return;
      }
    }

    // (1b) Drain u2d pipe -> downstream socket (only after the stashed chunk is fully delivered).
    while (down_writable_ && u2d_.in_pipe > 0 && pending_down_off_ >= pending_down_.size()) {
      const ssize_t n =
          ::splice(u2d_.read_fd, nullptr, down_fd_, nullptr, u2d_.in_pipe, u2d_out_flags);
      if (n > 0) {
        u2d_.in_pipe -= static_cast<size_t>(n);
        on_u2d_bytes_(static_cast<uint64_t>(n));
        progress = true;
      } else if (n == 0) {
        complete(SpliceCompletion::Closed);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        down_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump u2d downstream write error, {}", std::strerror(errno));
        complete(SpliceCompletion::Closed);
        return;
      }
    }

    // (2) Fill u2d pipe <- upstream kTLS socket (read the decrypted download body). In bounded mode
    // this direction is read only while it has a byte budget left, and never beyond it, so the next
    // keep-alive message stays in the socket. An inactive direction (no limit) is skipped entirely.
    while (up_readable_ && !up_read_eof_ && u2d_.in_pipe < u2d_.capacity &&
           (!bounded_ || (u2d_limit_.has_value() && u2d_read_ < u2d_limit_.value()))) {
      size_t want = u2d_.capacity - u2d_.in_pipe;
      if (bounded_) {
        want = std::min(want, static_cast<size_t>(u2d_limit_.value() - u2d_read_));
      }
      const ssize_t n = ::splice(up_fd_, nullptr, u2d_.write_fd, nullptr, want, base_flags);
      if (n > 0) {
        u2d_.in_pipe += static_cast<size_t>(n);
        u2d_read_ += static_cast<uint64_t>(n);
        progress = true;
      } else if (n == 0) {
        up_read_eof_ = true;
        break;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // EAGAIN reading the source is only authoritative ("the upstream RX is empty right now")
        // when the pipe still had room, i.e. the read failed because the socket is drained, not
        // because the destination pipe is full. Pipe capacity is slot-accounted (one page slot per
        // spliced skb), so a pipe can be slot-full while in_pipe (bytes) is below capacity, or our
        // capacity estimate can be stale; in that case the EAGAIN means pipe-full, not
        // socket-empty, and claiming the source is drained (or, with EPOLLRDHUP latched, EOF) would
        // stall the tail or truncate a valid response. Only make the authoritative claim when the
        // pipe is empty; otherwise stop reading this pass and let the next pipe drain re-attempt
        // with the latch still set. (HAProxy raw_sock.c uses the same in_pipe>0 => pipe-full
        // disambiguation.)
        if (u2d_.in_pipe == 0) {
          up_readable_ = false;
          up_eagain_this_pass_ = true;
          // A prior Closed event (EPOLLRDHUP) plus a drained read side is the real EOF; splice() on
          // a half-closed socket returns EAGAIN, never 0, so this is the only way we learn it
          // closed.
          if (up_closed_) {
            up_read_eof_ = true;
          }
        }
        break;
      } else if (errno == EINTR) {
        continue;
      } else if (errno == EINVAL && up_is_ktls_) {
        if (drainUpstreamControlMessage()) {
          if (++control_records > kMaxControlRecordsPerPass) {
            ENVOY_LOG(debug, "splice pump too many kTLS control records, closing");
            complete(SpliceCompletion::Closed);
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
        complete(SpliceCompletion::Closed);
        return;
      }
    }

    // (3a) Flush any stashed pre-engage upstream-bound chunk FIRST so the request and upload body
    // leave in order, ahead of any d2u pipe bytes.
    while (up_writable_ && pending_up_off_ < pending_up_.size()) {
      const ssize_t w = ::write(up_fd_, pending_up_.data() + pending_up_off_,
                                pending_up_.size() - pending_up_off_);
      if (w > 0) {
        pending_up_off_ += static_cast<size_t>(w);
        on_d2u_bytes_(static_cast<uint64_t>(w));
        progress = true;
      } else if (w == 0) {
        complete(SpliceCompletion::Closed);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        up_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        complete(SpliceCompletion::Closed);
        return;
      }
    }

    // (3b) Drain d2u pipe -> upstream kTLS socket (the request and upload body). splice() into the
    // kTLS-TX socket encrypts in-kernel and the kernel frames the spliced bytes into TLS records.
    // Only after the stashed chunk is fully delivered, so ordering holds.
    while (up_writable_ && d2u_.in_pipe > 0 && pending_up_off_ >= pending_up_.size()) {
      const ssize_t n =
          ::splice(d2u_.read_fd, nullptr, up_fd_, nullptr, d2u_.in_pipe, d2u_out_flags);
      if (n > 0) {
        d2u_.in_pipe -= static_cast<size_t>(n);
        on_d2u_bytes_(static_cast<uint64_t>(n));
        progress = true;
      } else if (n == 0) {
        complete(SpliceCompletion::Closed);
        return;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        up_writable_ = false;
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump d2u upstream write error, {}", std::strerror(errno));
        complete(SpliceCompletion::Closed);
        return;
      }
    }

    // (4) Fill d2u pipe <- downstream socket (read the plaintext request and upload body), only
    // after draining toward the upstream so the bounded pipe releases backpressure first. In
    // bounded mode this direction is read only while it has a byte budget left, and never beyond
    // it; an inactive direction (no limit) is skipped so the next request stays in the downstream
    // socket.
    while (down_readable_ && !down_read_eof_ && d2u_.in_pipe < d2u_.capacity &&
           (!bounded_ || (d2u_limit_.has_value() && d2u_read_ < d2u_limit_.value()))) {
      size_t want = d2u_.capacity - d2u_.in_pipe;
      if (bounded_) {
        want = std::min(want, static_cast<size_t>(d2u_limit_.value() - d2u_read_));
      }
      const ssize_t n = ::splice(down_fd_, nullptr, d2u_.write_fd, nullptr, want, base_flags);
      if (n > 0) {
        d2u_.in_pipe += static_cast<size_t>(n);
        d2u_read_ += static_cast<uint64_t>(n);
        progress = true;
      } else if (n == 0) {
        down_read_eof_ = true;
        // The client closed its send side. A keep-alive upstream (S3) never sends EOF, so
        // completion for this connection will rely on an authoritative upstream drain. If the
        // up_readable_ latch is stale-false from an earlier pass, section (2) would be skipped and
        // we could either leak (never confirm the upstream is empty) or truncate (complete while
        // bytes sit unread). Re-arm the upstream read and loop once more so section (2) runs,
        // delivers any buffered response, and then observes a real EAGAIN or EOF.
        if (!up_read_eof_ && !up_readable_) {
          up_readable_ = true;
          progress = true;
        }
        break;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // EAGAIN here is authoritative ("client send side drained") only when the d2u pipe had
        // room; a full pipe (slot- or byte-full) also yields EAGAIN and must not be read as
        // socket-empty or promoted to EOF, or a slow/large upload would false-truncate. Only act
        // when the pipe is empty; otherwise stop reading this pass and let the next pipe drain
        // re-attempt with the latch still set. (Same in_pipe>0 => pipe-full disambiguation as
        // section (2).)
        if (d2u_.in_pipe == 0) {
          down_readable_ = false;
          // A prior Closed event (EPOLLRDHUP) plus a drained read side is the real client EOF.
          // splice() on a half-closed socket returns EAGAIN, not 0, so without this the pump never
          // learns the client closed and leaks the connection under keep-alive churn. Re-arm the
          // upstream read so section (2) performs a final authoritative drain (delivering any
          // buffered response) before completion gates on it, exactly as the n==0 arm does.
          if (down_closed_ && !down_read_eof_) {
            down_read_eof_ = true;
            if (!up_read_eof_ && !up_readable_) {
              up_readable_ = true;
              progress = true;
            }
          }
        }
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        ENVOY_LOG(debug, "splice pump d2u downstream read error, {}", std::strerror(errno));
        complete(SpliceCompletion::Closed);
        return;
      }
    }
  }
  maybeHalfCloseOrComplete();
}

bool SplicePump::drainUpstreamControlMessage() {
  // splice() cannot deliver a non-DATA TLS record into a pipe, so consume it with recvmsg() and
  // read its type from the TLS_GET_RECORD_TYPE control message.
  uint8_t buf[kMaxTlsRecordSize];
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
      up_eagain_this_pass_ = true; // upstream RX is empty right now, authoritative for completion
      return false;
    }
    ENVOY_LOG(debug, "splice pump kTLS control recvmsg error, {}", std::strerror(errno));
    complete(SpliceCompletion::Closed);
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
    complete(SpliceCompletion::Closed);
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
      ENVOY_LOG(debug, "splice pump upstream fatal TLS alert level {} desc {}", buf[0],
                n >= 2 ? buf[1] : 0xFF);
    } else {
      ENVOY_LOG(debug, "splice pump closing on TLS record type {}", record_type);
    }
    complete(SpliceCompletion::Closed);
    return false;
  }
  return false; // all ControlActions are handled above
}

bool SplicePump::upstreamHasExtraneousData() {
  // Peek (consume nothing) for one application-data byte. A queued control record yields EINVAL/EIO
  // (no cmsg buffer supplied) and an empty RX yields EAGAIN, both mean "no extraneous DATA". Only
  // a successful peek of >0 bytes is a real post-Content-Length data record.
  uint8_t b;
  ssize_t n;
  do {
    n = ::recv(up_fd_, &b, 1, MSG_PEEK | MSG_DONTWAIT);
  } while (n < 0 && errno == EINTR);
  return n > 0;
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
  if (bounded_) {
    // Bounded mode never half-closes. A source EOF before the byte budget is met is a truncated
    // message, so the connection cannot be reused.
    if ((u2d_limit_.has_value() && up_read_eof_ && u2d_read_ < u2d_limit_.value()) ||
        (d2u_limit_.has_value() && down_read_eof_ && d2u_read_ < d2u_limit_.value())) {
      complete(SpliceCompletion::Closed);
      return;
    }
    // A direction is done when it is inactive, or it has read its full budget and flushed both the
    // pre-engage chunk and the pipe to its destination. The sockets are left intact for the caller
    // to resume the codecs once every active direction is done.
    const bool u2d_done =
        !u2d_limit_.has_value() || (u2d_read_ >= u2d_limit_.value() && u2d_.in_pipe == 0 &&
                                    pending_down_off_ >= pending_down_.size());
    const bool d2u_done =
        !d2u_limit_.has_value() || (d2u_read_ >= d2u_limit_.value() && d2u_.in_pipe == 0 &&
                                    pending_up_off_ >= pending_up_.size());
    if (u2d_done && d2u_done) {
      // A bounded download leaves the upstream connection for keep-alive reuse, so it must hold no
      // bytes past the Content-Length boundary. The normal H1 client codec rejects "extraneous data
      // after response complete" and closes the connection; the splice skipped the codec, so prove
      // the same invariant here. A trusted-but-misbehaving (or compromised) upstream that sent more
      // than Content-Length would otherwise leave a crafted response queued on a pooled connection
      // that a different downstream client then reuses, cross-client response smuggling. Only a
      // peeked DATA record counts as extraneous; a queued control record (e.g. a NewSessionTicket,
      // which S3/s2n sends) is benign and the rustls socket drains it on the next read.
      if (u2d_limit_.has_value() && upstreamHasExtraneousData()) {
        ENVOY_LOG(debug, "splice pump: extraneous upstream data past Content-Length, not reusable");
        complete(SpliceCompletion::Closed);
        return;
      }
      complete(SpliceCompletion::BoundsReached);
    }
    return;
  }
  const bool u2d_drained =
      up_read_eof_ && u2d_.in_pipe == 0 && pending_down_off_ >= pending_down_.size();
  const bool d2u_drained =
      down_read_eof_ && d2u_.in_pipe == 0 && pending_up_off_ >= pending_up_.size();
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
    complete(SpliceCompletion::Closed);
    return;
  }
  // Upstream finished: it sent a real EOF or close_notify (u2d_drained requires up_read_eof_) and
  // its full response has been delivered downstream. A kTLS upstream that closed its send side
  // cannot carry another keep-alive request, so the exchange is over even if the client has not
  // closed its own write side. Without this arm a keep-alive client that received its response but
  // left the connection open (returned it to its pool) keeps d2u_drained false forever, so neither
  // the both-drained path above nor the client-close path below fires, and the pump holds both
  // sockets and the two pipes until the worker recycles. This is the dominant leak under PUT churn.
  // Require the upload side to be quiescent first (nothing in the d2u pipe and the pre-engage
  // upload fully flushed), so an in-flight upload still draining toward the upstream is not
  // truncated on a half-duplex tunnel.
  if (u2d_drained && down_write_shutdown_ && d2u_.in_pipe == 0 &&
      pending_up_off_ >= pending_up_.size()) {
    complete(SpliceCompletion::Closed);
    return;
  }
  // The client closed its send side (d2u_drained), the request was fully relayed, and the upstream
  // write was half-closed. A keep-alive upstream such as S3 does not send EOF, so waiting for
  // up_read_eof_ would hold both sockets and the two pipes open forever. We complete only once the
  // upstream has been AUTHORITATIVELY drained this pass (up_eagain_this_pass_, a real EAGAIN
  // observed now), never off the cross-pass up_readable_ latch whose false value can be stale and
  // does not prove the RX buffer is empty. Completing off the stale latch would close the upstream
  // NoFlush while response bytes still sit unread and truncate them. The section (4) EOF arm
  // re-arms up_readable_ so the pump performs that final authoritative drain (delivering any
  // buffered response downstream) before reaching here.
  if (d2u_drained && up_write_shutdown_ && up_eagain_this_pass_ && u2d_.in_pipe == 0 &&
      pending_down_off_ >= pending_down_.size()) {
    complete(SpliceCompletion::Closed);
  }
}

void SplicePump::complete(SpliceCompletion status) {
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
  on_complete_(status);
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
bool SplicePump::createPipes(bool, bool) { return false; }
bool SplicePump::prepare(std::string, std::string) { return false; }
void SplicePump::setBounds(absl::optional<uint64_t>, absl::optional<uint64_t>) {}
void SplicePump::arm() {}
absl::Status SplicePump::onUpReady(uint32_t) { return absl::OkStatus(); }
absl::Status SplicePump::onDownReady(uint32_t) { return absl::OkStatus(); }
void SplicePump::pump() {}
bool SplicePump::drainUpstreamControlMessage() { return false; }
bool SplicePump::upstreamHasExtraneousData() { return false; }
void SplicePump::sendUpstreamCloseNotify() {}
void SplicePump::maybeHalfCloseOrComplete() {}
void SplicePump::complete(SpliceCompletion) {}

#endif

} // namespace TcpProxy
} // namespace Envoy
