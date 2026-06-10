#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/platform.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/file_event.h"
#include "envoy/network/connection.h"

#include "source/common/common/logger.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace TcpProxy {

// What to do with a non-DATA kTLS record drained from the upstream socket.
enum class ControlAction {
  Retry, // benign record consumed (NewSessionTicket or ChangeCipherSpec), retry the splice
  Eof,   // peer sent close_notify, treat the upstream read as EOF
  Close, // fatal alert or unsupported record, tear the splice down
};

// Terminal outcome reported once through the SplicePump completion callback.
enum class SpliceCompletion {
  // A bounded transfer moved exactly the configured byte budget in every active direction. The
  // borrowed sockets are intact and can carry the next keep-alive message, so the caller resumes
  // the codecs rather than closing.
  BoundsReached,
  // The transfer ended because a peer closed or half-closed, an unbounded pump ran a socket to EOF,
  // or an error occurred. The sockets must not be reused.
  Closed,
};

// Classifies a non-DATA TLS record by its record type and bytes. Pure so it can be unit-tested
// without a kTLS socket. `data` and `len` are the decrypted record payload from recvmsg(). Exposed
// here for unit testing.
ControlAction classifyKtlsControlRecord(uint8_t record_type, const uint8_t* data, size_t len);

// Kernel splice() pump for the TCP proxy L4 fast-path. It moves bytes between a downstream
// plaintext socket and an upstream kernel-TLS (kTLS) socket entirely in-kernel through two Unix
// pipes, bypassing Envoy's userspace buffers and filter chain. Crypto stays in the kernel on the
// upstream leg and plaintext never reaches userspace, which removes the per-byte copy, the
// WatermarkBuffer and the filter-chain traversal that the buffered path pays.
//
// Ported from OSD's zerocopy-proxy `transfer.rs`. The two socket fds are borrowed. They stay owned
// and closed by their ConnectionImpls, and the pump owns only its pipes and FileEvents and never
// closes the sockets. Init has two phases. prepare() creates the pipes (unless the caller already
// made them via createPipes()) and queues the pre-engage chunk and can fail, so the caller runs it
// before detaching the ConnectionImpl FileEvents and a failure leaves the connection on the
// buffered path. arm() then installs the pump's FileEvents.
//
// The FileEvents are edge-triggered. Each wakeup drains every ready direction to EAGAIN and
// returns without blocking, which keeps the worker watchdog happy. Completion is delivered
// synchronously through on_complete_ while the owning Filter is alive, and that Filter defers its
// own teardown.
class SplicePump : public Logger::Loggable<Logger::Id::filter> {
public:
  using CompletionCb = std::function<void(SpliceCompletion)>;
  using BytesCb = std::function<void(uint64_t)>;

  SplicePump(os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls, Event::Dispatcher& dispatcher,
             CompletionCb on_complete, BytesCb on_upstream_to_downstream,
             BytesCb on_downstream_to_upstream);
  // The setup methods below and the destructor are virtual so the L7 body-splice coordinator's
  // unit test can substitute a no-op test double through its pump factory and drive completion
  // deterministically without a real kernel splice. They run once per splice at setup, never per
  // byte, so the virtual dispatch has no effect on the throughput hot path.
  virtual ~SplicePump();

  // Optional pre-step for callers (the L7 body-splice coordinator) that must create the pipes
  // BEFORE doing anything irreversible, the coordinator extracts the sink connection's pending
  // write to hand to prepare(), so a pipe2() failure must be observable while the buffered-path
  // fallback is still available. Creates only the requested directions (the bounded body-splice
  // uses one), and is idempotent: prepare() lazily creates both directions only if neither exists.
  // Returns false on pipe2() failure. The L4 path and tests skip this and call prepare() directly.
  virtual bool createPipes(bool need_u2d, bool need_d2u);
  // Phase 1, called before detaching the ConnectionImpl FileEvents. Creates the pipes (if not
  // already created via createPipes) and queues the pre-engage chunks the buffered path already
  // read just before engage, so they precede any spliced bytes and ordering is preserved.
  // `initial_u2d` is the decrypted upstream chunk bound for the downstream socket (the download
  // engage, e.g. a GET response). `initial_d2u` is the downstream chunk bound for the upstream
  // socket (the upload engage, e.g. a PUT body); exactly one is non-empty per engage. Returns false
  // only on unrecoverable setup failure such as pipe creation, in which case the caller must not
  // detach and should re-deliver on the buffered path.
  virtual bool prepare(std::string initial_u2d, std::string initial_d2u);
  // Switches the pump into bounded mode. Called between prepare() and arm(). Each direction with a
  // byte limit moves exactly that many bytes read from its source socket, then the pump completes
  // with SpliceCompletion::BoundsReached and leaves both sockets intact for keep-alive reuse. A
  // direction with absl::nullopt is inactive and its source socket is never read, so the bytes of
  // the next message stay queued for the codec. The limits count bytes read from the source socket
  // and exclude any pre-engage chunk handed to prepare(), which is delivered and accounted
  // separately. The HTTP body-splice runs one direction at a time (a response body up to down, or a
  // request body down to up), so exactly one limit is set per engage.
  virtual void setBounds(absl::optional<uint64_t> u2d_limit, absl::optional<uint64_t> d2u_limit);
  // Phase 2, called after detaching the ConnectionImpl FileEvents. Installs the pump's FileEvents
  // and primes the first pass.
  virtual void arm();

private:
  struct Pipe {
    int read_fd{-1};
    int write_fd{-1};
    size_t in_pipe{0};
    size_t capacity{0};
  };

  absl::Status onDownReady(uint32_t events);
  absl::Status onUpReady(uint32_t events);
  void pump();
  bool drainUpstreamControlMessage();
  // MSG_PEEK the upstream socket on bounded-download completion: returns true iff a DATA record is
  // queued past the Content-Length boundary (which makes the connection unsafe to pool-reuse). A
  // queued control record (NewSessionTicket / alert) peeks as an error and is treated as benign.
  bool upstreamHasExtraneousData();
  void sendUpstreamCloseNotify();
  void maybeHalfCloseOrComplete();
  void complete(SpliceCompletion status);

  const os_fd_t down_fd_;
  const os_fd_t up_fd_;
  const bool up_is_ktls_;
  Event::Dispatcher& dispatcher_;
  CompletionCb on_complete_;
  BytesCb on_u2d_bytes_;
  BytesCb on_d2u_bytes_;

  // Bounded-mode state (HTTP body-splice). bounded_ is set by setBounds(). Each limit, when
  // present, caps the bytes read from that direction's source socket so the splice stops exactly on
  // the Content-Length boundary and the next keep-alive message stays in the socket. The *_read_
  // counters track bytes already read from each source.
  bool bounded_{false};
  absl::optional<uint64_t> u2d_limit_;
  absl::optional<uint64_t> d2u_limit_;
  uint64_t u2d_read_{0};
  uint64_t d2u_read_{0};

  Pipe u2d_; // upstream to downstream, the download body, moved in-kernel by splice
  // The downstream-to-upstream direction (request and upload body) is also moved in-kernel by
  // splice through its own pipe. splice() into a kTLS-TX socket on a modern kernel (verified on
  // 6.17, matching OSD's zerocopy proxy) frames TLS records correctly, the kernel auto-chunks the
  // spliced bytes into 16 KiB application-data records, so the upload gets the same zero-copy
  // treatment as the download rather than a per-byte userspace copy.
  Pipe d2u_;
  Event::FileEventPtr up_file_event_;
  Event::FileEventPtr down_file_event_;

  // The pre-engage decrypted chunk that did not fit the downstream socket send buffer at prepare()
  // time. It flushes to down_fd_ ahead of any u2d pipe bytes as the socket drains. It can exceed
  // the pipe capacity, so it is held here rather than routed through the pipe.
  std::string pending_down_;
  size_t pending_down_off_{0};
  // Symmetric to pending_down_ for the upload direction. The pre-engage downstream chunk that did
  // not fit the upstream socket send buffer at prepare() time. It flushes to up_fd_ ahead of any
  // d2u pipe bytes so the request and upload body leave in order.
  std::string pending_up_;
  size_t pending_up_off_{0};

  // Readiness latches set by FileEvents and cleared on EAGAIN, mirroring transfer.rs loop state.
  bool up_readable_{false};
  bool up_writable_{false};
  bool down_readable_{false};
  bool down_writable_{false};
  bool up_read_eof_{false};
  bool down_read_eof_{false};
  bool down_write_shutdown_{false};
  bool up_write_shutdown_{false};
  bool completed_{false};
  // True only when the current pump() pass observed a real EAGAIN reading the upstream, proving the
  // upstream RX buffer is drained right now. Reset at the top of every pass. Completion on the
  // keep-alive path gates on THIS rather than the cross-pass up_readable_ latch, whose false value
  // can be stale from an earlier pass and does not prove the socket is empty. Gating completion on
  // a stale latch would close the upstream with NoFlush while response bytes still sit unread and
  // truncate them.
  bool up_eagain_this_pass_{false};
  // Set when the FileEvent reports Closed (EPOLLRDHUP), i.e. the peer half-closed its write side.
  // splice() from a half-closed TCP socket returns EAGAIN, not 0, so it never surfaces the EOF the
  // way read() would. We therefore treat a Closed event plus a subsequent read EAGAIN (read side
  // fully drained) as the authoritative read-EOF, instead of waiting for a splice() 0 that a
  // half-closed socket never delivers. Without this the pump never learns the peer closed and leaks
  // the connection under keep-alive churn.
  bool down_closed_{false};
  bool up_closed_{false};
};

using SplicePumpPtr = std::unique_ptr<SplicePump>;

} // namespace TcpProxy
} // namespace Envoy
