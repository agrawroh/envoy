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

namespace Envoy {
namespace TcpProxy {

// What to do with a non-DATA kTLS record drained from the upstream socket.
enum class ControlAction {
  Retry, // benign record consumed (NewSessionTicket or ChangeCipherSpec), retry the splice
  Eof,   // peer sent close_notify, treat the upstream read as EOF
  Close, // fatal alert or unsupported record, tear the splice down
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
// closes the sockets. Init has two phases. prepare() creates the pipes and queues the pre-engage
// chunk and can fail, so the caller runs it before detaching the ConnectionImpl FileEvents and a
// failure leaves the connection on the buffered path. arm() then installs the pump's FileEvents.
//
// The FileEvents are edge-triggered. Each wakeup drains every ready direction to EAGAIN and
// returns without blocking, which keeps the worker watchdog happy. Completion is delivered
// synchronously through on_complete_ while the owning Filter is alive, and that Filter defers its
// own teardown.
class SplicePump : public Logger::Loggable<Logger::Id::filter> {
public:
  using CompletionCb = std::function<void(Network::ConnectionEvent)>;
  using BytesCb = std::function<void(uint64_t)>;

  SplicePump(os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls, Event::Dispatcher& dispatcher,
             CompletionCb on_complete, BytesCb on_upstream_to_downstream,
             BytesCb on_downstream_to_upstream);
  ~SplicePump();

  // Phase 1, called before detaching the ConnectionImpl FileEvents. Creates the pipes and queues
  // `initial_downstream_data`, the already-decrypted upstream chunk the buffered path read just
  // before engage, for delivery to the downstream socket ahead of any spliced bytes. Returns false
  // only on unrecoverable setup failure such as pipe creation, in which case the caller must not
  // detach and should re-deliver the chunk on the buffered path.
  bool prepare(std::string initial_downstream_data);
  // Phase 2, called after detaching the ConnectionImpl FileEvents. Installs the pump's FileEvents
  // and primes the first pass.
  void arm();

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
  void sendUpstreamCloseNotify();
  void maybeHalfCloseOrComplete();
  void complete(Network::ConnectionEvent event);

  const os_fd_t down_fd_;
  const os_fd_t up_fd_;
  const bool up_is_ktls_;
  Event::Dispatcher& dispatcher_;
  CompletionCb on_complete_;
  BytesCb on_u2d_bytes_;
  BytesCb on_d2u_bytes_;

  Pipe u2d_; // upstream to downstream, the download bulk, moved in-kernel by splice
  // The downstream-to-upstream direction (request or upload) is copied through userspace rather
  // than spliced. It is the small direction, and write() into a kTLS-TX socket uses the kernel
  // sendmsg path that frames TLS records correctly, whereas splice() into kTLS-TX (sendpage)
  // misframes on some kernels. This mirrors OSD's zerocopy proxy, which reads requests in
  // userspace and splices only the response body.
  std::vector<char> d2u_buf_;
  size_t d2u_len_{0}; // valid bytes currently in d2u_buf_
  size_t d2u_off_{0}; // bytes of d2u_buf_ already written to the upstream socket
  Event::FileEventPtr up_file_event_;
  Event::FileEventPtr down_file_event_;

  // The pre-engage decrypted chunk that did not fit the downstream socket send buffer at prepare()
  // time. It flushes to down_fd_ ahead of any u2d pipe bytes as the socket drains. It can exceed
  // the pipe capacity, so it is held here rather than routed through the pipe.
  std::string pending_down_;
  size_t pending_down_off_{0};

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
};

using SplicePumpPtr = std::unique_ptr<SplicePump>;

} // namespace TcpProxy
} // namespace Envoy
