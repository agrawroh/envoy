#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/optref.h"
#include "envoy/event/schedulable_cb.h"
#include "envoy/event/timer.h"
#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/tcp_proxy/splice_pump.h"

namespace Envoy {
namespace Router {

class UpstreamRequest;

// Drives the L7 HTTP/1.1 kTLS body-splice fast path for a single message on behalf of its owning
// UpstreamRequest, in either direction:
//   - Download: a Content-Length response body is relayed from the kTLS upstream socket to the
//     downstream socket.
//   - Upload: a Content-Length request body is relayed from the downstream socket to the kTLS-TX
//     upstream socket (the kernel frames the TLS records on write).
// In both cases an in-kernel splice (TcpProxy::SplicePump in bounded mode) bypasses Envoy's
// userspace buffers and the encoder/decoder filter chains. The splice is bounded to the
// Content-Length so both sockets stay intact for the next keep-alive message; on truncation or
// error the coordinator resets the stream and never reuses the connections.
//
// Because the body bypasses the filter chain, the runtime feature that gates this path must not be
// enabled alongside filters that transform the body (e.g. compression), which would otherwise see
// headers describe a body the peer never receives in that form.
//
// Engage and finalize are both deferred onto schedulable callbacks. While armed but not yet engaged
// the coordinator holds back the body (rather than forwarding it to the sink codec) so the sink's
// write buffer carries only the headers; engage then emits the held body ahead of the spliced
// remainder, keeping the sink off its write high watermark so the splice engages reliably. The held
// body is bounded by MaxHeldBodyBytes; past that the coordinator falls back to the buffered path.
// The upload additionally polls at engage until the upstream connection is ready and its kTLS-TX is
// installed, which both complete only after the request headers are written. Finalize runs once the
// SplicePump completion callback unwinds: the pump only disables its file events while inside one
// of them, so the borrowed sockets cannot be re-armed until the pump (and its epoll registrations)
// is destroyed.
class SpliceCoordinator : public Logger::Loggable<Logger::Id::router> {
public:
  explicit SpliceCoordinator(UpstreamRequest& upstream_request);
  ~SpliceCoordinator();

  // Direction of the body relayed by the splice.
  enum class Direction {
    Download, // Upstream (kTLS) -> downstream: a response body.
    Upload,   // Downstream -> upstream (kTLS-TX): a request body.
  };

  // Evaluates download-splice eligibility for the just-decoded response and records the
  // Content-Length when eligible. Returns true when the splice was armed; the caller must forward
  // the response headers downstream and then call scheduleEngage(). `end_stream` is the response
  // headers' end-of-stream flag.
  bool maybeArmForResponse(const Http::ResponseHeaderMap& headers, bool end_stream);

  // Evaluates upload-splice eligibility for the request being sent and records the Content-Length
  // when eligible. Returns true when the splice was armed; the caller must encode the request
  // headers upstream and then call scheduleEngage(). `end_stream` is the request headers'
  // end-of-stream flag (a body-less request is not eligible).
  bool maybeArmForRequest(const Http::RequestHeaderMap& headers, bool end_stream);

  // Schedules the deferred engage. Called after the headers have been encoded onto the sink leg, so
  // the engage runs once their write has been activated, with only the headers in the sink write
  // buffer.
  void scheduleEngage();

  // Holds back body that arrives before the scheduled engage runs so it does not reach the sink
  // codec; engage emits it ahead of the spliced body. Returns true when the body was taken and the
  // caller must not forward it. Returns false when the message ends first or the held body exceeds
  // MaxHeldBodyBytes: any held body is flushed through the normal path, the splice is disarmed, and
  // the caller forwards the data. Called while armed but not yet engaged.
  bool bufferPreEngageBody(Buffer::Instance& data, bool end_stream);

  // Cancels a pending arm and tears down any in-flight splice. Safe to call repeatedly and from
  // UpstreamRequest teardown paths.
  void reset();

  // Direction-specific armed predicates. The response path (download) and request path (upload)
  // must each only intercept their own body, so an early response arriving while an upload is armed
  // (the upstream is not read-disabled) is never mistaken for request body.
  bool armedForResponse() const { return armed_ && direction_ == Direction::Download; }
  bool armedForRequest() const { return armed_ && direction_ == Direction::Upload; }
  bool engaged() const { return splice_pump_ != nullptr; }

private:
  // Minimum Content-Length worth splicing. Below this the in-kernel setup cost outweighs the saved
  // copies, and the body usually fits in the read that carried the headers anyway.
  static constexpr uint64_t MinSpliceBodyBytes = 64 * 1024;
  // Upper bound on body held in memory while waiting to engage. The download holds at most one
  // upstream read; the upload may hold more while it polls for the kTLS-TX install, so cap it and
  // fall back to the buffered path past this point rather than buffer without bound.
  static constexpr uint64_t MaxHeldBodyBytes = 4 * 1024 * 1024;
  // Defensive backstop on the upload's engage poll. The poll normally ends within a few iterations
  // (the request headers write triggers the kTLS-TX install) or via teardown; this bounds a stuck
  // upstream that handshakes but never installs.
  static constexpr uint32_t MaxEngagePolls = 64;

  void engage();
  void onSpliceComplete(TcpProxy::SpliceCompletion status);
  void finalize();
  void disarm();
  // Gives up an armed-but-not-engaged splice: flushes any held body, re-enables source reads
  // (upload), and disarms. Used by the engage bail-outs, the poll bound, and a message that ends
  // before engage.
  void abandon();
  // Reschedules engage on a short timer, up to MaxEngagePolls, while the upload waits for the
  // upstream connection and its kTLS-TX install. Abandons (falls back) past the bound. A timer
  // rather than a current/next-iteration callback so the poll spaces out across the upstream's
  // connect/handshake I/O rather than busy-looping.
  void rescheduleEngage();
  // Forwards any body held for an abandoned splice back through the normal path so the message
  // completes. Called when the message ends before engage or when engage bails out.
  void flushPreEngageBody();
  // Re-enables source reads if the upload read-disabled them at arm to hold the request body in the
  // kernel. No-op for the download (which never read-disables) and idempotent.
  void maybeReadEnableSource();
  // Destroys the pump and re-arms each borrowed leg that is still open, restoring Envoy-driven I/O
  // before the refs are cleared. Shared by finalize() (normal completion) and reset() (teardown) so
  // a mid-splice abort never leaves a connection detached.
  void releaseSplice();
  // The two legs the splice borrows, resolved through the owning request. Each returns an empty
  // OptRef unless its codec is a single, non-multiplexed HTTP/1.1 socket.
  OptRef<Network::Connection> upstreamConnection();
  OptRef<Network::Connection> downstreamConnection();

  UpstreamRequest& upstream_request_;
  Event::SchedulableCallbackPtr engage_callback_;
  Event::TimerPtr engage_poll_timer_;
  Event::SchedulableCallbackPtr finalize_callback_;
  TcpProxy::SplicePumpPtr splice_pump_;
  // The borrowed legs held while a splice is in flight so finalize() can re-arm their file events.
  OptRef<Network::Connection> upstream_connection_;
  OptRef<Network::Connection> downstream_connection_;
  uint64_t content_length_{0};
  // Body that arrived before engage, held back from the sink codec so it can be emitted ahead of
  // the spliced remainder. Bounded by MaxHeldBodyBytes, and moved into the pump at engage.
  Buffer::OwnedImpl pre_engage_body_;
  // Bytes the in-kernel splice itself relayed (Content-Length minus the held pre-engage body). The
  // source leg's wire meter already counts the held body via the codec's read accounting, so only
  // this remainder is added there on completion.
  uint64_t spliced_body_bytes_{0};
  TcpProxy::SpliceCompletion completion_status_{TcpProxy::SpliceCompletion::Closed};
  Direction direction_{Direction::Download};
  uint32_t engage_polls_{0};
  bool armed_{false};
  // True when the upload read-disabled the source to hold the request body in the kernel until
  // engage; cleared once reads are re-enabled.
  bool source_read_disabled_{false};
};

using SpliceCoordinatorPtr = std::unique_ptr<SpliceCoordinator>;

} // namespace Router
} // namespace Envoy
