#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/optref.h"
#include "envoy/event/schedulable_cb.h"
#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/tcp_proxy/splice_pump.h"

namespace Envoy {
namespace Router {

class UpstreamRequest;

// Drives the L7 HTTP/1.1 kTLS body-splice fast path for a single response on behalf of its owning
// UpstreamRequest. Once the response headers arrive, a Content-Length response body is relayed from
// the kTLS upstream socket to the downstream socket with an in-kernel splice (TcpProxy::SplicePump
// in bounded mode) that bypasses Envoy's userspace buffers and the encoder filter chain. The splice
// is bounded to the Content-Length so both sockets stay intact for the next keep-alive message; on
// truncation or error the coordinator resets the stream and never reuses the connections.
//
// Because the body bypasses the encoder filter chain, the runtime feature that gates this path must
// not be enabled alongside response filters that transform the body (e.g. compression), which would
// otherwise see headers describe a body the client never receives in that form.
//
// Engage and finalize are both deferred onto schedulable callbacks. While armed but not yet engaged
// the coordinator holds back the response body (rather than forwarding it to the downstream codec)
// so the downstream write buffer carries only the headers; engage then emits the held body ahead of
// the spliced remainder, keeping the downstream off its write high watermark so the splice engages
// reliably. Finalize runs after the SplicePump completion callback unwinds, because the pump only
// disables its file events while inside one of them; the borrowed sockets cannot be re-armed until
// the pump (and its epoll registrations) is destroyed.
class SpliceCoordinator : public Logger::Loggable<Logger::Id::router> {
public:
  explicit SpliceCoordinator(UpstreamRequest& upstream_request);
  ~SpliceCoordinator();

  // Evaluates download-splice eligibility for the just-decoded response and records the
  // Content-Length when eligible. Returns true when the splice was armed; the caller must forward
  // the response headers downstream and then call scheduleEngage(). `end_stream` is the response
  // headers' end-of-stream flag.
  bool maybeArmForResponse(const Http::ResponseHeaderMap& headers, bool end_stream);

  // Schedules the deferred engage. Called after the response headers have been encoded downstream,
  // so the engage runs once their write has been activated, with only the headers in the downstream
  // write buffer.
  void scheduleEngage();

  // Holds back response body that arrives before the scheduled engage runs so it does not reach the
  // downstream encoder; engage emits it ahead of the spliced body. Returns true when the body was
  // taken and the caller must not forward it. Returns false when the response ends first (the whole
  // body arrived before engage): any held body is flushed through the normal path, the splice is
  // disarmed, and the caller forwards the terminal chunk. Called from UpstreamRequest::decodeData
  // while armed but not yet engaged.
  bool bufferPreEngageResponseBody(Buffer::Instance& data, bool end_stream);

  // Cancels a pending arm and tears down any in-flight splice. Safe to call repeatedly and from
  // UpstreamRequest teardown paths.
  void reset();

  bool armed() const { return armed_; }
  bool engaged() const { return splice_pump_ != nullptr; }

private:
  // Minimum Content-Length worth splicing. Below this the in-kernel setup cost outweighs the saved
  // copies, and the body usually fits in the read that carried the headers anyway.
  static constexpr uint64_t MinSpliceBodyBytes = 64 * 1024;

  void engage();
  void onSpliceComplete(TcpProxy::SpliceCompletion status);
  void finalize();
  void disarm();
  // Forwards any body held for an abandoned splice back through the normal decode path so the
  // response still completes. Called when the response ends before engage or when engage bails out.
  void flushPreEngageBody();
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
  Event::SchedulableCallbackPtr finalize_callback_;
  TcpProxy::SplicePumpPtr splice_pump_;
  // The borrowed legs held while a splice is in flight so finalize() can re-arm their file events.
  OptRef<Network::Connection> upstream_connection_;
  OptRef<Network::Connection> downstream_connection_;
  uint64_t content_length_{0};
  // Response body that arrived before engage, held back from the downstream encoder so it can be
  // emitted ahead of the spliced remainder. Bounded by the upstream connection's read buffer limit
  // (engage runs before the next read is dispatched), and moved into the pump at engage.
  Buffer::OwnedImpl pre_engage_body_;
  // Bytes the in-kernel splice itself relayed (Content-Length minus the held pre-engage body). The
  // upstream wire-received meter already counts the held body via the codec's read accounting, so
  // only this remainder is added there on completion.
  uint64_t spliced_body_bytes_{0};
  TcpProxy::SpliceCompletion completion_status_{TcpProxy::SpliceCompletion::Closed};
  bool armed_{false};
};

using SpliceCoordinatorPtr = std::unique_ptr<SpliceCoordinator>;

} // namespace Router
} // namespace Envoy
