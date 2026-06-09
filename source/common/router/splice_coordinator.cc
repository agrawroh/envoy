#include "source/common/router/splice_coordinator.h"

#include "envoy/http/header_map.h"
#include "envoy/network/address.h"

#include "source/common/common/assert.h"
#include "source/common/router/router.h"
#include "source/common/router/upstream_request.h"
#include "source/common/runtime/runtime_features.h"

#include "absl/strings/numbers.h"

namespace Envoy {
namespace Router {

namespace {

// Returns the borrowable OS fd for a connection that backs the splice, or absl::nullopt if the
// connection is not a real, open OS socket (e.g. an internal-listener user-space IoHandle).
absl::optional<os_fd_t> spliceableFd(Network::Connection& connection) {
  if (connection.state() != Network::Connection::State::Open) {
    return absl::nullopt;
  }
  // An internal-listener connection has no kernel fd to splice on.
  if (connection.connectionInfoProvider().localAddress()->type() ==
      Network::Address::Type::EnvoyInternal) {
    return absl::nullopt;
  }
  const os_fd_t fd = connection.getSocket()->ioHandle().fdDoNotUse();
  if (fd == INVALID_SOCKET) {
    return absl::nullopt;
  }
  return fd;
}

} // namespace

SpliceCoordinator::SpliceCoordinator(UpstreamRequest& upstream_request)
    : upstream_request_(upstream_request) {}

SpliceCoordinator::~SpliceCoordinator() = default;

bool SpliceCoordinator::maybeArmForResponse(const Http::ResponseHeaderMap& headers,
                                            bool end_stream) {
  if (!Runtime::runtimeFeatureEnabled("envoy.reloadable_features.http1_ktls_body_splice")) {
    return false;
  }
  // A header-only response has no body to splice.
  if (end_stream) {
    return false;
  }
  // Only the request side that has finished encoding can hand its connection to the splice; a
  // download GET satisfies this by the time its response headers arrive.
  if (!upstream_request_.encodeComplete()) {
    return false;
  }
  // The body must be Content-Length framed and large enough to be worth the in-kernel setup. A
  // chunked or close-delimited body has no fixed boundary to bound the splice on.
  const Http::HeaderEntry* content_length_header = headers.ContentLength();
  if (content_length_header == nullptr) {
    return false;
  }
  uint64_t content_length = 0;
  if (!absl::SimpleAtoi(content_length_header->value().getStringView(), &content_length) ||
      content_length < MinSpliceBodyBytes) {
    return false;
  }
  // Both legs must be single, non-multiplexed HTTP/1.1 sockets.
  OptRef<Network::Connection> upstream = upstreamConnection();
  OptRef<Network::Connection> downstream = downstreamConnection();
  if (!upstream.has_value() || !downstream.has_value()) {
    return false;
  }
  // The upstream leg must have kernel TLS installed and be a trusted peer, so reads off its socket
  // yield decrypted plaintext that is safe to relay.
  OptRef<const Network::KtlsBytestreamInfo> ktls = upstream->ktlsBytestreamInfo();
  if (!ktls.has_value() || !ktls->installed || !ktls->trusted_peer) {
    return false;
  }
  // The downstream leg must be plaintext or kTLS, i.e. it must not run userspace TLS that the
  // splice would bypass. The rustls kTLS socket and a plaintext socket both report no ssl().
  if (downstream->ssl() != nullptr) {
    return false;
  }

  content_length_ = content_length;
  direction_ = Direction::Download;
  engage_polls_ = 0;
  armed_ = true;
  ENVOY_LOG(debug, "kTLS body-splice armed for {}-byte response body", content_length_);
  return true;
}

bool SpliceCoordinator::maybeArmForRequest(const Http::RequestHeaderMap& headers, bool end_stream) {
  if (!Runtime::runtimeFeatureEnabled("envoy.reloadable_features.http1_ktls_body_splice")) {
    return false;
  }
  // A body-less request has nothing to splice.
  if (end_stream) {
    return false;
  }
  // The body must be Content-Length framed and large enough to be worth the in-kernel setup. A
  // chunked or close-delimited body has no fixed boundary to bound the splice on.
  const Http::HeaderEntry* content_length_header = headers.ContentLength();
  if (content_length_header == nullptr) {
    return false;
  }
  uint64_t content_length = 0;
  if (!absl::SimpleAtoi(content_length_header->value().getStringView(), &content_length) ||
      content_length < MinSpliceBodyBytes) {
    return false;
  }
  // The downstream (source) leg must be a single, non-multiplexed HTTP/1.1 socket that is plaintext
  // or kTLS, i.e. not running userspace TLS the splice would bypass. The upstream (sink) leg is not
  // connected yet, so engage() polls for it and its kTLS-TX install.
  OptRef<Network::Connection> downstream = downstreamConnection();
  if (!downstream.has_value() || downstream->ssl() != nullptr) {
    return false;
  }

  content_length_ = content_length;
  direction_ = Direction::Upload;
  engage_polls_ = 0;
  armed_ = true;
  // Hold the request body in the kernel until engage by read-disabling the source. Without this the
  // body would flood Envoy's buffers before the upstream connects and installs kTLS-TX, exceeding
  // the hold bound and falling back; TCP flow control throttles the client while the body waits.
  // The already-read remainder of the headers' read still flows once, and is held in memory
  // (bounded).
  downstream->readDisable(true);
  source_read_disabled_ = true;
  ENVOY_LOG(debug, "kTLS body-splice armed for {}-byte request body", content_length_);
  return true;
}

void SpliceCoordinator::scheduleEngage() {
  if (!armed_) {
    return;
  }
  if (engage_callback_ == nullptr) {
    engage_callback_ =
        upstream_request_.parent_.callbacks()->dispatcher().createSchedulableCallback(
            [this]() { engage(); });
  }
  // Engage after the current upstream read unwinds, by which point the headers have been encoded
  // and any body in this read has been held back, so only the headers sit in the downstream buffer.
  engage_callback_->scheduleCallbackCurrentIteration();
}

bool SpliceCoordinator::bufferPreEngageBody(Buffer::Instance& data, bool end_stream) {
  ASSERT(armed_ && !engaged());
  // Stop holding when the message ends before engage (splicing buys nothing) or when holding more
  // would exceed the in-memory bound: abandon the splice and let the caller forward this data
  // through the normal path. The upload normally holds at most the headers' read since the source
  // is read-disabled at arm, so the bound here mainly guards the download.
  if (end_stream || pre_engage_body_.length() + data.length() > MaxHeldBodyBytes) {
    abandon();
    return false;
  }
  // Hold the body back from the sink codec; engage emits it ahead of the spliced remainder.
  pre_engage_body_.move(data);
  return true;
}

void SpliceCoordinator::disarm() {
  armed_ = false;
  if (engage_callback_ != nullptr) {
    engage_callback_->cancel();
  }
  if (engage_poll_timer_ != nullptr) {
    engage_poll_timer_->disableTimer();
  }
}

void SpliceCoordinator::abandon() {
  // Forward any held body, then re-enable source reads so the remainder flows through the normal
  // path, then disarm. Order matters: the held bytes must precede the resumed reads on the wire.
  flushPreEngageBody();
  maybeReadEnableSource();
  disarm();
}

void SpliceCoordinator::maybeReadEnableSource() {
  if (!source_read_disabled_) {
    return;
  }
  source_read_disabled_ = false;
  OptRef<Network::Connection> downstream = downstreamConnection();
  // readDisable() asserts the connection is open, so guard like the re-arm paths do; a closed
  // source is being torn down and needs no re-enable.
  if (downstream.has_value() && downstream->state() == Network::Connection::State::Open) {
    downstream->readDisable(false);
  }
}

void SpliceCoordinator::rescheduleEngage() {
  if (++engage_polls_ > MaxEngagePolls) {
    // The upstream is taking too long to ready or install kTLS-TX; fall back to the buffered path.
    ENVOY_LOG(debug, "kTLS body-splice skipped: upstream not ready after {} polls", engage_polls_);
    abandon();
    return;
  }
  if (engage_poll_timer_ == nullptr) {
    engage_poll_timer_ =
        upstream_request_.parent_.callbacks()->dispatcher().createTimer([this]() { engage(); });
  }
  // A short delay rather than next-iteration so the poll spaces out across the upstream's connect,
  // handshake, and kTLS-TX install I/O instead of busy-looping through the bound in microseconds.
  engage_poll_timer_->enableTimer(std::chrono::milliseconds(2));
}

void SpliceCoordinator::engage() {
  if (!armed_) {
    return;
  }

  OptRef<Network::Connection> upstream = upstreamConnection();
  OptRef<Network::Connection> downstream = downstreamConnection();

  // The upload's sink (upstream) connects and installs kTLS-TX only after the request headers are
  // written, so poll until both are ready; the download's legs are already settled at arm.
  if (direction_ == Direction::Upload) {
    if (!downstream.has_value()) {
      abandon();
      return;
    }
    if (!upstream.has_value()) {
      rescheduleEngage(); // Upstream pool not ready yet.
      return;
    }
    OptRef<const Network::KtlsBytestreamInfo> ktls = upstream->ktlsBytestreamInfo();
    if (!ktls.has_value()) {
      // Not a kTLS upstream; the splice cannot frame TLS records, so use the buffered path.
      abandon();
      return;
    }
    if (!ktls->installed || !ktls->trusted_peer) {
      rescheduleEngage(); // kTLS-TX still installing.
      return;
    }
  }

  armed_ = false;

  if (!upstream.has_value() || !downstream.has_value()) {
    ENVOY_LOG(debug, "kTLS body-splice skipped: a leg is no longer borrowable");
    abandon();
    return;
  }

  // The sink leg (where the splice writes) must not run userspace TLS the splice would bypass, and
  // the upstream leg must have kTLS installed and be a trusted peer. Any bail-out here flushes the
  // held body back through the normal path so the message still completes.
  const bool download = direction_ == Direction::Download;
  Network::Connection& sink = download ? downstream.ref() : upstream.ref();
  OptRef<const Network::KtlsBytestreamInfo> ktls = upstream->ktlsBytestreamInfo();
  if (!ktls.has_value() || !ktls->installed || !ktls->trusted_peer || sink.ssl() != nullptr) {
    abandon();
    return;
  }
  const absl::optional<os_fd_t> up_fd = spliceableFd(upstream.ref());
  const absl::optional<os_fd_t> down_fd = spliceableFd(downstream.ref());
  if (!up_fd.has_value() || !down_fd.has_value()) {
    abandon();
    return;
  }
  // If the whole body arrived before engage, there is nothing left to splice; deliver it normally.
  const uint64_t buffered = pre_engage_body_.length();
  if (buffered >= content_length_) {
    abandon();
    return;
  }
  spliced_body_bytes_ = content_length_ - buffered;

  auto pump = std::make_unique<TcpProxy::SplicePump>(
      down_fd.value(), up_fd.value(), /*up_is_ktls=*/true,
      upstream_request_.parent_.callbacks()->dispatcher(),
      [this](TcpProxy::SpliceCompletion status) { onSpliceComplete(status); },
      // Reset the per-try idle timer as bytes move so a long transfer does not trip the idle
      // timeout. The active direction's callback does the work; the other is inactive.
      [this](uint64_t) { upstream_request_.resetPerTryIdleTimer(); },
      [this](uint64_t) { upstream_request_.resetPerTryIdleTimer(); });
  // Hand the pump the sink's pending output (the encoded headers) followed by the body held before
  // engage, as the pre-engage chunk, so they precede the spliced body and wire order is preserved.
  // prepare() creates the pipes before emitting this chunk; on the rare pipe-creation failure the
  // taken bytes cannot be requeued, so reset rather than drop them and corrupt the message.
  std::string pre_engage = sink.extractPendingWriteForSplice();
  pre_engage += pre_engage_body_.toString();
  pre_engage_body_.drain(buffered);
  // The pre-engage chunk and the splice bound apply to the active direction: u2d for a download
  // (upstream -> downstream), d2u for an upload (downstream -> upstream).
  const bool ok = download ? pump->prepare(std::move(pre_engage), /*initial_d2u=*/"")
                           : pump->prepare(/*initial_u2d=*/"", std::move(pre_engage));
  if (!ok) {
    ENVOY_LOG(warn, "kTLS body-splice setup failed after taking pending output, resetting");
    upstream_request_.onResetStream(Http::StreamResetReason::ConnectionTermination,
                                    "kTLS body-splice setup failed");
    return;
  }
  if (download) {
    pump->setBounds(/*u2d_limit=*/spliced_body_bytes_, /*d2u_limit=*/absl::nullopt);
  } else {
    pump->setBounds(/*u2d_limit=*/absl::nullopt, /*d2u_limit=*/spliced_body_bytes_);
  }
  // Commit: remove both ConnectionImpl file events so the pump owns the only registration on each
  // fd, then arm it.
  upstream->getSocket()->ioHandle().resetFileEvents();
  downstream->getSocket()->ioHandle().resetFileEvents();
  upstream_connection_ = upstream;
  downstream_connection_ = downstream;
  splice_pump_ = std::move(pump);
  splice_pump_->arm();
  ENVOY_LOG(debug, "kTLS body-splice engaged: {} {} body bytes (down_fd={}, up_fd={})",
            spliced_body_bytes_, download ? "response" : "request", down_fd.value(), up_fd.value());
}

void SpliceCoordinator::flushPreEngageBody() {
  if (pre_engage_body_.length() == 0) {
    return;
  }
  // Forward the held body through the normal path so the message resumes; remaining body and the
  // terminal chunk follow once disarmed.
  if (direction_ == Direction::Download) {
    // Response body to the downstream encoder.
    upstream_request_.parent_.onUpstreamData(pre_engage_body_, upstream_request_, false);
  } else {
    // Request body to the upstream encoder via the upstream filter chain (the leg held it before
    // filter_manager_->decodeData in acceptDataFromRouter).
    upstream_request_.filter_manager_->decodeData(pre_engage_body_, false);
  }
}

void SpliceCoordinator::onSpliceComplete(TcpProxy::SpliceCompletion status) {
  // The pump only disables its file events before invoking this from within one of them, so the
  // pump cannot be destroyed nor the legs re-armed here. Defer that to finalize().
  completion_status_ = status;
  if (finalize_callback_ == nullptr) {
    finalize_callback_ =
        upstream_request_.parent_.callbacks()->dispatcher().createSchedulableCallback(
            [this]() { finalize(); });
  }
  finalize_callback_->scheduleCallbackCurrentIteration();
}

void SpliceCoordinator::finalize() {
  releaseSplice();

  if (completion_status_ != TcpProxy::SpliceCompletion::BoundsReached) {
    // A truncated or failed splice cannot be recovered: part of the body has already left for the
    // sink socket. Drive the upstream-reset machinery so the router resets the peer and defers
    // deletion of the UpstreamRequest, rather than reusing either connection. resetStream() alone
    // would only latch a flag without tearing the stream down.
    ENVOY_LOG(debug, "kTLS body-splice aborted before the Content-Length boundary, resetting");
    upstream_request_.onResetStream(Http::StreamResetReason::ConnectionTermination,
                                    "kTLS body-splice truncated before Content-Length");
    return;
  }

  // Account the body the splice carried. The sink codec emitted only the headers (the whole body
  // bypassed it via the pump), so the full Content-Length body is added to the sink's wire meter
  // and legacy counter here. The source side already counts the held pre-engage body through its
  // codec's read path, so only the spliced remainder is added there (in completeSpliced*).
  StreamInfo::StreamInfo& downstream_info = upstream_request_.parent_.callbacks()->streamInfo();
  ENVOY_LOG(debug, "kTLS body-splice complete: {} body bytes relayed", spliced_body_bytes_);
  if (direction_ == Direction::Download) {
    downstream_info.getDownstreamBytesMeter()->addWireBytesSent(content_length_);
    downstream_info.addBytesSent(content_length_);
    upstream_request_.stream_info_.addBytesReceived(spliced_body_bytes_);
    // Finalize the response: deliver the terminal end-of-stream to the decode path (which finalizes
    // the downstream encoder) and ready the upstream for the next keep-alive response. It may tear
    // down the owning UpstreamRequest, so touch no members afterwards. The upstream is always
    // present: a BoundsReached completion implies the borrowed leg is intact and teardown would
    // have cancelled this callback.
    ASSERT(upstream_request_.upstream_ != nullptr);
    upstream_request_.upstream_->completeSplicedResponse(spliced_body_bytes_);
    return;
  }

  // Upload: the upstream is the sink. Account the request body to the upstream wire meter; the
  // downstream already counts the held body, so completeSplicedRequest adds the spliced remainder.
  if (downstream_info.getUpstreamBytesMeter() != nullptr) {
    downstream_info.getUpstreamBytesMeter()->addWireBytesSent(content_length_);
  }
  downstream_info.addBytesReceived(spliced_body_bytes_);
  // Finalize the request: the terminal end-of-stream to the request decoder finalizes the upstream
  // encoder (so the response is awaited) and readies the downstream for the next request. It may
  // tear down the owning UpstreamRequest, so touch no members afterwards.
  auto downstream_callbacks = upstream_request_.parent_.callbacks()->downstreamCallbacks();
  if (downstream_callbacks.has_value()) {
    downstream_callbacks->completeSplicedRequest(spliced_body_bytes_);
  }
}

void SpliceCoordinator::reset() {
  armed_ = false;
  if (engage_callback_ != nullptr) {
    engage_callback_->cancel();
  }
  if (engage_poll_timer_ != nullptr) {
    engage_poll_timer_->disableTimer();
  }
  if (finalize_callback_ != nullptr) {
    finalize_callback_->cancel();
  }
  // Drop the pump and re-arm any borrowed legs. reset() is only reached from UpstreamRequest
  // teardown, never from inside the pump's own callback, so destroying the pump here is safe.
  releaseSplice();
}

void SpliceCoordinator::releaseSplice() {
  // Destroy the pump first so its pipes close and its epoll registrations are removed, freeing the
  // fds for the ConnectionImpl file events to be re-armed.
  splice_pump_.reset();

  // Re-arm each borrowed leg that is still open so Envoy resumes driving its I/O. A detached leg
  // left behind would silently drop its events (the downstream client connection would hang).
  if (upstream_connection_.has_value() &&
      upstream_connection_->state() == Network::Connection::State::Open) {
    upstream_connection_->reinstallFileEvents();
  }
  if (downstream_connection_.has_value() &&
      downstream_connection_->state() == Network::Connection::State::Open) {
    downstream_connection_->reinstallFileEvents();
  }
  upstream_connection_ = {};
  downstream_connection_ = {};
  // Re-enable source reads if the upload read-disabled them; the re-armed file event then carries
  // the next keep-alive message. No-op for the download.
  maybeReadEnableSource();
}

OptRef<Network::Connection> SpliceCoordinator::upstreamConnection() {
  return upstream_request_.upstream_ != nullptr
             ? upstream_request_.upstream_->upstreamConnectionForSplice()
             : OptRef<Network::Connection>{};
}

OptRef<Network::Connection> SpliceCoordinator::downstreamConnection() {
  auto downstream_callbacks = upstream_request_.parent_.callbacks()->downstreamCallbacks();
  return downstream_callbacks.has_value() ? downstream_callbacks->downstreamConnectionForSplice()
                                          : OptRef<Network::Connection>{};
}

} // namespace Router
} // namespace Envoy
