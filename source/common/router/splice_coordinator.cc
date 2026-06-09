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
  armed_ = true;
  ENVOY_LOG(debug, "kTLS body-splice armed for {}-byte response body", content_length_);
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

bool SpliceCoordinator::bufferPreEngageResponseBody(Buffer::Instance& data, bool end_stream) {
  ASSERT(armed_ && !engaged());
  if (end_stream) {
    // The whole body arrived before engage; splicing buys nothing. Flush whatever was held, disarm,
    // and let the caller forward this terminal chunk so the response completes through the encoder.
    flushPreEngageBody();
    disarm();
    return false;
  }
  // Hold the body back from the downstream encoder; engage emits it ahead of the spliced remainder.
  pre_engage_body_.move(data);
  return true;
}

void SpliceCoordinator::disarm() {
  armed_ = false;
  if (engage_callback_ != nullptr) {
    engage_callback_->cancel();
  }
}

void SpliceCoordinator::engage() {
  if (!armed_) {
    return;
  }
  armed_ = false;

  OptRef<Network::Connection> upstream = upstreamConnection();
  OptRef<Network::Connection> downstream = downstreamConnection();
  if (!upstream.has_value() || !downstream.has_value()) {
    ENVOY_LOG(debug, "kTLS body-splice skipped: a leg is no longer borrowable");
    flushPreEngageBody();
    return;
  }

  // Re-verify the gates that can change between arm and engage, then resolve both fds. Any bail-out
  // here must flush the held body back through the normal path so the response still completes.
  OptRef<const Network::KtlsBytestreamInfo> ktls = upstream->ktlsBytestreamInfo();
  if (!ktls.has_value() || !ktls->installed || !ktls->trusted_peer ||
      downstream->ssl() != nullptr) {
    flushPreEngageBody();
    return;
  }
  const absl::optional<os_fd_t> up_fd = spliceableFd(upstream.ref());
  const absl::optional<os_fd_t> down_fd = spliceableFd(downstream.ref());
  if (!up_fd.has_value() || !down_fd.has_value()) {
    flushPreEngageBody();
    return;
  }
  // If the whole body arrived before engage, there is nothing left to splice; deliver it normally.
  const uint64_t buffered = pre_engage_body_.length();
  if (buffered >= content_length_) {
    flushPreEngageBody();
    return;
  }
  spliced_body_bytes_ = content_length_ - buffered;

  auto pump = std::make_unique<TcpProxy::SplicePump>(
      down_fd.value(), up_fd.value(), /*up_is_ktls=*/true,
      upstream_request_.parent_.callbacks()->dispatcher(),
      [this](TcpProxy::SpliceCompletion status) { onSpliceComplete(status); },
      // Download direction: reset the per-try idle timer as bytes move so a long transfer does not
      // trip the idle timeout. Wire-byte accounting happens once on completion.
      [this](uint64_t) { upstream_request_.resetPerTryIdleTimer(); },
      // The upload direction is inactive for a download splice.
      [](uint64_t) {});
  // Hand the pump the downstream's pending output (the encoded response headers) followed by the
  // body held back before engage, as the pre-engage chunk, so they precede the spliced body and the
  // order is preserved. prepare() creates the pipes before emitting this chunk; on the rare
  // pipe-creation failure the taken bytes cannot be requeued, so reset rather than drop them and
  // corrupt the response.
  std::string pre_engage = downstream->extractPendingWriteForSplice();
  pre_engage += pre_engage_body_.toString();
  pre_engage_body_.drain(buffered);
  if (!pump->prepare(std::move(pre_engage), /*initial_d2u=*/"")) {
    ENVOY_LOG(warn, "kTLS body-splice setup failed after taking downstream output, resetting");
    upstream_request_.onResetStream(Http::StreamResetReason::ConnectionTermination,
                                    "kTLS body-splice setup failed");
    return;
  }
  pump->setBounds(/*u2d_limit=*/spliced_body_bytes_, /*d2u_limit=*/absl::nullopt);
  // Commit: remove both ConnectionImpl file events so the pump owns the only registration on each
  // fd, then arm it.
  upstream->getSocket()->ioHandle().resetFileEvents();
  downstream->getSocket()->ioHandle().resetFileEvents();
  upstream_connection_ = upstream;
  downstream_connection_ = downstream;
  splice_pump_ = std::move(pump);
  splice_pump_->arm();
  ENVOY_LOG(debug, "kTLS body-splice engaged: {} body bytes to splice (down_fd={}, up_fd={})",
            spliced_body_bytes_, down_fd.value(), up_fd.value());
}

void SpliceCoordinator::flushPreEngageBody() {
  if (pre_engage_body_.length() == 0) {
    return;
  }
  // Forward the held body to the downstream encoder so the response resumes on the normal path. Any
  // remaining body and the terminal chunk follow through decodeData once disarmed.
  upstream_request_.parent_.onUpstreamData(pre_engage_body_, upstream_request_, false);
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

  if (completion_status_ == TcpProxy::SpliceCompletion::BoundsReached) {
    // Account the body the splice carried. The downstream encoder emitted only the headers (the
    // whole body bypassed it via the pump), so the full Content-Length body is added to the
    // downstream wire-sent meter and the legacy bytes-sent counter here. The upstream side already
    // counts the held pre-engage body through the codec's read path, so only the spliced remainder
    // is added to its wire-received meter (in completeSplicedResponse) and bytes-received counter.
    StreamInfo::StreamInfo& downstream_info = upstream_request_.parent_.callbacks()->streamInfo();
    downstream_info.getDownstreamBytesMeter()->addWireBytesSent(content_length_);
    downstream_info.addBytesSent(content_length_);
    upstream_request_.stream_info_.addBytesReceived(spliced_body_bytes_);
    // Finalize the response: this delivers the terminal end-of-stream to the decode path (which
    // finalizes the downstream encoder) and readies the upstream connection for the next keep-alive
    // response. It may tear down the owning UpstreamRequest, so touch no members afterwards. The
    // upstream is always present here: a BoundsReached completion implies the leg engage() borrowed
    // is still intact, and teardown would have cancelled this callback.
    ASSERT(upstream_request_.upstream_ != nullptr);
    ENVOY_LOG(debug, "kTLS body-splice complete: {} body bytes relayed", spliced_body_bytes_);
    upstream_request_.upstream_->completeSplicedResponse(spliced_body_bytes_);
    return;
  }

  // A truncated or failed splice cannot be recovered: part of the body has already left for the
  // downstream socket. Drive the upstream-reset machinery so the router resets the downstream and
  // defers deletion of the UpstreamRequest, rather than reusing either connection. resetStream()
  // alone would only latch a flag without tearing the stream down.
  ENVOY_LOG(debug, "kTLS body-splice aborted before the Content-Length boundary, resetting stream");
  upstream_request_.onResetStream(Http::StreamResetReason::ConnectionTermination,
                                  "kTLS body-splice truncated before Content-Length");
}

void SpliceCoordinator::reset() {
  armed_ = false;
  if (engage_callback_ != nullptr) {
    engage_callback_->cancel();
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
