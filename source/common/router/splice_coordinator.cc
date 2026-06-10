#include "source/common/router/splice_coordinator.h"

#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/stats/scope.h"

#include "source/common/common/assert.h"
#include "source/common/router/router.h"
#include "source/common/router/upstream_request.h"
#include "source/common/runtime/runtime_features.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"

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
  // The downstream sink must be a plaintext (raw_buffer) or installed-kTLS socket, never a
  // userspace-TLS socket, into which writing raw plaintext would bypass encryption. ssl()==nullptr
  // alone does not prove that (a rustls userspace socket also reports null), so use the positive
  // signal.
  if (!sinkLegIsRawOrKtls(downstream.ref())) {
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
  // The downstream source must be a single, non-multiplexed HTTP/1.1 socket that is plaintext
  // (raw_buffer) or installed-kTLS, never userspace TLS, off which the pump would read ciphertext
  // and relay it as the request body. ssl()==nullptr alone does not prove that, so use the positive
  // signal. The upstream (sink) leg is not connected yet, so engage() polls for it and its kTLS-TX.
  OptRef<Network::Connection> downstream = downstreamConnection();
  if (!downstream.has_value() || !sinkLegIsRawOrKtls(downstream.ref())) {
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
  incSpliceCounter("abandoned");
  flushPreEngageBody();
  maybeReadEnableSource();
  disarm();
}

bool SpliceCoordinator::sinkLegIsRawOrKtls(Network::Connection& connection) {
  // Splicing raw bytes into (download sink) or out of (upload source) a userspace-TLS socket would
  // bypass its in-place encryption, plaintext on the wire, or relayed ciphertext. Two signals are
  // both required:
  //   1. ssl() == nullptr. A userspace-TLS socket that exposes Ssl::ConnectionInfo, e.g. the
  //      BoringSSL `tls` transport socket, reports a non-null ssl(); reject it. This is the ONLY
  //      thing that distinguishes a BoringSSL/standard-TLS leg, which does not expose
  //      KtlsBytestreamInfo at all (it inherits the empty base default, indistinguishable from
  //      plaintext on that signal alone).
  //   2. The KtlsBytestreamInfo signal then separates a rustls socket (which always reports
  //      ssl()==nullptr) running userspace TLS (installed=false, reject) from one with kTLS
  //      installed (safe) and from a plaintext raw_buffer socket (no info at all, safe).
  // Net: plaintext raw_buffer (ssl null, no info) and installed-kTLS rustls (ssl null, installed)
  // pass; BoringSSL-userspace (ssl non-null) and rustls-userspace/pending (ssl null, installed
  // false) are rejected.
  if (connection.ssl() != nullptr) {
    return false;
  }
  OptRef<const Network::KtlsBytestreamInfo> info = connection.ktlsBytestreamInfo();
  if (!info.has_value()) {
    return true; // no TLS-capable transport: plaintext raw socket, safe to splice
  }
  return info->installed; // rustls: safe only when kTLS is actually installed
}

void SpliceCoordinator::onSpliceProgress() {
  upstream_request_.resetPerTryIdleTimer();
  // No decode/encode event refreshes the HCM stream idle timer while the codec is bypassed; refresh
  // it here so an actively-progressing splice is not killed mid-body by stream_idle_timeout.
  upstream_request_.parent_.callbacks()->resetIdleTimer();
  // Re-arm the no-progress watchdog: only a genuine stall (no bytes for ProgressWatchdogTimeout)
  // should let it fire.
  if (progress_watchdog_ != nullptr) {
    progress_watchdog_->enableTimer(ProgressWatchdogTimeout);
  }
}

void SpliceCoordinator::armProgressWatchdog() {
  if (progress_watchdog_ == nullptr) {
    progress_watchdog_ = upstream_request_.parent_.callbacks()->dispatcher().createTimer([this]() {
      // A wedged splice (peer stalled with the codec detached, so no route/HCM timer is driven
      // by I/O) is reaped here independent of route-timeout configuration. Part of the body has
      // already left for the sink, so the message cannot recover and the stream is reset. The
      // teardown reaches reset(), which force-closes the borrowed upstream and counts the
      // truncation, so it is not counted here.
      ENVOY_LOG(debug, "kTLS body-splice no-progress watchdog fired, resetting");
      upstream_request_.onResetStream(Http::StreamResetReason::ConnectionTermination,
                                      "kTLS body-splice stalled");
    });
  }
  progress_watchdog_->enableTimer(ProgressWatchdogTimeout);
}

void SpliceCoordinator::incSpliceCounter(absl::string_view event) {
  // Per-cluster splice lifecycle counters cluster.<name>.http1_ktls_splice.<engaged|abandoned|
  // completed|truncated>. `abandoned` ticks when the splice falls back to the buffered path before
  // engaging. `engaged` ticks once when a splice commits, then exactly one of `completed` (reached
  // the Content-Length boundary) or `truncated` (torn down first) ticks. Counted once per splice
  // decision, never per byte.
  const Upstream::ClusterInfoConstSharedPtr cluster = upstream_request_.parent_.cluster();
  if (cluster == nullptr) {
    return;
  }
  cluster->statsScope().counterFromString(absl::StrCat("http1_ktls_splice.", event)).inc();
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
    // The source is read-disabled only on an upload, which means engage() already detached this
    // leg's file event. readDisable(false) re-enables that event, so reinstall it first. The
    // success path reaches here too, so this is the single reinstall point for the source leg.
    if (legs_detached_) {
      downstream->reinstallFileEvents();
    }
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
    // Streaming shadows replay the request body through decodeData, which an engaged upload
    // bypasses by reading the body raw off the socket. They are started after arm, so re-check
    // here and stay on the buffered path when one is active so the shadow still gets the body.
    if (upstream_request_.parent_.shadowStreamsActive()) {
      abandon();
      return;
    }
    if (!downstream.has_value()) {
      abandon();
      return;
    }
    if (!upstream.has_value()) {
      // Distinguish "pool not ready yet" (keep polling) from "the upstream connected but is not a
      // borrowable HTTP/1.1 socket" (an HTTP/2 or HTTP/3 upstream, upstreamConnectionForSplice()
      // is empty forever). Polling the latter to the bound would read-disable the client for ~130
      // ms for nothing, so abandon immediately to the buffered path once the pool stream exists.
      if (upstream_request_.upstream_ != nullptr) {
        ENVOY_LOG(debug, "kTLS body-splice skipped: upstream is not a borrowable HTTP/1.1 socket");
        abandon();
        return;
      }
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

  // Re-validate after the schedulable-callback gap: the upstream leg must have kTLS installed and
  // be a trusted peer, and the downstream leg (the splice's sink for a download, its source for an
  // upload) must be plaintext or installed-kTLS, never userspace TLS the splice would bypass. Any
  // bail-out here flushes the held body back through the normal path so the message still
  // completes.
  const bool download = direction_ == Direction::Download;
  OptRef<const Network::KtlsBytestreamInfo> ktls = upstream->ktlsBytestreamInfo();
  if (!ktls.has_value() || !ktls->installed || !ktls->trusted_peer ||
      !sinkLegIsRawOrKtls(downstream.ref())) {
    abandon();
    return;
  }
  // The leg the splice writes to: downstream for a download (response body), upstream for an
  // upload.
  Network::Connection& sink = download ? downstream.ref() : upstream.ref();
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

  auto pump = splice_pump_factory_(
      down_fd.value(), up_fd.value(), /*up_is_ktls=*/true,
      upstream_request_.parent_.callbacks()->dispatcher(),
      [this](TcpProxy::SpliceCompletion status) { onSpliceComplete(status); },
      // Each byte callback keeps the transfer's liveness timers fresh: the per-try idle timer (so a
      // long transfer does not trip it) and the coordinator's own no-progress watchdog. It also
      // resets the HCM stream idle timer, which no decode/encode event refreshes while the codec is
      // bypassed, otherwise an actively-progressing splice slower than stream_idle_timeout would
      // be killed mid-body. The active direction's callback does the work; the other is inactive.
      [this](uint64_t) { onSpliceProgress(); }, [this](uint64_t) { onSpliceProgress(); });

  // Create only the active direction's pipe, and do it BEFORE extracting the sink's pending write
  // (which is irreversible). A pipe2() failure here, e.g. EMFILE/ENFILE under fd pressure, then
  // falls back to the buffered path losslessly instead of resetting a connection whose write buffer
  // we already drained.
  if (!pump->createPipes(/*need_u2d=*/download, /*need_d2u=*/!download)) {
    ENVOY_LOG(debug, "kTLS body-splice skipped: pipe creation failed, using buffered path");
    abandon();
    return;
  }

  // Hand the pump the sink's pending output (the encoded headers) followed by the body held before
  // engage, as the pre-engage chunk, so they precede the spliced body and wire order is preserved.
  std::string pre_engage = sink.extractPendingWriteForSplice();
  pre_engage.reserve(pre_engage.size() + pre_engage_body_.length());
  pre_engage += pre_engage_body_.toString();
  pre_engage_body_.drain(buffered);
  // The sink write buffer is now drained, so the splice is committed. Count it engaged here so a
  // prepare() failure below still counts as engaged then truncated.
  incSpliceCounter("engaged");
  // The pre-engage chunk and the splice bound apply to the active direction: u2d for a download
  // (upstream -> downstream), d2u for an upload (downstream -> upstream). The pipes already exist,
  // so prepare() only emits the chunk; it returns false only if the sink socket is already broken,
  // in which case the drained bytes cannot be requeued and the stream must be reset.
  const bool ok = download ? pump->prepare(std::move(pre_engage), /*initial_d2u=*/"")
                           : pump->prepare(/*initial_u2d=*/"", std::move(pre_engage));
  if (!ok) {
    // The pending output was already drained from the sink, so this is a reset, not a fallback.
    // Count it with the other splice-driven resets.
    incSpliceCounter("truncated");
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

  // An engaged upload streams the request body raw off the downstream socket past the router's
  // retry-buffer accounting, so the buffered prefix the router holds is no longer the whole body. A
  // retry would replay only that prefix against a fresh upstream (a short, corrupt request) and, on
  // truncation, leave the downstream H1 parser desynced. Disable retries for the rest of this
  // stream the moment an upload engages. (Downloads are past the request entirely, so they are
  // unaffected.)
  if (!download) {
    upstream_request_.parent_.disableRetries();
  }

  // Commit: remove both ConnectionImpl file events so the pump owns the only registration on each
  // fd, then arm it. The legs now have no file event, so any later readDisable or re-arm must
  // reinstall first.
  upstream->getSocket()->ioHandle().resetFileEvents();
  downstream->getSocket()->ioHandle().resetFileEvents();
  legs_detached_ = true;
  upstream_connection_ = upstream;
  downstream_connection_ = downstream;
  splice_pump_ = std::move(pump);
  splice_pump_->arm();
  // Arm a no-progress watchdog so a wedged splice (a peer that stalls with the codec detached, so
  // no HCM/router timer is driven by I/O) is reaped independent of route timeout configuration.
  // Each byte callback re-arms it; only a genuine stall lets it fire.
  armProgressWatchdog();
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
  // ORDERING INVARIANT (the crux of crash-safety): destroy the pump first so the borrowed fds are
  // free, but leave the ConnectionImpl file events DETACHED while the codec stream is finalized.
  // The codec completion (completeSpliced*) runs out-of-band, from this scheduled callback, not
  // from within dispatch(), so it must not race a socket event. With events detached, no read can
  // fire and dispatch into the half-finalized codec, and no peer-close can hit a still-active
  // ActiveRequest. Only AFTER the stream is finalized (so the codec's active_requests_ no longer
  // references it) do we re-arm the legs for reuse. The original order (re-arm, then finalize)
  // exposed the window where a remote-close dispatched into the just-spliced stream, the
  // "Wrapped decoder use after free" / CodecClient::onEvent segfault under connection churn.
  if (progress_watchdog_ != nullptr) {
    progress_watchdog_->disableTimer();
  }
  splice_pump_.reset();

  // Capture the borrowed legs on the stack and clear the members up front: completeSpliced* below
  // may defer-delete the owning UpstreamRequest (and this coordinator), but the captured OptRefs
  // and the connection objects (pooled upstream, keep-alive downstream) remain valid for the rest
  // of this synchronous call.
  OptRef<Network::Connection> up = upstream_connection_;
  OptRef<Network::Connection> down = downstream_connection_;
  upstream_connection_ = {};
  downstream_connection_ = {};

  if (completion_status_ != TcpProxy::SpliceCompletion::BoundsReached) {
    // A truncated or failed splice cannot be recovered: part of the body has already left for the
    // sink socket. Do NOT re-arm the borrowed legs (a pending peer-close would dispatch into the
    // still-active, soon-dead stream). Re-enable the source read (upload may have read-disabled it)
    // so teardown is not blocked, then force-close the upstream NoFlush, mirroring the proven L4
    // tearDownSplice. The upstream close drives the codec reset, which propagates through the
    // router to reset the downstream stream too, so neither connection is reused.
    incSpliceCounter("truncated");
    ENVOY_LOG(debug, "kTLS body-splice aborted before the Content-Length boundary, resetting");
    maybeReadEnableSource();
    if (up.has_value() && up->state() == Network::Connection::State::Open) {
      up->close(Network::ConnectionCloseType::NoFlush);
    }
    return;
  }

  // The splice reached the Content-Length boundary. Count the clean completion now, before
  // completeSpliced* below may defer-delete this coordinator.
  incSpliceCounter("completed");

  // The spliced body bypassed the sink codec, so its full Content-Length is added to the sink wire
  // meter and legacy counter here. The headers were already counted by the codec at encode time, so
  // they are not added again. The source side counts the held pre-engage body through its codec
  // read path, so only the spliced remainder is added there (in completeSpliced*).
  StreamInfo::StreamInfo& downstream_info = upstream_request_.parent_.callbacks()->streamInfo();
  ENVOY_LOG(debug, "kTLS body-splice complete: {} body bytes relayed", spliced_body_bytes_);
  if (direction_ == Direction::Download) {
    if (downstream_info.getDownstreamBytesMeter() != nullptr) {
      downstream_info.getDownstreamBytesMeter()->addWireBytesSent(content_length_);
    }
    downstream_info.addBytesSent(content_length_);
    upstream_request_.stream_info_.addBytesReceived(spliced_body_bytes_);
    // Re-arm the downstream (client keep-alive) BEFORE delivering its end-stream, so the encoder's
    // write flushes and the next request is read.
    if (down.has_value() && down->state() == Network::Connection::State::Open) {
      down->reinstallFileEvents();
    }
    // Finalize the response while the UPSTREAM events are still detached: deliver the terminal
    // end-of-stream (which finalizes the downstream encoder and removes the codec's ActiveRequest)
    // and ready the upstream codec for keep-alive reuse. May tear down the owning UpstreamRequest,
    // so touch no members afterwards. The upstream is always present: a BoundsReached completion
    // implies the borrowed leg is intact and teardown would have cancelled this callback.
    ASSERT(upstream_request_.upstream_ != nullptr);
    upstream_request_.upstream_->completeSplicedResponse(spliced_body_bytes_);
    // Now that the codec stream is finalized (active_requests_ no longer references it), re-arm the
    // upstream for keep-alive reuse. A pending remote-close that fires next iteration now lands on
    // an idle connection with an empty active_requests_ and is handled cleanly by the conn pool.
    if (up.has_value() && up->state() == Network::Connection::State::Open) {
      up->reinstallFileEvents();
    }
    return;
  }

  // Upload: the upstream is the sink and still awaits the response, so both legs are re-armed and
  // reused. Re-arm the sink BEFORE completing (the response is read off the re-armed upstream),
  // then re-enable the held source read (maybeReadEnableSource reinstalls the source leg), then
  // account and finalize.
  if (up.has_value() && up->state() == Network::Connection::State::Open) {
    up->reinstallFileEvents();
  }
  maybeReadEnableSource();
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
  if (progress_watchdog_ != nullptr) {
    progress_watchdog_->disableTimer();
  }
  // reset() is reached only from UpstreamRequest teardown (cleanUp / onResetStream / resetStream),
  // never from inside the pump's own callback, so destroying the pump here is safe. After a normal
  // finalize() this is a no-op (pump already gone, refs cleared). When it fires WITH a splice in
  // flight (the stream is reset mid-transfer), dispose of the borrowed legs the same way the
  // truncation path does: destroy the pump, re-enable the source read, and force-close the borrowed
  // upstream NoFlush so a detached socket is never left behind. Do NOT re-arm it (the stream is
  // being torn down, and re-arming an idle connection whose ActiveRequest is still in flight is
  // what raced a peer-close into the codec). The surrounding teardown closes the downstream.
  if (splice_pump_ != nullptr) {
    // An engaged splice torn down mid-transfer (external reset, or the watchdog) is a truncation.
    // finalize() clears the pump before its own teardown reaches here, so this never double-counts.
    incSpliceCounter("truncated");
  }
  splice_pump_.reset();
  maybeReadEnableSource();
  if (upstream_connection_.has_value() &&
      upstream_connection_->state() == Network::Connection::State::Open) {
    // The NoFlush close runs the codec reset cascade inline, which re-enters
    // UpstreamRequest::onResetStream. Latch the guard so that nested call is a no-op and the
    // request leaves the parent list exactly once, whichever path entered reset() (onResetStream,
    // the watchdog, resetStream, or cleanUp).
    upstream_request_.on_reset_stream_in_progress_ = true;
    upstream_connection_->close(Network::ConnectionCloseType::NoFlush);
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
