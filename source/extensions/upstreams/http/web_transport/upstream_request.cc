#include "source/extensions/upstreams/http/web_transport/upstream_request.h"

#include <memory>

#include "envoy/http/conn_pool.h"
#include "envoy/upstream/upstream.h"

#include "source/common/router/router.h"

using Envoy::Router::GenericConnectionPoolCallbacks;

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

WebTransportUpstream::WebTransportUpstream(Router::UpstreamToDownstream& upstream_request,
                                           Envoy::Http::RequestEncoder* encoder,
                                           Stats::Scope& scope)
    : upstream_request_(upstream_request), request_encoder_(encoder),
      stats_(Quic::WebTransportStats::atomicGet(stats_atomic_, scope)) {
  request_encoder_->getStream().addCallbacks(*this);
  // The downstream connection drives both sides of the relay, so reset on its dispatcher.
  OptRef<const Network::Connection> connection = upstream_request_.connection();
  if (connection.has_value()) {
    teardown_callback_ = connection->dispatcher().createSchedulableCallback([this]() {
      upstream_request_.onResetStream(Envoy::Http::StreamResetReason::RemoteReset, "");
    });
  }
}

WebTransportUpstream::~WebTransportUpstream() {
  // Drop the ready callback so a late upstream SETTINGS frame cannot call back into this destroyed
  // upstream.
  request_encoder_->setWebTransportConnectReadyCallback(nullptr);
  releaseActiveSession();
}

void WebTransportUpstream::releaseActiveSession() {
  if (session_active_recorded_) {
    stats_.sessions_active_.dec();
    session_active_recorded_ = false;
  }
}

void WebTransportConnPool::newStream(GenericConnectionPoolCallbacks* callbacks) {
  callbacks_ = callbacks;
  // A reset can happen inline within the newStream() call, deleting this pool. Only store the
  // handle when it is not nullptr to cope with that case.
  Envoy::Http::ConnectionPool::Cancellable* handle =
      pool_data_.value().newStream(callbacks->upstreamToDownstream(), *this,
                                   callbacks->upstreamToDownstream().upstreamStreamOptions());
  if (handle) {
    conn_pool_stream_handle_ = handle;
  }
}

bool WebTransportConnPool::cancelAnyPendingStream() {
  if (conn_pool_stream_handle_) {
    conn_pool_stream_handle_->cancel(ConnectionPool::CancelPolicy::Default);
    conn_pool_stream_handle_ = nullptr;
    return true;
  }
  return false;
}

void WebTransportConnPool::onPoolFailure(ConnectionPool::PoolFailureReason reason,
                                         absl::string_view transport_failure_reason,
                                         Upstream::HostDescriptionConstSharedPtr host) {
  conn_pool_stream_handle_ = nullptr;
  callbacks_->onPoolFailure(reason, transport_failure_reason, host);
}

void WebTransportConnPool::onPoolReady(Envoy::Http::RequestEncoder& request_encoder,
                                       Upstream::HostDescriptionConstSharedPtr host,
                                       StreamInfo::StreamInfo& info,
                                       absl::optional<Envoy::Http::Protocol> protocol) {
  conn_pool_stream_handle_ = nullptr;
  auto upstream = std::make_unique<WebTransportUpstream>(callbacks_->upstreamToDownstream(),
                                                         &request_encoder, cluster_scope_);
  callbacks_->onPoolReady(std::move(upstream), host,
                          request_encoder.getStream().connectionInfoProvider(), info, protocol);
}

Envoy::Http::Status
WebTransportUpstream::encodeHeaders(const Envoy::Http::RequestHeaderMap& headers, bool end_stream) {
  // The upstream CONNECT may be deferred until the upstream SETTINGS arrive, so set up the relay
  // from the ready callback rather than inline. The callback fires once the CONNECT is written and
  // webTransport() is definitive.
  request_encoder_->setWebTransportConnectReadyCallback([this]() { setupRelay(); });
  return request_encoder_->encodeHeaders(headers, end_stream);
}

void WebTransportUpstream::setupRelay() {
  // The upstream session exists once the extended CONNECT is sent and the upstream advertised
  // WebTransport. The downstream session is the CONNECT the router is proxying.
  OptRef<Envoy::Http::WebTransportSession> upstream_session = request_encoder_->webTransport();
  OptRef<Envoy::Http::WebTransportSession> downstream_session = upstream_request_.webTransport();
  if (!upstream_session.has_value() || !downstream_session.has_value() ||
      downstream_session->sessionLimitExceeded()) {
    stats_.sessions_rejected_.inc();
    // Defer the reset so this never re-enters the encoder from inside its own ready callback.
    if (teardown_callback_ != nullptr) {
      teardown_callback_->scheduleCallbackNextIteration();
    }
    return;
  }
  relay_ =
      std::make_unique<WebTransportRelay>(downstream_session.ref(), upstream_session.ref(), *this);
  stats_.sessions_total_.inc();
  stats_.sessions_active_.inc();
  session_active_recorded_ = true;
}

void WebTransportUpstream::resetStream() {
  relay_.reset();
  auto& stream = request_encoder_->getStream();
  stream.removeCallbacks(*this);
  stream.resetStream(Envoy::Http::StreamResetReason::LocalReset);
}

void WebTransportUpstream::onRelayClosed() {
  releaseActiveSession();
  // A session closed. Defer the reset so this callback can unwind before the relay is freed.
  if (teardown_callback_ != nullptr) {
    teardown_callback_->scheduleCallbackNextIteration();
  }
}

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
