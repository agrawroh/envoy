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
  auto upstream =
      std::make_unique<WebTransportUpstream>(callbacks_->upstreamToDownstream(), &request_encoder);
  callbacks_->onPoolReady(std::move(upstream), host,
                          request_encoder.getStream().connectionInfoProvider(), info, protocol);
}

Envoy::Http::Status
WebTransportUpstream::encodeHeaders(const Envoy::Http::RequestHeaderMap& headers, bool end_stream) {
  Envoy::Http::Status status = request_encoder_->encodeHeaders(headers, end_stream);
  if (!status.ok()) {
    return status;
  }
  // The upstream session exists once the extended CONNECT is sent and the upstream advertised
  // WebTransport. The downstream session is the CONNECT the router is proxying.
  OptRef<Envoy::Http::WebTransportSession> upstream_session = request_encoder_->webTransport();
  OptRef<Envoy::Http::WebTransportSession> downstream_session = upstream_request_.webTransport();
  if (!upstream_session.has_value() || !downstream_session.has_value() ||
      downstream_session->sessionLimitExceeded()) {
    // The upstream did not negotiate WebTransport or the downstream is over its session limit.
    // Reset rather than relay a half open session.
    return absl::InternalError("cannot establish WebTransport relay");
  }
  relay_ = std::make_unique<WebTransportRelay>(downstream_session.ref(), upstream_session.ref());
  return Envoy::Http::okStatus();
}

void WebTransportUpstream::resetStream() {
  relay_.reset();
  auto& stream = request_encoder_->getStream();
  stream.removeCallbacks(*this);
  stream.resetStream(Envoy::Http::StreamResetReason::LocalReset);
}

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
