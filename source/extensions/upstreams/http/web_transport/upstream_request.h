#pragma once

#include <memory>

#include "envoy/event/schedulable_cb.h"
#include "envoy/http/codec.h"
#include "envoy/http/conn_pool.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/thread_local_cluster.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/quic/web_transport_stats.h"
#include "source/common/router/upstream_request.h"
#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

// Obtains an upstream HTTP/3 stream for a WebTransport CONNECT. WebTransport runs only over HTTP/3,
// so the connection pool is the cluster's HTTP pool with the downstream protocol carried through.
class WebTransportConnPool : public Router::GenericConnPool,
                             public Envoy::Http::ConnectionPool::Callbacks {
public:
  WebTransportConnPool(Upstream::HostConstSharedPtr host,
                       Upstream::ThreadLocalCluster& thread_local_cluster,
                       Upstream::ResourcePriority priority,
                       absl::optional<Envoy::Http::Protocol> downstream_protocol,
                       Upstream::LoadBalancerContext* ctx)
      : cluster_scope_(thread_local_cluster.info()->statsScope()) {
    pool_data_ = thread_local_cluster.httpConnPool(host, priority, downstream_protocol, ctx);
  }
  ~WebTransportConnPool() override {
    ASSERT(conn_pool_stream_handle_ == nullptr, "conn_pool_stream_handle not null");
  }

  // GenericConnPool
  void newStream(Router::GenericConnectionPoolCallbacks* callbacks) override;
  bool cancelAnyPendingStream() override;
  bool valid() const override { return pool_data_.has_value(); }
  Upstream::HostDescriptionConstSharedPtr host() const override {
    return pool_data_.value().host();
  }

  // Http::ConnectionPool::Callbacks
  void onPoolFailure(ConnectionPool::PoolFailureReason reason,
                     absl::string_view transport_failure_reason,
                     Upstream::HostDescriptionConstSharedPtr host) override;
  void onPoolReady(Envoy::Http::RequestEncoder& callbacks_encoder,
                   Upstream::HostDescriptionConstSharedPtr host, StreamInfo::StreamInfo& info,
                   absl::optional<Envoy::Http::Protocol> protocol) override;

private:
  Stats::Scope& cluster_scope_;
  absl::optional<Envoy::Upstream::HttpPoolData> pool_data_;
  Envoy::Http::ConnectionPool::Cancellable* conn_pool_stream_handle_{};
  Router::GenericConnectionPoolCallbacks* callbacks_{};
};

// Relays a downstream WebTransport session to an upstream one. The extended CONNECT is forwarded to
// the upstream as is, the upstream 200 flows back to the downstream through the router, and a
// WebTransportRelay forwards datagrams in both directions.
class WebTransportUpstream : public Router::GenericUpstream,
                             public Envoy::Http::StreamCallbacks,
                             public WebTransportRelay::Callbacks,
                             protected Logger::Loggable<Logger::Id::upstream> {
public:
  WebTransportUpstream(Router::UpstreamToDownstream& upstream_request,
                       Envoy::Http::RequestEncoder* encoder, Stats::Scope& scope);
  ~WebTransportUpstream() override;

  // GenericUpstream
  void encodeData(Buffer::Instance& data, bool end_stream) override {
    request_encoder_->encodeData(data, end_stream);
  }
  void encodeMetadata(const Envoy::Http::MetadataMapVector& metadata_map_vector) override {
    request_encoder_->encodeMetadata(metadata_map_vector);
  }
  Envoy::Http::Status encodeHeaders(const Envoy::Http::RequestHeaderMap& headers,
                                    bool end_stream) override;
  void encodeTrailers(const Envoy::Http::RequestTrailerMap& trailers) override {
    request_encoder_->encodeTrailers(trailers);
  }
  void enableTcpTunneling() override { request_encoder_->enableTcpTunneling(); }
  void readDisable(bool disable) override { request_encoder_->getStream().readDisable(disable); }
  void resetStream() override;
  void setAccount(Buffer::BufferMemoryAccountSharedPtr account) override {
    request_encoder_->getStream().setAccount(std::move(account));
  }
  const StreamInfo::BytesMeterSharedPtr& bytesMeter() override {
    return request_encoder_->getStream().bytesMeter();
  }

  // Http::StreamCallbacks
  void onResetStream(Envoy::Http::StreamResetReason reason,
                     absl::string_view transport_failure_reason) override {
    upstream_request_.onResetStream(reason, transport_failure_reason);
  }
  void onAboveWriteBufferHighWatermark() override {
    upstream_request_.onAboveWriteBufferHighWatermark();
  }
  void onBelowWriteBufferLowWatermark() override {
    upstream_request_.onBelowWriteBufferLowWatermark();
  }

  // WebTransportRelay::Callbacks
  void onRelayClosed() override;
  // A relayed datagram is both received from one peer and sent to the other by this proxy. Relayed
  // traffic keeps the downstream stream alive, so reset its idle timer too.
  void onDatagramRelayed() override {
    stats_.datagrams_rx_.inc();
    stats_.datagrams_tx_.inc();
    upstream_request_.onWebTransportActivity();
  }
  // A relayed data stream keeps the downstream stream alive, so reset its idle timer.
  void onWebTransportActivity() override { upstream_request_.onWebTransportActivity(); }

private:
  // Wires the relay once the upstream CONNECT has been issued, or refuses it if either side did not
  // negotiate WebTransport or the downstream is over its session limit. Runs from the encoder ready
  // callback, which may fire after the upstream SETTINGS arrive.
  void setupRelay();
  // Drops the active-session gauge once. Called on relay close and on destruction.
  void releaseActiveSession();

  Router::UpstreamToDownstream& upstream_request_;
  Envoy::Http::RequestEncoder* request_encoder_{};
  Quic::WebTransportStats::AtomicPtr stats_atomic_;
  Quic::WebTransportStats& stats_;
  bool session_active_recorded_{false};
  std::unique_ptr<WebTransportRelay> relay_;
  // Resets the stream after a relay close unwinds, so the close callback never re-enters and frees
  // the relay while it is on the stack. Owned here so it is cancelled if this upstream is destroyed
  // first.
  Event::SchedulableCallbackPtr teardown_callback_;
  // True while encodeHeaders runs, so a synchronous rejection is returned as an error there rather
  // than as a deferred reset.
  bool encoding_headers_{false};
  // Set when the relay is refused, carried into the encodeHeaders error or the reset details.
  absl::optional<std::string> reject_reason_;
  // Reason and details for the deferred reset, defaulting to the relay close case.
  Envoy::Http::StreamResetReason teardown_reason_{Envoy::Http::StreamResetReason::RemoteReset};
  std::string teardown_details_;
};

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
