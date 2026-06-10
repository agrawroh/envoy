#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/upstreams/http/web_transport/upstream_request.h"

#include "test/mocks/http/stream_encoder.h"
#include "test/mocks/router/mocks.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {
namespace {

using ::testing::NiceMock;

// A WebTransport session that reports whether it is over its limit and records the registered
// callbacks.
class FakeWebTransportSession : public Envoy::Http::WebTransportSession {
public:
  bool sessionLimitExceeded() const override { return limit_exceeded_; }
  void
  setWebTransportSessionCallbacks(Envoy::Http::WebTransportSessionCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  void sendWebTransportDatagram(absl::string_view) override {}
  bool canOpenWebTransportStream(bool) const override { return false; }
  Envoy::Http::WebTransportStream* openWebTransportStream(bool) override { return nullptr; }

  bool limit_exceeded_{false};
  Envoy::Http::WebTransportSessionCallbacks* callbacks_{nullptr};
};

// A request encoder whose WebTransport session is controllable by the test.
class FakeRequestEncoder : public Envoy::Http::MockRequestEncoder {
public:
  OptRef<Envoy::Http::WebTransportSession> webTransport() override { return session_; }
  OptRef<Envoy::Http::WebTransportSession> session_;
};

// An upstream to downstream interface whose downstream WebTransport session is controllable.
class FakeUpstreamToDownstream : public Router::MockUpstreamToDownstream {
public:
  OptRef<Envoy::Http::WebTransportSession> webTransport() override { return session_; }
  OptRef<Envoy::Http::WebTransportSession> session_;
};

class WebTransportUpstreamTest : public testing::Test {
protected:
  Envoy::Http::TestRequestHeaderMapImpl connectHeaders() {
    return Envoy::Http::TestRequestHeaderMapImpl{{":method", "CONNECT"},
                                                 {":protocol", "webtransport"},
                                                 {":scheme", "https"},
                                                 {":path", "/"},
                                                 {":authority", "host"}};
  }

  uint64_t counter(absl::string_view name) {
    return store_.counterFromString(absl::StrCat("webtransport.", name)).value();
  }
  uint64_t gauge(absl::string_view name) {
    return store_
        .gaugeFromString(absl::StrCat("webtransport.", name), Stats::Gauge::ImportMode::Accumulate)
        .value();
  }

  Stats::IsolatedStoreImpl store_;
  NiceMock<FakeRequestEncoder> encoder_;
  NiceMock<FakeUpstreamToDownstream> upstream_to_downstream_;
  FakeWebTransportSession upstream_session_;
  FakeWebTransportSession downstream_session_;
};

// With both sessions negotiated the extended CONNECT is encoded and the relay is wired on both.
TEST_F(WebTransportUpstreamTest, EncodeHeadersEstablishesRelay) {
  encoder_.session_ = upstream_session_;
  upstream_to_downstream_.session_ = downstream_session_;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_TRUE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_NE(nullptr, upstream_session_.callbacks_);
  EXPECT_NE(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(1, counter("sessions_total"));
  EXPECT_EQ(1, gauge("sessions_active"));
}

// Without an upstream session the upstream did not negotiate WebTransport, so the relay is refused.
TEST_F(WebTransportUpstreamTest, EncodeHeadersWithoutUpstreamSessionFails) {
  upstream_to_downstream_.session_ = downstream_session_;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_FALSE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(1, counter("sessions_rejected"));
}

// Without a downstream session there is nothing to proxy, so the relay is refused.
TEST_F(WebTransportUpstreamTest, EncodeHeadersWithoutDownstreamSessionFails) {
  encoder_.session_ = upstream_session_;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_FALSE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(nullptr, upstream_session_.callbacks_);
}

// When the downstream connection is over its WebTransport session limit the relay is refused.
TEST_F(WebTransportUpstreamTest, EncodeHeadersOverDownstreamLimitFails) {
  encoder_.session_ = upstream_session_;
  downstream_session_.limit_exceeded_ = true;
  upstream_to_downstream_.session_ = downstream_session_;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_FALSE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(nullptr, downstream_session_.callbacks_);
}

} // namespace
} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
