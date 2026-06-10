#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/upstreams/http/web_transport/upstream_request.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/stream_encoder.h"
#include "test/mocks/network/mocks.h"
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
using ::testing::Return;

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

// A request encoder whose WebTransport session is controllable by the test. By default it fires the
// ready callback inline from encodeHeaders, mirroring an upstream that already advertised
// WebTransport. Set auto_fire_ready_ to false to model a CONNECT deferred until SETTINGS arrive.
class FakeRequestEncoder : public Envoy::Http::MockRequestEncoder {
public:
  OptRef<Envoy::Http::WebTransportSession> webTransport() override { return session_; }
  void setWebTransportConnectReadyCallback(std::function<void()> callback) override {
    ready_cb_ = std::move(callback);
  }
  Envoy::Http::Status encodeHeaders(const Envoy::Http::RequestHeaderMap&, bool) override {
    if (auto_fire_ready_ && ready_cb_ != nullptr) {
      ready_cb_();
    }
    return Envoy::Http::okStatus();
  }
  void fireReady() {
    if (ready_cb_ != nullptr) {
      ready_cb_();
    }
  }

  OptRef<Envoy::Http::WebTransportSession> session_;
  std::function<void()> ready_cb_;
  bool auto_fire_ready_{true};
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
  NiceMock<Network::MockConnection> connection_;
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

// A CONNECT deferred until SETTINGS does not wire the relay until the ready callback fires.
TEST_F(WebTransportUpstreamTest, EncodeHeadersDeferredUntilReady) {
  encoder_.session_ = upstream_session_;
  upstream_to_downstream_.session_ = downstream_session_;
  encoder_.auto_fire_ready_ = false;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_TRUE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(nullptr, upstream_session_.callbacks_);
  EXPECT_EQ(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(0, counter("sessions_total"));

  // SETTINGS arrive, the CONNECT is written and the relay is wired.
  encoder_.fireReady();
  EXPECT_NE(nullptr, upstream_session_.callbacks_);
  EXPECT_NE(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(1, counter("sessions_total"));
  EXPECT_EQ(1, gauge("sessions_active"));
}

// Without an upstream session the upstream did not negotiate WebTransport, so an inline CONNECT is
// refused with an error response.
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
  EXPECT_EQ(1, counter("sessions_rejected"));
}

// When the downstream connection is over its WebTransport session limit the relay is refused.
TEST_F(WebTransportUpstreamTest, EncodeHeadersOverDownstreamLimitFails) {
  encoder_.session_ = upstream_session_;
  downstream_session_.limit_exceeded_ = true;
  upstream_to_downstream_.session_ = downstream_session_;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_FALSE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(1, counter("sessions_rejected"));
}

// A CONNECT deferred until SETTINGS that the upstream then declines is refused once the ready
// callback fires.
TEST_F(WebTransportUpstreamTest, DeferredConnectWithoutUpstreamSessionFails) {
  upstream_to_downstream_.session_ = downstream_session_;
  encoder_.auto_fire_ready_ = false;
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_TRUE(upstream.encodeHeaders(connectHeaders(), false).ok());
  EXPECT_EQ(0, counter("sessions_rejected"));

  encoder_.fireReady();
  EXPECT_EQ(nullptr, downstream_session_.callbacks_);
  EXPECT_EQ(1, counter("sessions_rejected"));
}

// A deferred CONNECT the upstream then declines resets the stream with the reason as the failure
// detail, rather than charging outlier detection like a connection failure.
TEST_F(WebTransportUpstreamTest, DeferredRejectResetsWithReason) {
  upstream_to_downstream_.session_ = downstream_session_;
  ON_CALL(upstream_to_downstream_, connection())
      .WillByDefault(Return(OptRef<const Network::Connection>(connection_)));
  encoder_.auto_fire_ready_ = false;
  // Captures the teardown callback the upstream schedules. Ownership passes to the upstream.
  auto* teardown = new NiceMock<Event::MockSchedulableCallback>(&connection_.dispatcher_);
  WebTransportUpstream upstream(upstream_to_downstream_, &encoder_, *store_.rootScope());

  EXPECT_TRUE(upstream.encodeHeaders(connectHeaders(), false).ok());
  encoder_.fireReady();
  EXPECT_EQ(1, counter("sessions_rejected"));

  EXPECT_CALL(upstream_to_downstream_,
              onResetStream(Envoy::Http::StreamResetReason::LocalReset,
                            absl::string_view("upstream did not negotiate WebTransport")));
  teardown->invokeCallback();
}

} // namespace
} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
