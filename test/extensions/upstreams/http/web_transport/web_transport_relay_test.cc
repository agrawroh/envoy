#include <memory>
#include <string>
#include <vector>

#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {
namespace {

// A WebTransport session that records sent datagrams and exposes the registered callbacks so a
// test can drive received datagrams and close events. When notify_on_destroy_ is set the
// destructor notifies its consumer, mimicking the session bridge teardown.
class FakeWebTransportSession : public Envoy::Http::WebTransportSession {
public:
  ~FakeWebTransportSession() override {
    if (notify_on_destroy_ && callbacks_ != nullptr) {
      callbacks_->onWebTransportSessionClosed();
    }
  }
  bool sessionLimitExceeded() const override { return false; }
  void
  setWebTransportSessionCallbacks(Envoy::Http::WebTransportSessionCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  void sendWebTransportDatagram(absl::string_view datagram) override {
    sent_.emplace_back(datagram);
  }

  Envoy::Http::WebTransportSessionCallbacks* callbacks_{nullptr};
  std::vector<std::string> sent_;
  bool notify_on_destroy_{false};
};

// Counts relay close notifications.
class CountingRelayCallbacks : public WebTransportRelay::Callbacks {
public:
  void onRelayClosed() override { ++closed_count_; }
  int closed_count_{0};
};

class WebTransportRelayTest : public testing::Test {
protected:
  FakeWebTransportSession downstream_;
  FakeWebTransportSession upstream_;
  CountingRelayCallbacks callbacks_;
};

// The relay registers callbacks on both sessions when it is created.
TEST_F(WebTransportRelayTest, RegistersOnBothSessions) {
  WebTransportRelay relay(downstream_, upstream_, callbacks_);
  EXPECT_NE(nullptr, downstream_.callbacks_);
  EXPECT_NE(nullptr, upstream_.callbacks_);
}

// A datagram received on the downstream session is forwarded to the upstream session.
TEST_F(WebTransportRelayTest, ForwardsDownstreamToUpstream) {
  WebTransportRelay relay(downstream_, upstream_, callbacks_);
  downstream_.callbacks_->onWebTransportDatagram("ping");
  ASSERT_EQ(1, upstream_.sent_.size());
  EXPECT_EQ("ping", upstream_.sent_[0]);
  EXPECT_TRUE(downstream_.sent_.empty());
}

// A datagram received on the upstream session is forwarded to the downstream session.
TEST_F(WebTransportRelayTest, ForwardsUpstreamToDownstream) {
  WebTransportRelay relay(downstream_, upstream_, callbacks_);
  upstream_.callbacks_->onWebTransportDatagram("pong");
  ASSERT_EQ(1, downstream_.sent_.size());
  EXPECT_EQ("pong", downstream_.sent_[0]);
  EXPECT_TRUE(upstream_.sent_.empty());
}

// On close the relay detaches from the session and stops forwarding to it.
TEST_F(WebTransportRelayTest, DetachesAndStopsForwardingOnClose) {
  WebTransportRelay relay(downstream_, upstream_, callbacks_);
  downstream_.callbacks_->onWebTransportSessionClosed();
  EXPECT_EQ(nullptr, downstream_.callbacks_);
  upstream_.callbacks_->onWebTransportDatagram("pong");
  EXPECT_TRUE(downstream_.sent_.empty());
}

// The owner is notified exactly once even when both sessions close.
TEST_F(WebTransportRelayTest, NotifiesOwnerOnceOnClose) {
  WebTransportRelay relay(downstream_, upstream_, callbacks_);
  downstream_.callbacks_->onWebTransportSessionClosed();
  EXPECT_EQ(1, callbacks_.closed_count_);
  upstream_.callbacks_->onWebTransportSessionClosed();
  EXPECT_EQ(1, callbacks_.closed_count_);
}

// The relay detaches from both sessions when it is destroyed.
TEST_F(WebTransportRelayTest, DetachesOnDestruction) {
  {
    WebTransportRelay relay(downstream_, upstream_, callbacks_);
    EXPECT_NE(nullptr, downstream_.callbacks_);
    EXPECT_NE(nullptr, upstream_.callbacks_);
  }
  EXPECT_EQ(nullptr, downstream_.callbacks_);
  EXPECT_EQ(nullptr, upstream_.callbacks_);
}

// When a session bridge is destroyed it notifies the relay, which drops it so the relay neither
// forwards to nor detaches from the freed session.
TEST_F(WebTransportRelayTest, SurvivesSessionDestroyedFirst) {
  auto downstream = std::make_unique<FakeWebTransportSession>();
  downstream->notify_on_destroy_ = true;
  WebTransportRelay relay(*downstream, upstream_, callbacks_);

  downstream.reset();
  EXPECT_EQ(1, callbacks_.closed_count_);

  // A datagram from the still open upstream is not forwarded to the freed session.
  upstream_.callbacks_->onWebTransportDatagram("pong");
  // The relay still detaches cleanly from the open upstream on destruction.
}

} // namespace
} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
