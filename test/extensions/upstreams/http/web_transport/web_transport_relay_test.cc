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
// test can drive received datagrams and close events.
class FakeWebTransportSession : public Envoy::Http::WebTransportSession {
public:
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
};

class WebTransportRelayTest : public testing::Test {
protected:
  FakeWebTransportSession downstream_;
  FakeWebTransportSession upstream_;
};

// The relay registers callbacks on both sessions when it is created.
TEST_F(WebTransportRelayTest, RegistersOnBothSessions) {
  WebTransportRelay relay(downstream_, upstream_);
  EXPECT_NE(nullptr, downstream_.callbacks_);
  EXPECT_NE(nullptr, upstream_.callbacks_);
}

// A datagram received on the downstream session is forwarded to the upstream session.
TEST_F(WebTransportRelayTest, ForwardsDownstreamToUpstream) {
  WebTransportRelay relay(downstream_, upstream_);
  downstream_.callbacks_->onWebTransportDatagram("ping");
  ASSERT_EQ(1, upstream_.sent_.size());
  EXPECT_EQ("ping", upstream_.sent_[0]);
  EXPECT_TRUE(downstream_.sent_.empty());
}

// A datagram received on the upstream session is forwarded to the downstream session.
TEST_F(WebTransportRelayTest, ForwardsUpstreamToDownstream) {
  WebTransportRelay relay(downstream_, upstream_);
  upstream_.callbacks_->onWebTransportDatagram("pong");
  ASSERT_EQ(1, downstream_.sent_.size());
  EXPECT_EQ("pong", downstream_.sent_[0]);
  EXPECT_TRUE(upstream_.sent_.empty());
}

// Once a session closes, the relay stops forwarding to it.
TEST_F(WebTransportRelayTest, StopsForwardingToClosedSession) {
  WebTransportRelay relay(downstream_, upstream_);
  downstream_.callbacks_->onWebTransportSessionClosed();
  upstream_.callbacks_->onWebTransportDatagram("pong");
  EXPECT_TRUE(downstream_.sent_.empty());
}

// The relay detaches from a session that is still open when it is destroyed, but leaves a closed
// session alone because that session is going away.
TEST_F(WebTransportRelayTest, DetachesOpenSessionsOnDestruction) {
  {
    WebTransportRelay relay(downstream_, upstream_);
    downstream_.callbacks_->onWebTransportSessionClosed();
  }
  EXPECT_NE(nullptr, downstream_.callbacks_);
  EXPECT_EQ(nullptr, upstream_.callbacks_);
}

} // namespace
} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
