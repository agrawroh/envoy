#include <algorithm>
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

// A WebTransport stream that serves queued readable bytes, records writes, and gates writes on a
// settable flag so a test can drive backpressure.
class FakeWebTransportStream : public Envoy::Http::WebTransportStream {
public:
  explicit FakeWebTransportStream(bool bidirectional) : bidirectional_(bidirectional) {}

  bool bidirectional() const override { return bidirectional_; }
  void
  setWebTransportStreamCallbacks(Envoy::Http::WebTransportStreamCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  Envoy::Http::WebTransportStreamReadResult
  readWebTransportStream(absl::Span<char> buffer) override {
    const size_t count = std::min(buffer.size(), readable_.size());
    std::copy_n(readable_.begin(), count, buffer.begin());
    readable_.erase(0, count);
    const bool end = readable_.empty() && read_fin_;
    return {count, end};
  }
  bool writeWebTransportStream(absl::string_view data, bool end_stream) override {
    if (!can_write_) {
      return false;
    }
    written_.append(data.data(), data.size());
    wrote_fin_ = wrote_fin_ || end_stream;
    return true;
  }
  bool canWriteWebTransportStream() const override { return can_write_; }
  void resetWebTransportStream(uint32_t error_code) override {
    reset_ = true;
    reset_code_ = error_code;
  }
  void stopSendingWebTransportStream(uint32_t error_code) override {
    stop_sending_ = true;
    stop_sending_code_ = error_code;
  }

  const bool bidirectional_;
  Envoy::Http::WebTransportStreamCallbacks* callbacks_{nullptr};
  std::string readable_;
  bool read_fin_{false};
  bool can_write_{true};
  std::string written_;
  bool wrote_fin_{false};
  bool reset_{false};
  uint32_t reset_code_{0};
  bool stop_sending_{false};
  uint32_t stop_sending_code_{0};
};

// A WebTransport session that records sent datagrams and exposes the registered callbacks so a
// test can drive received datagrams, opened streams and close events. When notify_on_destroy_ is
// set the destructor notifies its consumer, mimicking the session bridge teardown.
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
  bool canOpenWebTransportStream(bool) const override { return can_open_; }
  Envoy::Http::WebTransportStream* openWebTransportStream(bool) override { return next_outgoing_; }

  Envoy::Http::WebTransportSessionCallbacks* callbacks_{nullptr};
  std::vector<std::string> sent_;
  bool notify_on_destroy_{false};
  bool can_open_{true};
  Envoy::Http::WebTransportStream* next_outgoing_{nullptr};
};

// Counts relay close and datagram notifications.
class CountingRelayCallbacks : public WebTransportRelay::Callbacks {
public:
  void onRelayClosed() override { ++closed_count_; }
  void onDatagramRelayed() override { ++datagrams_relayed_; }
  void onWebTransportActivity() override { ++activity_count_; }
  int closed_count_{0};
  int datagrams_relayed_{0};
  int activity_count_{0};
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
  EXPECT_EQ(1, callbacks_.datagrams_relayed_);
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
  upstream_.callbacks_->onWebTransportDatagram("pong");
}

// An incoming stream is mirrored onto the peer session and its data is forwarded.
TEST_F(WebTransportRelayTest, MirrorsStreamAndForwardsData) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  incoming.readable_ = "hello";
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);

  EXPECT_NE(nullptr, incoming.callbacks_);
  EXPECT_EQ("hello", mirror.written_);
  // Relaying signals activity once for the stream open and once for the forwarded initial data.
  EXPECT_EQ(2, callbacks_.activity_count_);
}

// Data forwarded on an already open relayed stream signals activity, so a session whose only
// traffic is a long lived stream is kept alive.
TEST_F(WebTransportRelayTest, StreamDataSignalsActivity) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  // The open with no initial data signals once for the open.
  EXPECT_EQ(1, callbacks_.activity_count_);

  // More data arriving on the open stream forwards it and signals activity again.
  incoming.readable_ = "more";
  incoming.callbacks_->onWebTransportStreamData();
  EXPECT_EQ("more", mirror.written_);
  EXPECT_EQ(2, callbacks_.activity_count_);
}

// A blocked peer applies backpressure, and the held bytes flush once it can write again.
TEST_F(WebTransportRelayTest, StreamBackpressureHoldsThenFlushes) {
  FakeWebTransportStream mirror(true);
  mirror.can_write_ = false;
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  incoming.readable_ = "hello";
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  EXPECT_TRUE(mirror.written_.empty());

  mirror.can_write_ = true;
  mirror.callbacks_->onWebTransportStreamCanWrite();
  EXPECT_EQ("hello", mirror.written_);
}

// A reset received on one stream is propagated to its mirror.
TEST_F(WebTransportRelayTest, StreamResetPropagated) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  incoming.callbacks_->onWebTransportStreamReset(7);
  EXPECT_TRUE(mirror.reset_);
  EXPECT_EQ(7, mirror.reset_code_);
}

// When the peer session cannot open a mirror the incoming stream is reset rather than relayed.
TEST_F(WebTransportRelayTest, StreamRejectedWhenPeerCannotOpen) {
  upstream_.can_open_ = false;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  EXPECT_TRUE(incoming.reset_);
  // A rejected stream is not relayed, so it does not signal activity.
  EXPECT_EQ(0, callbacks_.activity_count_);
}

// A unidirectional stream is mirrored and its data forwarded.
TEST_F(WebTransportRelayTest, RelaysUnidirectionalStream) {
  FakeWebTransportStream mirror(false);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(false);
  incoming.readable_ = "uni";
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, false);
  EXPECT_EQ("uni", mirror.written_);
}

// A bidirectional stream forwards data in the mirror to incoming direction too.
TEST_F(WebTransportRelayTest, RelaysBidirectionalReverseDirection) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);

  mirror.readable_ = "back";
  mirror.callbacks_->onWebTransportStreamData();
  EXPECT_EQ("back", incoming.written_);
}

// A stop sending received on one stream is propagated to its mirror.
TEST_F(WebTransportRelayTest, StreamStopSendingPropagated) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  incoming.callbacks_->onWebTransportStreamStopSending(9);
  EXPECT_TRUE(mirror.stop_sending_);
  EXPECT_EQ(9, mirror.stop_sending_code_);
}

// Data carrying the end of stream is held while the peer is blocked and the end is delivered once
// the peer can write again.
TEST_F(WebTransportRelayTest, StreamFinFlushesAfterBackpressure) {
  FakeWebTransportStream mirror(true);
  mirror.can_write_ = false;
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  incoming.readable_ = "bye";
  incoming.read_fin_ = true;
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  EXPECT_TRUE(mirror.written_.empty());
  EXPECT_FALSE(mirror.wrote_fin_);

  mirror.can_write_ = true;
  mirror.callbacks_->onWebTransportStreamCanWrite();
  EXPECT_EQ("bye", mirror.written_);
  EXPECT_TRUE(mirror.wrote_fin_);
}

// A stream that ends without data forwards the end of stream to the mirror.
TEST_F(WebTransportRelayTest, RelaysLoneFin) {
  FakeWebTransportStream mirror(true);
  upstream_.next_outgoing_ = &mirror;
  WebTransportRelay relay(downstream_, upstream_, callbacks_);

  FakeWebTransportStream incoming(true);
  incoming.read_fin_ = true;
  downstream_.callbacks_->onWebTransportStreamIncoming(incoming, true);
  EXPECT_TRUE(mirror.written_.empty());
  EXPECT_TRUE(mirror.wrote_fin_);
}

} // namespace
} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
