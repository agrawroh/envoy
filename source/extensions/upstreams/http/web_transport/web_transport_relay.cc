#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

#include <array>

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

namespace {
// Matches the QUICHE default stream read budget. Reads larger than this are split across pumps.
constexpr size_t MaxStreamReadSize = 16 * 1024;
// Error code relayed to a peer when its counterpart stream is gone.
constexpr uint32_t StreamGoneErrorCode = 0;
} // namespace

WebTransportStreamRelay::WebTransportStreamRelay(Envoy::Http::WebTransportStream& incoming,
                                                 Envoy::Http::WebTransportStream& mirror)
    : incoming_(incoming), mirror_(mirror), incoming_end_(*this, true), mirror_end_(*this, false) {
  incoming_.setWebTransportStreamCallbacks(&incoming_end_);
  mirror_.setWebTransportStreamCallbacks(&mirror_end_);
  // Drain anything already buffered on the incoming stream.
  pump(true);
}

void WebTransportStreamRelay::pump(bool from_incoming) {
  Envoy::Http::WebTransportStream& source = stream(from_incoming);
  Envoy::Http::WebTransportStream& destination = stream(!from_incoming);
  std::string& pending = from_incoming ? incoming_pending_ : mirror_pending_;
  bool& pending_fin = from_incoming ? incoming_pending_fin_ : mirror_pending_fin_;
  bool& done = from_incoming ? incoming_done_ : mirror_done_;
  if (done) {
    return;
  }

  // Flush bytes held from an earlier blocked write before reading more.
  if (!pending.empty()) {
    if (!destination.canWriteWebTransportStream() ||
        !destination.writeWebTransportStream(pending, pending_fin)) {
      return;
    }
    pending.clear();
    if (pending_fin) {
      done = true;
      return;
    }
  }

  std::array<char, MaxStreamReadSize> buffer;
  while (destination.canWriteWebTransportStream()) {
    Envoy::Http::WebTransportStreamReadResult result =
        source.readWebTransportStream(absl::MakeSpan(buffer));
    if (result.bytes_read == 0 && !result.end_stream) {
      return;
    }
    absl::string_view data(buffer.data(), result.bytes_read);
    if (!destination.writeWebTransportStream(data, result.end_stream)) {
      // Hold the bytes and the end flag until the destination can write again.
      pending.assign(data.data(), data.size());
      pending_fin = result.end_stream;
      return;
    }
    if (result.end_stream) {
      done = true;
      return;
    }
  }
}

void WebTransportStreamRelay::onReset(bool on_incoming, uint32_t error_code) {
  stream(!on_incoming).resetWebTransportStream(error_code);
}

void WebTransportStreamRelay::onStopSending(bool on_incoming, uint32_t error_code) {
  stream(!on_incoming).stopSendingWebTransportStream(error_code);
}

WebTransportRelay::WebTransportRelay(Envoy::Http::WebTransportSession& downstream,
                                     Envoy::Http::WebTransportSession& upstream,
                                     Callbacks& callbacks)
    : callbacks_(callbacks), downstream_side_(*this, Direction::Downstream),
      upstream_side_(*this, Direction::Upstream), downstream_(&downstream), upstream_(&upstream) {
  downstream_->setWebTransportSessionCallbacks(&downstream_side_);
  upstream_->setWebTransportSessionCallbacks(&upstream_side_);
  ENVOY_LOG(debug, "WebTransport relay established");
}

WebTransportRelay::~WebTransportRelay() {
  if (downstream_ != nullptr) {
    downstream_->setWebTransportSessionCallbacks(nullptr);
  }
  if (upstream_ != nullptr) {
    upstream_->setWebTransportSessionCallbacks(nullptr);
  }
}

void WebTransportRelay::forwardDatagram(Direction from, absl::string_view datagram) {
  Envoy::Http::WebTransportSession* peer = from == Direction::Downstream ? upstream_ : downstream_;
  if (peer != nullptr) {
    peer->sendWebTransportDatagram(datagram);
  }
}

void WebTransportRelay::relayStream(Direction from, Envoy::Http::WebTransportStream& incoming,
                                    bool bidirectional) {
  Envoy::Http::WebTransportSession* peer = from == Direction::Downstream ? upstream_ : downstream_;
  if (peer == nullptr || !peer->canOpenWebTransportStream(bidirectional)) {
    // The peer session is gone or cannot open a stream now, so reject this one.
    incoming.resetWebTransportStream(StreamGoneErrorCode);
    return;
  }
  Envoy::Http::WebTransportStream* mirror = peer->openWebTransportStream(bidirectional);
  if (mirror == nullptr) {
    incoming.resetWebTransportStream(StreamGoneErrorCode);
    return;
  }
  stream_relays_.push_back(std::make_unique<WebTransportStreamRelay>(incoming, *mirror));
}

void WebTransportRelay::onSessionClosed(Direction which) {
  Envoy::Http::WebTransportSession*& closed = session(which);
  if (closed != nullptr) {
    // Detach so a late event cannot reach the relay after the session closes, and drop the pointer
    // so the relay stops forwarding to it.
    closed->setWebTransportSessionCallbacks(nullptr);
    closed = nullptr;
  }
  if (!notified_) {
    notified_ = true;
    callbacks_.onRelayClosed();
  }
}

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
