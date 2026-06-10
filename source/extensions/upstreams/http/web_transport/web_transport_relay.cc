#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

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
