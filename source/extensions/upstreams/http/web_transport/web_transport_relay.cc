#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

WebTransportRelay::WebTransportRelay(Envoy::Http::WebTransportSession& downstream,
                                     Envoy::Http::WebTransportSession& upstream)
    : downstream_side_(*this, Direction::Downstream), upstream_side_(*this, Direction::Upstream),
      downstream_(&downstream), upstream_(&upstream) {
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
  // The closed session is going away. Drop the pointer so the relay stops forwarding to it and does
  // not detach from it on destruction.
  session(which) = nullptr;
}

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
