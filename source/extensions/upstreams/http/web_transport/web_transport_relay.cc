#include "source/extensions/upstreams/http/web_transport/web_transport_relay.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

WebTransportRelay::Side::Side(WebTransportRelay& relay, Envoy::Http::WebTransportSession& self,
                              Envoy::Http::WebTransportSession& peer)
    : relay_(relay), self_(self), peer_(peer) {
  self_.setWebTransportSessionCallbacks(this);
}

WebTransportRelay::WebTransportRelay(Envoy::Http::WebTransportSession& downstream,
                                     Envoy::Http::WebTransportSession& upstream,
                                     Callbacks& callbacks)
    : callbacks_(callbacks), downstream_side_(*this, downstream, upstream),
      upstream_side_(*this, upstream, downstream) {
  ENVOY_LOG(debug, "WebTransport relay established");
}

void WebTransportRelay::onSideClosed() {
  if (closed_) {
    return;
  }
  closed_ = true;
  ENVOY_LOG(debug, "WebTransport relay closing");
  callbacks_.onRelayClosed();
}

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
