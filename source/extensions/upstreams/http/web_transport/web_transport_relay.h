#pragma once

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

// Relays datagrams between a downstream WebTransport session and an upstream one. The relay
// registers callbacks on both sessions and forwards each received datagram to the peer. When
// either session closes it notifies the owner once so the owner can tear down the stream. The
// relay detaches from both sessions on destruction, so neither session is left with a dangling
// callback.
class WebTransportRelay : protected Logger::Loggable<Logger::Id::upstream> {
public:
  // Notified once when either session closes.
  class Callbacks {
  public:
    virtual ~Callbacks() = default;
    virtual void onRelayClosed() PURE;
  };

  WebTransportRelay(Envoy::Http::WebTransportSession& downstream,
                    Envoy::Http::WebTransportSession& upstream, Callbacks& callbacks);

private:
  // One direction of the relay. Forwards datagrams received on its own session to the peer and
  // reports a close back to the relay.
  class Side : public Envoy::Http::WebTransportSessionCallbacks {
  public:
    Side(WebTransportRelay& relay, Envoy::Http::WebTransportSession& self,
         Envoy::Http::WebTransportSession& peer);
    ~Side() override { self_.setWebTransportSessionCallbacks(nullptr); }

    // Http::WebTransportSessionCallbacks
    void onWebTransportSessionReady() override {}
    void onWebTransportDatagram(absl::string_view datagram) override {
      peer_.sendWebTransportDatagram(datagram);
    }
    void onWebTransportSessionClosed() override { relay_.onSideClosed(); }

  private:
    WebTransportRelay& relay_;
    Envoy::Http::WebTransportSession& self_;
    Envoy::Http::WebTransportSession& peer_;
  };

  // Notifies the owner the first time either session closes.
  void onSideClosed();

  Callbacks& callbacks_;
  Side downstream_side_;
  Side upstream_side_;
  bool closed_{false};
};

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
