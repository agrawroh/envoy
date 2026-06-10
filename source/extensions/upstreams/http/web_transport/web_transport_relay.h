#pragma once

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

// Relays datagrams between a downstream WebTransport session and an upstream one. The relay
// registers on both sessions and forwards each received datagram to the peer. A session that closes
// drops out of the relay, so the relay never forwards to or detaches from a freed session, and the
// relay detaches from any still open session on destruction. Stream resets tear the proxied flow
// down, so the relay does not propagate closure itself.
class WebTransportRelay : protected Logger::Loggable<Logger::Id::upstream> {
public:
  WebTransportRelay(Envoy::Http::WebTransportSession& downstream,
                    Envoy::Http::WebTransportSession& upstream);
  ~WebTransportRelay();

private:
  enum class Direction { Downstream, Upstream };

  // Routes one session's events to the relay. The relay owns both Side objects.
  class Side : public Envoy::Http::WebTransportSessionCallbacks {
  public:
    Side(WebTransportRelay& relay, Direction direction) : relay_(relay), direction_(direction) {}

    // Http::WebTransportSessionCallbacks
    void onWebTransportSessionReady() override {}
    void onWebTransportDatagram(absl::string_view datagram) override {
      relay_.forwardDatagram(direction_, datagram);
    }
    void onWebTransportSessionClosed() override { relay_.onSessionClosed(direction_); }

  private:
    WebTransportRelay& relay_;
    const Direction direction_;
  };

  void forwardDatagram(Direction from, absl::string_view datagram);
  void onSessionClosed(Direction which);
  Envoy::Http::WebTransportSession*& session(Direction direction) {
    return direction == Direction::Downstream ? downstream_ : upstream_;
  }

  Side downstream_side_;
  Side upstream_side_;
  // Nulled when the matching session closes so the relay neither forwards to nor detaches a freed
  // session.
  Envoy::Http::WebTransportSession* downstream_;
  Envoy::Http::WebTransportSession* upstream_;
};

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
