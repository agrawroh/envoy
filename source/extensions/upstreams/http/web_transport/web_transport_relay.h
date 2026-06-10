#pragma once

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

// Relays datagrams between a downstream WebTransport session and an upstream one. The relay
// registers on both sessions and forwards each received datagram to the peer. When a session
// closes the relay detaches from it and stops forwarding, then notifies the owner once so the
// owner can tear the proxied flow down. The relay also detaches from any still open session on
// destruction, so no session is ever left holding a callback into a freed relay.
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

  Callbacks& callbacks_;
  Side downstream_side_;
  Side upstream_side_;
  // Nulled when the matching session closes so the relay neither forwards to nor detaches a freed
  // session.
  Envoy::Http::WebTransportSession* downstream_;
  Envoy::Http::WebTransportSession* upstream_;
  bool notified_{false};
};

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
