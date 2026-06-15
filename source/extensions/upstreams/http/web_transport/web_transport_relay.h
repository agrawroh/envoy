#pragma once

#include <memory>
#include <string>
#include <vector>

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Upstreams {
namespace Http {
namespace WebTransport {

class WebTransportRelay;

// Relays one WebTransport data stream onto a mirror stream on the peer session, in both directions
// for a bidirectional stream. Reads are gated on the peer being writable, so a slow peer applies
// backpressure to the source. A stream that closes resolves to a no-op in the session, so the relay
// holds the pair for the life of the session relay.
class WebTransportStreamRelay {
public:
  WebTransportStreamRelay(WebTransportRelay& owner, Envoy::Http::WebTransportStream& incoming,
                          Envoy::Http::WebTransportStream& mirror);
  // Detaches the End callbacks so a stream that outlives the relay does not reach a freed End.
  ~WebTransportStreamRelay();

  // Whether both directions have closed, so the owner can reclaim this relay.
  bool finished() const { return incoming_done_ && mirror_done_; }

private:
  // One end of the relayed stream pair. Routes the stream's events to the relay. Its callbacks are
  // registered on the stream for the life of the relay and detached when the relay is destroyed.
  class End : public Envoy::Http::WebTransportStreamCallbacks {
  public:
    End(WebTransportStreamRelay& relay, bool incoming) : relay_(relay), incoming_(incoming) {}

    // Http::WebTransportStreamCallbacks
    void onWebTransportStreamData() override {
      relay_.notifyActivity();
      relay_.pump(incoming_);
    }
    // When this stream can write again, resume the pump whose destination is this stream, which
    // reads from the opposite direction.
    void onWebTransportStreamCanWrite() override {
      relay_.notifyActivity();
      relay_.pump(!incoming_);
    }
    void onWebTransportStreamReset(uint32_t error_code) override {
      relay_.onReset(incoming_, error_code);
    }
    void onWebTransportStreamStopSending(uint32_t error_code) override {
      relay_.onStopSending(incoming_, error_code);
    }

  private:
    WebTransportStreamRelay& relay_;
    const bool incoming_;
  };

  // Moves readable bytes from the source stream to the peer, holding bytes a blocked peer cannot
  // accept yet. from_incoming selects the source direction.
  void pump(bool from_incoming);
  // Tells the owner the relayed stream saw read or write activity, so a busy session is not reaped.
  void notifyActivity();
  void onReset(bool on_incoming, uint32_t error_code);
  void onStopSending(bool on_incoming, uint32_t error_code);
  Envoy::Http::WebTransportStream& stream(bool incoming) { return incoming ? incoming_ : mirror_; }

  WebTransportRelay& owner_;
  Envoy::Http::WebTransportStream& incoming_;
  Envoy::Http::WebTransportStream& mirror_;
  End incoming_end_;
  End mirror_end_;
  // Bytes read from one side that the other side could not accept yet, flushed on the next write
  // opportunity. Indexed by source direction.
  std::string incoming_pending_;
  std::string mirror_pending_;
  bool incoming_pending_fin_{false};
  bool mirror_pending_fin_{false};
  bool incoming_done_{false};
  bool mirror_done_{false};
};

// Relays datagrams and data streams between a downstream WebTransport session and an upstream one.
// The relay registers on both sessions and forwards each received datagram to the peer and mirrors
// each opened stream onto the peer. When a session closes the relay detaches from it and stops
// forwarding, then notifies the owner once so the owner can tear the proxied flow down. The relay
// also detaches from any still open session on destruction, so no session is ever left holding a
// callback into a freed relay.
class WebTransportRelay : protected Logger::Loggable<Logger::Id::upstream> {
public:
  // Notified of relay events on the owning upstream.
  class Callbacks {
  public:
    virtual ~Callbacks() = default;
    // Called once when either session closes.
    virtual void onRelayClosed() PURE;
    // Called for each datagram forwarded to a peer, so the owner can count it.
    virtual void onDatagramRelayed() PURE;
    // Called when a data stream is relayed, so the owner can keep a busy session alive.
    virtual void onWebTransportActivity() PURE;
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
    void onWebTransportStreamIncoming(Envoy::Http::WebTransportStream& stream,
                                      bool bidirectional) override {
      relay_.relayStream(direction_, stream, bidirectional);
    }
    void onCanCreateWebTransportStream(bool) override {}

  private:
    WebTransportRelay& relay_;
    const Direction direction_;
  };

  void forwardDatagram(Direction from, absl::string_view datagram);
  void onSessionClosed(Direction which);
  void relayStream(Direction from, Envoy::Http::WebTransportStream& incoming, bool bidirectional);
  // Signals relay activity to the owner so a busy session is not reaped. Called when a stream is
  // opened and when a relayed stream sees read or write activity.
  void signalActivity() { callbacks_.onWebTransportActivity(); }
  Envoy::Http::WebTransportSession*& session(Direction direction) {
    return direction == Direction::Downstream ? downstream_ : upstream_;
  }

  friend class WebTransportStreamRelay;

  Callbacks& callbacks_;
  Side downstream_side_;
  Side upstream_side_;
  // Nulled when the matching session closes so the relay neither forwards to nor detaches a freed
  // session.
  Envoy::Http::WebTransportSession* downstream_;
  Envoy::Http::WebTransportSession* upstream_;
  // Each relayed stream pair holds its End callbacks on the peer stream adapters while live.
  // Finished pairs are reclaimed when the next stream is relayed, and the whole list is cleared
  // when either session closes, so a peer cannot grow this without bound through stream churn.
  std::vector<std::unique_ptr<WebTransportStreamRelay>> stream_relays_;
  bool notified_{false};
};

} // namespace WebTransport
} // namespace Http
} // namespace Upstreams
} // namespace Extensions
} // namespace Envoy
