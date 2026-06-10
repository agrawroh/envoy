#pragma once

#include "envoy/common/pure.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Http {

// Application callbacks for a terminated WebTransport session. Implemented by the HTTP filter.
class WebTransportSessionCallbacks {
public:
  virtual ~WebTransportSessionCallbacks() = default;

  // Called once the session is ready. Delivered synchronously while the accepting response is
  // encoded.
  virtual void onWebTransportSessionReady() PURE;

  // Called for each received datagram. The view is valid only during the call.
  virtual void onWebTransportDatagram(absl::string_view datagram) PURE;

  // Called once when the session closes. No further callbacks or calls are valid afterward.
  virtual void onWebTransportSessionClosed() PURE;
};

// Application surface for a terminated WebTransport session. The QUIC layer adapts the vendored
// QUICHE session so consumers avoid QUICHE headers. Owned by the codec stream and valid until
// onWebTransportSessionClosed() or filter destruction.
class WebTransportSession {
public:
  virtual ~WebTransportSession() = default;

  // Whether the connection is already at its WebTransport session limit. A consumer must reject the
  // request instead of claiming the session when this is true.
  virtual bool sessionLimitExceeded() const PURE;

  // Registers session-event callbacks. A nullptr detaches the consumer.
  virtual void setWebTransportSessionCallbacks(WebTransportSessionCallbacks* callbacks) PURE;

  // Sends a datagram on the session. Datagrams are unreliable and may be dropped.
  virtual void sendWebTransportDatagram(absl::string_view datagram) PURE;
};

} // namespace Http
} // namespace Envoy
