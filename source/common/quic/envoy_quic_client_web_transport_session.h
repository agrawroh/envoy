#pragma once

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"

#include "quiche/quic/core/http/web_transport_http3.h"

namespace Envoy {
namespace Quic {

// Adapts a vendored QUICHE client WebTransportHttp3 session to the Envoy Http::WebTransportSession
// interface so the router upstream can relay a session without including QUICHE headers. The bridge
// and the QUICHE session share one owner, the EnvoyQuicClientStream. The bridge is a derived-class
// member so it destructs before the base-class QUICHE session that owns the visitor. The destructor
// detaches the visitor and the visitor null checks the bridge, so neither outlives the other
// unsafely. The bridge installs its visitor on construction because the client initiates the
// session rather than accepting one.
class EnvoyQuicClientWebTransportSession : public Http::WebTransportSession,
                                           protected Logger::Loggable<Logger::Id::connection> {
public:
  explicit EnvoyQuicClientWebTransportSession(quic::WebTransportHttp3* session);
  ~EnvoyQuicClientWebTransportSession() override;

  // Http::WebTransportSession
  // The client side does not enforce a session limit, the upstream server does.
  bool sessionLimitExceeded() const override { return false; }
  void setWebTransportSessionCallbacks(Http::WebTransportSessionCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  void sendWebTransportDatagram(absl::string_view datagram) override;

private:
  // QUICHE session visitor. The QUICHE session owns it and outlives the bridge, so it holds a back
  // pointer that the bridge clears on destruction.
  class Visitor : public webtransport::SessionVisitor {
  public:
    explicit Visitor(EnvoyQuicClientWebTransportSession& bridge) : bridge_(&bridge) {}
    void detach() { bridge_ = nullptr; }

    // webtransport::SessionVisitor
    void OnSessionReady() override;
    void OnSessionClosed(webtransport::SessionErrorCode error_code,
                         const std::string& error_message) override;
    void OnIncomingBidirectionalStreamAvailable() override {}
    void OnIncomingUnidirectionalStreamAvailable() override {}
    void OnDatagramReceived(absl::string_view datagram) override;
    void OnCanCreateNewOutgoingBidirectionalStream() override {}
    void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  private:
    EnvoyQuicClientWebTransportSession* bridge_;
  };

  quic::WebTransportHttp3* session_;
  Http::WebTransportSessionCallbacks* callbacks_{nullptr};
  Visitor* visitor_{nullptr};
  bool closed_{false};
};

} // namespace Quic
} // namespace Envoy
