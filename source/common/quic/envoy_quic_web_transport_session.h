#pragma once

#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"
#include "source/common/quic/web_transport_stats.h"

#include "quiche/quic/core/http/web_transport_http3.h"

namespace Envoy {
namespace Quic {

// Adapts a vendored QUICHE WebTransportHttp3 session to the Envoy Http::WebTransportSession
// interface so an HTTP filter can terminate a session without including QUICHE headers. The bridge
// and the QUICHE session share one owner, the EnvoyQuicServerStream. The bridge is a derived-class
// member so it destructs before the base-class QUICHE session that owns the visitor. The
// destructor detaches the visitor and the visitor null checks the bridge, so neither outlives the
// other unsafely.
class EnvoyQuicWebTransportSession : public Http::WebTransportSession,
                                     protected Logger::Loggable<Logger::Id::connection> {
public:
  EnvoyQuicWebTransportSession(quic::WebTransportHttp3* session, WebTransportStats& stats,
                               bool session_limit_exceeded)
      : session_(session), stats_(stats), session_limit_exceeded_(session_limit_exceeded) {}
  ~EnvoyQuicWebTransportSession() override;

  // Installs the QUICHE session visitor and marks the session ready. Must be called after the 2xx
  // response headers are written and only when a filter has claimed the session. Idempotent.
  void accept();

  // Whether an HTTP filter has registered to consume the session.
  bool claimed() const { return callbacks_ != nullptr; }

  // Http::WebTransportSession
  bool sessionLimitExceeded() const override { return session_limit_exceeded_; }
  void setWebTransportSessionCallbacks(Http::WebTransportSessionCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  void sendWebTransportDatagram(absl::string_view datagram) override;

private:
  // QUICHE session visitor. The QUICHE session owns it and outlives the bridge, so it holds a back
  // pointer that the bridge clears on destruction.
  class Visitor : public webtransport::SessionVisitor {
  public:
    explicit Visitor(EnvoyQuicWebTransportSession& bridge) : bridge_(&bridge) {}
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
    EnvoyQuicWebTransportSession* bridge_;
  };

  // Drops the active-session gauge once. Called from the close path and the destructor.
  void releaseActiveGauge();

  quic::WebTransportHttp3* session_;
  WebTransportStats& stats_;
  Http::WebTransportSessionCallbacks* callbacks_{nullptr};
  Visitor* visitor_{nullptr};
  const bool session_limit_exceeded_;
  bool accepted_{false};
  bool closed_{false};
  bool active_gauge_held_{false};
};

} // namespace Quic
} // namespace Envoy
