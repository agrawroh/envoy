#include "source/common/quic/envoy_quic_client_web_transport_session.h"

#include <string>

namespace Envoy {
namespace Quic {

EnvoyQuicClientWebTransportSession::EnvoyQuicClientWebTransportSession(
    quic::WebTransportHttp3* session)
    : session_(session) {
  auto visitor = std::make_unique<Visitor>(*this);
  visitor_ = visitor.get();
  session_->SetVisitor(std::move(visitor));
}

EnvoyQuicClientWebTransportSession::~EnvoyQuicClientWebTransportSession() {
  if (visitor_ != nullptr) {
    visitor_->detach();
  }
  // Tell a consumer the session is gone if it was not already closed, so it drops its reference
  // before this bridge is freed.
  if (!closed_ && callbacks_ != nullptr) {
    callbacks_->onWebTransportSessionClosed();
  }
}

void EnvoyQuicClientWebTransportSession::sendWebTransportDatagram(absl::string_view datagram) {
  if (closed_) {
    return;
  }
  session_->SendOrQueueDatagram(datagram);
}

void EnvoyQuicClientWebTransportSession::Visitor::OnSessionReady() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportSessionReady();
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnSessionClosed(
    webtransport::SessionErrorCode error_code, const std::string& error_message) {
  if (bridge_ == nullptr) {
    return;
  }
  ENVOY_LOG(debug, "upstream WebTransport session closed, error_code {} message {}", error_code,
            error_message);
  bridge_->closed_ = true;
  if (bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportSessionClosed();
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnDatagramReceived(absl::string_view datagram) {
  if (bridge_ == nullptr || bridge_->closed_) {
    return;
  }
  if (bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportDatagram(datagram);
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnIncomingBidirectionalStreamAvailable() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    // The client side does not enforce a per-session stream limit, the upstream server does.
    acceptIncomingWebTransportStreams(*bridge_->session_, bridge_->streams_, *bridge_->callbacks_,
                                      true, 0);
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnIncomingUnidirectionalStreamAvailable() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    acceptIncomingWebTransportStreams(*bridge_->session_, bridge_->streams_, *bridge_->callbacks_,
                                      false, 0);
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnCanCreateNewOutgoingBidirectionalStream() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onCanCreateWebTransportStream(true);
  }
}

void EnvoyQuicClientWebTransportSession::Visitor::OnCanCreateNewOutgoingUnidirectionalStream() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onCanCreateWebTransportStream(false);
  }
}

bool EnvoyQuicClientWebTransportSession::canOpenWebTransportStream(bool bidirectional) const {
  return bidirectional ? session_->CanOpenNextOutgoingBidirectionalStream()
                       : session_->CanOpenNextOutgoingUnidirectionalStream();
}

Http::WebTransportStream*
EnvoyQuicClientWebTransportSession::openWebTransportStream(bool bidirectional) {
  return openTrackedWebTransportStream(*session_, streams_, bidirectional);
}

} // namespace Quic
} // namespace Envoy
