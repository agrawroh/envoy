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

} // namespace Quic
} // namespace Envoy
