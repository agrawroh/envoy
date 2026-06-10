#include "source/common/quic/envoy_quic_web_transport_session.h"

#include <string>

#include "source/common/common/assert.h"

#include "quiche/common/http/http_header_block.h"

namespace Envoy {
namespace Quic {

EnvoyQuicWebTransportSession::~EnvoyQuicWebTransportSession() {
  // The stats are owned by the session and freed before the QUICHE stream maps that hold this
  // bridge, so the active gauge must already be released by the stream close path.
  ASSERT(!active_gauge_held_);
  if (visitor_ != nullptr) {
    visitor_->detach();
  }
  // Tell a consumer the session is gone if it was not already closed, so it drops its reference
  // before this bridge is freed.
  if (!closed_ && callbacks_ != nullptr) {
    callbacks_->onWebTransportSessionClosed();
  }
}

void EnvoyQuicWebTransportSession::accept() {
  // QUICHE does not guard a second SetVisitor or HeadersReceived, so latch here.
  if (accepted_) {
    return;
  }
  accepted_ = true;
  stats_.sessions_total_.inc();
  stats_.sessions_active_.inc();
  active_gauge_held_ = true;
  ENVOY_LOG(debug, "accepting WebTransport session");
  auto visitor = std::make_unique<Visitor>(*this);
  visitor_ = visitor.get();
  session_->SetVisitor(std::move(visitor));
  // The server side ignores the header block, so an empty one is sufficient.
  session_->HeadersReceived(quiche::HttpHeaderBlock());
}

void EnvoyQuicWebTransportSession::sendWebTransportDatagram(absl::string_view datagram) {
  if (closed_) {
    return;
  }
  stats_.datagrams_tx_.inc();
  session_->SendOrQueueDatagram(datagram);
}

void EnvoyQuicWebTransportSession::releaseActiveGauge() {
  if (active_gauge_held_) {
    stats_.sessions_active_.dec();
    active_gauge_held_ = false;
  }
}

void EnvoyQuicWebTransportSession::Visitor::OnSessionReady() {
  if (bridge_ != nullptr && bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportSessionReady();
  }
}

void EnvoyQuicWebTransportSession::Visitor::OnSessionClosed(
    webtransport::SessionErrorCode error_code, const std::string& error_message) {
  if (bridge_ == nullptr) {
    return;
  }
  ENVOY_LOG(debug, "WebTransport session closed, error_code {} message {}", error_code,
            error_message);
  bridge_->closed_ = true;
  bridge_->releaseActiveGauge();
  if (bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportSessionClosed();
  }
}

void EnvoyQuicWebTransportSession::Visitor::OnDatagramReceived(absl::string_view datagram) {
  if (bridge_ == nullptr || bridge_->closed_) {
    return;
  }
  bridge_->stats_.datagrams_rx_.inc();
  if (bridge_->callbacks_ != nullptr) {
    bridge_->callbacks_->onWebTransportDatagram(datagram);
  }
}

} // namespace Quic
} // namespace Envoy
