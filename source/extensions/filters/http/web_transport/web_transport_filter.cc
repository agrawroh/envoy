#include "source/extensions/filters/http/web_transport/web_transport_filter.h"

#include "source/common/http/header_map_impl.h"

#include "quiche/web_transport/web_transport_headers.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WebTransport {

namespace {
// Selects a subprotocol for the 200 response by echoing the client's most preferred offer. The
// client lists its offers in the wt-available-protocols request header as a structured field list,
// most preferred first, and the server returns its single choice in the wt-protocol response
// header. A missing or malformed offer leaves the response without a selection, which the spec
// allows, so negotiation never fails the handshake.
void maybeSelectSubprotocol(const Http::RequestHeaderMap& request_headers,
                            Http::ResponseHeaderMap& response_headers) {
  const auto offer = request_headers.get(
      Http::LowerCaseString(std::string(webtransport::kSubprotocolRequestHeader)));
  if (offer.empty()) {
    return;
  }
  const absl::StatusOr<std::vector<std::string>> offered =
      webtransport::ParseSubprotocolRequestHeader(offer[0]->value().getStringView());
  if (!offered.ok() || offered->empty()) {
    return;
  }
  const absl::StatusOr<std::string> selected =
      webtransport::SerializeSubprotocolResponseHeader(offered->front());
  if (!selected.ok()) {
    return;
  }
  response_headers.addCopy(
      Http::LowerCaseString(std::string(webtransport::kSubprotocolResponseHeader)), *selected);
}
} // namespace

Http::FilterHeadersStatus WebTransportFilter::decodeHeaders(Http::RequestHeaderMap& request_headers,
                                                            bool) {
  OptRef<Http::WebTransportSession> session = decoder_callbacks_->webTransport();
  if (!session.has_value()) {
    // Not a WebTransport session. Let normal routing handle the request.
    return Http::FilterHeadersStatus::Continue;
  }
  if (session->sessionLimitExceeded()) {
    // The connection is at its WebTransport session limit. Reject without a body so the client
    // capsule parser is not fed an unexpected payload.
    ENVOY_STREAM_LOG(debug, "rejecting WebTransport session over the connection limit",
                     *decoder_callbacks_);
    Http::ResponseHeaderMapPtr headers = Http::ResponseHeaderMapImpl::create();
    headers->setStatus(429);
    decoder_callbacks_->encodeHeaders(std::move(headers), true, "web_transport_session_limit");
    return Http::FilterHeadersStatus::StopIteration;
  }
  session_ = &session.ref();
  session_->setWebTransportSessionCallbacks(this);

  // Accept the session with a 200. The response must not end the stream so the session stays open.
  ENVOY_STREAM_LOG(debug, "accepting WebTransport session", *decoder_callbacks_);
  Http::ResponseHeaderMapPtr response_headers = Http::ResponseHeaderMapImpl::create();
  response_headers->setStatus(200);
  maybeSelectSubprotocol(request_headers, *response_headers);
  decoder_callbacks_->encodeHeaders(std::move(response_headers), false, "web_transport");
  return Http::FilterHeadersStatus::StopIteration;
}

void WebTransportFilter::onWebTransportDatagram(absl::string_view datagram) {
  if (session_ != nullptr) {
    // Session activity keeps the stream alive, so reset the idle timer on each datagram.
    decoder_callbacks_->resetIdleTimer();
    ENVOY_LOG(trace, "echoing WebTransport datagram of {} bytes", datagram.size());
    session_->sendWebTransportDatagram(datagram);
  }
}

void WebTransportFilter::onWebTransportSessionClosed() {
  ENVOY_LOG(debug, "WebTransport session closed");
  session_ = nullptr;
}

void WebTransportFilter::onDestroy() {
  if (session_ != nullptr) {
    session_->setWebTransportSessionCallbacks(nullptr);
    session_ = nullptr;
  }
}

} // namespace WebTransport
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
