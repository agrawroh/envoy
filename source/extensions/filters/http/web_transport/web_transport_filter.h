#pragma once

#include "envoy/http/filter.h"
#include "envoy/http/web_transport.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WebTransport {

// Terminates a WebTransport over HTTP/3 session and echoes received datagrams back to the client.
// The session reference comes from the codec stream and is detached on filter destruction.
class WebTransportFilter : public Http::PassThroughFilter,
                           public Http::WebTransportSessionCallbacks,
                           public Logger::Loggable<Logger::Id::filter> {
public:
  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  void onDestroy() override;

  // Http::WebTransportSessionCallbacks
  void onWebTransportSessionReady() override {}
  void onWebTransportDatagram(absl::string_view datagram) override;
  void onWebTransportSessionClosed() override;
  // This reference handler echoes datagrams only and does not relay data streams.
  void onWebTransportStreamIncoming(Http::WebTransportStream&, bool) override {}
  void onCanCreateWebTransportStream(bool) override {}

private:
  Http::WebTransportSession* session_{nullptr};
};

} // namespace WebTransport
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
