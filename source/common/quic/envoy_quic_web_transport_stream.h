#pragma once

#include <memory>
#include <vector>

#include "envoy/http/web_transport.h"

#include "quiche/web_transport/web_transport.h"

namespace Envoy {
namespace Quic {

class EnvoyQuicWebTransportStream;

// Owns the WebTransport stream adapters created for one session. The adapters live for the session
// and become inert no-ops once their QUICHE stream closes, so individual streams need no cleanup.
using WebTransportStreamList = std::vector<std::unique_ptr<EnvoyQuicWebTransportStream>>;

// Opens an outgoing stream and tracks its adapter, or returns nullptr if flow control blocks it.
Http::WebTransportStream* openTrackedWebTransportStream(webtransport::Session& session,
                                                        WebTransportStreamList& streams,
                                                        bool bidirectional);

// Number of tracked adapters whose QUICHE stream is still open.
uint32_t liveWebTransportStreamCount(const WebTransportStreamList& streams);

// Accepts every pending incoming stream of the given kind, tracking each adapter and notifying the
// session callbacks. When max_streams is non-zero, a stream that would exceed the live count is
// reset instead of relayed. Returns the number of streams rejected this way.
uint32_t acceptIncomingWebTransportStreams(webtransport::Session& session,
                                           WebTransportStreamList& streams,
                                           Http::WebTransportSessionCallbacks& callbacks,
                                           bool bidirectional, uint32_t max_streams);

// Adapts a vendored QUICHE WebTransport stream to the Envoy Http::WebTransportStream interface so
// the router relay can move bytes without including QUICHE headers. The adapter holds the stream id
// and re-resolves the QUICHE stream on every call, because QUICHE stream pointers must not be
// retained. A QUICHE stream that has closed resolves to nullptr and every operation becomes a safe
// no-op. The adapter and its QUICHE stream visitor hold back pointers to each other and clear them
// on destruction, so whichever is freed first leaves no dangling pointer.
class EnvoyQuicWebTransportStream : public Http::WebTransportStream {
public:
  EnvoyQuicWebTransportStream(webtransport::Session& session, webtransport::StreamId id,
                              bool bidirectional);
  ~EnvoyQuicWebTransportStream() override;

  // Whether the underlying QUICHE stream is still open. A closed stream resolves to nullptr.
  bool isOpen() const { return stream() != nullptr; }

  // Http::WebTransportStream
  bool bidirectional() const override { return bidirectional_; }
  void setWebTransportStreamCallbacks(Http::WebTransportStreamCallbacks* callbacks) override {
    callbacks_ = callbacks;
  }
  Http::WebTransportStreamReadResult readWebTransportStream(absl::Span<char> buffer) override;
  bool writeWebTransportStream(absl::string_view data, bool end_stream) override;
  bool canWriteWebTransportStream() const override;
  void resetWebTransportStream(uint32_t error_code) override;
  void stopSendingWebTransportStream(uint32_t error_code) override;

private:
  // QUICHE stream visitor. The QUICHE stream owns it and may free it before the adapter, so it
  // holds a back pointer that each side clears on destruction.
  class Visitor : public webtransport::StreamVisitor {
  public:
    Visitor(EnvoyQuicWebTransportStream& stream) : stream_(&stream) {}
    ~Visitor() override;
    void detach() { stream_ = nullptr; }

    // webtransport::StreamVisitor
    void OnCanRead() override;
    void OnCanWrite() override;
    void OnResetStreamReceived(webtransport::StreamErrorCode error) override;
    void OnStopSendingReceived(webtransport::StreamErrorCode error) override;
    void OnWriteSideInDataRecvdState() override {}

  private:
    EnvoyQuicWebTransportStream* stream_;
  };

  webtransport::Stream* stream() const { return session_.GetStreamById(id_); }

  webtransport::Session& session_;
  const webtransport::StreamId id_;
  const bool bidirectional_;
  Http::WebTransportStreamCallbacks* callbacks_{nullptr};
  Visitor* visitor_{nullptr};
};

} // namespace Quic
} // namespace Envoy
