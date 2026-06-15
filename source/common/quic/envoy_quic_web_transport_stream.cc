#include "source/common/quic/envoy_quic_web_transport_stream.h"

#include <array>
#include <memory>

#include "quiche/common/quiche_mem_slice.h"

namespace Envoy {
namespace Quic {

Http::WebTransportStream* openTrackedWebTransportStream(webtransport::Session& session,
                                                        WebTransportStreamList& streams,
                                                        bool bidirectional) {
  webtransport::Stream* stream = bidirectional ? session.OpenOutgoingBidirectionalStream()
                                               : session.OpenOutgoingUnidirectionalStream();
  if (stream == nullptr) {
    return nullptr;
  }
  streams.push_back(
      std::make_unique<EnvoyQuicWebTransportStream>(session, stream->GetStreamId(), bidirectional));
  return streams.back().get();
}

uint32_t liveWebTransportStreamCount(const WebTransportStreamList& streams) {
  uint32_t count = 0;
  for (const auto& stream : streams) {
    if (stream->isOpen()) {
      ++count;
    }
  }
  return count;
}

uint32_t acceptIncomingWebTransportStreams(webtransport::Session& session,
                                           WebTransportStreamList& streams,
                                           Http::WebTransportSessionCallbacks& callbacks,
                                           bool bidirectional, uint32_t max_streams) {
  uint32_t rejected = 0;
  for (webtransport::Stream* stream = bidirectional ? session.AcceptIncomingBidirectionalStream()
                                                    : session.AcceptIncomingUnidirectionalStream();
       stream != nullptr; stream = bidirectional ? session.AcceptIncomingBidirectionalStream()
                                                 : session.AcceptIncomingUnidirectionalStream()) {
    if (max_streams != 0 && liveWebTransportStreamCount(streams) >= max_streams) {
      // Over the per-session stream cap, so refuse this stream rather than relay it.
      stream->ResetWithUserCode(0);
      ++rejected;
      continue;
    }
    streams.push_back(std::make_unique<EnvoyQuicWebTransportStream>(session, stream->GetStreamId(),
                                                                    bidirectional));
    callbacks.onWebTransportStreamIncoming(*streams.back(), bidirectional);
  }
  return rejected;
}

EnvoyQuicWebTransportStream::EnvoyQuicWebTransportStream(webtransport::Session& session,
                                                         webtransport::StreamId id,
                                                         bool bidirectional)
    : session_(session), id_(id), bidirectional_(bidirectional) {
  webtransport::Stream* stream = this->stream();
  if (stream != nullptr) {
    auto visitor = std::make_unique<Visitor>(*this);
    visitor_ = visitor.get();
    stream->SetVisitor(std::move(visitor));
  }
}

EnvoyQuicWebTransportStream::~EnvoyQuicWebTransportStream() {
  if (visitor_ != nullptr) {
    visitor_->detach();
  }
}

EnvoyQuicWebTransportStream::Visitor::~Visitor() {
  if (stream_ != nullptr) {
    stream_->visitor_ = nullptr;
  }
}

Http::WebTransportStreamReadResult
EnvoyQuicWebTransportStream::readWebTransportStream(absl::Span<char> buffer) {
  webtransport::Stream* stream = this->stream();
  if (stream == nullptr) {
    return {0, true};
  }
  auto result = stream->Read(buffer);
  return {result.bytes_read, result.fin};
}

bool EnvoyQuicWebTransportStream::writeWebTransportStream(absl::string_view data, bool end_stream) {
  webtransport::Stream* stream = this->stream();
  if (stream == nullptr || !stream->CanWrite()) {
    return false;
  }
  if (data.empty()) {
    return end_stream ? stream->SendFin() : true;
  }
  webtransport::StreamWriteOptions options;
  options.set_send_fin(end_stream);
  std::array<quiche::QuicheMemSlice, 1> slices = {quiche::QuicheMemSlice::Copy(data)};
  return stream->Writev(absl::MakeSpan(slices), options).ok();
}

bool EnvoyQuicWebTransportStream::canWriteWebTransportStream() const {
  webtransport::Stream* stream = this->stream();
  return stream != nullptr && stream->CanWrite();
}

void EnvoyQuicWebTransportStream::resetWebTransportStream(uint32_t error_code) {
  webtransport::Stream* stream = this->stream();
  if (stream != nullptr) {
    stream->ResetWithUserCode(error_code);
  }
}

void EnvoyQuicWebTransportStream::stopSendingWebTransportStream(uint32_t error_code) {
  webtransport::Stream* stream = this->stream();
  if (stream != nullptr) {
    stream->SendStopSending(error_code);
  }
}

void EnvoyQuicWebTransportStream::Visitor::OnCanRead() {
  if (stream_ != nullptr && stream_->callbacks_ != nullptr) {
    stream_->callbacks_->onWebTransportStreamData();
  }
}

void EnvoyQuicWebTransportStream::Visitor::OnCanWrite() {
  if (stream_ != nullptr && stream_->callbacks_ != nullptr) {
    stream_->callbacks_->onWebTransportStreamCanWrite();
  }
}

void EnvoyQuicWebTransportStream::Visitor::OnResetStreamReceived(
    webtransport::StreamErrorCode error) {
  if (stream_ != nullptr && stream_->callbacks_ != nullptr) {
    stream_->callbacks_->onWebTransportStreamReset(error);
  }
}

void EnvoyQuicWebTransportStream::Visitor::OnStopSendingReceived(
    webtransport::StreamErrorCode error) {
  if (stream_ != nullptr && stream_->callbacks_ != nullptr) {
    stream_->callbacks_->onWebTransportStreamStopSending(error);
  }
}

} // namespace Quic
} // namespace Envoy
