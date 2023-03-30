#include "source/extensions/filters/listener/http_inspector/http_inspector.h"

#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/macros.h"
#include "source/common/common/hex.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"

#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace HttpInspector {

Config::Config(Stats::Scope& scope)
    : stats_{ALL_HTTP_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "http_inspector."))} {}

const absl::string_view Filter::HTTP2_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

Filter::Filter(const ConfigSharedPtr config) : config_(config) {
  http_parser_init(&parser_, HTTP_REQUEST);
}

http_parser_settings Filter::settings_{
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
};

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  auto raw_slice = buffer.rawSlice();
  auto buf = reinterpret_cast<const uint8_t*>(raw_slice.mem_);
  ENVOY_LOG(trace, "inspector: onData() buffer = {}", Envoy::Hex::encode(buf, raw_slice.len_));
  return Network::FilterStatus::Continue;

  /*
  auto raw_slice = buffer.rawSlice();
  const char* buf = static_cast<const char*>(raw_slice.mem_);
  const auto parse_state = parseHttpHeader(absl::string_view(buf, raw_slice.len_));
  switch (parse_state) {
  case ParseState::Error:
    // Invalid HTTP preface found, then just continue for next filter.
    done(false);
    return Network::FilterStatus::Continue;
  case ParseState::Done:
    done(true);
    return Network::FilterStatus::Continue;
  case ParseState::Continue:
    return Network::FilterStatus::StopIteration;
  }
  PANIC_DUE_TO_CORRUPT_ENUM
  */
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "inspector: new connection accepted");
  cb_ = &cb;

  Network::ConnectionSocket& socket = cb.socket();
  Buffer::OwnedImpl out_buffer_{};
  // 4a 00 00 00 0a 38 2e 30 2e 33 32 00 d8 01 00 00 75 71 73 14 58 07 30 40 00 ff ff ff 02 00 ff df 15 00 00 00 00 00 00 00 00 00 00 28 41 38 4f 57 45 21 0e 22 15 77 38 00 63 61 63 68 69 6e 67 5f 73 68 61 32 5f 70 61 73 73 77 6f 72 64 00
  const uint8_t buff_val[78]{74, 0, 0, 0, 10, 56, 46, 48, 46, 51, 50, 0, 216, 1, 0, 0, 117, 113, 115, 20, 88, 7, 48, 64, 0, 255, 255, 255, 2, 0, 255, 223, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 65, 56, 79, 87, 69, 33, 14, 34, 21, 119, 56, 0, 99, 97, 99, 104, 105, 110, 103, 95, 115, 104, 97, 50, 95, 112, 97, 115, 115, 119, 111, 114, 100, 0};
  out_buffer_.add(buff_val, 78);
  socket.ioHandle().write(out_buffer_);

  // Peek first
  auto buffer_ = std::make_unique<uint8_t[]>(36);
  auto peek_buf_ = buffer_.get();
  int retry = 0;
  do {
    auto result = socket.ioHandle().recv(peek_buf_, 36, MSG_PEEK);
    if (retry == 25 && (!result.ok() || result.return_value_ != 36)) {
      ENVOY_LOG(trace, "inspector: failed to drain mysql short handshake packet");
      socket.ioHandle().close();
    } else if (result.ok() && result.return_value_ == 36) {
      ENVOY_LOG(trace, "inspector: peek data = {}", Envoy::Hex::encode(peek_buf_, 36));
      break;
    }

    retry++;
    absl::SleepFor(absl::Milliseconds(10));
  } while (true);

  // Now actually read
  Buffer::OwnedImpl in_buffer_{};
  auto result = socket.ioHandle().read(in_buffer_, 36);
  if (result.ok()) {
    auto hex_string = Envoy::Hex::encode(static_cast<uint8_t*>(in_buffer_.linearize(in_buffer_.length())), in_buffer_.length());
    ENVOY_LOG(trace, "inspector: buffer data = {}", hex_string);

    // ROHIT: Insert the logic to inspect the 36 bytes. If SSL is not requested then we simply close
    // the connection or otherwise if SSL is requested then we continue.

    const std::string metadata_key = "tidb-listener";
    ProtobufWkt::Value metadata_value;
    metadata_value.set_string_value(hex_string);
    ProtobufWkt::Struct metadata((*cb_->dynamicMetadata().mutable_filter_metadata())[metadata_key]);
    metadata.mutable_fields()->insert({"short_handshake", metadata_value});
    cb_->setDynamicMetadata(metadata_key, metadata);

    // Clean up the buffer as we already consumed these 36 bytes of data, and we don't want to send
    // this to the next filter.
    in_buffer_.drain(36);
  }

  /*
  const absl::string_view transport_protocol = socket.detectedTransportProtocol();
  if (!transport_protocol.empty() && transport_protocol != "raw_buffer") {
    ENVOY_LOG(trace, "http inspector: cannot inspect http protocol with transport socket {}",
              transport_protocol);
    return Network::FilterStatus::Continue;
  }
  */

  return Network::FilterStatus::StopIteration;
}

ParseState Filter::parseHttpHeader(absl::string_view data) {
  const size_t len = std::min(data.length(), Filter::HTTP2_CONNECTION_PREFACE.length());
  if (Filter::HTTP2_CONNECTION_PREFACE.compare(0, len, data, 0, len) == 0) {
    if (data.length() < Filter::HTTP2_CONNECTION_PREFACE.length()) {
      return ParseState::Continue;
    }
    ENVOY_LOG(trace, "http inspector: http2 connection preface found");
    protocol_ = "HTTP/2";
    return ParseState::Done;
  } else {
    ASSERT(!data.empty());
    // Ensure first line (also request line for HTTP request) in the buffer is not empty.
    if (data[0] == '\r' || data[0] == '\n') {
      return ParseState::Error;
    }

    absl::string_view new_data = data.substr(parser_.nread);
    const size_t pos = new_data.find_first_of("\r\n");

    if (pos != absl::string_view::npos) {
      // Include \r or \n
      new_data = new_data.substr(0, pos + 1);
      ssize_t rc = http_parser_execute(&parser_, &settings_, new_data.data(), new_data.length());
      ENVOY_LOG(trace, "http inspector: http_parser parsed {} chars, error code: {}", rc,
                HTTP_PARSER_ERRNO(&parser_));

      // Errors in parsing HTTP.
      if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK && HTTP_PARSER_ERRNO(&parser_) != HPE_PAUSED) {
        return ParseState::Error;
      }

      if (parser_.http_major == 1 && parser_.http_minor == 1) {
        protocol_ = Http::Headers::get().ProtocolStrings.Http11String;
      } else {
        // Set other HTTP protocols to HTTP/1.0
        protocol_ = Http::Headers::get().ProtocolStrings.Http10String;
      }
      return ParseState::Done;
    } else {
      ssize_t rc = http_parser_execute(&parser_, &settings_, new_data.data(), new_data.length());
      ENVOY_LOG(trace, "http inspector: http_parser parsed {} chars, error code: {}", rc,
                HTTP_PARSER_ERRNO(&parser_));

      // Errors in parsing HTTP.
      if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK && HTTP_PARSER_ERRNO(&parser_) != HPE_PAUSED) {
        return ParseState::Error;
      } else {
        return ParseState::Continue;
      }
    }
  }
}

void Filter::done(bool success) {
  ENVOY_LOG(trace, "http inspector: done: {}", success);

  if (success) {
    absl::string_view protocol;
    if (protocol_ == Http::Headers::get().ProtocolStrings.Http10String) {
      config_->stats().http10_found_.inc();
      protocol = Http::Utility::AlpnNames::get().Http10;
    } else if (protocol_ == Http::Headers::get().ProtocolStrings.Http11String) {
      config_->stats().http11_found_.inc();
      protocol = Http::Utility::AlpnNames::get().Http11;
    } else {
      ASSERT(protocol_ == "HTTP/2");
      config_->stats().http2_found_.inc();
      // h2 HTTP/2 over TLS, h2c HTTP/2 over TCP
      // TODO(yxue): use detected protocol from http inspector and support h2c token in HCM
      protocol = Http::Utility::AlpnNames::get().Http2c;
    }
    ENVOY_LOG(debug, "http inspector: set application protocol to {}", protocol);

    cb_->socket().setRequestedApplicationProtocols({protocol});
  } else {
    config_->stats().http_not_found_.inc();
  }
}

} // namespace HttpInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
