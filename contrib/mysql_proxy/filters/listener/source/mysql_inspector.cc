#include "contrib/mysql_proxy/filters/listener/source/mysql_inspector.h"

#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/hex.h"
#include "source/common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace MySQLInspector {

Config::Config(Stats::Scope& scope)
    : stats_{ALL_MYSQL_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "mysql_inspector."))} {}

Filter::Filter(const ConfigSharedPtr config) : config_(config) {
  http_parser_init(&parser_, HTTP_REQUEST);
}

http_parser_settings Filter::settings_{
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
};

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "mysql_inspector: new connection accepted");
  cb_ = &cb;

  // Responsibilities:
  // 1. Send Server Greeting Packet
  // 2. Check Whether Client Wants SSL
  // 3. Close Connection if SSL is not requested or if SSL is requested then stop iteration
  // 4. onData() would be called again, and we can write the first 36 bytes of the packet to the
  // filter metadata namespace
  // 5. Record Metrics

  // ################################ Send Server Greeting Packet ##################################
  Network::ConnectionSocket& socket = cb.socket();
  Buffer::OwnedImpl write_buffer{};
  const uint8_t server_greeting[78]{74,  0,   0,  0,   10,  56,  46,  48,  46,  51,  50,  0,   216,
                                    1,   0,   0,  117, 113, 115, 20,  88,  7,   48,  64,  0,   255,
                                    255, 255, 2,  0,   255, 223, 21,  0,   0,   0,   0,   0,   0,
                                    0,   0,   0,  0,   40,  65,  56,  79,  87,  69,  33,  14,  34,
                                    21,  119, 56, 0,   99,  97,  99,  104, 105, 110, 103, 95,  115,
                                    104, 97,  50, 95,  112, 97,  115, 115, 119, 111, 114, 100, 0};

  // Write directly to the socket's buffer
  write_buffer.add(server_greeting, 78);
  socket.ioHandle().write(write_buffer);

  // ############################## Receive Client Handshake Packet ################################
  constexpr int kExpectedSize = 36;
  std::vector<uint8_t> buffer(kExpectedSize);

  int totalReceived = 0;
  int retry = 0;

  while (totalReceived < kExpectedSize && retry < 100) {
    auto result = socket.ioHandle().recv(buffer.data() + totalReceived,
                                         kExpectedSize - totalReceived, MSG_PEEK);

    if (!result.ok() || result.return_value_ <= 0) {
      absl::SleepFor(absl::Milliseconds(10));
      retry++;
      continue;
    }

    totalReceived += result.return_value_;

    if (totalReceived == kExpectedSize) {
      std::string hex_string = Envoy::Hex::encode(buffer.data(), kExpectedSize);
      ENVOY_LOG(trace, "mysql_inspector: buffer data = {}", hex_string);
      break;
    }
  }

  // Verify the data
  if (totalReceived == kExpectedSize) {
    // Perform the read without MSG_PEEK to actually consume the data
    Buffer::OwnedImpl in_buffer{};
    auto read_result = socket.ioHandle().read(in_buffer, kExpectedSize);

    if (read_result.ok()) {
      auto hex_string = Envoy::Hex::encode(
          static_cast<uint8_t*>(in_buffer.linearize(kExpectedSize)), kExpectedSize);

      // Your inspection logic here...

      const std::string metadata_key = "mysql-inspector";
      ProtobufWkt::Value metadata_value;
      metadata_value.set_string_value(hex_string);

      ProtobufWkt::Struct metadata(
          (*cb_->dynamicMetadata().mutable_filter_metadata())[metadata_key]);
      metadata.mutable_fields()->insert({"short_handshake", metadata_value});
      cb_->setDynamicMetadata(metadata_key, metadata);
    }

    // Ensure the consumed data doesn't go to the next filter
    // (assuming in_buffer is not used elsewhere)
    ENVOY_LOG(trace, "mysql_inspector: successfully drained mysql short handshake packet");
    in_buffer.drain(kExpectedSize);
  } else {
    ENVOY_LOG(debug, "mysql_inspector: failed to drain mysql short handshake packet");
    socket.ioHandle().close();
  }

  return Network::FilterStatus::Continue;
}

} // namespace MySQLInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
