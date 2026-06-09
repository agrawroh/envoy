#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "quiche/quic/tools/web_transport_test_visitors.h"
#include "quiche/web_transport/stream_helpers.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

// These tests verify that the QUICHE WebTransport test tooling links and runs inside Envoy's build.
// The tooling is the foundation for WebTransport integration tests once the session bridge lands.

namespace Envoy {
namespace Quic {
namespace {

using testing::_;
using testing::An;

// The QUICHE bidirectional echo visitor reads from a stream and writes the same bytes back.
TEST(WebTransportTestTools, BidirectionalEchoVisitorEchoesData) {
  webtransport::test::MockStream stream;
  quic::WebTransportBidirectionalEchoVisitor visitor(&stream);

  EXPECT_CALL(stream, Read(An<std::string*>())).WillOnce([](std::string* output) {
    output->append("hello");
    return webtransport::Stream::ReadResult{5, false};
  });
  std::string written;
  EXPECT_CALL(stream, Writev(_, _))
      .WillOnce([&written](absl::Span<quiche::QuicheMemSlice> data,
                           const webtransport::StreamWriteOptions&) {
        for (const quiche::QuicheMemSlice& slice : data) {
          written.append(slice.AsStringView());
        }
        return absl::OkStatus();
      });

  visitor.OnCanRead();
  EXPECT_EQ(written, "hello");
}

// The stream_helpers convenience functions drive a stream write through the QUICHE Stream API.
TEST(WebTransportTestTools, WriteIntoStreamWritesData) {
  webtransport::test::MockStream stream;
  std::string written;
  EXPECT_CALL(stream, Writev(_, _))
      .WillOnce([&written](absl::Span<quiche::QuicheMemSlice> data,
                           const webtransport::StreamWriteOptions& options) {
        EXPECT_FALSE(options.send_fin());
        for (const quiche::QuicheMemSlice& slice : data) {
          written.append(slice.AsStringView());
        }
        return absl::OkStatus();
      });

  EXPECT_TRUE(webtransport::WriteIntoStream(stream, "payload").ok());
  EXPECT_EQ(written, "payload");
}

// A session visitor can echo a received datagram back through the session.
TEST(WebTransportTestTools, EchoSessionVisitorEchoesDatagram) {
  webtransport::test::MockSession session;
  quic::EchoWebTransportSessionVisitor visitor(&session,
                                               /*open_server_initiated_echo_stream=*/false);

  std::string echoed;
  EXPECT_CALL(session, SendOrQueueDatagram(_)).WillOnce([&echoed](absl::string_view datagram) {
    echoed = std::string(datagram);
    return webtransport::DatagramStatus(webtransport::DatagramStatusCode::kSuccess, "");
  });

  visitor.OnDatagramReceived("ping");
  EXPECT_EQ(echoed, "ping");
}

} // namespace
} // namespace Quic
} // namespace Envoy
