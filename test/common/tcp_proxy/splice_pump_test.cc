#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "source/common/api/api_impl.h"
#include "source/common/event/dispatcher_impl.h"
#include "source/common/tcp_proxy/splice_pump.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace TcpProxy {
namespace {

// TLS record type bytes, mirrored from splice_pump.cc for the classifier tests.
constexpr uint8_t kChangeCipherSpec = 20;
constexpr uint8_t kAlert = 21;
constexpr uint8_t kHandshake = 22;
constexpr uint8_t kNewSessionTicket = 4;

// Builds a handshake record body of `count` NewSessionTicket messages, each with a `body_len`-byte
// body, so the classifier's coalesced-message walk can be exercised.
std::vector<uint8_t> newSessionTickets(int count, uint8_t body_len) {
  std::vector<uint8_t> out;
  for (int i = 0; i < count; i++) {
    out.push_back(kNewSessionTicket);
    out.push_back(0);
    out.push_back(0);
    out.push_back(body_len);
    out.insert(out.end(), body_len, 0xAB);
  }
  return out;
}

TEST(ClassifyKtlsControlRecord, CloseNotifyAlertIsEof) {
  const uint8_t alert[] = {1, 0}; // warning, close_notify
  EXPECT_EQ(ControlAction::Eof, classifyKtlsControlRecord(kAlert, alert, sizeof(alert)));
}

TEST(ClassifyKtlsControlRecord, FatalAlertIsClose) {
  const uint8_t alert[] = {2, 50}; // fatal, decode_error
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kAlert, alert, sizeof(alert)));
}

TEST(ClassifyKtlsControlRecord, ShortAlertIsClose) {
  const uint8_t alert[] = {1};
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kAlert, alert, sizeof(alert)));
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kAlert, nullptr, 0));
}

TEST(ClassifyKtlsControlRecord, ChangeCipherSpecIsRetry) {
  const uint8_t ccs[] = {1};
  EXPECT_EQ(ControlAction::Retry, classifyKtlsControlRecord(kChangeCipherSpec, ccs, sizeof(ccs)));
}

TEST(ClassifyKtlsControlRecord, SingleNewSessionTicketIsRetry) {
  const std::vector<uint8_t> hs = newSessionTickets(1, 8);
  EXPECT_EQ(ControlAction::Retry, classifyKtlsControlRecord(kHandshake, hs.data(), hs.size()));
}

TEST(ClassifyKtlsControlRecord, CoalescedNewSessionTicketsAreRetry) {
  const std::vector<uint8_t> hs = newSessionTickets(3, 16);
  EXPECT_EQ(ControlAction::Retry, classifyKtlsControlRecord(kHandshake, hs.data(), hs.size()));
}

TEST(ClassifyKtlsControlRecord, NonTicketHandshakeIsClose) {
  const uint8_t hs[] = {1, 0, 0, 0}; // ClientHello, not serviceable post-kTLS
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kHandshake, hs, sizeof(hs)));
}

TEST(ClassifyKtlsControlRecord, TicketThenRekeyIsClose) {
  std::vector<uint8_t> hs = newSessionTickets(1, 4);
  hs.push_back(8); // KeyUpdate type, must force a close
  hs.push_back(0);
  hs.push_back(0);
  hs.push_back(1);
  hs.push_back(0);
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kHandshake, hs.data(), hs.size()));
}

TEST(ClassifyKtlsControlRecord, UnknownRecordTypeIsClose) {
  const uint8_t data[] = {0};
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(99, data, sizeof(data)));
}

#ifdef __linux__
// Real I/O test of the pump's data path. Two AF_UNIX socketpairs stand in for the downstream and
// upstream sockets. up_is_ktls is false, so the pump runs its plain splice and userspace relay
// without the kTLS control-message path. The test drives a real dispatcher.
class SplicePumpIoTest : public testing::Test {
public:
  SplicePumpIoTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test_thread")) {
    makePair(down_);
    makePair(up_);
  }

  ~SplicePumpIoTest() override {
    for (int fd : {down_.test_end, up_.test_end}) {
      if (fd >= 0) {
        ::close(fd);
      }
    }
  }

  struct Pair {
    int test_end{-1};
    int pump_end{-1};
  };

  void makePair(Pair& p) {
    int fds[2];
    ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ::fcntl(fds[0], F_SETFL, O_NONBLOCK);
    ::fcntl(fds[1], F_SETFL, O_NONBLOCK);
    p.test_end = fds[0];
    p.pump_end = fds[1];
  }

  void buildAndArm(const std::string& initial_downstream = "") {
    pump_ = std::make_unique<SplicePump>(
        down_.pump_end, up_.pump_end, /*up_is_ktls=*/false, *dispatcher_,
        [this](Network::ConnectionEvent) { completed_ = true; },
        [this](uint64_t n) { u2d_bytes_ += n; }, [this](uint64_t n) { d2u_bytes_ += n; });
    ASSERT_TRUE(pump_->prepare(initial_downstream));
    pump_->arm();
  }

  // Runs the dispatcher until `pred` holds or the iteration budget is exhausted.
  void runUntil(const std::function<bool()>& pred, int max_iters = 200) {
    for (int i = 0; i < max_iters && !pred(); i++) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
  }

  std::string readAll(int fd) {
    std::string out;
    char buf[16384];
    for (;;) {
      const ssize_t n = ::read(fd, buf, sizeof(buf));
      if (n > 0) {
        out.append(buf, static_cast<size_t>(n));
      } else {
        break;
      }
    }
    return out;
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  Pair down_;
  Pair up_;
  SplicePumpPtr pump_;
  uint64_t u2d_bytes_{0};
  uint64_t d2u_bytes_{0};
  bool completed_{false};
};

// Bytes written on the upstream socket reach the downstream socket (the download path) and are
// accounted in the u2d byte callback.
TEST_F(SplicePumpIoTest, UpstreamToDownstream) {
  buildAndArm();
  const std::string payload(40000, 'x');
  ASSERT_EQ(static_cast<ssize_t>(payload.size()),
            ::write(up_.test_end, payload.data(), payload.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return received.size() >= payload.size();
  });
  EXPECT_EQ(payload, received);
  EXPECT_EQ(payload.size(), u2d_bytes_);
}

// The pre-engage chunk handed to prepare() is delivered to the downstream socket before any
// spliced bytes.
TEST_F(SplicePumpIoTest, PreEngageChunkDeliveredFirst) {
  buildAndArm("HEADER");
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return received.size() >= 6;
  });
  EXPECT_EQ("HEADER", received);
  EXPECT_EQ(6u, u2d_bytes_);
}

// Bytes written on the downstream socket reach the upstream socket (the request path) and are
// accounted in the d2u byte callback.
TEST_F(SplicePumpIoTest, DownstreamToUpstream) {
  buildAndArm();
  const std::string request = "GET /object HTTP/1.1\r\n\r\n";
  ASSERT_EQ(static_cast<ssize_t>(request.size()),
            ::write(down_.test_end, request.data(), request.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(up_.test_end);
    return received.size() >= request.size();
  });
  EXPECT_EQ(request, received);
  EXPECT_EQ(request.size(), d2u_bytes_);
}

// A pre-engage chunk larger than the downstream socket send buffer overflows into pending_down_
// and is fully flushed by the pump ahead of any spliced bytes.
TEST_F(SplicePumpIoTest, LargePreEngageChunkStashedAndDrained) {
  const std::string header(2 * 1024 * 1024, 'h');
  buildAndArm(header);
  std::string received;
  runUntil(
      [&]() {
        received += readAll(down_.test_end);
        return received.size() >= header.size();
      },
      2000);
  EXPECT_EQ(header.size(), received.size());
  EXPECT_EQ(header, received);
  EXPECT_EQ(header.size(), u2d_bytes_);
}

// Once the upstream peer closes and its bytes are drained, the pump half-closes the downstream
// write side so the downstream peer observes EOF.
TEST_F(SplicePumpIoTest, UpstreamCloseHalfClosesDownstream) {
  buildAndArm();
  const std::string payload(8192, 'y');
  ASSERT_EQ(static_cast<ssize_t>(payload.size()),
            ::write(up_.test_end, payload.data(), payload.size()));
  ::close(up_.test_end);
  up_.test_end = -1;
  std::string received;
  bool saw_eof = false;
  runUntil([&]() {
    char buf[16384];
    const ssize_t n = ::read(down_.test_end, buf, sizeof(buf));
    if (n > 0) {
      received.append(buf, static_cast<size_t>(n));
    } else if (n == 0) {
      saw_eof = true;
    }
    return saw_eof;
  });
  EXPECT_EQ(payload, received);
  EXPECT_TRUE(saw_eof);
}

// Closing both peer ends drives the pump to completion through its on_complete_ callback.
TEST_F(SplicePumpIoTest, BothPeersCloseCompletes) {
  buildAndArm();
  ::close(up_.test_end);
  up_.test_end = -1;
  ::close(down_.test_end);
  down_.test_end = -1;
  runUntil([&]() { return completed_; });
  EXPECT_TRUE(completed_);
}
#endif

} // namespace
} // namespace TcpProxy
} // namespace Envoy
