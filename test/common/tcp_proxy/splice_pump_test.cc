#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "source/common/api/api_impl.h"
#include "source/common/event/dispatcher_impl.h"
#include "source/common/tcp_proxy/splice_pump.h"

#include "test/test_common/utility.h"

#include "absl/types/optional.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace TcpProxy {
namespace {

// TLS record type bytes, mirrored from splice_pump.cc for the classifier tests.
constexpr uint8_t kChangeCipherSpec = 20;
constexpr uint8_t kAlert = 21;
constexpr uint8_t kHandshake = 22;
constexpr uint8_t kNewSessionTicket = 4;
constexpr uint8_t kKeyUpdate = 24;

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
  hs.push_back(kKeyUpdate); // must force a close
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

TEST(ClassifyKtlsControlRecord, HandshakeWithOverlongLengthIsClose) {
  // A NewSessionTicket whose declared length (~16M) runs past the 5-byte record is malformed.
  const uint8_t hs[] = {kNewSessionTicket, 0xFF, 0xFF, 0xFF, 0x00};
  EXPECT_EQ(ControlAction::Close, classifyKtlsControlRecord(kHandshake, hs, sizeof(hs)));
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
        [this](SpliceCompletion status) {
          completed_ = true;
          completion_ = status;
        },
        [this](uint64_t n) { u2d_bytes_ += n; }, [this](uint64_t n) { d2u_bytes_ += n; });
    ASSERT_TRUE(pump_->prepare(initial_downstream, /*initial_d2u=*/""));
    pump_->arm();
  }

  // Builds a bounded pump (the HTTP body-splice mode). Exactly one direction is usually active. The
  // pre-engage chunk for the active direction precedes any spliced bytes and is accounted but not
  // counted against the byte limit.
  void buildAndArmBounded(absl::optional<uint64_t> u2d_limit, absl::optional<uint64_t> d2u_limit,
                          const std::string& initial_u2d = "",
                          const std::string& initial_d2u = "") {
    pump_ = std::make_unique<SplicePump>(
        down_.pump_end, up_.pump_end, /*up_is_ktls=*/false, *dispatcher_,
        [this](SpliceCompletion status) {
          completed_ = true;
          completion_ = status;
        },
        [this](uint64_t n) { u2d_bytes_ += n; }, [this](uint64_t n) { d2u_bytes_ += n; });
    ASSERT_TRUE(pump_->prepare(initial_u2d, initial_d2u));
    pump_->setBounds(u2d_limit, d2u_limit);
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
  absl::optional<SpliceCompletion> completion_;
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

// The upstream finishes its response and closes (EOF / close_notify) while the downstream client
// keeps its connection open, as a keep-alive client does when it returns the connection to its pool
// without closing. The pump must deliver the full response and then complete, freeing its fds and
// pipes, rather than leak them waiting for a downstream close that never comes. Regression for the
// dominant connection leak observed under PUT churn (engaged greatly exceeding torndown): before
// the upstream-finished completion arm, this state satisfied neither the both-closed path nor the
// client-close path, so the pump held its resources until the worker recycled.
TEST_F(SplicePumpIoTest, UpstreamCloseCompletesWhileDownstreamStaysOpen) {
  buildAndArm();
  const std::string response(8192, 'z');
  ASSERT_EQ(static_cast<ssize_t>(response.size()),
            ::write(up_.test_end, response.data(), response.size()));
  ::close(up_.test_end);
  up_.test_end = -1;
  // The downstream end is deliberately left open for the whole test.
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return completed_;
  });
  EXPECT_TRUE(completed_);
  EXPECT_EQ(response, received);
}

// A large upstream response is fully buffered before the client closes. On the client close the
// pump must deliver every buffered upstream byte before completing, never closing the upstream
// while response bytes remain unread. Regression for the truncation that a stale readiness latch
// could cause: completion now waits for an authoritative in-pass upstream drain, and the
// client-close arm re-arms the upstream read so that final drain happens.
TEST_F(SplicePumpIoTest, DownstreamCloseDeliversBufferedUpstreamBytes) {
  buildAndArm();
  const std::string response(200000, 'r');
  ASSERT_EQ(static_cast<ssize_t>(response.size()),
            ::write(up_.test_end, response.data(), response.size()));
  ::close(up_.test_end);
  up_.test_end = -1;
  // The client closes its connection right after, the typical keep-alive retire.
  ::shutdown(down_.test_end, SHUT_WR);
  std::string received;
  runUntil(
      [&]() {
        received += readAll(down_.test_end);
        return completed_;
      },
      2000);
  EXPECT_TRUE(completed_);
  EXPECT_EQ(response.size(), received.size());
  EXPECT_EQ(response, received);
}

// A keep-alive upstream that never sends EOF: the client sends its request, reads the full
// response, and closes its connection (retiring it). The pump must complete via the client-close
// path rather than wait forever for an upstream EOF that a keep-alive peer never sends.
TEST_F(SplicePumpIoTest, ClientCloseCompletesWithKeepAliveUpstream) {
  buildAndArm();
  const std::string response(8192, 'r');
  ASSERT_EQ(static_cast<ssize_t>(response.size()),
            ::write(up_.test_end, response.data(), response.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return received.size() >= response.size();
  });
  EXPECT_EQ(response, received);
  // The client closes fully while the upstream stays open (keep-alive).
  ::close(down_.test_end);
  down_.test_end = -1;
  runUntil([&]() { return completed_; });
  EXPECT_TRUE(completed_);
}

// Bounded download: the pump splices exactly the Content-Length budget from the upstream to the
// downstream, then completes with BoundsReached and leaves the bytes beyond the budget (the next
// keep-alive message) untouched in the upstream socket.
TEST_F(SplicePumpIoTest, BoundedDownloadStopsAtLimit) {
  buildAndArmBounded(/*u2d_limit=*/absl::make_optional<uint64_t>(8192), /*d2u_limit=*/absl::nullopt);
  const std::string body(20000, 'b');
  ASSERT_EQ(static_cast<ssize_t>(body.size()),
            ::write(up_.test_end, body.data(), body.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return completed_;
  });
  received += readAll(down_.test_end);
  EXPECT_TRUE(completed_);
  ASSERT_TRUE(completion_.has_value());
  EXPECT_EQ(SpliceCompletion::BoundsReached, completion_.value());
  EXPECT_EQ(8192u, received.size());
  EXPECT_EQ(body.substr(0, 8192), received);
  EXPECT_EQ(8192u, u2d_bytes_);
  // The bytes past the budget stay queued in the upstream socket for the next message.
  const std::string leftover = readAll(up_.pump_end);
  EXPECT_EQ(body.size() - 8192, leftover.size());
}

// Bounded upload: symmetric to the download case in the downstream-to-upstream direction.
TEST_F(SplicePumpIoTest, BoundedUploadStopsAtLimit) {
  buildAndArmBounded(/*u2d_limit=*/absl::nullopt, /*d2u_limit=*/absl::make_optional<uint64_t>(8192));
  const std::string body(20000, 'u');
  ASSERT_EQ(static_cast<ssize_t>(body.size()),
            ::write(down_.test_end, body.data(), body.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(up_.test_end);
    return completed_;
  });
  received += readAll(up_.test_end);
  EXPECT_TRUE(completed_);
  ASSERT_TRUE(completion_.has_value());
  EXPECT_EQ(SpliceCompletion::BoundsReached, completion_.value());
  EXPECT_EQ(8192u, received.size());
  EXPECT_EQ(8192u, d2u_bytes_);
  const std::string leftover = readAll(down_.pump_end);
  EXPECT_EQ(body.size() - 8192, leftover.size());
}

// The pre-engage chunk precedes the spliced body and is delivered in full on top of the byte
// budget, so the downstream receives chunk + limit bytes in order.
TEST_F(SplicePumpIoTest, BoundedDownloadDeliversPreEngageThenLimit) {
  buildAndArmBounded(/*u2d_limit=*/absl::make_optional<uint64_t>(4096), /*d2u_limit=*/absl::nullopt,
                     /*initial_u2d=*/"PREFIX");
  const std::string body(4096, 'p');
  ASSERT_EQ(static_cast<ssize_t>(body.size()),
            ::write(up_.test_end, body.data(), body.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return completed_;
  });
  received += readAll(down_.test_end);
  EXPECT_TRUE(completed_);
  ASSERT_TRUE(completion_.has_value());
  EXPECT_EQ(SpliceCompletion::BoundsReached, completion_.value());
  EXPECT_EQ("PREFIX" + body, received);
  EXPECT_EQ(6u + 4096u, u2d_bytes_);
}

// Bounded completion never half-closes the downstream write side, so a subsequent read observes
// EAGAIN rather than EOF and the connection can carry the next keep-alive message.
TEST_F(SplicePumpIoTest, BoundedCompletionLeavesSocketsOpen) {
  buildAndArmBounded(/*u2d_limit=*/absl::make_optional<uint64_t>(4096), /*d2u_limit=*/absl::nullopt);
  const std::string body(4096, 'k');
  ASSERT_EQ(static_cast<ssize_t>(body.size()),
            ::write(up_.test_end, body.data(), body.size()));
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return completed_;
  });
  received += readAll(down_.test_end);
  ASSERT_TRUE(completion_.has_value());
  EXPECT_EQ(SpliceCompletion::BoundsReached, completion_.value());
  EXPECT_EQ(4096u, received.size());
  char buf[16];
  const ssize_t n = ::read(down_.test_end, buf, sizeof(buf));
  EXPECT_EQ(-1, n);
  EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
}

// A source EOF before the byte budget is met is a truncated message, so the bounded pump completes
// with Closed and the caller must reset rather than reuse the connection.
TEST_F(SplicePumpIoTest, BoundedDownloadPrematureCloseCompletesClosed) {
  buildAndArmBounded(/*u2d_limit=*/absl::make_optional<uint64_t>(8192), /*d2u_limit=*/absl::nullopt);
  const std::string body(4096, 'q'); // fewer than the budget
  ASSERT_EQ(static_cast<ssize_t>(body.size()),
            ::write(up_.test_end, body.data(), body.size()));
  ::close(up_.test_end);
  up_.test_end = -1;
  std::string received;
  runUntil([&]() {
    received += readAll(down_.test_end);
    return completed_;
  });
  EXPECT_TRUE(completed_);
  ASSERT_TRUE(completion_.has_value());
  EXPECT_EQ(SpliceCompletion::Closed, completion_.value());
}
#endif

} // namespace
} // namespace TcpProxy
} // namespace Envoy
