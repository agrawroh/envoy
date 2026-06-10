// Behavioral unit tests for TcpProxy::UpstreamPool, the Phase-2 warm upstream connection pool that
// lets high-churn small PUTs reuse already-handshaked, kTLS-installed upstream connections instead
// of paying a TLS handshake plus kTLS install per request. The pool owns the warm-idle connections
// between requests, so its connection ownership and lifetime handling is the area at risk for a
// use-after-free, and it shipped with zero direct tests. These tests pin checkout, checkin, the
// LIFO ordering, the MSG_PEEK clean-check, capacity eviction, idle-TTL eviction via the maintenance
// timer, the idle-callback rebind, and the destructor close path.
//
// The pool stores connections as Tcp::GenericUpstreamPtr. There is no shared GenericUpstream mock,
// so this file defines a minimal TestPooledUpstream double modeled on the TestGenericUpstream
// double in test/common/router/splice_coordinator_test.cc: it overrides only the methods the pool
// calls (upstreamConnection and rebindUpstreamCallbacks) and stubs the rest of the interface so the
// class is concrete. Each double owns a NiceMock<Network::MockConnection> whose
// getSocket()->ioHandle() resolves to a NiceMock<Network::MockIoHandle>, so a test controls
// clean-vs-stale entirely through the mock recv() result, the connection state(), and
// ioHandle().isOpen() with no real socket I/O.
//
// Time is driven by a SimulatedTimeSystem installed on the MockDispatcher, so monotonicTime() is
// advanceable for the idle-TTL test, and the maintenance timer is a MockTimer whose captured
// callback the fixture fires directly (no real event loop).

#include <chrono>
#include <memory>

#include "envoy/api/io_error.h"
#include "envoy/network/connection.h"

#include "source/common/network/io_socket_error_impl.h"
#include "source/common/tcp_proxy/upstream_pool.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/connection.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/simulated_time_system.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::_;
using ::testing::Const;
using ::testing::Return;
using ::testing::ReturnRef;

namespace Envoy {
namespace TcpProxy {
namespace {

// A GenericUpstream double that exposes only the seams UpstreamPool touches: upstreamConnection()
// (read by isClean, closeConnection, and the destructor) and rebindUpstreamCallbacks() (called on
// check-in). Everything else on the interface is stubbed so the class is concrete. The double owns
// its connection and socket mocks so a test can drive state(), ioHandle().isOpen(), and recv()
// directly. recv() defaults to EAGAIN, so a freshly built double is clean unless a test changes it.
class TestPooledUpstream : public GenericUpstream {
public:
  TestPooledUpstream() {
    socket_ptr_.reset(&socket_);
    ON_CALL(connection_, getSocket()).WillByDefault(ReturnRef(socket_ptr_));
    ON_CALL(socket_, ioHandle()).WillByDefault(ReturnRef(io_handle_));
    ON_CALL(Const(socket_), ioHandle()).WillByDefault(ReturnRef(io_handle_));
    ON_CALL(connection_, state()).WillByDefault(Return(Network::Connection::State::Open));
    ON_CALL(io_handle_, isOpen()).WillByDefault(Return(true));
    // Clean by default: a one-byte MSG_PEEK with no pending data returns EAGAIN.
    setClean();
  }

  ~TestPooledUpstream() override {
    // socket_ptr_ is a non-owning wrapper around the stack socket_ member, so release it before the
    // unique_ptr destructor would double-free the stack object.
    socket_ptr_.release();
  }

  // Make isClean() return true: a non-blocking MSG_PEEK reports no pending data (EAGAIN).
  void setClean() {
    ON_CALL(io_handle_, recv(_, _, _)).WillByDefault([]() {
      return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
    });
  }

  // Make isClean() return false via leftover bytes: a one-byte peek that succeeds with a return
  // value (here 1) signals unexpected pending data, so the connection is not cleanly reusable.
  void setStalePeekBytes() {
    ON_CALL(io_handle_, recv(_, _, _)).WillByDefault([]() {
      return Api::IoCallUint64Result(1, Api::IoError::none());
    });
  }

  // Make isClean() return false via orderly close: a one-byte peek that succeeds with return value
  // 0 signals the peer performed an orderly close.
  void setStalePeekClosed() {
    ON_CALL(io_handle_, recv(_, _, _)).WillByDefault([]() {
      return Api::IoCallUint64Result(0, Api::IoError::none());
    });
  }

  // GenericUpstream seams the pool uses.
  OptRef<Network::Connection> upstreamConnection() override { return connection_; }
  void rebindUpstreamCallbacks(Tcp::ConnectionPool::UpstreamCallbacks&) override {
    ++rebind_count_;
  }

  // Unused GenericUpstream surface, stubbed so the class is concrete.
  bool readDisable(bool) override { return true; }
  void encodeData(Buffer::Instance&, bool) override {}
  void addBytesSentCallback(Network::Connection::BytesSentCb) override {}
  Tcp::ConnectionPool::ConnectionData* onDownstreamEvent(Network::ConnectionEvent,
                                                         absl::string_view) override {
    return nullptr;
  }
  bool startUpstreamSecureTransport() override { return false; }
  Ssl::ConnectionInfoConstSharedPtr getUpstreamConnectionSslInfo() override { return nullptr; }
  StreamInfo::DetectedCloseType detectedCloseType() const override {
    return StreamInfo::DetectedCloseType::Normal;
  }

  NiceMock<Network::MockConnection> connection_;
  NiceMock<Network::MockConnectionSocket> socket_;
  NiceMock<Network::MockIoHandle> io_handle_;
  Network::ConnectionSocketPtr socket_ptr_;
  uint32_t rebind_count_{0};
};

class UpstreamPoolTest : public testing::Test {
public:
  UpstreamPoolTest() {
    auto sim_time = std::make_unique<Event::SimulatedTimeSystem>();
    time_system_ = sim_time.get();
    dispatcher_.time_system_ = std::move(sim_time);
    // Construct the maintenance MockTimer before the pool so the pool's createTimer() call resolves
    // to it and the timer body callback is captured for the fixture to fire directly.
    maintenance_timer_ = new NiceMock<Event::MockTimer>(&dispatcher_);
    pool_ = std::make_unique<UpstreamPool>(dispatcher_, cluster_manager_);
  }

protected:
  // Builds a clean test double and returns the raw pointer (still owned by the caller via the
  // returned unique_ptr). Lets a test keep observing the connection mock after handing the
  // unique_ptr to the pool.
  std::unique_ptr<NiceMock<TestPooledUpstream>> makeUpstream() {
    return std::make_unique<NiceMock<TestPooledUpstream>>();
  }

  // Expects a NoFlush close on the given double's connection. Use before the close is supposed to
  // happen.
  void expectClose(NiceMock<TestPooledUpstream>& up) {
    EXPECT_CALL(up.connection_, close(Network::ConnectionCloseType::NoFlush));
  }

  const UpstreamPool::Stats& stats() { return pool_->stats(); }

  Event::SimulatedTimeSystem* time_system_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  // Owned by the dispatcher contract: createTimer() returns ownership of this raw pointer to the
  // pool, which holds it in maintenance_timer_, so the fixture must not delete it.
  NiceMock<Event::MockTimer>* maintenance_timer_;
  std::unique_ptr<UpstreamPool> pool_;
};

// Checkout on an unknown host (and the empty-key edge) is a miss: nullptr, checkout_miss bumped, no
// other counters move.
TEST_F(UpstreamPoolTest, CheckoutMissOnUnknownHost) {
  EXPECT_EQ(nullptr, pool_->checkout("10.0.0.1:443"));
  EXPECT_EQ(1, stats().checkout_miss);

  EXPECT_EQ(nullptr, pool_->checkout(""));
  EXPECT_EQ(2, stats().checkout_miss);

  EXPECT_EQ(0, stats().checkout_hit);
  EXPECT_EQ(0, stats().stale_discarded);
  EXPECT_EQ(0, stats().checkin_dropped);
}

// A clean check-in followed by a checkout for the same host returns the same connection, bumps
// checkout_hit, and size() reflects the deque growing then draining.
TEST_F(UpstreamPoolTest, CheckinCleanThenCheckoutHit) {
  auto up = makeUpstream();
  GenericUpstream* raw = up.get();

  EXPECT_EQ(0, pool_->size("h"));
  pool_->checkin("h", std::move(up), /*is_clean=*/true);
  EXPECT_EQ(1, pool_->size("h"));

  GenericUpstreamPtr out = pool_->checkout("h");
  EXPECT_EQ(raw, out.get());
  EXPECT_EQ(1, stats().checkout_hit);
  EXPECT_EQ(0, stats().checkout_miss);
  // The host bucket is erased once it empties.
  EXPECT_EQ(0, pool_->size("h"));
}

// LIFO: with A then B checked in, checkout returns the freshest (B) first, then A. Both are hits.
TEST_F(UpstreamPoolTest, CheckoutIsLifo) {
  auto up_a = makeUpstream();
  auto up_b = makeUpstream();
  GenericUpstream* raw_a = up_a.get();
  GenericUpstream* raw_b = up_b.get();

  pool_->checkin("h", std::move(up_a), true);
  pool_->checkin("h", std::move(up_b), true);
  EXPECT_EQ(2, pool_->size("h"));

  EXPECT_EQ(raw_b, pool_->checkout("h").get());
  EXPECT_EQ(raw_a, pool_->checkout("h").get());
  EXPECT_EQ(2, stats().checkout_hit);
  EXPECT_EQ(0, pool_->size("h"));
}

// A check-in flagged not-clean is dropped, not pooled, and the connection is closed (NoFlush).
TEST_F(UpstreamPoolTest, CheckinNotCleanIsDroppedAndClosed) {
  auto up = makeUpstream();
  expectClose(*up);

  pool_->checkin("h", std::move(up), /*is_clean=*/false);

  EXPECT_EQ(1, stats().checkin_dropped);
  EXPECT_EQ(0, stats().stale_discarded);
  EXPECT_EQ(0, pool_->size("h"));
}

// A check-in flagged clean but whose MSG_PEEK shows leftover bytes is discarded as stale, closed,
// and not pooled.
TEST_F(UpstreamPoolTest, CheckinCleanButPeekStaleIsDiscardedAndClosed) {
  auto up = makeUpstream();
  up->setStalePeekClosed();
  expectClose(*up);

  pool_->checkin("h", std::move(up), /*is_clean=*/true);

  EXPECT_EQ(1, stats().stale_discarded);
  EXPECT_EQ(0, stats().checkin_dropped);
  EXPECT_EQ(0, pool_->size("h"));
}

// Checkout skips entries that fail the clean-check, closing each one, and returns the first clean
// entry it finds. Here B (freshest, popped first) is stale and A is clean, so checkout discards B
// (stale_discarded, closed) and returns A (checkout_hit). The pool owns both after check-in, but
// the fixture keeps non-owning raw pointers so it can flip B stale and assert B's close.
TEST_F(UpstreamPoolTest, CheckoutSkipsStaleUntilClean) {
  auto up_a = makeUpstream();
  auto up_b = makeUpstream();
  NiceMock<TestPooledUpstream>* raw_a = up_a.get();
  NiceMock<TestPooledUpstream>* raw_b = up_b.get();

  pool_->checkin("h", std::move(up_a), true);
  pool_->checkin("h", std::move(up_b), true);
  EXPECT_EQ(2, pool_->size("h"));

  // B was clean at check-in (so it was pooled) but goes stale before the checkout clean-check runs.
  raw_b->setStalePeekBytes();
  expectClose(*raw_b);

  GenericUpstreamPtr out = pool_->checkout("h");
  EXPECT_EQ(raw_a, out.get());
  EXPECT_EQ(1, stats().stale_discarded);
  EXPECT_EQ(1, stats().checkout_hit);
  EXPECT_EQ(0, stats().checkout_miss);
  EXPECT_EQ(0, pool_->size("h"));
}

// All pooled entries fail the clean-check: checkout discards every one (stale_discarded each) and
// returns a miss, and the empty bucket is erased.
TEST_F(UpstreamPoolTest, CheckoutAllStaleIsMiss) {
  auto up_a = makeUpstream();
  auto up_b = makeUpstream();
  NiceMock<TestPooledUpstream>* raw_a = up_a.get();
  NiceMock<TestPooledUpstream>* raw_b = up_b.get();

  // Both are clean at check-in (so they pool), then both go stale before the checkout clean-check.
  pool_->checkin("h", std::move(up_a), true);
  pool_->checkin("h", std::move(up_b), true);
  EXPECT_EQ(2, pool_->size("h"));

  raw_a->setStalePeekBytes();
  raw_b->setStalePeekBytes();
  // Each stale entry must be closed when discarded.
  expectClose(*raw_a);
  expectClose(*raw_b);

  EXPECT_EQ(nullptr, pool_->checkout("h"));
  EXPECT_EQ(2, stats().stale_discarded);
  EXPECT_EQ(1, stats().checkout_miss);
  EXPECT_EQ(0, stats().checkout_hit);
  EXPECT_EQ(0, pool_->size("h"));
}

// At MaxPoolSizePerHost the next check-in evicts the oldest (front) entry: the front connection is
// closed, checkin_dropped is bumped, and the bucket stays at MaxPoolSizePerHost.
TEST_F(UpstreamPoolTest, CheckinEvictsFrontAtCapacity) {
  NiceMock<TestPooledUpstream>* front = nullptr;
  for (size_t i = 0; i < UpstreamPool::MaxPoolSizePerHost; ++i) {
    auto up = makeUpstream();
    if (i == 0) {
      front = up.get();
    }
    pool_->checkin("h", std::move(up), true);
  }
  EXPECT_EQ(UpstreamPool::MaxPoolSizePerHost, pool_->size("h"));
  ASSERT_NE(nullptr, front);
  // The oldest entry (first checked in, front of the deque) is the one evicted on overflow.
  expectClose(*front);

  auto overflow = makeUpstream();
  pool_->checkin("h", std::move(overflow), true);

  EXPECT_EQ(UpstreamPool::MaxPoolSizePerHost, pool_->size("h"));
  EXPECT_EQ(1, stats().checkin_dropped);
}

// A clean check-in rebinds the connection's read callbacks to the pool's idle sink exactly once, so
// an idle-window upstream byte or close event cannot reach the destroyed minting Filter.
TEST_F(UpstreamPoolTest, CheckinRebindsIdleCallbacks) {
  auto up = makeUpstream();
  NiceMock<TestPooledUpstream>* raw = up.get();

  pool_->checkin("h", std::move(up), true);

  EXPECT_EQ(1, raw->rebind_count_);
}

// Maintenance evicts entries idle longer than IdleTtl: after advancing the simulated clock past
// IdleTtl and firing the captured maintenance callback, the entry is closed, evicted_idle is
// bumped, the empty bucket is erased, and the timer is re-armed.
TEST_F(UpstreamPoolTest, MaintenanceEvictsIdleEntries) {
  auto up = makeUpstream();
  expectClose(*up);

  pool_->checkin("h", std::move(up), true);
  EXPECT_EQ(1, pool_->size("h"));

  // Push the clock past IdleTtl so the lone entry is older than the TTL when maintenance runs.
  time_system_->advanceTimeWait(UpstreamPool::IdleTtl + std::chrono::seconds(1));

  // The maintenance body re-arms the timer at the end of the sweep.
  EXPECT_CALL(*maintenance_timer_, enableTimer(_, _));
  maintenance_timer_->invokeCallback();

  EXPECT_EQ(1, stats().evicted_idle);
  EXPECT_EQ(0, pool_->size("h"));
}

// Maintenance keeps entries younger than IdleTtl: firing the sweep before the TTL elapses leaves
// the entry pooled and does not bump evicted_idle.
TEST_F(UpstreamPoolTest, MaintenanceKeepsFreshEntries) {
  auto up = makeUpstream();
  pool_->checkin("h", std::move(up), true);

  time_system_->advanceTimeWait(std::chrono::seconds(1));
  EXPECT_CALL(*maintenance_timer_, enableTimer(_, _));
  maintenance_timer_->invokeCallback();

  EXPECT_EQ(0, stats().evicted_idle);
  EXPECT_EQ(1, pool_->size("h"));
}

// The destructor closes every pooled connection (NoFlush) across multiple host buckets before the
// deques drop the unique_ptrs.
TEST_F(UpstreamPoolTest, DestructorClosesAllPooledConnections) {
  auto up_a = makeUpstream();
  auto up_b = makeUpstream();
  auto up_c = makeUpstream();
  expectClose(*up_a);
  expectClose(*up_b);
  expectClose(*up_c);

  pool_->checkin("h1", std::move(up_a), true);
  pool_->checkin("h1", std::move(up_b), true);
  pool_->checkin("h2", std::move(up_c), true);

  // Destroying the pool must close all three connections.
  pool_.reset();
}

} // namespace
} // namespace TcpProxy
} // namespace Envoy
