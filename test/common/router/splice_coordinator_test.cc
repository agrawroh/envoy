// Behavioral unit tests for Router::SpliceCoordinator. The coordinator drives the L7 HTTP/1.1 kTLS
// body-splice fast path on behalf of an UpstreamRequest. These tests construct a real
// UpstreamRequest (the same way upstream_request_test.cc does) and a SpliceCoordinator over it,
// then drive the arm, engage, complete, finalize, and reset state machine deterministically.
//
// The engage path normally constructs a real TcpProxy::SplicePump that runs pipe2()/splice() on the
// borrowed fds. To make engage and completion deterministic without any kernel I/O, the coordinator
// exposes a public SplicePumpFactory seam (setSplicePumpFactoryForTest). The fixture injects a
// FakeSplicePump that overrides the virtual setup methods (createPipes, prepare, setBounds, arm) so
// nothing touches a real socket, and captures the completion and byte callbacks so a test can fire
// them on demand. The real kernel splice byte path is covered by splice_pump_test.cc and is out of
// scope here.

#include "envoy/network/address.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"
#include "source/common/router/splice_coordinator.h"
#include "source/common/router/upstream_request.h"
#include "source/common/tcp_proxy/splice_pump.h"

#include "test/common/http/common.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/network/connection.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/router/router_filter_interface.h"
#include "test/mocks/ssl/mocks.h"
#include "test/test_common/test_runtime.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace Envoy {
namespace Router {
namespace {

// Fds handed to the coordinator. The FakeSplicePump ignores them, but they must be non-INVALID so
// spliceableFd() accepts the legs. They are never read or written.
constexpr os_fd_t kUpstreamFd = 11;
constexpr os_fd_t kDownstreamFd = 10;
// A Content-Length comfortably above MinSpliceBodyBytes (64 KiB).
constexpr uint64_t kBodyBytes = 128 * 1024;

// A no-I/O SplicePump test double. The base constructor only stores its arguments, so forwarding to
// it is safe. The setup methods are virtual in production solely so this double can replace them.
// Result of createPipes and prepare are fixture-controlled knobs.
class FakeSplicePump : public TcpProxy::SplicePump {
public:
  FakeSplicePump(os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls, Event::Dispatcher& dispatcher,
                 TcpProxy::SplicePump::CompletionCb on_complete,
                 TcpProxy::SplicePump::BytesCb on_u2d_bytes,
                 TcpProxy::SplicePump::BytesCb on_d2u_bytes)
      : TcpProxy::SplicePump(down_fd, up_fd, up_is_ktls, dispatcher, std::move(on_complete),
                             std::move(on_u2d_bytes), std::move(on_d2u_bytes)) {}

  bool createPipes(bool need_u2d, bool need_d2u) override {
    create_pipes_called_ = true;
    need_u2d_ = need_u2d;
    need_d2u_ = need_d2u;
    return create_pipes_result_;
  }
  bool prepare(std::string initial_u2d, std::string initial_d2u) override {
    prepare_called_ = true;
    prepare_initial_u2d_ = std::move(initial_u2d);
    prepare_initial_d2u_ = std::move(initial_d2u);
    return prepare_result_;
  }
  void setBounds(absl::optional<uint64_t> u2d_limit, absl::optional<uint64_t> d2u_limit) override {
    set_bounds_called_ = true;
    u2d_limit_ = u2d_limit;
    d2u_limit_ = d2u_limit;
  }
  void arm() override { arm_called_ = true; }

  // Fixture knobs.
  bool create_pipes_result_{true};
  bool prepare_result_{true};

  // Observations.
  bool create_pipes_called_{false};
  bool prepare_called_{false};
  bool set_bounds_called_{false};
  bool arm_called_{false};
  bool need_u2d_{false};
  bool need_d2u_{false};
  std::string prepare_initial_u2d_;
  std::string prepare_initial_d2u_;
  absl::optional<uint64_t> u2d_limit_;
  absl::optional<uint64_t> d2u_limit_;
};

// A GenericUpstream double that exposes only the splice seams the coordinator uses. Installed as
// upstream_request_->upstream_ so upstreamConnection() resolves to upstream_conn_.
class TestGenericUpstream : public GenericUpstream {
public:
  // Splice seams under test.
  OptRef<Network::Connection> upstreamConnectionForSplice() override { return splice_connection_; }
  MOCK_METHOD(void, completeSplicedResponse, (uint64_t response_body_bytes), (override));

  // Unused GenericUpstream surface, stubbed so the class is concrete.
  void encodeData(Buffer::Instance&, bool) override {}
  void encodeMetadata(const Http::MetadataMapVector&) override {}
  Http::Status encodeHeaders(const Http::RequestHeaderMap&, bool) override {
    return Http::okStatus();
  }
  void encodeTrailers(const Http::RequestTrailerMap&) override {}
  void enableTcpTunneling() override {}
  void readDisable(bool) override {}
  void resetStream() override {}
  void setAccount(Buffer::BufferMemoryAccountSharedPtr) override {}
  const StreamInfo::BytesMeterSharedPtr& bytesMeter() override { return bytes_meter_; }

  OptRef<Network::Connection> splice_connection_;
  StreamInfo::BytesMeterSharedPtr bytes_meter_{std::make_shared<StreamInfo::BytesMeter>()};
};

// Subclass of the shared downstream filter callbacks mock that adds the two splice seams the
// coordinator reaches through callbacks()->downstreamCallbacks().
class TestDownstreamFilterCallbacks : public Http::MockDownstreamStreamFilterCallbacks {
public:
  MOCK_METHOD(OptRef<Network::Connection>, downstreamConnectionForSplice, (), (override));
  MOCK_METHOD(void, completeSplicedRequest, (uint64_t request_body_bytes), (override));
};

} // namespace

// The fixture lives directly in Envoy::Router (not the anonymous namespace) so the
// `friend class SpliceCoordinatorTest;` declaration in UpstreamRequest resolves to it and grants
// access to the private members the coordinator reads. The helper doubles above stay anonymous.
class SpliceCoordinatorTest : public testing::Test {
public:
  SpliceCoordinatorTest() {
    scoped_runtime_.mergeValues({{"envoy.reloadable_features.http1_ktls_body_splice", "true"}});
    HttpTestUtility::addDefaultHeaders(downstream_request_header_map_);
    ON_CALL(parent_, downstreamHeaders()).WillByDefault(Return(&downstream_request_header_map_));
  }

protected:
  // Builds the UpstreamRequest, the coordinator, wires every mock the coordinator reads, and
  // injects the fake-pump factory. Call once per test before driving anything.
  void initialize() {
    auto conn_pool = std::make_unique<NiceMock<MockGenericConnPool>>();
    conn_pool_ = conn_pool.get();
    ON_CALL(*conn_pool_, host()).WillByDefault(Return(host_));
    upstream_request_ = std::make_unique<UpstreamRequest>(parent_, std::move(conn_pool),
                                                          /*can_send_early_data=*/false,
                                                          /*can_use_http3=*/true,
                                                          /*enable_half_close=*/false);

    coord_ = std::make_unique<SpliceCoordinator>(*upstream_request_);

    // Dispatcher: capture-and-fire. The coordinator creates schedulable callbacks lazily in the
    // order engage-callback then finalize-callback, so the first capture is engage and the second
    // is finalize. createTimer is captured into the next free timer slot (poll then watchdog).
    Event::MockDispatcher& disp = parent_.callbacks_.dispatcher_;
    ON_CALL(disp, createSchedulableCallback_(_))
        .WillByDefault(Invoke([this](std::function<void()> cb) -> Event::SchedulableCallback* {
          auto* sched = new NiceMock<Event::MockSchedulableCallback>(
              &this->parent_.callbacks_.dispatcher_, cb);
          if (engage_sched_ == nullptr) {
            engage_sched_ = sched;
            engage_cb_ = cb;
          } else {
            finalize_sched_ = sched;
            finalize_cb_ = cb;
          }
          return sched;
        }));
    // Timers are created lazily and in a direction-dependent order: an upload-poll creates the 2ms
    // poll timer first, then a successful engage creates the 30s progress watchdog. A download
    // creates only the watchdog. Classify each timer the first time it is enabled by its duration
    // rather than by creation order so both directions resolve correctly.
    ON_CALL(disp, createTimer_(_)).WillByDefault(Invoke([this](Event::TimerCb cb) -> Event::Timer* {
      auto* timer = new NiceMock<Event::MockTimer>();
      timer->callback_ = cb;
      ON_CALL(*timer, enableTimer(_, _))
          .WillByDefault(
              Invoke([this, timer](std::chrono::milliseconds d, const ScopeTrackedObject* scope) {
                timer->enabled_ = true;
                timer->scope_ = scope;
                if (d == std::chrono::milliseconds(2)) {
                  poll_timer_ = timer;
                } else {
                  watchdog_timer_ = timer;
                }
              }));
      return timer;
    }));

    // Downstream leg: resolved via
    // callbacks()->downstreamCallbacks()->downstreamConnectionForSplice.
    ON_CALL(down_cb_, downstreamConnectionForSplice())
        .WillByDefault(Return(OptRef<Network::Connection>(downstream_conn_)));
    ON_CALL(parent_.callbacks_, downstreamCallbacks())
        .WillByDefault(Return(OptRef<Http::DownstreamStreamFilterCallbacks>(down_cb_)));

    // Downstream sink: plaintext raw (ssl()==nullptr, no kTLS info) so sinkLegIsRawOrKtls is true.
    wireConnection(downstream_conn_, down_socket_, down_io_, down_socket_ptr_, kDownstreamFd);
    ON_CALL(downstream_conn_, ssl()).WillByDefault(Return(nullptr));
    ON_CALL(downstream_conn_, ktlsBytestreamInfo())
        .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>{}));

    // Upstream leg: kTLS installed and trusted, ssl()==nullptr.
    wireConnection(upstream_conn_, up_socket_, up_io_, up_socket_ptr_, kUpstreamFd);
    ON_CALL(upstream_conn_, ssl()).WillByDefault(Return(nullptr));
    up_ktls_.installed = true;
    up_ktls_.trusted_peer = true;
    up_ktls_.fd = kUpstreamFd;
    ON_CALL(upstream_conn_, ktlsBytestreamInfo())
        .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>(up_ktls_)));

    // GenericUpstream installed so upstreamConnection() resolves to upstream_conn_.
    auto test_upstream = std::make_unique<NiceMock<TestGenericUpstream>>();
    test_upstream_ = test_upstream.get();
    test_upstream_->splice_connection_ = upstream_conn_;
    upstream_request_->upstream_ = std::move(test_upstream);

    // Pending write the sink hands to the pump; non-empty so prepare receives the headers chunk.
    ON_CALL(upstream_conn_, extractPendingWriteForSplice())
        .WillByDefault(Return(std::string("UP-HEADERS")));
    ON_CALL(downstream_conn_, extractPendingWriteForSplice())
        .WillByDefault(Return(std::string("DOWN-HEADERS")));

    // The fake-pump factory: build a FakeSplicePump, copy the fixture knobs onto it, capture the
    // completion and byte callbacks, and stash the raw pointer for observation.
    coord_->setSplicePumpFactoryForTest(
        [this](os_fd_t down_fd, os_fd_t up_fd, bool up_is_ktls, Event::Dispatcher& dispatcher,
               TcpProxy::SplicePump::CompletionCb on_complete,
               TcpProxy::SplicePump::BytesCb on_u2d_bytes,
               TcpProxy::SplicePump::BytesCb on_d2u_bytes) -> TcpProxy::SplicePumpPtr {
          factory_called_ = true;
          factory_down_fd_ = down_fd;
          factory_up_fd_ = up_fd;
          factory_up_is_ktls_ = up_is_ktls;
          completion_cb_ = std::move(on_complete);
          u2d_bytes_cb_ = std::move(on_u2d_bytes);
          d2u_bytes_cb_ = std::move(on_d2u_bytes);
          auto pump = std::make_unique<FakeSplicePump>(
              down_fd, up_fd, up_is_ktls, dispatcher, completion_cb_, u2d_bytes_cb_, d2u_bytes_cb_);
          pump->create_pipes_result_ = create_pipes_result_;
          pump->prepare_result_ = prepare_result_;
          fake_pump_ = pump.get();
          return pump;
        });
  }

  void TearDown() override {
    // The ConnectionSocketPtrs are non-owning wrappers around stack mocks; release so the
    // unique_ptr does not double-free a stack object.
    up_socket_ptr_.release();
    down_socket_ptr_.release();
  }

  // Wires a connection mock so getSocket()->ioHandle().fdDoNotUse() returns `fd`, resetFileEvents()
  // is a no-op, and a non-internal local address is present so spliceableFd accepts it.
  void wireConnection(NiceMock<Network::MockConnection>& c,
                      NiceMock<Network::MockConnectionSocket>& s,
                      NiceMock<Network::MockIoHandle>& io, Network::ConnectionSocketPtr& sptr,
                      os_fd_t fd) {
    sptr.reset(&s);
    ON_CALL(c, getSocket()).WillByDefault(ReturnRef(sptr));
    ON_CALL(s, ioHandle()).WillByDefault(ReturnRef(io));
    ON_CALL(Const(s), ioHandle()).WillByDefault(ReturnRef(io));
    ON_CALL(io, fdDoNotUse()).WillByDefault(Return(fd));
    c.connectionInfoSetter().setLocalAddress(
        Network::Utility::parseInternetAddressAndPortNoThrow("127.0.0.1:80"));
    // state() defaults Open via initializeMockConnection, readDisable returns a status.
    ON_CALL(c, readDisable(_))
        .WillByDefault(Return(Network::Connection::ReadDisableStatus::StillReadDisabled));
  }

  // Arms a download splice for `cl` bytes. encodeComplete() must already be true (set via the
  // friend). Returns the arm result.
  bool armDownload(uint64_t cl = kBodyBytes) {
    setEncodeComplete(true);
    Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                            {"content-length", absl::StrCat(cl)}};
    return coord_->maybeArmForResponse(headers, /*end_stream=*/false);
  }

  // Arms an upload splice for `cl` bytes.
  bool armUpload(uint64_t cl = kBodyBytes) {
    Http::TestRequestHeaderMapImpl headers{{":method", "PUT"},
                                           {":path", "/"},
                                           {":authority", "host"},
                                           {"content-length", absl::StrCat(cl)}};
    return coord_->maybeArmForRequest(headers, /*end_stream=*/false);
  }

  void fireEngage() {
    ASSERT_TRUE(engage_cb_ != nullptr);
    engage_cb_();
  }
  void fireFinalize() {
    ASSERT_TRUE(finalize_cb_ != nullptr);
    finalize_cb_();
  }

  uint64_t counter(absl::string_view name) {
    return parent_.cluster_info_->stats_store_.counter(absl::StrCat("http1_ktls_splice.", name))
        .value();
  }

  // Private-member accessors. The fixture class is a friend of UpstreamRequest, but friendship is
  // not inherited by the per-TEST_F subclasses, so these helpers live here on the fixture and the
  // tests call them.
  void setEncodeComplete(bool complete) { upstream_request_->router_sent_end_stream_ = complete; }
  void clearUpstream() { upstream_request_->upstream_.reset(); }
  bool onResetStreamInProgress() const { return upstream_request_->on_reset_stream_in_progress_; }
  // Re-enters onResetStream as the codec reset cascade would when the upstream is force-closed.
  void reenterOnResetStream() {
    upstream_request_->onResetStream(Http::StreamResetReason::ConnectionTermination,
                                     "codec reset cascade");
  }

  TestScopedRuntime scoped_runtime_;
  NiceMock<MockRouterFilterInterface> parent_;
  Http::TestRequestHeaderMapImpl downstream_request_header_map_;
  MockGenericConnPool* conn_pool_{nullptr};
  std::shared_ptr<NiceMock<Upstream::MockHostDescription>> host_{
      new NiceMock<Upstream::MockHostDescription>()};
  std::unique_ptr<UpstreamRequest> upstream_request_;
  std::unique_ptr<SpliceCoordinator> coord_;

  NiceMock<Network::MockConnection> upstream_conn_;
  NiceMock<Network::MockConnection> downstream_conn_;
  NiceMock<Network::MockConnectionSocket> up_socket_;
  NiceMock<Network::MockConnectionSocket> down_socket_;
  NiceMock<Network::MockIoHandle> up_io_;
  NiceMock<Network::MockIoHandle> down_io_;
  Network::ConnectionSocketPtr up_socket_ptr_;
  Network::ConnectionSocketPtr down_socket_ptr_;
  Network::KtlsBytestreamInfo up_ktls_;
  Network::KtlsBytestreamInfo down_ktls_;

  NiceMock<TestDownstreamFilterCallbacks> down_cb_;
  TestGenericUpstream* test_upstream_{nullptr};

  // Captured dispatcher artifacts.
  std::function<void()> engage_cb_;
  std::function<void()> finalize_cb_;
  Event::MockSchedulableCallback* engage_sched_{nullptr};
  Event::MockSchedulableCallback* finalize_sched_{nullptr};
  Event::MockTimer* poll_timer_{nullptr};
  Event::MockTimer* watchdog_timer_{nullptr};

  // Fake pump factory knobs and observations.
  bool create_pipes_result_{true};
  bool prepare_result_{true};
  bool factory_called_{false};
  os_fd_t factory_down_fd_{0};
  os_fd_t factory_up_fd_{0};
  bool factory_up_is_ktls_{false};
  FakeSplicePump* fake_pump_{nullptr};
  TcpProxy::SplicePump::CompletionCb completion_cb_;
  TcpProxy::SplicePump::BytesCb u2d_bytes_cb_;
  TcpProxy::SplicePump::BytesCb d2u_bytes_cb_;
};

// ----------------------------------------------------------------------------------------------
// A. ARM - Download (maybeArmForResponse)
// ----------------------------------------------------------------------------------------------

// #1 arm-dl-happy
TEST_F(SpliceCoordinatorTest, ArmDownloadHappy) {
  initialize();
  EXPECT_TRUE(armDownload());
  EXPECT_TRUE(coord_->armedForResponse());
  EXPECT_FALSE(coord_->armedForRequest());
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(0, counter("abandoned"));
}

// #2 arm-dl-flag-off
TEST_F(SpliceCoordinatorTest, ArmDownloadFlagOff) {
  scoped_runtime_.mergeValues({{"envoy.reloadable_features.http1_ktls_body_splice", "false"}});
  initialize();
  EXPECT_FALSE(armDownload());
  EXPECT_FALSE(coord_->armedForResponse());
}

// #3 arm-dl-end-stream
TEST_F(SpliceCoordinatorTest, ArmDownloadEndStream) {
  initialize();
  setEncodeComplete(true);
  Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                          {"content-length", absl::StrCat(kBodyBytes)}};
  EXPECT_FALSE(coord_->maybeArmForResponse(headers, /*end_stream=*/true));
}

// #4 arm-dl-encode-incomplete
TEST_F(SpliceCoordinatorTest, ArmDownloadEncodeIncomplete) {
  initialize();
  setEncodeComplete(false);
  Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                          {"content-length", absl::StrCat(kBodyBytes)}};
  EXPECT_FALSE(coord_->maybeArmForResponse(headers, /*end_stream=*/false));
}

// #5 arm-dl-no-content-length
TEST_F(SpliceCoordinatorTest, ArmDownloadNoContentLength) {
  initialize();
  setEncodeComplete(true);
  Http::TestResponseHeaderMapImpl headers{{":status", "200"}};
  EXPECT_FALSE(coord_->maybeArmForResponse(headers, /*end_stream=*/false));
}

// #6 arm-dl-cl-unparseable
TEST_F(SpliceCoordinatorTest, ArmDownloadContentLengthUnparseable) {
  initialize();
  setEncodeComplete(true);
  Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"content-length", "abc"}};
  EXPECT_FALSE(coord_->maybeArmForResponse(headers, /*end_stream=*/false));
}

// #7 arm-dl-cl-below-min
TEST_F(SpliceCoordinatorTest, ArmDownloadContentLengthBelowMin) {
  initialize();
  // Well below the 64 KiB minimum.
  EXPECT_FALSE(armDownload(1024));
}

// #8 arm-dl-cl-at-min (boundary: MinSpliceBodyBytes == 65536, predicate is `<`)
TEST_F(SpliceCoordinatorTest, ArmDownloadContentLengthAtMin) {
  initialize();
  EXPECT_TRUE(armDownload(65536));
}

// #9 arm-dl-cl-just-below (pins the boundary in #8)
TEST_F(SpliceCoordinatorTest, ArmDownloadContentLengthJustBelowMin) {
  initialize();
  EXPECT_FALSE(armDownload(65535));
}

// #10 arm-dl-upstream-not-borrowable
TEST_F(SpliceCoordinatorTest, ArmDownloadUpstreamNotBorrowable) {
  initialize();
  test_upstream_->splice_connection_ = {}; // upstreamConnection() empty
  EXPECT_FALSE(armDownload());
}

// #11 arm-dl-downstream-not-borrowable
TEST_F(SpliceCoordinatorTest, ArmDownloadDownstreamNotBorrowable) {
  initialize();
  ON_CALL(down_cb_, downstreamConnectionForSplice())
      .WillByDefault(Return(OptRef<Network::Connection>{}));
  EXPECT_FALSE(armDownload());
}

// #12 arm-dl-upstream-no-ktls-info
TEST_F(SpliceCoordinatorTest, ArmDownloadUpstreamNoKtlsInfo) {
  initialize();
  ON_CALL(upstream_conn_, ktlsBytestreamInfo())
      .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>{}));
  EXPECT_FALSE(armDownload());
}

// #13 arm-dl-upstream-ktls-not-installed
TEST_F(SpliceCoordinatorTest, ArmDownloadUpstreamKtlsNotInstalled) {
  initialize();
  up_ktls_.installed = false;
  EXPECT_FALSE(armDownload());
}

// #14 arm-dl-upstream-ktls-untrusted
TEST_F(SpliceCoordinatorTest, ArmDownloadUpstreamKtlsUntrusted) {
  initialize();
  up_ktls_.trusted_peer = false;
  EXPECT_FALSE(armDownload());
}

// #15 arm-dl-sink-boringssl (downstream ssl() non-null -> reject)
TEST_F(SpliceCoordinatorTest, ArmDownloadSinkBoringSsl) {
  initialize();
  auto ssl_info = std::make_shared<NiceMock<Ssl::MockConnectionInfo>>();
  ON_CALL(downstream_conn_, ssl()).WillByDefault(Return(ssl_info));
  EXPECT_FALSE(armDownload());
}

// #16 arm-dl-sink-rustls-userspace-trap (ssl null but kTLS installed=false -> reject)
TEST_F(SpliceCoordinatorTest, ArmDownloadSinkRustlsUserspaceTrap) {
  initialize();
  down_ktls_.installed = false;
  ON_CALL(downstream_conn_, ktlsBytestreamInfo())
      .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>(down_ktls_)));
  EXPECT_FALSE(armDownload());
}

// #17 arm-dl-sink-rustls-ktls-installed (ssl null, kTLS installed -> accept)
TEST_F(SpliceCoordinatorTest, ArmDownloadSinkRustlsKtlsInstalled) {
  initialize();
  down_ktls_.installed = true;
  ON_CALL(downstream_conn_, ktlsBytestreamInfo())
      .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>(down_ktls_)));
  EXPECT_TRUE(armDownload());
}

// #18 arm-dl-sink-plaintext-raw (ssl null, no kTLS info -> accept)
TEST_F(SpliceCoordinatorTest, ArmDownloadSinkPlaintextRaw) {
  initialize();
  EXPECT_TRUE(armDownload());
}

// ----------------------------------------------------------------------------------------------
// B. ARM - Upload (maybeArmForRequest)
// ----------------------------------------------------------------------------------------------

// #19 arm-ul-happy
TEST_F(SpliceCoordinatorTest, ArmUploadHappy) {
  initialize();
  EXPECT_CALL(downstream_conn_, readDisable(true))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::StillReadDisabled));
  EXPECT_TRUE(armUpload());
  EXPECT_TRUE(coord_->armedForRequest());
  EXPECT_FALSE(coord_->armedForResponse());
  EXPECT_EQ(0, counter("abandoned"));
}

// #20 arm-ul-flag-off
TEST_F(SpliceCoordinatorTest, ArmUploadFlagOff) {
  scoped_runtime_.mergeValues({{"envoy.reloadable_features.http1_ktls_body_splice", "false"}});
  initialize();
  EXPECT_CALL(downstream_conn_, readDisable(true)).Times(0);
  EXPECT_FALSE(armUpload());
}

// #21 arm-ul-end-stream-bodyless
TEST_F(SpliceCoordinatorTest, ArmUploadEndStreamBodyless) {
  initialize();
  EXPECT_CALL(downstream_conn_, readDisable(true)).Times(0);
  Http::TestRequestHeaderMapImpl headers{{":method", "PUT"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"content-length", absl::StrCat(kBodyBytes)}};
  EXPECT_FALSE(coord_->maybeArmForRequest(headers, /*end_stream=*/true));
}

// #22 arm-ul-no-content-length
TEST_F(SpliceCoordinatorTest, ArmUploadNoContentLength) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{
      {":method", "PUT"}, {":path", "/"}, {":authority", "host"}};
  EXPECT_FALSE(coord_->maybeArmForRequest(headers, /*end_stream=*/false));
}

// #23 arm-ul-cl-unparseable
TEST_F(SpliceCoordinatorTest, ArmUploadContentLengthUnparseable) {
  initialize();
  Http::TestRequestHeaderMapImpl headers{
      {":method", "PUT"}, {":path", "/"}, {":authority", "host"}, {"content-length", "xyz"}};
  EXPECT_FALSE(coord_->maybeArmForRequest(headers, /*end_stream=*/false));
}

// #24 arm-ul-cl-below-min
TEST_F(SpliceCoordinatorTest, ArmUploadContentLengthBelowMin) {
  initialize();
  EXPECT_FALSE(armUpload(65535));
}

// #25 arm-ul-cl-at-min (boundary)
TEST_F(SpliceCoordinatorTest, ArmUploadContentLengthAtMin) {
  initialize();
  EXPECT_CALL(downstream_conn_, readDisable(true))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::StillReadDisabled));
  EXPECT_TRUE(armUpload(65536));
}

// #26 arm-ul-source-not-borrowable
TEST_F(SpliceCoordinatorTest, ArmUploadSourceNotBorrowable) {
  initialize();
  ON_CALL(down_cb_, downstreamConnectionForSplice())
      .WillByDefault(Return(OptRef<Network::Connection>{}));
  EXPECT_CALL(downstream_conn_, readDisable(true)).Times(0);
  EXPECT_FALSE(armUpload());
}

// #27 arm-ul-source-boringssl
TEST_F(SpliceCoordinatorTest, ArmUploadSourceBoringSsl) {
  initialize();
  auto ssl_info = std::make_shared<NiceMock<Ssl::MockConnectionInfo>>();
  ON_CALL(downstream_conn_, ssl()).WillByDefault(Return(ssl_info));
  EXPECT_FALSE(armUpload());
}

// #28 arm-ul-source-rustls-trap (ssl null, kTLS installed=false)
TEST_F(SpliceCoordinatorTest, ArmUploadSourceRustlsTrap) {
  initialize();
  down_ktls_.installed = false;
  ON_CALL(downstream_conn_, ktlsBytestreamInfo())
      .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>(down_ktls_)));
  EXPECT_FALSE(armUpload());
}

// #29 arm-ul-source-rustls/raw (installed-ktls or raw -> accept; no upstream check at arm)
TEST_F(SpliceCoordinatorTest, ArmUploadSourceRaw) {
  initialize();
  EXPECT_CALL(downstream_conn_, readDisable(true))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::StillReadDisabled));
  EXPECT_TRUE(armUpload());
}

// ----------------------------------------------------------------------------------------------
// C. PRE-ENGAGE buffering (bufferPreEngageBody)
// ----------------------------------------------------------------------------------------------

// #30 buf-take-body
TEST_F(SpliceCoordinatorTest, BufferTakeBody) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl data("0123456789");
  EXPECT_TRUE(coord_->bufferPreEngageBody(data, /*end_stream=*/false));
  EXPECT_EQ(0, data.length());
  EXPECT_EQ(0, counter("abandoned"));
  EXPECT_TRUE(coord_->armedForResponse());
}

// #31 buf-message-ends-before-engage (download flush goes through onUpstreamData)
TEST_F(SpliceCoordinatorTest, BufferMessageEndsBeforeEngageDownload) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl held("held");
  ASSERT_TRUE(coord_->bufferPreEngageBody(held, /*end_stream=*/false));
  Buffer::OwnedImpl data("final");
  EXPECT_CALL(parent_, onUpstreamData(_, _, false));
  EXPECT_FALSE(coord_->bufferPreEngageBody(data, /*end_stream=*/true));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_FALSE(coord_->armedForResponse());
}

// #32 buf-exceeds-max-held
TEST_F(SpliceCoordinatorTest, BufferExceedsMaxHeld) {
  initialize();
  ASSERT_TRUE(armDownload());
  // Hold just under the 4 MiB cap, then push it over.
  Buffer::OwnedImpl held(std::string(4 * 1024 * 1024 - 10, 'x'));
  ASSERT_TRUE(coord_->bufferPreEngageBody(held, /*end_stream=*/false));
  Buffer::OwnedImpl data(std::string(20, 'y'));
  EXPECT_CALL(parent_, onUpstreamData(_, _, false));
  EXPECT_FALSE(coord_->bufferPreEngageBody(data, /*end_stream=*/false));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #33 buf-at-max-held-boundary (held+data == 4 MiB; predicate is `>`, so still taken)
TEST_F(SpliceCoordinatorTest, BufferAtMaxHeldBoundary) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl data(std::string(4 * 1024 * 1024, 'z'));
  EXPECT_TRUE(coord_->bufferPreEngageBody(data, /*end_stream=*/false));
  EXPECT_EQ(0, data.length());
  EXPECT_EQ(0, counter("abandoned"));
}

// ----------------------------------------------------------------------------------------------
// D. ENGAGE - Download
// ----------------------------------------------------------------------------------------------

// #35 engage-dl-success
TEST_F(SpliceCoordinatorTest, EngageDownloadSuccess) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  // A download must not disable retries.
  EXPECT_CALL(parent_, disableRetries()).Times(0);
  fireEngage();
  EXPECT_TRUE(coord_->engaged());
  EXPECT_EQ(1, counter("engaged"));
  EXPECT_EQ(0, counter("abandoned"));
  ASSERT_NE(nullptr, fake_pump_);
  // Download uses the u2d pipe only and bounds the u2d direction.
  EXPECT_TRUE(fake_pump_->need_u2d_);
  EXPECT_FALSE(fake_pump_->need_d2u_);
  ASSERT_TRUE(fake_pump_->u2d_limit_.has_value());
  EXPECT_EQ(kBodyBytes, fake_pump_->u2d_limit_.value());
  EXPECT_FALSE(fake_pump_->d2u_limit_.has_value());
  EXPECT_TRUE(fake_pump_->arm_called_);
  // up_is_ktls is always true on the download upstream leg.
  EXPECT_TRUE(factory_up_is_ktls_);
  // Watchdog armed at engage.
  ASSERT_NE(nullptr, watchdog_timer_);
  EXPECT_TRUE(watchdog_timer_->enabled_);
}

// #36 engage-dl-leg-lost-after-schedule
TEST_F(SpliceCoordinatorTest, EngageDownloadLegLostAfterSchedule) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  test_upstream_->splice_connection_ = {}; // upstream leg now empty
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #37 engage-dl-revalidate-ktls-lost
TEST_F(SpliceCoordinatorTest, EngageDownloadRevalidateKtlsLost) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  up_ktls_.installed = false; // kTLS lost across the schedule gap
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #38 engage-dl-fd-not-spliceable (leg no longer Open)
TEST_F(SpliceCoordinatorTest, EngageDownloadFdNotSpliceable) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  upstream_conn_.state_ = Network::Connection::State::Closed;
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #39 engage-dl-whole-body-buffered (held >= CL -> nothing to splice)
TEST_F(SpliceCoordinatorTest, EngageDownloadWholeBodyBuffered) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl whole(std::string(kBodyBytes, 'b'));
  ASSERT_TRUE(coord_->bufferPreEngageBody(whole, /*end_stream=*/false));
  coord_->scheduleEngage();
  EXPECT_CALL(parent_, onUpstreamData(_, _, false)); // held delivered via flush
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #40 engage-dl-pipe-create-fails (createPipes false -> abandon, no engaged, no pending extract)
TEST_F(SpliceCoordinatorTest, EngageDownloadPipeCreateFails) {
  initialize();
  create_pipes_result_ = false;
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  // Pending write must NOT be extracted when pipe creation fails before the irreversible drain.
  EXPECT_CALL(downstream_conn_, extractPendingWriteForSplice()).Times(0);
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
  ASSERT_NE(nullptr, fake_pump_);
  EXPECT_TRUE(fake_pump_->create_pipes_called_);
  EXPECT_FALSE(fake_pump_->prepare_called_);
}

// #41 engage-dl-prepare-fails-after-extract (createPipes ok, prepare false -> engaged THEN
// truncated)
TEST_F(SpliceCoordinatorTest, EngageDownloadPrepareFailsAfterExtract) {
  initialize();
  prepare_result_ = false;
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  EXPECT_CALL(parent_, onUpstreamReset(Http::StreamResetReason::ConnectionTermination,
                                       "kTLS body-splice setup failed", _));
  fireEngage();
  EXPECT_EQ(1, counter("engaged"));
  EXPECT_EQ(1, counter("truncated"));
  EXPECT_EQ(0, counter("abandoned"));
}

// #41b engage-dl-partial-pre-engage-buffer: a held prefix shrinks the spliced bound and is
// prepended to the pre-engage chunk. Validates the spliced_body_bytes_ = content_length_ - buffered
// accounting, the reduced setBounds, and that the held body follows the sink's pending headers.
TEST_F(SpliceCoordinatorTest, EngageDownloadPartialPreEngageBuffer) {
  initialize();
  ASSERT_TRUE(armDownload());
  constexpr uint64_t kHeld = 4096;
  Buffer::OwnedImpl held(std::string(kHeld, 'x'));
  ASSERT_TRUE(coord_->bufferPreEngageBody(held, /*end_stream=*/false));
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  EXPECT_EQ(1, counter("engaged"));
  ASSERT_NE(nullptr, fake_pump_);
  // The bound is the Content-Length minus the body already held in memory.
  ASSERT_TRUE(fake_pump_->u2d_limit_.has_value());
  EXPECT_EQ(kBodyBytes - kHeld, fake_pump_->u2d_limit_.value());
  EXPECT_FALSE(fake_pump_->d2u_limit_.has_value());
  // The download pre-engage chunk is the sink's pending headers followed by the held body.
  EXPECT_EQ(absl::StrCat("DOWN-HEADERS", std::string(kHeld, 'x')),
            fake_pump_->prepare_initial_u2d_);
  EXPECT_TRUE(fake_pump_->prepare_initial_d2u_.empty());
}

// #38b engage-dl-fd-invalid-socket: a leg with no kernel fd (INVALID_SOCKET) abandons to the
// buffered path rather than splicing on a bogus descriptor.
TEST_F(SpliceCoordinatorTest, EngageDownloadFdInvalidSocket) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  ON_CALL(up_io_, fdDoNotUse()).WillByDefault(Return(INVALID_SOCKET));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
}

// #38c engage-dl-leg-internal-listener: an internal-listener leg has no kernel fd to splice on, so
// engage abandons.
TEST_F(SpliceCoordinatorTest, EngageDownloadLegEnvoyInternal) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  upstream_conn_.connectionInfoSetter().setLocalAddress(
      std::make_shared<Network::Address::EnvoyInternalInstance>("test_internal"));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
}

// #40b engage-dl-sink-tls-flip: the sink leg turns into a userspace-TLS socket (ssl() non-null)
// across the schedule gap, so the engage re-validation refuses to splice plaintext into it.
TEST_F(SpliceCoordinatorTest, EngageDownloadSinkTlsFlipAfterSchedule) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  auto ssl_info = std::make_shared<NiceMock<Ssl::MockConnectionInfo>>();
  ON_CALL(downstream_conn_, ssl()).WillByDefault(Return(ssl_info));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
}

// ----------------------------------------------------------------------------------------------
// E. ENGAGE - Upload (poll + bail)
// ----------------------------------------------------------------------------------------------

// #42 engage-ul-shadow-active
TEST_F(SpliceCoordinatorTest, EngageUploadShadowActive) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  ON_CALL(parent_, shadowStreamsActive()).WillByDefault(Return(true));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #43 engage-ul-downstream-lost
TEST_F(SpliceCoordinatorTest, EngageUploadDownstreamLost) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  ON_CALL(down_cb_, downstreamConnectionForSplice())
      .WillByDefault(Return(OptRef<Network::Connection>{}));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #44 engage-ul-pool-not-ready-poll (upstream leg empty AND upstream_ null -> reschedule)
TEST_F(SpliceCoordinatorTest, EngageUploadPoolNotReadyPoll) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  clearUpstream(); // pool not ready
  test_upstream_ = nullptr;
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("abandoned"));
  ASSERT_NE(nullptr, poll_timer_);
  EXPECT_TRUE(poll_timer_->enabled_); // rescheduled on the 2ms poll timer
}

// #45 engage-ul-upstream-not-h1 (upstream leg empty but upstream_ present -> immediate abandon)
TEST_F(SpliceCoordinatorTest, EngageUploadUpstreamNotHttp1) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  test_upstream_->splice_connection_ = {}; // present but not borrowable
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
  // Did not create a poll timer.
  EXPECT_EQ(nullptr, poll_timer_);
}

// #46 engage-ul-upstream-no-ktls
TEST_F(SpliceCoordinatorTest, EngageUploadUpstreamNoKtls) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  ON_CALL(upstream_conn_, ktlsBytestreamInfo())
      .WillByDefault(Return(OptRef<const Network::KtlsBytestreamInfo>{}));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #47 engage-ul-ktls-installing-poll
TEST_F(SpliceCoordinatorTest, EngageUploadKtlsInstallingPoll) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  up_ktls_.installed = false; // kTLS-TX still installing
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("abandoned"));
  ASSERT_NE(nullptr, poll_timer_);
  EXPECT_TRUE(poll_timer_->enabled_);
}

// #48 engage-ul-poll-exceeds-max (boundary at MaxEngagePolls == 64)
TEST_F(SpliceCoordinatorTest, EngageUploadPollExceedsMax) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  up_ktls_.installed = false; // keep polling forever
  fireEngage();               // engage_polls_ -> 1, schedules poll timer
  ASSERT_NE(nullptr, poll_timer_);
  // Fire the poll timer until the bound is exceeded. The first fireEngage already did poll 1.
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
  // 64 more poll-timer fires bring engage_polls_ from 1 to 65; the 65th (> 64) abandons.
  for (int i = 0; i < 64; i++) {
    ASSERT_TRUE(poll_timer_->enabled_);
    poll_timer_->invokeCallback();
  }
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #49 engage-ul-success
TEST_F(SpliceCoordinatorTest, EngageUploadSuccess) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  // Upload must disable retries the moment it engages.
  EXPECT_CALL(parent_, disableRetries());
  fireEngage();
  EXPECT_TRUE(coord_->engaged());
  EXPECT_EQ(1, counter("engaged"));
  ASSERT_NE(nullptr, fake_pump_);
  // Upload uses the d2u pipe only and bounds the d2u direction.
  EXPECT_FALSE(fake_pump_->need_u2d_);
  EXPECT_TRUE(fake_pump_->need_d2u_);
  ASSERT_TRUE(fake_pump_->d2u_limit_.has_value());
  EXPECT_EQ(kBodyBytes, fake_pump_->d2u_limit_.value());
  EXPECT_FALSE(fake_pump_->u2d_limit_.has_value());
  ASSERT_NE(nullptr, watchdog_timer_);
  EXPECT_TRUE(watchdog_timer_->enabled_);
}

// #50 engage-ul-not-armed-noop
TEST_F(SpliceCoordinatorTest, EngageNotArmedNoop) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  coord_->reset(); // clears armed_
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_FALSE(factory_called_);
  EXPECT_EQ(0, counter("engaged"));
}

// ----------------------------------------------------------------------------------------------
// F. COMPLETE (onSpliceComplete -> finalize)
// ----------------------------------------------------------------------------------------------

// #51 complete-dl-bounds-reached
TEST_F(SpliceCoordinatorTest, CompleteDownloadBoundsReached) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  // onSpliceComplete only schedules finalize; pump not yet gone.
  EXPECT_TRUE(coord_->engaged());

  {
    InSequence seq;
    EXPECT_CALL(downstream_conn_, reinstallFileEvents());
    EXPECT_CALL(*test_upstream_, completeSplicedResponse(kBodyBytes));
    EXPECT_CALL(upstream_conn_, reinstallFileEvents());
  }
  // Neither leg is closed on a clean completion.
  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  EXPECT_CALL(downstream_conn_, close(_)).Times(0);
  fireFinalize();
  EXPECT_FALSE(coord_->engaged());
  // Per-engaged invariant: one engaged, then exactly one of completed XOR truncated.
  EXPECT_EQ(1, counter("engaged"));
  EXPECT_EQ(1, counter("completed"));
  EXPECT_EQ(0, counter("truncated"));
}

// #52 complete-ul-bounds-reached
TEST_F(SpliceCoordinatorTest, CompleteUploadBoundsReached) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  {
    InSequence seq;
    // Upload: re-arm sink (upstream) first, then re-enable the held source read (which reinstalls
    // the source leg first), then complete the request.
    EXPECT_CALL(upstream_conn_, reinstallFileEvents());
    EXPECT_CALL(downstream_conn_, reinstallFileEvents());
    EXPECT_CALL(downstream_conn_, readDisable(false))
        .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
    EXPECT_CALL(down_cb_, completeSplicedRequest(kBodyBytes));
  }
  fireFinalize();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("engaged"));
  EXPECT_EQ(1, counter("completed"));
  EXPECT_EQ(0, counter("truncated"));
}

// #53 complete-truncated (Closed)
TEST_F(SpliceCoordinatorTest, CompleteTruncated) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  completion_cb_(TcpProxy::SpliceCompletion::Closed);
  // Truncation force-closes the upstream NoFlush and does NOT re-arm the legs.
  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush));
  EXPECT_CALL(upstream_conn_, reinstallFileEvents()).Times(0);
  EXPECT_CALL(downstream_conn_, reinstallFileEvents()).Times(0);
  fireFinalize();
  EXPECT_EQ(1, counter("engaged"));
  EXPECT_EQ(1, counter("truncated"));
  EXPECT_EQ(0, counter("completed"));
}

// #53b complete-truncated-upstream-already-closed: on the truncation path an upstream that is
// already Closed is not force-closed again, mirroring the BoundsReached leg-closed skip in
// FinalizeLegClosedSkipRearm. The truncation is still counted.
TEST_F(SpliceCoordinatorTest, CompleteTruncatedUpstreamAlreadyClosed) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  completion_cb_(TcpProxy::SpliceCompletion::Closed);
  upstream_conn_.state_ = Network::Connection::State::Closed;
  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  fireFinalize();
  EXPECT_EQ(1, counter("truncated"));
}

// #54 complete-error == Closed (same truncation branch; there is no separate Error enum value)
TEST_F(SpliceCoordinatorTest, CompleteErrorRoutesToTruncation) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  // Upload that truncates re-enables the held source before force-closing the upstream.
  completion_cb_(TcpProxy::SpliceCompletion::Closed);
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush));
  fireFinalize();
  EXPECT_EQ(1, counter("truncated"));
}

// #55 complete-finalize-callback-deferred
TEST_F(SpliceCoordinatorTest, CompleteFinalizeDeferred) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  // The completion callback must not destroy the pump inline. engaged() stays true until finalize.
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  EXPECT_TRUE(coord_->engaged());
  ASSERT_TRUE(finalize_cb_ != nullptr);
  EXPECT_TRUE(finalize_sched_->enabled_);
  fireFinalize();
  EXPECT_FALSE(coord_->engaged());
}

// ----------------------------------------------------------------------------------------------
// G. RESET / re-entrancy
// ----------------------------------------------------------------------------------------------

// #56 reset-while-engaged
TEST_F(SpliceCoordinatorTest, ResetWhileEngaged) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush));
  coord_->reset();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(1, counter("truncated"));
  // The latch is set before the close so a re-entrant onResetStream is a no-op.
  EXPECT_TRUE(onResetStreamInProgress());
}

// #57 reset-double-free-guard (LOAD-BEARING).
// The NoFlush close on the upstream drives the codec reset cascade synchronously back into
// UpstreamRequest::onResetStream. Because reset() latched on_reset_stream_in_progress_=true BEFORE
// the close, that nested onResetStream must short-circuit at the latch and not act again: it must
// NOT call parent_.onUpstreamReset (which is what removes the request from the parent list). So
// onUpstreamReset fires exactly zero times here, proving the request leaves the list exactly once
// (the outer teardown owns that, not the nested cascade), and there is no double-free.
TEST_F(SpliceCoordinatorTest, ResetDoubleFreeGuard) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  bool latch_set_at_close = false;
  int close_reentries = 0;
  // close(NoFlush) re-enters onResetStream, simulating the codec reset cascade. We record the latch
  // value observed at the moment of the close and re-enter onResetStream just as the real cascade
  // would. This must NOT be a plain no-op stub or the guard is never exercised (a false green).
  ON_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush)).WillByDefault(Invoke([&]() {
    ++close_reentries;
    latch_set_at_close = onResetStreamInProgress();
    reenterOnResetStream();
  }));
  // The nested onResetStream must short-circuit at the latch and NOT reach onUpstreamReset.
  EXPECT_CALL(parent_, onUpstreamReset(_, _, _)).Times(0);
  // The upstream is force-closed exactly once.
  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush)).Times(1);

  // The latch is clear before reset(), proving reset() itself sets it (not fixture init).
  EXPECT_FALSE(onResetStreamInProgress());
  // Drive the in-flight reset, simulating UpstreamRequest teardown reaching the coordinator.
  coord_->reset();

  // The close fired and re-entered onResetStream exactly once: the cascade really ran.
  EXPECT_EQ(1, close_reentries);
  EXPECT_TRUE(latch_set_at_close); // latch was set BEFORE the close
  EXPECT_EQ(1, counter("truncated"));
}

// #58 reset-not-engaged-noop-counter (clean finalize then reset, or never engaged)
TEST_F(SpliceCoordinatorTest, ResetNotEngagedNoTruncated) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  fireFinalize(); // clean completion, pump cleared
  ASSERT_EQ(1, counter("completed"));

  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  coord_->reset();
  // After a clean finalize the pump is already gone, so reset() does not count a truncation.
  EXPECT_EQ(0, counter("truncated"));
}

// #59 reset-idempotent
TEST_F(SpliceCoordinatorTest, ResetIdempotent) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());

  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush)).Times(1);
  coord_->reset();
  coord_->reset(); // second reset is a no-op: no second close, no second truncated
  EXPECT_EQ(1, counter("truncated"));
}

// #60 reset-armed-not-engaged
TEST_F(SpliceCoordinatorTest, ResetArmedNotEngaged) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  coord_->reset();
  EXPECT_FALSE(coord_->armedForResponse());
  EXPECT_EQ(0, counter("truncated"));
  EXPECT_EQ(0, counter("abandoned"));
}

// #61 reset-after-finalize (no double count, no double close)
TEST_F(SpliceCoordinatorTest, ResetAfterFinalize) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .WillRepeatedly(Return(Network::Connection::ReadDisableStatus::NoTransition));
  fireFinalize();
  ASSERT_EQ(1, counter("completed"));

  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  coord_->reset();
  EXPECT_EQ(0, counter("truncated"));
}

// ----------------------------------------------------------------------------------------------
// H. FINALIZE ordering invariant (crash-safety crux)
// ----------------------------------------------------------------------------------------------

// #62 finalize-pump-before-rearm: the pump is destroyed (engaged() false) before any leg re-arm.
TEST_F(SpliceCoordinatorTest, FinalizePumpDestroyedBeforeRearm) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);

  bool pump_gone_at_first_rearm = false;
  ON_CALL(downstream_conn_, reinstallFileEvents()).WillByDefault(Invoke([&]() {
    pump_gone_at_first_rearm = !coord_->engaged();
  }));
  EXPECT_CALL(*test_upstream_, completeSplicedResponse(_));
  fireFinalize();
  EXPECT_TRUE(pump_gone_at_first_rearm);
}

// #63 finalize-dl-rearm-order
TEST_F(SpliceCoordinatorTest, FinalizeDownloadRearmOrder) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  {
    InSequence seq;
    EXPECT_CALL(downstream_conn_, reinstallFileEvents());
    EXPECT_CALL(*test_upstream_, completeSplicedResponse(kBodyBytes));
    EXPECT_CALL(upstream_conn_, reinstallFileEvents());
  }
  fireFinalize();
}

// #64 finalize-captures-refs-on-stack: the connection members are cleared before completeSpliced*,
// so a defer-delete inside completeSpliced* (simulated here by reset()) finds no dangling refs.
TEST_F(SpliceCoordinatorTest, FinalizeCapturesRefsOnStack) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);

  EXPECT_CALL(*test_upstream_, completeSplicedResponse(_)).WillOnce(Invoke([&](uint64_t) {
    // Simulate teardown re-entering reset() from inside the codec finalize. With the members
    // already cleared, this must not re-close or re-truncate.
    coord_->reset();
  }));
  // The upstream is re-armed (not closed) on the clean path; the nested reset finds no refs so it
  // does not close.
  EXPECT_CALL(upstream_conn_, close(_)).Times(0);
  fireFinalize();
  EXPECT_EQ(0, counter("truncated"));
  EXPECT_EQ(1, counter("completed"));
}

// #65 finalize-leg-closed-skip-rearm
TEST_F(SpliceCoordinatorTest, FinalizeLegClosedSkipRearm) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);

  upstream_conn_.state_ = Network::Connection::State::Closed; // captured upstream not Open
  EXPECT_CALL(downstream_conn_, reinstallFileEvents());
  EXPECT_CALL(*test_upstream_, completeSplicedResponse(_));
  EXPECT_CALL(upstream_conn_, reinstallFileEvents()).Times(0); // closed leg not re-armed
  fireFinalize();
}

// #66 finalize-readEnableSource-reinstall-first (upload: reinstall the source before readDisable)
TEST_F(SpliceCoordinatorTest, FinalizeReadEnableSourceReinstallFirst) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  {
    InSequence seq;
    // Upstream sink re-armed first.
    EXPECT_CALL(upstream_conn_, reinstallFileEvents());
    // Then the held source is re-enabled: reinstall the source file event before
    // readDisable(false).
    EXPECT_CALL(downstream_conn_, reinstallFileEvents());
    EXPECT_CALL(downstream_conn_, readDisable(false))
        .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
    EXPECT_CALL(down_cb_, completeSplicedRequest(_));
  }
  fireFinalize();
}

// ----------------------------------------------------------------------------------------------
// I. WATCHDOG
// ----------------------------------------------------------------------------------------------

// #67 watchdog-rearmed-on-progress
TEST_F(SpliceCoordinatorTest, WatchdogRearmedOnProgress) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_NE(nullptr, watchdog_timer_);

  // resetIdleTimer on the downstream HCM callbacks is refreshed on progress.
  EXPECT_CALL(parent_.callbacks_, resetIdleTimer());
  // The no-progress watchdog is re-armed at its 30-second timeout on every byte callback.
  EXPECT_CALL(*watchdog_timer_, enableTimer(std::chrono::milliseconds(30000), _));
  // A byte callback drives onSpliceProgress.
  ASSERT_TRUE(u2d_bytes_cb_ != nullptr);
  u2d_bytes_cb_(4096);
}

// #68 watchdog-fires-on-stall
TEST_F(SpliceCoordinatorTest, WatchdogFiresOnStall) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_NE(nullptr, watchdog_timer_);

  // The watchdog callback resets the stream with the stall reason. It does not count the truncation
  // itself; that happens when teardown reaches reset().
  EXPECT_CALL(parent_, onUpstreamReset(Http::StreamResetReason::ConnectionTermination,
                                       "kTLS body-splice stalled", _));
  ASSERT_TRUE(watchdog_timer_->enabled_);
  watchdog_timer_->invokeCallback();
  EXPECT_EQ(0, counter("truncated"));
}

// #69 watchdog-armed-at-engage
TEST_F(SpliceCoordinatorTest, WatchdogArmedAtEngage) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_NE(nullptr, watchdog_timer_);
  EXPECT_TRUE(watchdog_timer_->enabled_);
}

// #70 watchdog-disabled-on-finalize-and-reset
TEST_F(SpliceCoordinatorTest, WatchdogDisabledOnFinalize) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_NE(nullptr, watchdog_timer_);
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  EXPECT_CALL(*test_upstream_, completeSplicedResponse(_));
  EXPECT_CALL(*watchdog_timer_, disableTimer());
  fireFinalize();
}

TEST_F(SpliceCoordinatorTest, WatchdogDisabledOnReset) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_NE(nullptr, watchdog_timer_);
  EXPECT_CALL(upstream_conn_, close(Network::ConnectionCloseType::NoFlush));
  EXPECT_CALL(*watchdog_timer_, disableTimer());
  coord_->reset();
}

// ----------------------------------------------------------------------------------------------
// J. maybeReadEnableSource idempotency
// ----------------------------------------------------------------------------------------------

// #71 readenable-download-noop (download never read-disables)
TEST_F(SpliceCoordinatorTest, ReadEnableDownloadNoop) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  fireEngage();
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  EXPECT_CALL(*test_upstream_, completeSplicedResponse(_));
  EXPECT_CALL(downstream_conn_, readDisable(false)).Times(0);
  fireFinalize();
}

// #72 readenable-upload-once (upload re-enables the held source exactly once)
TEST_F(SpliceCoordinatorTest, ReadEnableUploadOnce) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .Times(1)
      .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
  EXPECT_CALL(down_cb_, completeSplicedRequest(_));
  fireFinalize();
}

// #74 readenable-source-closed-skip (source not Open -> flag cleared but no readDisable)
TEST_F(SpliceCoordinatorTest, ReadEnableSourceClosedSkip) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  downstream_conn_.state_ = Network::Connection::State::Closed;
  EXPECT_CALL(downstream_conn_, readDisable(false)).Times(0);
  EXPECT_CALL(down_cb_, completeSplicedRequest(_));
  fireFinalize();
}

// #75 readenable-not-detached-no-reinstall (upload abandon pre-engage: readDisable without
// reinstall)
TEST_F(SpliceCoordinatorTest, ReadEnableNotDetachedNoReinstall) {
  initialize();
  ASSERT_TRUE(armUpload());
  // Abandon before engage (message ends), so legs were never detached.
  Buffer::OwnedImpl data("x");
  EXPECT_CALL(downstream_conn_, reinstallFileEvents()).Times(0);
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .WillOnce(Return(Network::Connection::ReadDisableStatus::NoTransition));
  // The held remainder is flushed through decodeData on the upload path; allow it.
  EXPECT_FALSE(coord_->bufferPreEngageBody(data, /*end_stream=*/true));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// ----------------------------------------------------------------------------------------------
// K. abandon / flushPreEngageBody
// ----------------------------------------------------------------------------------------------

// #77 flush-download-path (held body -> onUpstreamData)
TEST_F(SpliceCoordinatorTest, FlushDownloadPath) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl held("held-body");
  ASSERT_TRUE(coord_->bufferPreEngageBody(held, /*end_stream=*/false));
  Buffer::OwnedImpl end;
  EXPECT_CALL(parent_, onUpstreamData(_, _, false));
  EXPECT_FALSE(coord_->bufferPreEngageBody(end, /*end_stream=*/true));
}

// #78 flush-upload-path (held body -> filter_manager_->decodeData) is intentionally not covered
// here. The upload flush calls upstream_request_.filter_manager_->decodeData, which dispatches into
// a fully wired UpstreamFilterManager with an established stream. Exercising it in this isolated
// coordinator fixture would re-test the filter manager rather than the coordinator. The download
// flush counterpart is covered by FlushDownloadPath (#77), and the upload abandon counter and
// re-enable accounting are covered by the engage-upload abandon tests (E section).

// #79 flush-empty-noop (no held body -> no flush call)
TEST_F(SpliceCoordinatorTest, FlushEmptyNoop) {
  initialize();
  ASSERT_TRUE(armDownload());
  Buffer::OwnedImpl end;
  EXPECT_CALL(parent_, onUpstreamData(_, _, _)).Times(0);
  EXPECT_FALSE(coord_->bufferPreEngageBody(end, /*end_stream=*/true));
  EXPECT_EQ(1, counter("abandoned"));
  EXPECT_EQ(0, counter("engaged"));
}

// #80 disarm-cancels-callbacks (a later fireEngage sees !armed_ and returns)
TEST_F(SpliceCoordinatorTest, DisarmCancelsCallbacks) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  ASSERT_NE(nullptr, engage_sched_);
  EXPECT_CALL(*engage_sched_, cancel());
  coord_->reset(); // reaches disarm-equivalent cancel path
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_FALSE(factory_called_);
}

// ----------------------------------------------------------------------------------------------
// L. scheduleEngage guards
// ----------------------------------------------------------------------------------------------

// #81 schedule-not-armed-noop
TEST_F(SpliceCoordinatorTest, ScheduleNotArmedNoop) {
  initialize();
  // Not armed: scheduleEngage creates no callback.
  coord_->scheduleEngage();
  EXPECT_EQ(nullptr, engage_sched_);
  EXPECT_FALSE(static_cast<bool>(engage_cb_));
}

// #82 schedule-creates-callback-once (repeat reuses the same callback)
TEST_F(SpliceCoordinatorTest, ScheduleCreatesCallbackOnce) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  ASSERT_NE(nullptr, engage_sched_);
  Event::MockSchedulableCallback* first = engage_sched_;
  EXPECT_CALL(*first, scheduleCallbackCurrentIteration()).Times(AnyNumber());
  coord_->scheduleEngage();
  // Still the same callback object; no second engage callback was created.
  EXPECT_EQ(first, engage_sched_);
}

// ----------------------------------------------------------------------------------------------
// M. Additional branch coverage (defensive guard arms)
// ----------------------------------------------------------------------------------------------

// engage-dl-down-fd-invalid: the SINK (downstream) leg has no kernel fd. Mirrors the upstream
// INVALID_SOCKET test and covers the `!down_fd` arm of the engage fd check.
TEST_F(SpliceCoordinatorTest, EngageDownloadDownFdInvalidSocket) {
  initialize();
  ASSERT_TRUE(armDownload());
  coord_->scheduleEngage();
  ON_CALL(down_io_, fdDoNotUse()).WillByDefault(Return(INVALID_SOCKET));
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("engaged"));
  EXPECT_EQ(1, counter("abandoned"));
}

// engage-ul-untrusted-poll: kTLS is installed but the peer is not yet trusted, which keeps the
// upload polling (the trusted_peer half of the install-poll gate), distinct from not-installed.
TEST_F(SpliceCoordinatorTest, EngageUploadUntrustedPeerPolls) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  up_ktls_.installed = true;
  up_ktls_.trusted_peer = false;
  fireEngage();
  EXPECT_FALSE(coord_->engaged());
  EXPECT_EQ(0, counter("abandoned"));
  ASSERT_NE(nullptr, poll_timer_);
  EXPECT_TRUE(poll_timer_->enabled_);
}

// reset-during-poll-disables-timer: a reset that arrives while the upload is polling for the
// kTLS-TX install disables the pending poll timer (the `engage_poll_timer_` arm of reset()).
TEST_F(SpliceCoordinatorTest, ResetDuringPollDisablesTimer) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  up_ktls_.installed = false; // keep polling
  fireEngage();
  ASSERT_NE(nullptr, poll_timer_);
  EXPECT_CALL(*poll_timer_, disableTimer());
  coord_->reset();
  EXPECT_FALSE(coord_->engaged());
  // No splice was in flight, so nothing is counted truncated.
  EXPECT_EQ(0, counter("truncated"));
}

// complete-ul-no-downstream-callbacks: an upload finalize on the clean path with the downstream
// callbacks gone skips completeSplicedRequest without crashing (the has_value guard at finalize).
TEST_F(SpliceCoordinatorTest, CompleteUploadNoDownstreamCallbacks) {
  initialize();
  ASSERT_TRUE(armUpload());
  coord_->scheduleEngage();
  fireEngage();
  ASSERT_TRUE(coord_->engaged());
  completion_cb_(TcpProxy::SpliceCompletion::BoundsReached);
  // The downstream callbacks go away before finalize runs.
  ON_CALL(parent_.callbacks_, downstreamCallbacks())
      .WillByDefault(Return(OptRef<Http::DownstreamStreamFilterCallbacks>{}));
  EXPECT_CALL(down_cb_, completeSplicedRequest(_)).Times(0);
  EXPECT_CALL(downstream_conn_, readDisable(false))
      .WillRepeatedly(Return(Network::Connection::ReadDisableStatus::NoTransition));
  fireFinalize();
  EXPECT_EQ(1, counter("completed"));
}

} // namespace Router
} // namespace Envoy
