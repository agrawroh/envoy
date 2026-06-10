#include "envoy/http/web_transport.h"

#include "source/extensions/filters/http/web_transport/web_transport_filter.h"

#include "test/mocks/http/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WebTransport {
namespace {

using testing::_;
using testing::Return;
using testing::SaveArg;

class MockWebTransportSession : public Http::WebTransportSession {
public:
  MOCK_METHOD(bool, sessionLimitExceeded, (), (const, override));
  MOCK_METHOD(void, setWebTransportSessionCallbacks, (Http::WebTransportSessionCallbacks*),
              (override));
  MOCK_METHOD(void, sendWebTransportDatagram, (absl::string_view), (override));
};

class WebTransportFilterTest : public testing::Test {
public:
  WebTransportFilterTest() { filter_.setDecoderFilterCallbacks(decoder_callbacks_); }

  WebTransportFilter filter_;
  testing::NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  testing::NiceMock<MockWebTransportSession> session_;
};

// A WebTransport CONNECT is accepted with a 200 and the filter registers as the session consumer.
TEST_F(WebTransportFilterTest, AcceptsWebTransportConnect) {
  EXPECT_CALL(decoder_callbacks_, webTransport())
      .WillOnce(Return(OptRef<Http::WebTransportSession>(session_)));
  Http::WebTransportSessionCallbacks* registered = nullptr;
  EXPECT_CALL(session_, setWebTransportSessionCallbacks(_)).WillOnce(SaveArg<0>(&registered));
  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(Http::HttpStatusIs(200), false));

  Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":protocol", "webtransport"}, {":authority", "example.com"}};
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_.decodeHeaders(headers, false));
  EXPECT_EQ(registered, &filter_);
}

// A WebTransport CONNECT over the connection session limit is rejected with a 429 and the filter
// does not claim the session.
TEST_F(WebTransportFilterTest, RejectsOverSessionLimit) {
  EXPECT_CALL(decoder_callbacks_, webTransport())
      .WillOnce(Return(OptRef<Http::WebTransportSession>(session_)));
  EXPECT_CALL(session_, sessionLimitExceeded()).WillOnce(Return(true));
  EXPECT_CALL(session_, setWebTransportSessionCallbacks(_)).Times(0);
  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(Http::HttpStatusIs(429), true));

  Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":protocol", "webtransport"}, {":authority", "example.com"}};
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_.decodeHeaders(headers, false));
}

// Received datagrams are echoed back on the session.
TEST_F(WebTransportFilterTest, EchoesDatagram) {
  EXPECT_CALL(decoder_callbacks_, webTransport())
      .WillOnce(Return(OptRef<Http::WebTransportSession>(session_)));
  Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":protocol", "webtransport"}, {":authority", "example.com"}};
  filter_.decodeHeaders(headers, false);

  EXPECT_CALL(session_, sendWebTransportDatagram(absl::string_view("ping")));
  filter_.onWebTransportDatagram("ping");

  // After the session closes the filter stops echoing.
  filter_.onWebTransportSessionClosed();
  EXPECT_CALL(session_, sendWebTransportDatagram(_)).Times(0);
  filter_.onWebTransportDatagram("late");
}

// Destroying the filter detaches it from the session so no stale callbacks fire.
TEST_F(WebTransportFilterTest, DetachesOnDestroy) {
  EXPECT_CALL(decoder_callbacks_, webTransport())
      .WillOnce(Return(OptRef<Http::WebTransportSession>(session_)));
  Http::TestRequestHeaderMapImpl headers{
      {":method", "CONNECT"}, {":protocol", "webtransport"}, {":authority", "example.com"}};
  filter_.decodeHeaders(headers, false);

  EXPECT_CALL(session_, setWebTransportSessionCallbacks(nullptr));
  filter_.onDestroy();
}

// Destroying a filter that never claimed a session does nothing.
TEST_F(WebTransportFilterTest, DestroyWithoutSessionIsNoOp) {
  EXPECT_CALL(session_, setWebTransportSessionCallbacks(_)).Times(0);
  filter_.onDestroy();
}

// A request that is not a WebTransport session passes through untouched.
TEST_F(WebTransportFilterTest, PassesThroughNonWebTransport) {
  EXPECT_CALL(decoder_callbacks_, webTransport())
      .WillOnce(Return(OptRef<Http::WebTransportSession>{}));
  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(_, _)).Times(0);

  Http::TestRequestHeaderMapImpl headers{{":method", "GET"}, {":path", "/"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_.decodeHeaders(headers, true));
}

} // namespace
} // namespace WebTransport
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
