#include <string>

#include "source/common/tcp_proxy/http_frame_tracker.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace TcpProxy {
namespace {

using Verdict = HttpFrameTracker::Verdict;

// Feeds the full request then the full response in one shot each and returns the final verdict.
Verdict runExchange(absl::string_view request, absl::string_view response) {
  HttpFrameTracker tracker;
  tracker.onRequestData(request);
  return tracker.onResponseData(response);
}

// A minimal, well-formed GET request with no body.
constexpr absl::string_view kGetReq = "GET /key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
// A minimal, well-formed 200 response with a 5-byte body.
constexpr absl::string_view kOkResp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

// -------------------------------------------------------------------------------------------------
// Happy paths -> ExchangeComplete.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, GetNoBodyThenOkBody) {
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(kGetReq, kOkResp));
}

TEST(HttpFrameTracker, PutWithBody) {
  const std::string req =
      "PUT /key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nContent-Length: 4\r\n\r\nbody";
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(req, resp));
}

TEST(HttpFrameTracker, ZeroLengthBodies) {
  const std::string req = "GET /key HTTP/1.1\r\nHost: h.amazonaws.com\r\nContent-Length: 0\r\n\r\n";
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(req, resp));
}

TEST(HttpFrameTracker, Response204NoBody) {
  const std::string resp = "HTTP/1.1 204 No Content\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(kGetReq, resp));
}

TEST(HttpFrameTracker, Response304NoBody) {
  const std::string resp = "HTTP/1.1 304 Not Modified\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(kGetReq, resp));
}

TEST(HttpFrameTracker, NonStandardStatusCodeWithCl) {
  const std::string resp = "HTTP/1.1 599 \r\nContent-Length: 2\r\n\r\nhi";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(kGetReq, resp));
}

TEST(HttpFrameTracker, AbsoluteFormTargetMatchingHost) {
  const std::string req =
      "GET http://b.s3.amazonaws.com/key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(req, kOkResp));
}

TEST(HttpFrameTracker, AbsoluteFormHostCaseInsensitive) {
  const std::string req =
      "GET http://B.S3.amazonaws.com/key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(req, kOkResp));
}

// -------------------------------------------------------------------------------------------------
// Incremental feeding: partial headers, split boundary, byte-at-a-time bodies.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, InProgressUntilBothComplete) {
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::InProgress, tracker.onRequestData("GET /key HTTP/1.1\r\n"));
  EXPECT_EQ(Verdict::InProgress, tracker.onRequestData("Host: b.amazonaws.com\r\n\r\n"));
  EXPECT_EQ(Verdict::InProgress, tracker.onResponseData("HTTP/1.1 200 OK\r\n"));
  EXPECT_EQ(Verdict::InProgress, tracker.onResponseData("Content-Length: 3\r\n\r\n"));
  EXPECT_EQ(Verdict::InProgress, tracker.onResponseData("ab"));
  EXPECT_EQ(Verdict::ExchangeComplete, tracker.onResponseData("c"));
}

TEST(HttpFrameTracker, BoundaryStraddlesTwoFeeds) {
  HttpFrameTracker tracker;
  // Split the CRLFCRLF terminator across two feeds.
  EXPECT_EQ(Verdict::InProgress,
            tracker.onRequestData("GET /k HTTP/1.1\r\nHost: h.amazonaws.com\r\n"));
  EXPECT_EQ(Verdict::InProgress, tracker.onRequestData("\r\n"));
  EXPECT_EQ(Verdict::ExchangeComplete, tracker.onResponseData(kOkResp));
}

TEST(HttpFrameTracker, ByteAtATimeBody) {
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  tracker.onResponseData("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n");
  EXPECT_EQ(Verdict::InProgress, tracker.onResponseData("x"));
  EXPECT_EQ(Verdict::InProgress, tracker.onResponseData("y"));
  EXPECT_EQ(Verdict::ExchangeComplete, tracker.onResponseData("z"));
}

TEST(HttpFrameTracker, HeaderAndBodyInSameFeed) {
  // The body bytes arrive in the same feed as the end-of-headers terminator.
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(kGetReq, kOkResp));
}

// -------------------------------------------------------------------------------------------------
// Bare-LF rejection (OSD http_utils.rs:93-106).
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsBareLfInRequestHeaders) {
  // LF without a preceding CR in the header block.
  const std::string req = "GET /key HTTP/1.1\nHost: b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
  EXPECT_EQ("bare LF in request headers", tracker.notPoolableReason());
}

TEST(HttpFrameTracker, RejectsBareLfInResponseHeaders) {
  const std::string resp = "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
  EXPECT_EQ("bare LF in response headers", tracker.notPoolableReason());
}

// -------------------------------------------------------------------------------------------------
// Transfer-Encoding (TE), and TE+CL desync class.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsTransferEncodingRequest) {
  const std::string req =
      "POST /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nTransfer-Encoding: chunked\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsTeAndClTogetherRequest) {
  // The classic TE+CL smuggling vector: both present must be rejected.
  const std::string req = "POST /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: "
                          "4\r\nTransfer-Encoding: chunked\r\n\r\nbody";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsTransferEncodingResponse) {
  const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
}

// -------------------------------------------------------------------------------------------------
// Content-Length validation (OSD server.rs:1196-1230).
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsMultipleContentLengthRequest) {
  const std::string req = "PUT /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: "
                          "4\r\nContent-Length: 5\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsNonCanonicalContentLengthLeadingZero) {
  const std::string req =
      "PUT /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: 007\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsNonCanonicalContentLengthPlusSign) {
  const std::string req =
      "PUT /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: +5\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsNonNumericContentLength) {
  const std::string req =
      "PUT /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: 4abc\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsMissingResponseContentLengthBodyBearing) {
  // A 200 with neither CL nor TE is close-delimited -> unframable -> reject.
  const std::string resp = "HTTP/1.1 200 OK\r\nServer: AmazonS3\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
  EXPECT_EQ("missing response Content-Length", tracker.notPoolableReason());
}

// -------------------------------------------------------------------------------------------------
// CVE-2020-25097: absolute-form request target vs Host.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsAbsoluteFormHostMismatch) {
  const std::string req =
      "GET http://evil.com/path HTTP/1.1\r\nHost: good.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsAbsoluteFormAuthorityWithUserinfo) {
  // authority host is evil.com (userinfo stripped) which must not match the Host.
  const std::string req = "GET http://good.s3.amazonaws.com@evil.com/key HTTP/1.1\r\nHost: "
                          "good.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsAbsoluteFormDoubleSlashPath) {
  const std::string req =
      "GET http://b.s3.amazonaws.com//evil.com/key HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsAuthorityFormTarget) {
  // "//evil.com/foo" with no scheme is authority-form; reject.
  const std::string req = "GET //evil.com/foo HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsNonHttpScheme) {
  const std::string req =
      "GET ftp://b.s3.amazonaws.com/x HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsAsteriskFormTarget) {
  const std::string req = "OPTIONS * HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

// -------------------------------------------------------------------------------------------------
// Multiple / userinfo Host headers (absolute-form host check depends on a single clean Host).
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsAbsoluteFormWithMultipleHosts) {
  const std::string req = "GET http://b.s3.amazonaws.com/key HTTP/1.1\r\nHost: "
                          "b.s3.amazonaws.com\r\nHost: evil.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

// -------------------------------------------------------------------------------------------------
// 1xx interim response is not a final response (OSD server.rs:424-426).
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, Rejects1xxInterimResponse) {
  const std::string resp = "HTTP/1.1 100 Continue\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
  EXPECT_EQ("1xx interim response not final", tracker.notPoolableReason());
}

// -------------------------------------------------------------------------------------------------
// Connection: close (request OR response) -> non-poolable (OSD server.rs:1032-1054).
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsConnectionCloseRequest) {
  const std::string req = "GET /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nConnection: close\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsConnectionCloseResponse) {
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
}

TEST(HttpFrameTracker, RejectsUnknownConnectionValue) {
  const std::string req =
      "GET /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nConnection: upgrade\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, AcceptsConnectionKeepAlive) {
  const std::string req =
      "GET /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nConnection: keep-alive\r\n\r\n";
  EXPECT_EQ(Verdict::ExchangeComplete, runExchange(req, kOkResp));
}

// -------------------------------------------------------------------------------------------------
// HEAD / DELETE / CONNECT routed off the pool path.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsHeadMethod) {
  const std::string req = "HEAD /key HTTP/1.1\r\nHost: b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
  EXPECT_EQ("non-poolable method", tracker.notPoolableReason());
}

TEST(HttpFrameTracker, RejectsDeleteMethod) {
  const std::string req = "DELETE /key HTTP/1.1\r\nHost: b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsConnectMethod) {
  const std::string req =
      "CONNECT b.amazonaws.com:443 HTTP/1.1\r\nHost: b.amazonaws.com:443\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

// -------------------------------------------------------------------------------------------------
// Pipelined / smuggled trailing bytes past a framed boundary.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsPipelinedRequestBytes) {
  // A complete GET (no body) followed by the start of a second request.
  const std::string req = std::string(kGetReq) + "GET /next HTTP/1.1\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
  EXPECT_EQ("pipelined bytes after request boundary", tracker.notPoolableReason());
}

TEST(HttpFrameTracker, RejectsRequestBodyExceedingContentLength) {
  // CL says 2 but 5 body bytes arrive.
  const std::string req =
      "PUT /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nContent-Length: 2\r\n\r\nhello";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
  EXPECT_EQ("request body exceeds Content-Length", tracker.notPoolableReason());
}

TEST(HttpFrameTracker, RejectsResponseBodyExceedingContentLength) {
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
}

TEST(HttpFrameTracker, RejectsTrailingBytesAfterResponseBoundaryInLaterFeed) {
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::ExchangeComplete, tracker.onResponseData(kOkResp));
  // A second response on the same connection (server pipelining / smuggling) is rejected.
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData("HTTP/1.1 200 OK\r\n"));
}

TEST(HttpFrameTracker, RejectsBodyBytesOnBodylessResponse) {
  // 204 must carry no body; trailing bytes are ambiguous framing.
  const std::string resp = "HTTP/1.1 204 No Content\r\n\r\nextra";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
}

// -------------------------------------------------------------------------------------------------
// Header well-formedness smuggling primitives: obs-fold, space-before-colon, missing colon.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsObsFoldContinuation) {
  const std::string req = "GET /key HTTP/1.1\r\nHost: b.amazonaws.com\r\nX-Foo: a\r\n bar\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsSpaceBeforeColon) {
  const std::string req = "GET /key HTTP/1.1\r\nHost : b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsHeaderWithoutColon) {
  const std::string req = "GET /key HTTP/1.1\r\nHostb.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsDoubledSpaceInRequestLine) {
  const std::string req = "GET  /key HTTP/1.1\r\nHost: b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

TEST(HttpFrameTracker, RejectsDoubledSpaceInStatusLine) {
  const std::string resp = "HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n";
  HttpFrameTracker tracker;
  tracker.onRequestData(kGetReq);
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(resp));
}

TEST(HttpFrameTracker, RejectsHttp10Request) {
  const std::string req = "GET /key HTTP/1.0\r\nHost: b.amazonaws.com\r\n\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

// -------------------------------------------------------------------------------------------------
// Size caps.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, RejectsOversizedHeaders) {
  std::string req = "GET /key HTTP/1.1\r\nHost: b.amazonaws.com\r\n";
  // Pad with a single huge header value past MaxHeaderSize, never terminating the block.
  req += "X-Pad: ";
  req += std::string(HttpFrameTracker::MaxHeaderSize + 16, 'a');
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
  EXPECT_EQ("request headers too large", tracker.notPoolableReason());
}

TEST(HttpFrameTracker, RejectsTooManyHeaders) {
  std::string req = "GET /key HTTP/1.1\r\n";
  for (size_t i = 0; i < HttpFrameTracker::HeaderMaxCount + 1; i++) {
    req += "X-H" + std::to_string(i) + ": v\r\n";
  }
  req += "\r\n";
  HttpFrameTracker tracker;
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(req));
}

// -------------------------------------------------------------------------------------------------
// Stickiness: once NotPoolable, stays NotPoolable.
// -------------------------------------------------------------------------------------------------

TEST(HttpFrameTracker, NotPoolableIsSticky) {
  HttpFrameTracker tracker;
  const std::string bad = "GET /key HTTP/1.1\nHost: b.amazonaws.com\r\n\r\n";
  EXPECT_EQ(Verdict::NotPoolable, tracker.onRequestData(bad));
  // Subsequent feeds, even well-formed ones, do not flip the verdict back.
  EXPECT_EQ(Verdict::NotPoolable, tracker.onResponseData(kOkResp));
  EXPECT_EQ(Verdict::NotPoolable, tracker.verdict());
}

} // namespace
} // namespace TcpProxy
} // namespace Envoy
