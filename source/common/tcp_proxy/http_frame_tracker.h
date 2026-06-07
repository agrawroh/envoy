#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace TcpProxy {

// Security-critical HTTP/1.1 frame tracker for the Phase-2 pooled buffered-relay path (see
// UPSTREAM_POOL_DESIGN.md). The pool can only return a connection whose request/response exchange
// finished on a clean message boundary; a spliced (unbounded) connection can never be returned. So
// the buffered relay feeds every request-direction and response-direction byte through this
// tracker, which finds the HTTP/1.1 message boundaries (headers terminated by CRLFCRLF, then a
// Content-Length-framed body) and reports whether the connection is returnable.
//
// This is the moment tcp_proxy becomes a partial HTTP/1.1 parser, which is a request-smuggling CVE
// surface. The framing rules and rejections are ported VERBATIM from OSD's zerocopy-proxy
// (object-storage-daemon/src/zerocopy-proxy/src/http_utils.rs + server.rs), which is the audited
// reference. In particular:
//   * bare-LF (LF not preceded by CR) in the header block is rejected
//     (http_utils.rs:93-106; CVE-2019-16785 / CVE-2025-58056 / CVE-2022-32214).
//   * Transfer-Encoding present together with (or instead of) Content-Length is rejected
//     (server.rs HOP_BY_HOP_HEADERS + validate_no_unsupported_features; the TE+CL desync class).
//   * Multiple Content-Length headers, or a non-canonical Content-Length ("+5", "007", non-digit),
//     are rejected (extract_content_length, server.rs:1196-1230).
//   * absolute-form request target whose authority host disagrees with the Host header is rejected
//     (CVE-2020-25097, server.rs:955-984); authority-form, "//"-prefixed and non-http(s) targets
//     are rejected too.
//   * Connection: close (request OR response) marks the connection non-poolable
//     (validate_connection_header, server.rs:1032-1054).
//   * 1xx interim responses are not treated as final (server.rs:424-426); 204/304 carry no body
//     (server.rs:427-454); a HEAD response is bodyless regardless of Content-Length.
//   * any byte beyond the framed boundary (pipelining / smuggled extra request) is rejected.
//
// The tracker is a pure observer: it is fed copies of the bytes the relay already buffered and
// never mutates the relay's data. It is self-contained (depends only on absl + the logger) so it
// can be unit-tested in isolation against every smuggling vector.
//
// Usage: one HttpFrameTracker per pooled exchange. Feed request-direction bytes with
// onRequestData() and response-direction bytes with onResponseData() as they arrive (any chunking
// is fine; partial headers are buffered internally). Each call returns the current Verdict. Once
// the verdict is ExchangeComplete the connection may be checked in; once it is NotPoolable the
// connection must be dropped, never pooled.
class HttpFrameTracker : public Logger::Loggable<Logger::Id::pool> {
public:
  enum class Verdict {
    // The exchange is still in flight: more request and/or response bytes are expected before a
    // boundary is reached. Keep feeding; do not check in yet.
    InProgress,
    // The full request (headers + Content-Length body) was sent AND the full response (headers +
    // Content-Length/bodyless body) was received, both ending exactly on a message boundary with no
    // trailing bytes. The connection is returnable to the pool.
    ExchangeComplete,
    // A framing/smuggling signal was seen, or the message cannot be Content-Length-framed (chunked
    // TE, missing Content-Length, Connection: close, HEAD/DELETE, pipelined trailing bytes, or any
    // of the ported smuggling rejections). The connection must be dropped, never pooled. Sticky:
    // once NotPoolable, every subsequent call returns NotPoolable.
    NotPoolable,
  };

  // Caps mirror OSD http_utils.rs:13,15. Headers larger than this, or more than HeaderMaxCount
  // header lines, are rejected (NotPoolable) rather than buffered without bound.
  static constexpr size_t MaxHeaderSize = 64 * 1024;
  static constexpr size_t HeaderMaxCount = 64;

  HttpFrameTracker() = default;

  // Feed `data` bytes observed flowing downstream->upstream (the request). Returns the verdict
  // after accounting for these bytes. `data` is copied as needed; the caller retains ownership.
  Verdict onRequestData(absl::string_view data);

  // Feed `data` bytes observed flowing upstream->downstream (the response). Returns the verdict.
  Verdict onResponseData(absl::string_view data);

  // Current verdict without feeding new bytes.
  Verdict verdict() const { return verdict_; }

  // Human-readable reason a connection was marked NotPoolable, for stats/debug. Empty otherwise.
  absl::string_view notPoolableReason() const { return not_poolable_reason_; }

private:
  // One direction's parse state. The request and the response are framed identically (header block
  // terminated by CRLFCRLF, then a fixed-length body), differing only in how the body length is
  // derived: the request from its Content-Length, the response from status code + Content-Length
  // (with the HEAD bodyless and 1xx/204/304 special cases applied by the caller).
  enum class Phase {
    Headers, // accumulating the header block until CRLFCRLF
    Body,    // counting `body_remaining_` body bytes
    Done,    // body fully consumed on this leg, sitting on the boundary
  };

  struct Leg {
    Phase phase{Phase::Headers};
    std::string headers; // accumulated header bytes (capped at MaxHeaderSize)
    uint64_t body_remaining{0};
  };

  // Marks the exchange NotPoolable with `reason` and returns NotPoolable. Idempotent.
  Verdict reject(absl::string_view reason);

  // Consumes request bytes, parsing the request header block and counting the request body. Returns
  // false (after calling reject()) on a framing/smuggling signal.
  bool consumeRequest(absl::string_view data);
  // Consumes response bytes, parsing the response header block and counting the response body.
  bool consumeResponse(absl::string_view data);

  // Parses the just-completed request header block (`leg_.headers`). Sets request_body_len_ and
  // request_connection_close_, applies every request-side smuggling rejection. Returns false (after
  // reject()) on any rejection.
  bool parseRequestHeaders();
  // Parses the just-completed response header block. Sets response body length from status + CL and
  // response_connection_close_, applies the response-side rejections. Returns false on rejection.
  bool parseResponseHeaders();

  // Recomputes verdict_ once both legs may have advanced. ExchangeComplete only when BOTH legs are
  // Done; never downgrades away from NotPoolable.
  Verdict recomputeVerdict();

  Verdict verdict_{Verdict::InProgress};
  std::string not_poolable_reason_;

  Leg request_;
  Leg response_;

  // Backing storage for the body bytes that arrive in the SAME feed as the end of a header block.
  // consumeRequest/consumeResponse re-point the working string_view at this owned string before
  // flowing it through the body path, so the view stays valid for the rest of the call.
  std::string body_overflow_buf_for_request_;
  std::string body_overflow_buf_for_response_;

  // The request method, upper-cased, captured from the request line. Used to apply the bodyless-
  // response rule for HEAD and to reject HEAD/DELETE from the pool path.
  std::string request_method_;
};

} // namespace TcpProxy
} // namespace Envoy
