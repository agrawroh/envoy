#include "source/common/tcp_proxy/http_frame_tracker.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace TcpProxy {

namespace {

constexpr absl::string_view kCrlfCrlf = "\r\n\r\n";
constexpr absl::string_view kCrlf = "\r\n";

// A header line split into name/value, both trimmed of OWS, name lower-cased for matching.
struct HeaderLine {
  std::string name;  // lower-cased
  std::string value; // OWS-trimmed, original case
};

// Splits the accumulated header block (request/status line + header lines, NOT including the final
// CRLFCRLF) into the first line and the list of header lines. Returns false if any header line is
// malformed (no colon, empty name, or obs-fold continuation), all of which OSD's httparse-backed
// path would reject, and which are smuggling-relevant. `header_block` must already have been
// bare-LF-checked by the caller.
bool splitHeaderBlock(absl::string_view header_block, absl::string_view& first_line,
                      std::vector<HeaderLine>& headers) {
  // The header block is "<first-line>\r\n<h1>\r\n...<hn>\r\n" with no trailing empty line (the
  // CRLFCRLF terminator was stripped before this call). Split on CRLF.
  std::vector<absl::string_view> lines = absl::StrSplit(header_block, kCrlf);
  if (lines.empty()) {
    return false;
  }
  first_line = lines.front();
  if (first_line.empty()) {
    return false;
  }

  for (size_t i = 1; i < lines.size(); i++) {
    absl::string_view line = lines[i];
    if (line.empty()) {
      // An empty line inside the header block would mean an early CRLFCRLF the boundary scan
      // missed; treat as malformed.
      return false;
    }
    // Reject obs-fold (a header line starting with SP/HTAB is a continuation of the previous line).
    // RFC 9112 deprecates obs-fold; a strict proxy rejects it to avoid desync (it is a classic
    // smuggling primitive). httparse rejects it too.
    if (line.front() == ' ' || line.front() == '\t') {
      return false;
    }
    const size_t colon = line.find(':');
    if (colon == absl::string_view::npos || colon == 0) {
      return false;
    }
    absl::string_view name = line.substr(0, colon);
    // RFC 9112 §5.1: no whitespace is allowed between the field name and the colon. Reject it; it
    // is the "Foo : bar" smuggling primitive that some parsers treat as "Foo" and others as
    // "Foo ".
    if (name.back() == ' ' || name.back() == '\t') {
      return false;
    }
    absl::string_view value = line.substr(colon + 1);
    value = absl::StripAsciiWhitespace(value);
    HeaderLine hl;
    hl.name = absl::AsciiStrToLower(name);
    hl.value = std::string(value);
    headers.push_back(std::move(hl));
  }
  return true;
}

// OSD reject_bare_lf, http_utils.rs:93-106. Rejects any LF not immediately preceded by CR. httparse
// (and many lenient parsers) accept bare LF as a line terminator; a strict proxy MUST reject it to
// avoid line-terminator-disagreement smuggling.
bool hasBareLf(absl::string_view raw) {
  char prev = '\0';
  for (const char c : raw) {
    if (c == '\n' && prev != '\r') {
      return true;
    }
    prev = c;
  }
  return false;
}

// Collects all values for a (lower-cased) header name.
std::vector<absl::string_view> valuesFor(const std::vector<HeaderLine>& headers,
                                         absl::string_view lower_name) {
  std::vector<absl::string_view> out;
  for (const HeaderLine& h : headers) {
    if (h.name == lower_name) {
      out.push_back(h.value);
    }
  }
  return out;
}

// OSD extract_content_length, server.rs:1196-1230. Returns:
//   kAbsent  -> no Content-Length header.
//   kInvalid -> multiple Content-Length headers, OR a non-canonical value (empty, non-digit,
//               leading zero like "007", "+5", overflow). Both are rejections.
//   otherwise the parsed length.
enum class ClStatus { Ok, Absent, Invalid };
ClStatus parseContentLength(const std::vector<HeaderLine>& headers, uint64_t& out) {
  std::vector<absl::string_view> values = valuesFor(headers, "content-length");
  if (values.empty()) {
    return ClStatus::Absent;
  }
  if (values.size() > 1) {
    // OSD MultipleContentLength.
    return ClStatus::Invalid;
  }
  absl::string_view v = values.front();
  // RFC 7230 §3.3.2: Content-Length = 1*DIGIT. Reject forms a permissive numeric parser would
  // accept ("+5", "005") which desync with upstreams that parse differently.
  if (v.empty()) {
    return ClStatus::Invalid;
  }
  for (const char c : v) {
    if (!absl::ascii_isdigit(static_cast<unsigned char>(c))) {
      return ClStatus::Invalid;
    }
  }
  // Reject leading zeros: "007" is not canonical, "0" is fine.
  if (v.size() > 1 && v.front() == '0') {
    return ClStatus::Invalid;
  }
  uint64_t parsed = 0;
  if (!absl::SimpleAtoi(v, &parsed)) {
    // Overflows uint64.
    return ClStatus::Invalid;
  }
  out = parsed;
  return ClStatus::Ok;
}

// OSD validate_connection_header, server.rs:1032-1054. Returns true if the connection must close
// (so it is non-poolable). Sets `invalid` true on a malformed Connection header (multiple, or a
// value other than close/keep-alive), which is itself a rejection.
bool connectionWantsClose(const std::vector<HeaderLine>& headers, bool& invalid) {
  invalid = false;
  std::vector<absl::string_view> values = valuesFor(headers, "connection");
  if (values.empty()) {
    return false;
  }
  if (values.size() > 1) {
    invalid = true;
    return true;
  }
  absl::string_view v = values.front();
  if (absl::EqualsIgnoreCase(v, "close")) {
    return true;
  }
  if (absl::EqualsIgnoreCase(v, "keep-alive")) {
    return false;
  }
  invalid = true;
  return true;
}

// Extracts the single Host header value (host without port), lower-cased, mirroring the relevant
// bits of OSD extract_host (server.rs:986-1020). Returns false (host_out untouched) if absent,
// duplicated, or carrying userinfo ('@').
bool extractHostNoPort(const std::vector<HeaderLine>& headers, std::string& host_out) {
  std::vector<absl::string_view> values = valuesFor(headers, "host");
  if (values.size() != 1) {
    return false;
  }
  absl::string_view host = values.front();
  // RFC 7230 §5.4: userinfo is not allowed in Host.
  if (absl::StrContains(host, '@')) {
    return false;
  }
  // Strip the port. For an IPv6 literal "[::1]:443" only strip the ':' after the closing bracket.
  std::string h = absl::AsciiStrToLower(host);
  if (!h.empty() && h.front() == '[') {
    const size_t close = h.find(']');
    if (close == std::string::npos) {
      return false;
    }
    h = h.substr(0, close + 1);
  } else {
    const size_t colon = h.find(':');
    if (colon != std::string::npos) {
      h = h.substr(0, colon);
    }
  }
  host_out = std::move(h);
  return true;
}

// OSD validate_request_target, server.rs:955-984 (origin/absolute-form acceptance + CVE-2020-25097
// host match). `target` is the request-line target. `headers` carry the Host header. Returns false
// on a dangerous target shape or a request-line authority that disagrees with Host.
bool validateRequestTarget(absl::string_view target, const std::vector<HeaderLine>& headers) {
  // asterisk-form and empty are not origin/absolute-form, so reject.
  if (target.empty() || target == "*") {
    return false;
  }

  // absolute-form: scheme "://" authority path. We accept only http/https.
  const size_t scheme_sep = target.find("://");
  if (scheme_sep != absl::string_view::npos) {
    absl::string_view scheme = target.substr(0, scheme_sep);
    if (!absl::EqualsIgnoreCase(scheme, "http") && !absl::EqualsIgnoreCase(scheme, "https")) {
      return false; // non-http(s) scheme.
    }
    absl::string_view rest = target.substr(scheme_sep + 3);
    // authority ends at the first '/', '?', or '#'.
    const size_t auth_end = rest.find_first_of("/?#");
    absl::string_view authority =
        auth_end == absl::string_view::npos ? rest : rest.substr(0, auth_end);
    absl::string_view path =
        auth_end == absl::string_view::npos ? absl::string_view("/") : rest.substr(auth_end);
    if (authority.empty()) {
      return false;
    }
    // The forwarded origin-form path could be reinterpreted as authority-form by the upstream:
    // reject a "//"-prefixed path even for absolute-form (server.rs:962-967).
    if (absl::StartsWith(path, "//")) {
      return false;
    }
    // CVE-2020-25097: the request-line authority host MUST match the Host header host.
    // Strip userinfo and port from the authority.
    absl::string_view auth_host = authority;
    const size_t at = auth_host.rfind('@');
    if (at != absl::string_view::npos) {
      auth_host = auth_host.substr(at + 1);
    }
    if (!auth_host.empty() && auth_host.front() == '[') {
      const size_t close = auth_host.find(']');
      if (close == absl::string_view::npos) {
        return false;
      }
      auth_host = auth_host.substr(0, close + 1);
    } else {
      const size_t colon = auth_host.find(':');
      if (colon != absl::string_view::npos) {
        auth_host = auth_host.substr(0, colon);
      }
    }
    std::string host_header;
    if (!extractHostNoPort(headers, host_header)) {
      return false;
    }
    if (!absl::EqualsIgnoreCase(auth_host, host_header)) {
      return false; // AbsoluteFormHostMismatch.
    }
    return true;
  }

  // Otherwise it must be origin-form: a path starting with a single '/'. Reject authority-form
  // ("//evil/..."), which would be reinterpreted as a host.
  if (!absl::StartsWith(target, "/")) {
    return false;
  }
  if (absl::StartsWith(target, "//")) {
    return false;
  }
  return true;
}

} // namespace

HttpFrameTracker::Verdict HttpFrameTracker::reject(absl::string_view reason) {
  if (verdict_ != Verdict::NotPoolable) {
    verdict_ = Verdict::NotPoolable;
    not_poolable_reason_ = std::string(reason);
    ENVOY_LOG(debug, "tcp_proxy frame tracker: connection not poolable: {}", reason);
  }
  return verdict_;
}

HttpFrameTracker::Verdict HttpFrameTracker::onRequestData(absl::string_view data) {
  if (verdict_ == Verdict::NotPoolable) {
    return verdict_;
  }
  if (!consumeRequest(data)) {
    return verdict_; // reject() already set the reason.
  }
  return recomputeVerdict();
}

HttpFrameTracker::Verdict HttpFrameTracker::onResponseData(absl::string_view data) {
  if (verdict_ == Verdict::NotPoolable) {
    return verdict_;
  }
  if (!consumeResponse(data)) {
    return verdict_;
  }
  return recomputeVerdict();
}

bool HttpFrameTracker::consumeRequest(absl::string_view data) {
  // A request whose body is already fully framed must not receive more bytes: trailing bytes are a
  // pipelined / smuggled second request (server.rs:645-650 rejects excess body).
  if (request_.phase == Phase::Done) {
    if (!data.empty()) {
      reject("pipelined bytes after request boundary");
      return false;
    }
    return true;
  }

  if (request_.phase == Phase::Headers) {
    // Accumulate until we see the end-of-headers CRLFCRLF. To find a boundary that straddles two
    // feeds, search from just before the newly appended bytes.
    const size_t search_from = request_.headers.size() >= (kCrlfCrlf.size() - 1)
                                   ? request_.headers.size() - (kCrlfCrlf.size() - 1)
                                   : 0;
    request_.headers.append(data.data(), data.size());
    if (request_.headers.size() > MaxHeaderSize) {
      reject("request headers too large");
      return false;
    }
    const size_t boundary = request_.headers.find(kCrlfCrlf.data(), search_from, kCrlfCrlf.size());
    if (boundary == std::string::npos) {
      return true; // still buffering headers.
    }
    // Split the buffer into the header block and any body bytes that arrived in the same feed.
    std::string body_overflow = request_.headers.substr(boundary + kCrlfCrlf.size());
    request_.headers.resize(boundary); // header block without the CRLFCRLF terminator.
    // parseRequestHeaders sets phase to Body (CL > 0) or Done (zero-body request).
    if (!parseRequestHeaders()) {
      return false;
    }
    if (request_.phase == Phase::Done) {
      // Zero-body request that completed within this feed: any overflow is a pipelined / smuggled
      // second request.
      if (!body_overflow.empty()) {
        reject("pipelined bytes after request boundary");
        return false;
      }
      return true;
    }
    // Feed the body overflow through the body path below.
    data = body_overflow_buf_for_request_ = std::move(body_overflow);
  }

  if (request_.phase == Phase::Body) {
    if (data.size() > request_.body_remaining) {
      reject("request body exceeds Content-Length");
      return false;
    }
    request_.body_remaining -= data.size();
    if (request_.body_remaining == 0) {
      request_.phase = Phase::Done;
    }
  }
  return true;
}

bool HttpFrameTracker::consumeResponse(absl::string_view data) {
  if (response_.phase == Phase::Done) {
    if (!data.empty()) {
      reject("bytes after response boundary");
      return false;
    }
    return true;
  }

  if (response_.phase == Phase::Headers) {
    const size_t search_from = response_.headers.size() >= (kCrlfCrlf.size() - 1)
                                   ? response_.headers.size() - (kCrlfCrlf.size() - 1)
                                   : 0;
    response_.headers.append(data.data(), data.size());
    if (response_.headers.size() > MaxHeaderSize) {
      reject("response headers too large");
      return false;
    }
    const size_t boundary = response_.headers.find(kCrlfCrlf.data(), search_from, kCrlfCrlf.size());
    if (boundary == std::string::npos) {
      return true;
    }
    std::string body_overflow = response_.headers.substr(boundary + kCrlfCrlf.size());
    response_.headers.resize(boundary);
    if (!parseResponseHeaders()) {
      return false;
    }
    // parseResponseHeaders may have set phase to Done directly (bodyless response). Only flow the
    // overflow through the body path if we are still expecting a body.
    if (response_.phase == Phase::Body) {
      data = body_overflow_buf_for_response_ = std::move(body_overflow);
    } else {
      // Bodyless response: any overflow is a smuggled extra response.
      if (!body_overflow.empty()) {
        reject("body bytes after bodyless response");
        return false;
      }
      return true;
    }
  }

  if (response_.phase == Phase::Body) {
    if (data.size() > response_.body_remaining) {
      reject("response body exceeds Content-Length");
      return false;
    }
    response_.body_remaining -= data.size();
    if (response_.body_remaining == 0) {
      response_.phase = Phase::Done;
    }
  }
  return true;
}

bool HttpFrameTracker::parseRequestHeaders() {
  // OSD reject_bare_lf (http_utils.rs:93-106): bare LF in the header block.
  if (hasBareLf(request_.headers)) {
    reject("bare LF in request headers");
    return false;
  }

  absl::string_view first_line;
  std::vector<HeaderLine> headers;
  if (!splitHeaderBlock(request_.headers, first_line, headers)) {
    reject("malformed request headers");
    return false;
  }
  if (headers.size() > HeaderMaxCount) {
    reject("too many request headers");
    return false;
  }

  // Request line: METHOD SP request-target SP HTTP/1.1, with EXACTLY one SP between each token.
  // Extra or missing spaces (and an empty method/target) are smuggling-relevant; reject.
  std::vector<absl::string_view> parts = absl::StrSplit(first_line, ' ');
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() || parts[2].empty()) {
    reject("malformed request line");
    return false;
  }
  absl::string_view method = parts[0];
  absl::string_view target = parts[1];
  absl::string_view version = parts[2];
  if (version != "HTTP/1.1") {
    reject("unsupported request version");
    return false;
  }
  request_method_ = absl::AsciiStrToUpper(method);

  // OSD validate_request_target (server.rs:955-984): absolute/origin-form acceptance and the
  // CVE-2020-25097 absolute-form Host-mismatch rejection.
  if (!validateRequestTarget(target, headers)) {
    reject("unsupported or smuggling request target");
    return false;
  }

  // OSD rejects Transfer-Encoding outright on the splice/pool path (it is hop-by-hop and
  // validate_no_unsupported_features rejects it; the TE+CL desync class). Reject whether or not a
  // Content-Length is also present.
  if (!valuesFor(headers, "transfer-encoding").empty()) {
    reject("transfer-encoding on pooled request");
    return false;
  }

  // Connection: close (or a malformed Connection value) makes the connection non-poolable.
  bool conn_invalid = false;
  if (connectionWantsClose(headers, conn_invalid)) {
    reject(conn_invalid ? "invalid request Connection header" : "request Connection: close");
    return false;
  }

  // HEAD / DELETE are routed off the pool path by design (non-framable, so buffered but NOT
  // pooled). HEAD in particular has a body-framing asymmetry (the response is bodyless regardless
  // of its Content-Length) that we do not pool.
  if (request_method_ == "HEAD" || request_method_ == "DELETE") {
    reject("non-poolable method");
    return false;
  }
  // CONNECT must never be framed/pooled.
  if (request_method_ == "CONNECT") {
    reject("CONNECT not allowed");
    return false;
  }

  // Content-Length framing. Missing CL on a body-bearing method would make the request
  // close-delimited (unframable), but for the methods we pool (GET/PUT/POST) a missing CL means a
  // zero-length body (OSD treats missing CL on PUT as 0, server.rs:593). We mirror that: absent ->
  // 0; invalid -> reject.
  uint64_t cl = 0;
  switch (parseContentLength(headers, cl)) {
  case ClStatus::Ok:
    request_.body_remaining = cl;
    break;
  case ClStatus::Absent:
    request_.body_remaining = 0;
    break;
  case ClStatus::Invalid:
    reject("invalid request Content-Length");
    return false;
  }

  // Stable copy of the declared body length for the pool router; request_.body_remaining
  // decrements.
  request_content_length_ = request_.body_remaining;
  request_.phase = request_.body_remaining == 0 ? Phase::Done : Phase::Body;
  return true;
}

bool HttpFrameTracker::parseResponseHeaders() {
  if (hasBareLf(response_.headers)) {
    reject("bare LF in response headers");
    return false;
  }

  absl::string_view first_line;
  std::vector<HeaderLine> headers;
  if (!splitHeaderBlock(response_.headers, first_line, headers)) {
    reject("malformed response headers");
    return false;
  }
  if (headers.size() > HeaderMaxCount) {
    reject("too many response headers");
    return false;
  }

  // Status line: HTTP/1.1 SP code SP [reason]. The reason phrase is optional and may itself contain
  // spaces, so split on at most the first two spaces; empty tokens are preserved (no SkipEmpty) so
  // a doubled space (e.g. "HTTP/1.1  200") yields an empty code token and is rejected.
  std::vector<absl::string_view> parts = absl::StrSplit(first_line, absl::MaxSplits(' ', 2));
  if (parts.size() < 2) {
    reject("malformed status line");
    return false;
  }
  if (parts[0] != "HTTP/1.1") {
    reject("unsupported response version");
    return false;
  }
  uint32_t code = 0;
  if (parts[1].size() != 3 || !absl::SimpleAtoi(parts[1], &code) || code < 100 || code > 599) {
    reject("malformed status code");
    return false;
  }

  // OSD rejects Transfer-Encoding on the poolable path (server.rs:459-476 falls back to copy and
  // does NOT pool). Treat TE response as non-poolable.
  if (!valuesFor(headers, "transfer-encoding").empty()) {
    reject("transfer-encoding on response");
    return false;
  }

  bool conn_invalid = false;
  if (connectionWantsClose(headers, conn_invalid)) {
    reject(conn_invalid ? "invalid response Connection header" : "response Connection: close");
    return false;
  }

  // 1xx interim responses are NOT a final response (server.rs:424-426 / 699-701). The exchange is
  // not complete and the connection is in an ambiguous interim state for our purposes. A final
  // response should have terminated 100-continue at the proxy. Reject.
  if (code >= 100 && code <= 199) {
    reject("1xx interim response not final");
    return false;
  }

  // 204 / 304 carry no body (server.rs:427-454). A HEAD response is bodyless regardless of its
  // Content-Length (HEAD is already rejected above, but keep the rule explicit and correct).
  const bool bodyless = code == 204 || code == 304 || request_method_ == "HEAD";
  if (bodyless) {
    response_.body_remaining = 0;
    response_.phase = Phase::Done;
    return true;
  }

  // Body-bearing response MUST be Content-Length-framed (server.rs:478-490: a missing CL is
  // close-delimited, which splice/pool cannot frame -> reject).
  uint64_t cl = 0;
  switch (parseContentLength(headers, cl)) {
  case ClStatus::Ok:
    response_.body_remaining = cl;
    break;
  case ClStatus::Absent:
    reject("missing response Content-Length");
    return false;
  case ClStatus::Invalid:
    reject("invalid response Content-Length");
    return false;
  }

  response_.phase = response_.body_remaining == 0 ? Phase::Done : Phase::Body;
  return true;
}

HttpFrameTracker::Verdict HttpFrameTracker::recomputeVerdict() {
  if (verdict_ == Verdict::NotPoolable) {
    return verdict_;
  }
  if (request_.phase == Phase::Done && response_.phase == Phase::Done) {
    verdict_ = Verdict::ExchangeComplete;
  }
  return verdict_;
}

} // namespace TcpProxy
} // namespace Envoy
