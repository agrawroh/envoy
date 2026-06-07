# Phase 2: OSD-style warm kTLS upstream connection pool for tcp_proxy

Goal: close the one remaining gap vs OSD zerocopy-proxy. Under AWS-SDK PUT churn (one downstream TCP
connection per request, ~1000/s) Envoy L4 tcp_proxy is strictly 1:1 — a fresh upstream S3 connection
+ full TLS handshake + kTLS install per downstream connection, never pooled (`tcp_proxy.cc:863` "we
never return open connections to the pool"; a spliced upstream is force-closed in `tearDownSplice`).
Result: ~42% drop on PUT 256kb@1000 (connection-admission churn, not CPU). OSD keeps 32–64 warm,
pre-handshaked, kTLS-installed connections per host and amortizes the handshake to ~0/request.

## The crux (why this is non-trivial)

OSD splices AND pools because its splice is **bounded**: it reads each leg's HTTP/1.1 Content-Length,
splices exactly that many bytes, and stops at the boundary with the fd intact (`server.rs:519-552`
GET splices-then-pools; `:744-768` PUT buffer-copies-response-then-pools), then returns the fd to the
pool. Our Envoy splice pump is an **unbounded L4 pump** that runs the fd to close and `resetFileEvents`
+ NoFlush-closes it (`tcp_proxy.cc:1422-1451`) by design. So a spliced Envoy connection cannot be
returned. Pooling therefore requires a **separate buffered relay path that tracks HTTP/1.1
Content-Length boundaries** to know when a connection is reusable — i.e. tcp_proxy becomes a partial
HTTP/1.1 parser. That is the real cost (security surface + layering), accepted by the decision-maker
for data-plane unification (one Envoy: GET-splice win + PUT-pool parity).

## Architecture (hybrid)

Keep the L4 splice fast-path for large GET/HEAD (beats OSD +9%); add a buffered+framed+pooled path
ONLY for high-churn small PUTs (where Envoy loses 42% and zero-copy buys nothing).

- Per-worker thread-local pool (NO mutex — single-worker-confined, unlike OSD's `Mutex<HashMap>`),
  allocated like `UpstreamDrainManager` (`tcp_proxy.cc:220,230-234,338`: `allocateSlot()`+`set()`+
  `getTyped<>()`). New files `source/common/tcp_proxy/upstream_pool.{h,cc}`.
- Per-host `deque<PoolEntry{unique_ptr<GenericUpstream>, usage_count, idle_since}>`, LIFO (pop_back
  on checkout = freshest, push_back on checkin, pop_front to evict at MAX). Keyed by host "ip:port".
- Constants mirror OSD `connection_pool.rs:24-36`: MIN_POOL_SIZE=32, MAX_POOL_SIZE_PER_HOST=64,
  IDLE_TTL=4s (S3 ~5s idle-close margin), MAINTENANCE_INTERVAL=1s.
- Stats: checkout_hit/miss, evicted_idle, checkin_dropped, stale_discarded, replenished.

## Decision rule (per request)
Pool-eligible iff we can make the upstream transfer bounded (fd survives). Today: pool-eligible ⟺
buffered-relay path; splice (unbounded pump) ⟹ never pooled. Gated behind a fail-closed proto flag
`l4_connection_pool`. Route: large GET → splice (unchanged); small PUT/POST/GET → buffered+framed+pool;
non-framable (chunked TE, no CL, `Connection: close`, HEAD/DELETE) → buffered, NOT pooled.

## Request/response boundary detection (Option A — minimal frame tracker, ~150-250 LOC)
A small state machine fed by the buffered relay: parse request headers to `\r\n\r\n`, read
Content-Length, count body bytes; same for the response (honor 204/304 bodyless, reject 1xx-as-final).
When request CL sent AND response CL received → exchange complete → schedule check-in. Port OSD's
smuggling rejections VERBATIM (`http_utils.rs:93-106` bare-LF; `server.rs:955-971` CVE-2020-25097
absolute-form/Host; reject TE+CL). The moment we count body bytes against CL, tcp_proxy is partial-L7.
(Option B — SPLICE_F_PEEK sniffing in the pump — rejected: rebuilds the pump into OSD's bounded
transfer.)

## Coexistence (GET/HEAD/large-PUT unaffected)
Splice path: `splice_pump_ != nullptr`. Pool path: `pool_eligible_ && splice_pump_ == nullptr`.
Decision picks one before either engages; `maybeEngageSplice` not called on the pool path. Clean XOR.

## Staleness/health (OSD `is_connection_clean`, `server.rs:926-932`)
Non-blocking `MSG_PEEK` 1-byte recv via `ioHandle().recv(buf,1,MSG_PEEK)`: EAGAIN ⟹ clean, 0/data ⟹
stale. Run at checkout (discard+newStream if stale) and check-in. kTLS still installed check via
`ktlsBytestreamInfo()`. On mid-exchange RemoteClose: existing teardown, do NOT check in.

## Ownership subtlety
Pooled `GenericUpstream` outlives its Filter (owned by the thread-local slot). On check-in the Filter
MUST null `upstream_` so `~Filter` doesn't close it; the pool owns the close. Mis-release = double-close
/ UAF.

## Phased plan
- 2.0 (skeleton, ships dark): `upstream_pool.{h,cc}`, thread-local slot in Config, proto flag,
  eviction-only maintenance timer, stats. No checkout/checkin wired. Verifies allocation/teardown/stats.
- 2.1 (check-in-only reuse): response-direction frame tracker + Connection:close + clean-check +
  check-in; checkout wired. First measurable hit-rate.
- 2.2 (PUT fix): request-direction CL framing, Expect:100-continue termination at proxy
  (`server.rs:632-638`), smuggling rejections ported. THE 42%-drop fix. Gate measurement: PUT
  256kb@1000 drop rate.
- 2.3: staleness retry loop + observability hardening.
- 3 (optional): off-path pre-warming (Filter-less `GenericConnectionPoolCallbacks` in maintenance
  loop, OSD `connection_pool.rs:161-185`). Only if cold-start dominates.

## Risks
- HIGH: partial HTTP/1.1 parser in L4 → smuggling CVE surface (port OSD rejections exactly) + upstream
  maintainer layering objection.
- MEDIUM: connection ownership across Filter lifetime (UAF if mis-released).
- MEDIUM: staleness/retry tail latency (OSD labels its own pool "benchmark-only").
- LOW: splice coexistence (clean XOR), thread-locality (proven slot pattern).

## Key file:line anchors
- OSD pool: `connection_pool.rs:24-36,38-50,63-96,149-185,1-7`.
- OSD framing: `http_utils.rs:25-91,93-106,148-203`; `server.rs:243-339,519-552,577-776,427-454,541,615,754,926-932,955-971`.
- Envoy: `tcp_proxy.cc:220,230-234,338,850-867,904-933,1363-1431,1433-1453,1455-1471`;
  `splice_pump.h:30-46,122-137`.
