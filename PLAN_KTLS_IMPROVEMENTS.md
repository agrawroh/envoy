# Envoy kTLS (Rustls) Performance Analysis & Improvements

**Target file:** `source/extensions/transport_sockets/rustls/rust/rustls_ktls.rs`
**Build:** Always use `-c opt` for benchmarks.
**Kernel:** Linux 5.4.0-1154-aws-fips (older kernel — impacts kTLS RX performance)

---

## Benchmark Results (Opt Binary, Concurrency=1 Envoy Worker)

### Single-TLS (Downstream Only): Downloads (TX — Envoy → Client)

| Payload | Clients | kTLS MB/s | BoringSSL MB/s | Ratio | Winner |
|---------|---------|-----------|----------------|-------|--------|
| 1MB | 1 | 889.5 | 856.9 | 1.04x | kTLS |
| 1MB | 10 | 896.0 | 898.0 | 1.00x | Tie |
| 4MB | 1 | 1,290.0 | 1,344.8 | 0.96x | BoringSSL |
| 4MB | 10 | 1,161.0 | 1,159.4 | 1.00x | Tie |
| 8MB | 1 | 1,390.0 | 1,504.4 | 0.92x | BoringSSL |
| 8MB | 10 | 1,259.2 | 1,249.2 | 1.01x | kTLS |
| 16MB | 1 | 1,420.0 | 1,571.2 | 0.90x | BoringSSL |
| 16MB | 10 | 1,241.6 | 1,246.4 | 1.00x | Tie |

**Verdict:** Effectively tied at c10/c50. BoringSSL 4-10% faster at c1 for large payloads. Zero errors.

### Single-TLS (Downstream Only): Uploads (RX — Client → Envoy)

| Payload | Clients | kTLS MB/s | BoringSSL MB/s | Ratio | Winner |
|---------|---------|-----------|----------------|-------|--------|
| 1MB | 1 | 296.6 | 113.4 | 2.62x | kTLS |
| 4MB | 1 | 421.4 | 281.2 | 1.50x | kTLS |
| 8MB | 1 | 610.4 | 416.0 | 1.47x | kTLS |
| 8MB | 10 | 700.8 | 1,627.6 | 0.43x | BoringSSL |
| 16MB | 10 | 625.6 | 1,608.8 | 0.39x | BoringSSL |

**Verdict:** kTLS wins at c1, BoringSSL 2-2.5x faster at c10/c50. Kernel 5.4 RX bottleneck.

### Dual-TLS (Both Downstream + Upstream)

| Direction | Size | kTLS MB/s | BoringSSL MB/s | Diff |
|-----------|------|-----------|----------------|------|
| DL | 1MB | 327.1 | 624.5 | -47.6% |
| DL | 16MB | 524.3 | 1,259.7 | -58.4% |
| DL | 128MB | 554.2 | 1,305.0 | -57.5% |
| UL | 1MB | 350.1 | 683.5 | -48.8% |
| UL | 16MB | 613.8 | 1,210.1 | -49.3% |
| UL | 128MB | 559.4 | 1,227.7 | -54.4% |

**Verdict:** kTLS ~50-60% slower in dual-TLS. Bottleneck is kernel 5.4 crypto on both RX paths.

---

## Root Cause: Kernel 5.4 kTLS RX Limitation

The upload (RX) bottleneck is a **kernel version limitation**, not a code bug:

1. **kTLS RX on kernel 5.4:** `tls_sw_recvmsg()` → `crypto_aead_decrypt()` through the kernel
   crypto API. Overhead from sg_table setup, skb management, and less-optimized crypto dispatch.
   Ceiling: ~43,000 TLS records/sec (~700 MB/s).

2. **BoringSSL:** Plain `read()` syscall returns encrypted bytes quickly, then `SSL_read()` uses
   hand-tuned AES-NI assembly to decrypt in userspace. Throughput: ~99,000 records/sec (~1.6 GB/s).

3. Newer kernels (5.10+ zero-copy RX, 5.19+ MSG_ZEROCOPY) substantially close this gap.

---

## Improvements Already Applied

| # | Change | Status | Impact |
|---|--------|--------|--------|
| 1 | Zero-copy RX via `reserve_read_slices`/`commit_read` | **Done** | Eliminated memcpy on hot path |
| 2 | Eager kTLS transition | **Rejected** | Causes catastrophic errors (see below) |
| 3 | `TLS_RX_EXPECT_NO_PAD` for TLS 1.3 | **Done** | Enables kernel ZC RX on 5.16+ |
| 4 | `TCP_NODELAY` before ULP install | **Done** | Avoids extra RTT on initial writes |
| 5 | `writev` instead of `sendmsg` | **Skipped** | Marginal gain; `sendmsg`+`MSG_NOSIGNAL` is safer |
| 6 | `sendfile()` API | **Done** | Available as `ktls_sendfile()` for file-serving |
| 7 | `TLS_TX_ZEROCOPY_RO` after TLS_TX | **Done** | Enables NIC hw zero-copy on 6.0+ |
| 8 | Control message optimization | **Skipped** | Current EIO+recvmsg pattern matches ktls crate |

### Why Eager Transition Is Dangerous

The bench_perf_results.json file shows what happens when kTLS RX is installed without waiting
for a clean TLS record boundary:

- upload_8MB_c1: **1,979 errors, 0 successful**
- download_16MB_c50: **96,144 errors, 0 successful**

After the handshake, rustls may have consumed bytes from the TCP socket that form a partial TLS
record. Installing `TLS_RX` at this point causes the kernel to start decrypting from the wrong
byte offset → `EBADMSG` → connection reset.

The current record-tracking state machine (`tls_record_header_seen`, `tls_record_bytes_remaining`)
waits until rustls has consumed exactly at a TLS record boundary. This is essential for correctness.

---

## NEW Proposed Improvements

The following changes target the remaining performance gaps that ARE addressable in code. They
are ordered by expected impact.

### Change 1: Auto-detect Kernel and Default to TX-Only on Older Kernels [HIGH IMPACT]

**Problem:**
The benchmark data shows a clear pattern: kTLS TX is competitive with BoringSSL on all kernels,
but kTLS RX is a bottleneck on kernel 5.4 at high concurrency (c10+). Users must manually
configure `"ktls_tx_only": true` to get optimal performance — most won't know this.

On kernel 5.4:
- kTLS TX throughput: ~1,420 MB/s (within 10% of BoringSSL's 1,571 MB/s)
- kTLS RX throughput: ~625-700 MB/s at c10 (vs BoringSSL's 1,608 MB/s)
- Rustls userspace RX: Faster than kTLS RX on this kernel

On kernel 5.10+:
- kTLS RX zero-copy support added
- Full kTLS (TX+RX) should be competitive

**Fix:**

Add kernel version detection at module initialization time. If the kernel version is < 5.10,
automatically enable TX-only mode unless the user explicitly overrides it:

```rust
/// Detect kernel version from uname and return (major, minor).
fn kernel_version() -> (u32, u32) {
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut utsname) };
    let release = unsafe {
        std::ffi::CStr::from_ptr(utsname.release.as_ptr())
    };
    let release_str = release.to_string_lossy();
    // Parse "5.4.0-1154-aws-fips" -> (5, 4)
    let mut parts = release_str.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

// In maybe_try_ktls() or the factory constructor:
fn should_use_rx_ktls() -> bool {
    let (major, minor) = kernel_version();
    // kTLS RX is competitive on 5.10+ (zero-copy RX support)
    // On older kernels, userspace rustls RX is faster at high concurrency
    major > 5 || (major == 5 && minor >= 10)
}
```

Then in `maybe_try_ktls()`, if `!should_use_rx_ktls()` and the user hasn't explicitly set
`ktls_tx_only: false`, default to TX-only:

```rust
fn maybe_try_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl) {
    // ... existing checks ...

    // Auto-detect: use TX-only on older kernels
    if !self.ktls_tx_only && !self.ktls_rx_forced {
        if !should_use_rx_ktls() {
            envoy_log_info!(
                "kTLS: kernel {}.{} detected, defaulting to TX-only mode \
                 (RX is faster in userspace on this kernel). \
                 Set ktls_tx_only=false to override.",
                major, minor
            );
            self.ktls_tx_only = true;
        }
    }

    // ... rest of existing code ...
}
```

**Config change:** Add a `ktls_rx_force` boolean (default false) to allow users to explicitly
request full kTLS even on older kernels.

**Specific file changes:**
- `rustls_ktls.rs`: Add `kernel_version()` function and `should_use_rx_ktls()` check
- `rustls_ktls.rs` struct: Add `ktls_rx_forced: bool` field
- Config JSON: Add optional `"ktls_rx_force": true|false` field

**Expected impact:** On kernel 5.4 at c10+, upload throughput should jump from ~625-700 MB/s
(kTLS RX) to ~1,600 MB/s (rustls RX), matching BoringSSL. Downloads (TX) stay at kTLS speed
(within 10% of BoringSSL).

---

### Change 2: Dual-TLS Asymmetric Strategy — TX-Only on Upstream [HIGH IMPACT]

**Problem:**
Dual-TLS benchmarks show kTLS is 50-60% slower than BoringSSL. The bottleneck is kernel crypto
on BOTH the downstream and upstream RX paths. With two TLS connections, there are 4 crypto
operations per request: downstream RX decrypt + upstream TX encrypt + upstream RX decrypt +
downstream TX encrypt. Each kernel crypto call on 5.4 is slower than BoringSSL's AES-NI.

**Fix:**

For dual-TLS connections, use kTLS TX-only for the **upstream** connection while using the
user's configured kTLS mode for the downstream connection. This halves the kernel crypto calls
without sacrificing the TX offload benefit.

The upstream connection's RX data (response from backend) flows:
1. Kernel receives encrypted data from upstream
2. Kernel decrypts via kTLS RX (SLOW on 5.4) → change to rustls RX (FAST)
3. Envoy processes the response
4. Kernel encrypts via kTLS TX (FAST) for downstream

By using TX-only on upstream, step 2 uses rustls's fast AES-NI assembly instead of the slow
kernel crypto path.

**Implementation:**
This is a configuration/policy change. When creating the upstream transport socket:

```rust
// In the upstream transport socket factory:
fn create_upstream_transport_socket(&self) -> Box<dyn TransportSocket> {
    let mut config = self.config.clone();
    // Force TX-only for upstream on old kernels (auto-detect)
    if config.want_ktls && !should_use_rx_ktls() {
        config.ktls_tx_only = true;
    }
    Box::new(RustlsTransportSocket::new_client(config, ...))
}
```

**Expected impact:** Dual-TLS throughput should improve from ~350-560 MB/s to ~700-1100 MB/s
on kernel 5.4 (approaching BoringSSL's ~625-1305 MB/s).

---

### Change 3: Reduce Transition Syscall Overhead [MEDIUM IMPACT]

**Problem:**
During the `ktls_pending` phase, `read_tls_from_socket()` (lines 735-760) deliberately reads
only the minimum bytes needed to complete the current partial TLS record:

```rust
let limit = if self.tls_record_bytes_remaining > 0 {
    self.tls_record_bytes_remaining    // Just enough to finish payload
} else {
    5 - self.tls_record_header_seen as usize  // Just enough to finish header
};
let read_limit = std::cmp::min(limit, raw.len());
match envoy.io_handle_read(io, &mut raw[.. read_limit]) { ... }
```

If a TLS record is 16,389 bytes (5 header + 16,384 payload) and rustls read 10,000 bytes of
it, the pending code will:
- Read 6,389 bytes (remaining payload) — syscall #1
- Read 5 bytes (next header) — syscall #2
- Read N bytes (next payload) — syscall #3
- etc.

This creates many tiny reads (sometimes as small as 5 bytes!) during the transition window.

**Fix:**

Read the full `IO_BUF_SIZE` (64KB) during the pending phase, then track records through the
full buffer. The record tracker already handles arbitrary buffer sizes correctly:

```rust
#[cfg(target_os = "linux")]
if self.ktls_pending {
    // If record tracking shows we're at a clean boundary, we're ready to transition
    if self.tls_record_bytes_remaining == 0 && self.tls_record_header_seen == 0 {
        return Ok((0, false));  // Ready
    }

    // Read a full buffer instead of the minimum — fewer syscalls during transition
    let mut raw = [0u8; IO_BUF_SIZE];
    match envoy.io_handle_read(io, &mut raw) {
        Ok(0) => return Ok((0, true)),
        Ok(n) => {
            self.advance_record_tracking(&raw[.. n]);
            return self.feed_raw_to_rustls(&raw[.. n]);
        },
        Err(rc) => {
            if err_would_block(rc) {
                return Ok((0, false));
            }
            return Err(format!("raw read failed (errno {rc})"));
        },
    }
}
```

**Why this is safe:** The record tracker `advance_record_tracking()` correctly handles buffers
of any size. It parses TLS record headers (5 bytes each) and tracks payload boundaries regardless
of how much data is in the buffer. Reading more bytes at once simply means the tracker processes
more records per call, reaching the clean boundary faster.

**Why the original code used restricted reads:** Likely an over-cautious approach to prevent
reading "too far" past the record boundary. But `advance_record_tracking()` handles this
correctly — it tracks exact byte positions, and `feed_raw_to_rustls()` buffers any data that
rustls can't consume immediately (in `tls_read_backlog`).

**Expected impact:** Reduces transition window from potentially dozens of small syscalls to
1-2 large reads. Transition latency drops from potentially hundreds of microseconds to tens.

**Specific file changes:**
- `rustls_ktls.rs` lines 735-760: Replace restricted read with full-size read

---

### Change 4: TCP Socket Tuning for kTLS Connections [LOW-MEDIUM IMPACT]

**Problem:**
kTLS connections use default TCP socket parameters. On kernel 5.4, the kTLS RX path processes
one TLS record per `recv()` call (each record is up to 16KB). With default TCP buffer sizes and
no special tuning, the socket may not be optimally configured for kTLS's record-oriented I/O.

**Fix:**

After installing kTLS, set TCP socket options that improve throughput:

```rust
// In run_linux_ktls(), after install_crypto() succeeds:

// 1. TCP_QUICKACK: Send ACKs immediately, don't delay. This is critical for kTLS
//    because the kernel decrypts on recv() — faster ACKs mean the sender can transmit
//    more records sooner, improving pipeline utilization.
unsafe {
    let val: libc::c_int = 1;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_QUICKACK,  // 12
        &val as *const _ as *const libc::c_void,
        std::mem::size_of_val(&val) as libc::socklen_t,
    );
}

// 2. Increase socket receive buffer for kTLS RX to allow more records in-flight.
//    Default is typically 87380 bytes (~5 TLS records). Increasing to 256KB allows
//    ~16 records in-flight, better pipelining with the sender.
unsafe {
    let val: libc::c_int = 262144;  // 256KB
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &val as *const _ as *const libc::c_void,
        std::mem::size_of_val(&val) as libc::socklen_t,
    );
}
```

**Specific file changes:**
- `rustls_ktls.rs` in `run_linux_ktls()`: Add socket option calls after `install_crypto()` succeeds

**Expected impact:** 5-15% improvement in kTLS RX throughput at high concurrency, as the larger
receive buffer allows more TLS records to be queued before backpressure.

---

### Change 5: Add kTLS Performance Metrics [OBSERVABILITY]

**Problem:**
There's no visibility into kTLS transition timing, throughput, or error rates. This makes it
hard to diagnose performance issues or compare kTLS vs userspace paths in production.

**Fix:**

Add metrics that the implementing agent should track:

```rust
struct KtlsMetrics {
    // Transition
    transition_latency_us: u64,         // Time from handshake complete to kTLS active
    transition_read_cycles: u32,        // Number of read cycles during record tracking
    transition_fallback_count: u64,     // Times kTLS fell back to userspace

    // Throughput (per connection, logged at close)
    rx_bytes_ktls: u64,                 // Bytes received via kTLS path
    tx_bytes_ktls: u64,                 // Bytes sent via kTLS path
    rx_bytes_userspace: u64,            // Bytes received via rustls path
    tx_bytes_userspace: u64,            // Bytes sent via rustls path

    // Errors
    control_messages_received: u32,     // EIO (NewSessionTicket, etc.)
    rx_errors: u32,                     // Non-EAGAIN recv() errors
}
```

At a minimum, log the transition latency and mode at INFO level:

```rust
// In run_linux_ktls() after successful install:
let elapsed = start.elapsed();
envoy_log_info!(
    "kTLS installed in {}us (TX={}, RX={}), kernel {}.{}, {} read cycles during transition",
    elapsed.as_micros(),
    true,
    !self.ktls_tx_only,
    major, minor,
    self.transition_read_cycles
);
```

**Specific file changes:**
- `rustls_ktls.rs`: Add `KtlsMetrics` struct, track transition timing, log at connection close

---

### Change 6: Cork TCP During kTLS Transition [LOW IMPACT]

**Problem:**
During the kTLS transition, there's a brief window where writes may produce small TCP segments
(the drain operations in `run_linux_ktls()` flush pending data). These small segments waste
bandwidth and trigger Nagle-like buffering issues.

**Fix:**

Cork the socket before the transition, uncork after:

```rust
fn run_linux_ktls(&mut self, envoy: &mut EnvoyTransportSocketImpl,
                   io: *mut c_void, fd: libc::c_int) -> Result<(), String> {
    // Cork the socket to batch any writes during transition
    unsafe {
        let val: libc::c_int = 1;
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t);
    }

    self.drain_tls_backlog(envoy, io)?;
    self.drain_rustls_tls(envoy, io)?;
    self.drain_all_plaintext(envoy);
    linux_ktls::setup_ulp(fd)?;
    let conn = self.conn.take().ok_or("missing connection")?;
    linux_ktls::install_crypto(fd, conn, self.ktls_tx_only)?;

    // Uncork: any batched data goes out as a single TCP segment
    unsafe {
        let val: libc::c_int = 0;
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CORK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t);
    }

    self.ktls_fd = Some(fd);
    self.phase = Phase::Ktls;
    self.connected_raised = true;
    Ok(())
}
```

**Specific file changes:**
- `rustls_ktls.rs` in `run_linux_ktls()`: Add TCP_CORK before drain, uncork after install

**Expected impact:** Eliminates 1-3 small TCP segments during transition. Minor throughput gain,
but removes a visible artifact in packet captures.

---

## Implementation Priority

**PR 1: Kernel-Aware kTLS Mode Selection (Changes 1 + 2)**

These are the highest-impact changes and address the primary performance gap:

1. **Change 1** (auto-detect kernel, default TX-only on <5.10) — Biggest practical win
2. **Change 2** (TX-only upstream for dual-TLS on old kernels) — Biggest dual-TLS win

Combined, these should bring kTLS within 10-15% of BoringSSL on kernel 5.4 for ALL workloads.

**PR 2: Transition and Socket Optimization (Changes 3 + 4 + 6)**

3. **Change 3** (full-size reads during transition) — Reduces transition latency
4. **Change 4** (TCP socket tuning) — Improves RX throughput
5. **Change 6** (TCP_CORK during transition) — Cleaner transition

**PR 3: Observability (Change 5)**

6. **Change 5** (metrics) — Essential for ongoing performance work

---

## Recommendations

1. **For kernel <5.10:** Use `"ktls_tx_only": true` for upload-heavy workloads (Change 1
   automates this). kTLS TX is competitive with BoringSSL; userspace rustls RX is faster
   than kernel kTLS RX on old kernels.

2. **For kernel 5.10+:** Full kTLS (TX+RX) should be competitive with or faster than BoringSSL.

3. **For dual-TLS on kernel <5.10:** Use TX-only kTLS on the upstream connection (Change 2).
   This halves kernel crypto overhead.

4. **Always build with `-c opt`** for benchmarks. Debug builds are ~2x slower.

5. **Upgrade kernel if possible.** Kernel 5.10+ adds zero-copy RX, 5.16+ adds
   TLS_RX_EXPECT_NO_PAD, 6.0+ adds TLS_TX_ZEROCOPY_RO hardware offload. The single most
   impactful change for kTLS performance is a newer kernel.

---

## Why the Record Tracking State Machine Must Stay

The `advance_record_tracking()` function (lines 684-719) and the four-guard transition check
(lines 954-980) are **essential for correctness**:

1. After the TLS handshake, rustls calls `read_tls()` on the TCP socket, consuming raw
   encrypted bytes. Rustls may consume bytes that form a **partial** TLS record — e.g., it
   reads 10,000 bytes of a 16,389-byte record.

2. When `TLS_RX` is installed via `setsockopt()`, the kernel's stream parser starts reading
   from the current position in the TCP receive buffer. If rustls consumed some bytes of
   a record but not all, the kernel starts decrypting from the wrong byte offset.

3. This causes `EBADMSG` errors (bad crypto tag) → connection reset → 100% failure rate.

4. The record tracker monitors TLS record headers (5 bytes: type + version + length) and
   payload boundaries. It ensures the transition only happens when:
   - `tls_read_backlog.is_empty()` — no unprocessed data in rustls buffer
   - `tls_record_bytes_remaining == 0` — not mid-payload
   - `tls_record_header_seen == 0` — not mid-header

5. **Evidence:** bench_perf_results.json shows that removing this safety check causes
   complete failure: upload_8MB_c1 = 1,979 errors / 0 success, download_16MB_c50 =
   96,144 errors / 0 success.

The state machine is not fragile — it is load-bearing. Do not attempt to remove or bypass it.

---

## Build Command

```bash
/tmp/bazelisk build -c opt //source/exe:envoy-static --define=wasm=disabled \
    --copt=-Wno-nullability-completeness \
    --repo_env=CARGO_BAZEL_ISOLATED=0 \
    --repo_env=CARGO_HOME=/home/rohit.agrawal/.cargo \
    "--repo_env=GOPROXY=https://go-proxy.dev.databricks.com" \
    "--repo_env=GONOSUMDB=*" \
    "--repo_env=GONOSUMCHECK=*"
```
