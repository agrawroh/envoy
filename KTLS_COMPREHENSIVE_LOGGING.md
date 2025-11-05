# kTLS Comprehensive Logging Summary

## What Was Added

I've added detailed diagnostic logging to every step of the kTLS enablement process:

### 1. Key Extraction (`key_extraction.rs`)

Logs added:
- `[KEY EXTRACT] 🔑 Starting client/server key extraction`
- Cipher suite information: `[KEY EXTRACT] 🔑 Cipher suite: ...`
- Protocol version: `[KEY EXTRACT] 🔑 Protocol version: ...`
- Success/failure of `dangerous_extract_secrets()` call
- TLS version (1.2 or 1.3)
- Sequence number: `[KEY EXTRACT] 🔑 TX sequence number: N`
- Cipher type (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- Key material sizes: `[KEY EXTRACT] 🔑 Key size: N bytes, IV size: N bytes`
- Salt and explicit IV sizes with sequence number

### 2. kTLS Socket Setup (`ktls.rs`)

Logs added:
- `[KTLS] 🔧 enable_ktls_impl called for TX/RX on fd=N`
- Kernel kTLS support check with instructions
- TLS version conversion with hex values
- Cipher type identification
- Key material validation for each cipher
- `setsockopt()` call details (fd, SOL_TLS, direction, struct size)
- Success: `[KTLS] ✅ setsockopt SUCCESS`
- Failure: `[KTLS] ❌ setsockopt FAILED: ret=N, errno=N, error: ...`

### 3. Connection State Management (`lib.rs`)

Already has logs:
- `[RUST FFI] 🔧 Attempting to enable kTLS TX/RX on fd=N`
- FD validation check
- Session key extraction status
- Final success/failure with connection state

## What You'll See When Testing

### Expected Log Sequence (Successful kTLS):

```
[2025-11-05 HH:MM:SS] rustls: attempting to enable kTLS offload
[RUST FFI] 🔧 Attempting to enable kTLS TX on fd=16
[KEY EXTRACT] 🔑 Starting server key extraction
[KEY EXTRACT] 🔑 Cipher suite: TLS13_AES_128_GCM_SHA256
[KEY EXTRACT] 🔑 Protocol version: TLSv1.3
[KEY EXTRACT] ✅ Successfully extracted secrets from server connection
[KEY EXTRACT] 🔑 TLS version: 1.3
[KEY EXTRACT] 🔑 TX sequence number: 0
[KEY EXTRACT] 🔑 Cipher: AES-128-GCM
[KEY EXTRACT] 🔑 Key size: 16 bytes, IV size: 12 bytes
[KEY EXTRACT] 🔑 Salt: 4 bytes, Explicit IV: 8 bytes, Seq: 0
[RUST FFI] 🔧 Session keys extracted, calling enable_ktls_tx()
[KTLS] 🔧 enable_ktls_impl called for TX on fd=16
[KTLS] 🔧 Checking if kernel supports kTLS...
[KTLS] ✅ Kernel supports kTLS
[KTLS] 🔧 TLS version: 1.3 (0x304)
[KTLS] 🔧 Cipher: AES-128-GCM (type=51)
[KTLS] 🔧 Setting up AES-128-GCM crypto info
[KTLS] ✅ Key material validated: key=16 bytes, salt=4 bytes, iv=8 bytes, seq=0
[KTLS] 🔧 Calling setsockopt(fd=16, SOL_TLS=282, direction=1, struct_size=...)
[KTLS] ✅ setsockopt SUCCESS: kTLS TX enabled for AES-128-GCM on fd=16
[RUST FFI] ✅ kTLS TX enabled successfully on fd=16
```

### Expected Log Sequence (Failed kTLS):

If kTLS fails, you'll see exactly WHERE and WHY:

```
[RUST FFI] 🔧 Attempting to enable kTLS TX on fd=16
[KEY EXTRACT] 🔑 Starting server key extraction
... (key extraction logs) ...
[KTLS] 🔧 enable_ktls_impl called for TX on fd=16
[KTLS] 🔧 Checking if kernel supports kTLS...
[KTLS] ❌ kTLS is not supported on this kernel - check /proc/sys/net/ipv4/tcp_available_ulp
[RUST FFI] ❌ Failed to enable kTLS TX on fd=16 - connection state lost!
```

OR if setsockopt fails:

```
[KTLS] ✅ Kernel supports kTLS
[KTLS] 🔧 TLS version: 1.3 (0x304)
[KTLS] 🔧 Cipher: AES-128-GCM (type=51)
[KTLS] 🔧 Setting up AES-128-GCM crypto info
[KTLS] ✅ Key material validated: key=16 bytes, salt=4 bytes, iv=8 bytes, seq=0
[KTLS] 🔧 Calling setsockopt(fd=16, SOL_TLS=282, direction=1, struct_size=40)
[KTLS] ❌ setsockopt FAILED: ret=-1, errno=22, error: Invalid argument
[RUST FFI] ❌ Failed to enable kTLS TX on fd=16 - connection state lost!
```

## Common errno Values

When kTLS fails, the errno will tell you why:

- **22 (EINVAL)**: Invalid argument - usually means:
  - FD is not a TCP socket
  - Wrong TLS version/cipher combination
  - Invalid key material format
  - Socket is not in correct state

- **95 (EOPNOTSUPP)**: Operation not supported
  - Kernel doesn't have kTLS module for this cipher
  - Wrong kernel version

- **19 (ENODEV)**: No such device
  - TLS ULP module not loaded

## How to Rebuild and Test

**On your Linux build machine:**

```bash
cd ~/envoy-fork

# Rebuild Rust FFI with comprehensive logging
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

# Rebuild Envoy
cd ../../../..
bazel clean
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

# Test
./bazel-bin/source/exe/envoy-static \
  -c examples/rustls/envoy.yaml \
  -l info 2>&1 | grep -E "(KTLS|KEY EXTRACT|RUST FFI)"
```

Then test with curl and you'll see EXACTLY why kTLS is failing!

## What to Look For

The logs will tell you:
1. ✅ Is the kernel kTLS check passing?
2. ✅ What cipher suite was negotiated?
3. ✅ What TLS version (1.2 or 1.3)?
4. ✅ Are the key sizes correct?
5. ✅ What's the exact setsockopt() error code?
6. ✅ Is the FD valid (-1 or real FD)?

With this information, we can diagnose the exact failure point!

