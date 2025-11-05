# kTLS AES-256-GCM Logging Fix 🔍

## Problem Discovered

From the logs, we saw:
```
[KTLS] 🔧 Cipher: AES-256-GCM (type=52)
[RUST FFI] ❌ kTLS TX failed  ← Jumped directly to failure with NO setsockopt log!
```

**The issue:** The AES-256-GCM code path in `ktls.rs` was using `log::error!()`, `log::info!()`, and `log::warn!()` instead of `eprintln!()`, so error messages were going to the Rust logger (which isn't configured) instead of stderr.

## Code Structure Issue

### Before (Inconsistent Logging):

```rust
// AES-128-GCM branch (lines 202-255)
TlsCipher::AesGcm128 => {
    eprintln!("[KTLS] 🔧 Setting up AES-128-GCM...");  ✅ Visible
    // ... comprehensive logging with eprintln! ...
    eprintln!("[KTLS] ✅ setsockopt SUCCESS...");
}

// AES-256-GCM branch (lines 257-312)  
TlsCipher::AesGcm256 => {
    log::error!("Invalid key material...");  ❌ SILENT!
    // ... using log::info!, log::warn! ...
    log::info!("kTLS TX enabled...");  ❌ SILENT!
}
```

### After (Consistent Logging):

```rust
// All branches now use eprintln!() for visibility
TlsCipher::AesGcm128 => {
    eprintln!("[KTLS] 🔧 Setting up AES-128-GCM...");  ✅
}

TlsCipher::AesGcm256 => {
    eprintln!("[KTLS] 🔧 Setting up AES-256-GCM...");  ✅ NOW VISIBLE!
    eprintln!("[KTLS] ✅ Key material validated...");
    eprintln!("[KTLS] 🔧 Calling setsockopt...");  ← This will reveal the issue!
    eprintln!("[KTLS] ✅ setsockopt SUCCESS...");
}

TlsCipher::Chacha20Poly1305 => {
    eprintln!("[KTLS] 🔧 Setting up ChaCha20-Poly1305...");  ✅
}
```

## Changes Made

### File: `source/extensions/transport_sockets/rustls/rustls_ffi/src/ktls.rs`

#### AES-256-GCM Branch (lines 257-315):
- Added comprehensive `eprintln!()` logging matching AES-128-GCM
- Added key material validation logging
- Added IV copy verification
- Added sequence number logging
- Added detailed setsockopt call logging
- Added errno and error details on failure

#### ChaCha20-Poly1305 Branch (lines 317-366):
- Replaced all `log::error!()`, `log::info!()`, `log::warn!()` with `eprintln!()`
- Added comprehensive logging matching other branches

## Expected New Log Output

### Success Case:
```
[KEY EXTRACT] ✅ Successfully extracted secrets
[KEY EXTRACT] 🔑 Cipher: AES-256-GCM
[KEY EXTRACT] 🔑 Key size: 32 bytes, IV size: 12 bytes
[RUST FFI] 🔧 Session keys extracted from server

[KTLS] 🔧 enable_ktls_impl called for TX on fd=183
[KTLS] ✅ Kernel supports kTLS
[KTLS] 🔧 TLS version: 1.3 (0x304)
[KTLS] 🔧 Cipher: AES-256-GCM (type=52)

[KTLS] 🔧 Setting up AES-256-GCM crypto info          ← NEW!
[KTLS] ✅ Key material validated: key=32 bytes, salt=4 bytes, iv=8 bytes, seq=1  ← NEW!
[KTLS] 🔧 Copied IV: 8 bytes                          ← NEW!
[KTLS] 🔧 Set sequence number: 1                      ← NEW!
[KTLS] 🔧 Calling setsockopt(fd=183, SOL_TLS=282, direction=1, struct_size=60)  ← NEW!

[KTLS] ✅ setsockopt SUCCESS: kTLS TX enabled for AES-256-GCM on fd=183  ← NEW!

[Same for RX...]

[RUST FFI] ✅ kTLS TX enabled successfully on fd=183
[RUST FFI] ✅ kTLS RX enabled successfully on fd=183
rustls: ✅ kTLS offload enabled (TX and RX)
```

### Failure Case (If It Fails):
```
[KTLS] 🔧 Setting up AES-256-GCM crypto info
[KTLS] ✅ Key material validated: key=32 bytes, salt=4 bytes, iv=8 bytes, seq=1
[KTLS] 🔧 Copied IV: 8 bytes
[KTLS] 🔧 Set sequence number: 1
[KTLS] 🔧 Calling setsockopt(fd=183, SOL_TLS=282, direction=1, struct_size=60)

[KTLS] ❌ setsockopt FAILED: ret=-1, errno=95, error: Operation not supported
[KTLS] ❌ Failed to enable kTLS TX on fd=183: Operation not supported
```

Now we'll see the EXACT reason for failure!

## Why This Was Hidden

1. **Different Logging APIs**: The code mixed `eprintln!()` (stderr, always visible) with `log::*!()` (requires logger initialization)
2. **Rust Logger Not Configured**: Envoy doesn't initialize the Rust logging framework
3. **Silent Failures**: Errors went to /dev/null essentially
4. **Cipher-Specific**: Only affected AES-256-GCM and ChaCha20-Poly1305, not AES-128-GCM

## Rebuild Instructions

Since we only changed Rust code:

```bash
cd /Users/rohit.agrawal/envoy-fork

# Rebuild Rust FFI only
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

# Rebuild Envoy (fast, just relinks)
cd /Users/rohit.agrawal/envoy-fork
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

Or use the rebuild script:
```bash
./REBUILD_KTLS_V3.sh
```

## What to Look For

After rebuild and test, the logs will show:

1. **If setsockopt succeeds:** We'll see SUCCESS messages and kTLS will work!
2. **If setsockopt fails:** We'll see errno and the exact kernel error (e.g., EOPNOTSUPP=95, EINVAL=22, etc.)

Common errno values:
- `22` (EINVAL): Invalid argument (wrong struct, wrong TLS version, etc.)
- `95` (EOPNOTSUPP): Operation not supported (kTLS not enabled in kernel for this cipher)
- `92` (ENOPROTOOPT): Protocol not available (SOL_TLS not supported)

## Files Modified

- `source/extensions/transport_sockets/rustls/rustls_ffi/src/ktls.rs`
  - AES-256-GCM branch: lines 257-315
  - ChaCha20-Poly1305 branch: lines 317-366

## Next Steps

1. Rebuild Rust FFI
2. Rebuild Envoy
3. Test again
4. Read the detailed logs to see EXACTLY where/why kTLS fails
5. Fix the root cause based on the actual error

---

**This should finally reveal what's happening!** We've been flying blind because errors were silently swallowed. Now every step is logged! 🔍

