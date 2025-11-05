# Build Diagnosis - Mixed Old/New Code

## Current Situation

You're running:
- ✅ **NEW C++ code** - Shows `🔵 V2_BUFFERED_READ_FIX`
- ❌ **OLD Rust code** - Missing "Calling server_conn.read_tls()" log

## Evidence

### C++ side (NEW):
```
[info] rustls: 🔵 V2_BUFFERED_READ_FIX socket callbacks set  ← NEW
[info] rustls: 🔵 V2_FIX: Checking for buffered application data  ← NEW
```

### Rust side (OLD):
```
[RUST FFI] rustls_connection_read_tls: len=191, wants_read=false, handshaking=false
← Should be followed by "Calling server_conn.read_tls()" but it's missing!
```

The Rust code at line 468 should print:
```rust
eprintln!("[RUST FFI] Calling server_conn.read_tls() with {} bytes (wants_read={})", len, wants_read);
```

But this log is **NOT appearing**, which means the Rust library is OLD.

## Why This Happened

When you rebuilt in Docker:
1. ✅ Bazel saw the changed C++ file (`rustls_socket.cc`) and recompiled it
2. ❌ Bazel did NOT rebuild the Rust library because it's pre-built and linked as a static `.a` file

The `BUILD` file links against:
```python
"//source/extensions/transport_sockets/rustls/rustls_ffi:target/release/libenvoy_rustls_ffi.a"
```

This is a **pre-built artifact**. Bazel doesn't know it needs to be rebuilt when `lib.rs` changes.

## Solution

You must rebuild the Rust library **INSIDE your Docker container** before building Envoy.

### Option 1: Manual Docker Build

```bash
# SSH/exec into your Docker container
docker exec -it <container-id> bash

# Inside container:
cd /path/to/envoy-fork/source/extensions/transport_sockets/rustls/rustls_ffi

# Rebuild Rust library
cargo clean
cargo build --release

# Verify it was built
ls -lh target/release/libenvoy_rustls_ffi.a
# Should show recent timestamp

# Now rebuild Envoy
cd /path/to/envoy-fork
bazel clean
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

### Option 2: Modify Your Docker Build Script

Update your Docker build script to always rebuild the Rust library first:

```bash
#!/bin/bash
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

cd ../../../../
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

### Option 3: Using test_rustls.sh

If `test_rustls.sh` works in your Docker environment:

```bash
# Inside Docker:
./test_rustls.sh
```

This script should rebuild both Rust and C++.

## Verification

After rebuilding, you MUST see ALL these logs:

```
[info] rustls: 🔵 V2_BUFFERED_READ_FIX socket callbacks set
[info] rustls: 🔵 V2_BUFFERED_READ_FIX doRead() called (handshake_complete: true)
[info] rustls: 🔵 V2_FIX: Checking for buffered application data BEFORE network read
[RUST FFI] rustls_connection_read_tls: len=191, wants_read=false, handshaking=false
[RUST FFI] Calling server_conn.read_tls() with 191 bytes (wants_read=false)  ← THIS MUST APPEAR
[RUST FFI] Server read_tls returned: N
```

If "Calling server_conn.read_tls()" is missing, the Rust library is still old.

## Quick Check

To verify which Rust library your binary is using:

```bash
# Check when the Rust library was last built
stat source/extensions/transport_sockets/rustls/rustls_ffi/target/release/libenvoy_rustls_ffi.a

# Should show a recent timestamp matching your C++ rebuild time
```

If the timestamp is OLD, that's your problem!

