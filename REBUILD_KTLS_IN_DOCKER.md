# Rebuild with kTLS FD Fix - Docker Instructions

## What We Fixed

1. **Added `rustls_connection_set_fd()` FFI function** in Rust to update the file descriptor
2. **Added `RustlsConnection::setFileDescriptor()` method** in C++ wrapper
3. **Called `setFileDescriptor()` in `RustlsSocket::onConnected()`** to set the real socket FD
4. **Now kTLS will have the actual file descriptor instead of -1**

## How to Rebuild

### Option 1: If you have cargo locally (Linux environment)

```bash
cd /Users/rohit.agrawal/envoy-fork
./REBUILD_WITH_KTLS_FIX.sh
```

### Option 2: Build in Docker (what you've been using)

```bash
cd /Users/rohit.agrawal/envoy-fork

# The Docker build will automatically rebuild the Rust FFI
./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release.server_only'
```

Or use your test script (which handles Docker):

```bash
cd /Users/rohit.agrawal/envoy-fork
./test_rustls.sh
```

### Option 3: Manual Docker build

```bash
cd /Users/rohit.agrawal/envoy-fork

# Enter Docker container
./ci/run_envoy_docker.sh /bin/bash

# Inside container:
cd /source
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release
cd /source
bazel clean --expunge
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

## What to Look For in Logs

After rebuilding and running, you should see:

```
[debug] rustls: setting file descriptor for kTLS: fd=16    ← Real FD, not -1!
[RUST FFI] 🔧 Setting file descriptor: old_fd=-1, new_fd=16
[debug] rustls: attempting to enable kTLS offload
[RUST FFI] 🔧 Attempting to enable kTLS TX on fd=16       ← Real FD!
[RUST FFI] 🔧 Session keys extracted, calling enable_ktls_tx()
[KTLS] 🔧 enable_ktls_impl called for TX on fd=16
[KTLS] ✅ Kernel supports kTLS
[KTLS] 🔧 TLS version: 1.2
[KTLS] 🔧 Cipher: AES-128-GCM (or similar)
[KTLS] 🔧 Calling setsockopt(fd=16, SOL_TLS=...)
[KTLS] ✅ setsockopt SUCCESS: kTLS TX enabled             ← SUCCESS!
[RUST FFI] ✅ kTLS TX enabled successfully on fd=16
```

## Testing

1. **Start backend server:**
   ```bash
   cd examples/rustls && python3 test_server.py
   ```

2. **Start Envoy (in Docker):**
   ```bash
   ./linux/amd64/build_envoy_debug/envoy -c examples/rustls/envoy.yaml -l debug
   ```

3. **Test connection:**
   ```bash
   curl -k --http1.1 https://localhost:10000/
   ```

4. **Check for kTLS success in logs**

## Files Changed

1. `source/extensions/transport_sockets/rustls/rustls_wrapper.h` - Added `setFileDescriptor()` method
2. `source/extensions/transport_sockets/rustls/rustls_wrapper.cc` - Implemented C++ wrapper
3. `source/extensions/transport_sockets/rustls/rustls_ffi/src/lib.rs` - Added `rustls_connection_set_fd()` FFI
4. `source/extensions/transport_sockets/rustls/rustls_socket.cc` - Call `setFileDescriptor()` in `onConnected()`

