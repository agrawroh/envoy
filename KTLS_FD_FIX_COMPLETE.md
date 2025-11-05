# kTLS FD Fix - Implementation Complete ✅

## Problem Identified

From your logs:
```
[RUST FFI] ❌ Cannot enable kTLS: invalid file descriptor (fd=-1)
```

The rustls connection was created with `fd=-1` as a placeholder, and **we never updated it with the real socket file descriptor**.

## Solution Implemented

### 1. **Added Rust FFI Function** (`rustls_connection_set_fd`)

**File:** `source/extensions/transport_sockets/rustls/rustls_ffi/src/lib.rs`

```rust
#[no_mangle]
pub unsafe extern "C" fn rustls_connection_set_fd(
    conn: *mut rustls_connection_handle,
    fd: RawFd,
) {
    if conn.is_null() {
        return;
    }

    let rustls_conn = &mut *(conn as *mut RustlsConnection);
    eprintln!("[RUST FFI] 🔧 Setting file descriptor: old_fd={}, new_fd={}", 
              rustls_conn.fd, fd);
    rustls_conn.fd = fd;
}
```

### 2. **Added C++ Wrapper Method**

**File:** `source/extensions/transport_sockets/rustls/rustls_wrapper.h`
```cpp
/**
 * Updates the file descriptor for kTLS offload.
 * Must be called after the socket is connected.
 * @param fd the real socket file descriptor.
 */
void setFileDescriptor(int fd);
```

**File:** `source/extensions/transport_sockets/rustls/rustls_wrapper.cc`
```cpp
void RustlsConnection::setFileDescriptor(int fd) {
  rustls_connection_set_fd(handle_, fd);
}
```

### 3. **Called in RustlsSocket::onConnected()**

**File:** `source/extensions/transport_sockets/rustls/rustls_socket.cc`

```cpp
void RustlsSocket::onConnected() {
  ENVOY_CONN_LOG(debug, "rustls: connection established, starting TLS handshake",
                 callbacks_->connection());
  
  // Update the file descriptor for kTLS (now that socket is connected).
  int fd = callbacks_->ioHandle().fdDoNotUse();
  ENVOY_CONN_LOG(debug, "rustls: setting file descriptor for kTLS: fd={}",
                 callbacks_->connection(), fd);
  rustls_conn_->setFileDescriptor(fd);
  
  // ... rest of handshake initialization
}
```

## What This Fixes

**Before:**
- RustlsConnection created with `fd=-1`
- kTLS enablement attempted with invalid FD
- `setsockopt(fd=-1, SOL_TLS, ...)` fails immediately
- Error: "Cannot enable kTLS: invalid file descriptor"

**After:**
- RustlsConnection created with `fd=-1` (temporary)
- When socket connects, we call `setFileDescriptor(real_fd)`
- kTLS enablement now has the real socket FD
- `setsockopt(fd=16, SOL_TLS, ...)` proceeds with real kernel socket
- kTLS can actually enable if kernel supports it

## How to Rebuild and Test

### Rebuild (on your Linux build machine):

```bash
# Navigate to project root
cd /path/to/envoy-fork

# Run rebuild script
chmod +x REBUILD_KTLS_SIMPLE.sh
./REBUILD_KTLS_SIMPLE.sh
```

Or manually:
```bash
# 1. Rebuild Rust FFI
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean && cargo build --release
cd ../../../../

# 2. Rebuild Envoy
bazel clean --expunge
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

### Test:

1. **Start backend server:**
   ```bash
   cd examples/rustls
   python3 test_server.py
   ```

2. **Start Envoy with debug logging:**
   ```bash
   ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l debug
   ```

3. **Send test request:**
   ```bash
   curl -k --http1.1 https://localhost:10000/
   ```

## Expected Log Output (Success Case)

```
[debug] rustls: connection established, starting TLS handshake
[debug] rustls: setting file descriptor for kTLS: fd=16          ← ✅ Real FD!
[RUST FFI] 🔧 Setting file descriptor: old_fd=-1, new_fd=16     ← ✅ Updated!

... handshake completes ...

[debug] rustls: attempting to enable kTLS offload
[RUST FFI] 🔧 Attempting to enable kTLS TX on fd=16             ← ✅ Real FD!
[RUST FFI] 🔧 Session keys extracted, calling enable_ktls_tx()
[KTLS] 🔧 enable_ktls_impl called for TX on fd=16
[KTLS] ✅ Kernel supports kTLS
[KTLS] 🔧 TLS version: 1.2 (0x303)
[KTLS] 🔧 Cipher: AES-128-GCM (type=51)
[KTLS] 🔧 Setting up AES-128-GCM crypto info
[KTLS] ✅ Key material validated: key=16 bytes, salt=4 bytes
[KTLS] 🔧 Calling setsockopt(fd=16, SOL_TLS=31, ...)            ← ✅ Real FD!
[KTLS] ✅ setsockopt SUCCESS: kTLS TX enabled                    ← ✅ SUCCESS!
[RUST FFI] ✅ kTLS TX enabled successfully on fd=16

... same for kTLS RX ...

[info] rustls: ✅ kTLS offload enabled (TX + RX)                 ← ✅ FULL SUCCESS!
```

## Possible Failure Scenarios (Even with Real FD)

### 1. Kernel doesn't support kTLS
```
[KTLS] ❌ kTLS is not supported on this kernel
```
**Solution:** Check `/proc/sys/net/ipv4/tcp_available_ulp` for "tls"

### 2. Kernel version too old
```
[KTLS] ❌ setsockopt FAILED: errno=22 (Invalid argument)
```
**Solution:** Upgrade to Linux 4.17+ for kTLS RX, 4.13+ for TX only

### 3. Cipher suite not supported
```
[KTLS] ❌ Unsupported cipher suite for kTLS
```
**Solution:** Only AES-GCM-128, AES-GCM-256, and ChaCha20-Poly1305 supported

## Why This Approach?

- **Uses official Envoy API:** `callbacks_->ioHandle().fdDoNotUse()` is the standard way to get FD
- **Safe timing:** FD is set in `onConnected()` when socket is actually connected
- **Clean separation:** Factory creates connection with placeholder FD, socket updates it when ready
- **No breaking changes:** Existing code flow unchanged, just adds FD update step

## Files Modified

1. `source/extensions/transport_sockets/rustls/rustls_wrapper.h` - Added `setFileDescriptor()` declaration
2. `source/extensions/transport_sockets/rustls/rustls_wrapper.cc` - Implemented C++ wrapper and FFI declaration
3. `source/extensions/transport_sockets/rustls/rustls_ffi/src/lib.rs` - Added Rust FFI function
4. `source/extensions/transport_sockets/rustls/rustls_socket.cc` - Call `setFileDescriptor()` in `onConnected()`

## Next Steps

1. **Rebuild** using the script or manual commands above
2. **Test** with the test steps above
3. **Verify** kTLS enablement in logs (look for "setsockopt SUCCESS")
4. **Celebrate** when you see "✅ kTLS offload enabled (TX + RX)" 🎉

## Status

- ✅ Code changes complete
- ⏳ Awaiting rebuild and test
- 🎯 Goal: Full kTLS offload working end-to-end

