# Application Data Flow Fix

## The Problem

After TLS handshake completion, when the client (curl) sends an HTTP request, Envoy reads the encrypted data from the network but `rustls_connection_read_tls()` returns 0 (doesn't consume the data). This causes the application data to be lost and the connection to hang.

### Symptoms
```
[2025-11-05 20:07:45.990] rustls: 📥 read 191 encrypted bytes from network
[2025-11-05 20:07:45.991] rustls: readTls() consumed 0 bytes from slice (len: 191)
[2025-11-05 20:07:45.991] rustls: 🔄 fed 0 bytes to rustls
[RUST FFI] rustls_connection_read_tls: len=191, wants_read=false, handshaking=false
```

The key observations:
- `wants_read=false` after handshake
- `read_tls()` returns 0 (refuses the data)
- Application data never gets decrypted

## Root Cause

**Rustls state machine behavior:** After the TLS handshake completes, rustls may have **already decrypted application data sitting in its internal buffer**. This happens because:

1. The final TLS handshake flight from the server may include encrypted application data (early data or 0-RTT)
2. When `process_new_packets()` is called, rustls decrypts everything - both handshake messages AND any early application data
3. The decrypted application data sits in rustls's internal reader buffer

**The critical invariant:** Rustls will refuse to accept more encrypted data (`wants_read()` returns false, `read_tls()` returns 0) when it has unconsumed decrypted data in its internal buffer.

This is by design - rustls wants the application to consume the decrypted data before feeding it more encrypted data. This prevents unbounded memory growth.

## The Incorrect Flow (Before Fix)

```
doRead() {
  1. Read 191 encrypted bytes from network ✅
  2. Call readTls(191 bytes) → returns 0 ❌  // rustls refuses because it has buffered data
  3. Call doHandshake() → process_new_packets() → nothing to process ❌
  4. Try to read application data → returns 0 ❌  // we already read it earlier but didn't return it
}
```

## The Correct Flow (After Fix)

```
doRead() {
  // PHASE 1: Check for buffered data first
  IF handshake_complete:
    Try to read application data from rustls
    IF got data:
      return it immediately ✅
  
  // PHASE 2: Only if no buffered data, read from network
  Read encrypted bytes from network
  Feed to rustls via readTls()
  Process packets via doHandshake()
  
  // PHASE 3: Read newly decrypted data
  Try to read application data from rustls
  Return it
}
```

## The Fix

Modified `RustlsSocket::doRead()` in `source/extensions/transport_sockets/rustls/rustls_socket.cc`:

```cpp
Network::IoResult RustlsSocket::doRead(Buffer::Instance& buffer) {
  ENVOY_CONN_LOG(debug, "rustls: doRead() called (handshake_complete: {})",
                 callbacks_->connection(), handshake_complete_);
  
  Network::PostIoAction action = Network::PostIoAction::KeepOpen;
  uint64_t bytes_read = 0;
  bool end_stream = false;

  // IMPORTANT: If handshake is complete, first try to read any buffered application data
  // that rustls has already decrypted. Rustls will refuse to accept more encrypted data
  // if it has unconsumed decrypted data in its internal buffer.
  if (handshake_complete_) {
    const uint64_t max_read_size = 16384;
    uint8_t app_buffer[max_read_size];
    ssize_t app_bytes = rustls_conn_->read(app_buffer, max_read_size);
    
    if (app_bytes > 0) {
      bytes_read = static_cast<uint64_t>(app_bytes);
      buffer.add(app_buffer, bytes_read);
      ENVOY_CONN_LOG(info, "rustls: 📖 read {} buffered application bytes (before network read)", 
                     callbacks_->connection(), bytes_read);
      return {action, bytes_read, end_stream};
    }
  }

  // ... rest of the function (network read, feed to rustls, process, read new data)
}
```

## Why This Works

1. **On first call after handshake completes:** 
   - Check for buffered data → find the buffered application data that was decrypted during handshake
   - Return it immediately
   - Rustls's internal buffer is now empty

2. **On subsequent calls:**
   - Check for buffered data → none found
   - Read new encrypted data from network
   - Feed to rustls → now `wants_read()` is true, `read_tls()` accepts the data
   - Process and decrypt it
   - Read the newly decrypted data
   - Return it

## Testing

To test this fix:

```bash
# Rebuild Envoy (no need to rebuild Rust)
cd /Users/rohit.agrawal/envoy-fork
bazel build //source/exe:envoy-static --define=wasm=disabled --copt=-Wno-nullability-completeness

# Start test server
cd examples/rustls
python3 test_server.py &

# Start Envoy
./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l debug

# Test with curl
curl -k --http1.1 -v https://localhost:10000/
```

Expected result: HTTP request should be processed successfully, with logs showing:
```
rustls: 📖 read N buffered application bytes (before network read)
```

## Related Files

- `source/extensions/transport_sockets/rustls/rustls_socket.cc` - The fix
- `source/extensions/transport_sockets/rustls/rustls_ffi/src/lib.rs` - No changes needed

## References

- Rustls documentation on `wants_read()`: https://docs.rs/rustls/latest/rustls/struct.ServerConnection.html#method.wants_read
- Rustls state machine: The reader buffer must be consumed before more encrypted data is accepted

