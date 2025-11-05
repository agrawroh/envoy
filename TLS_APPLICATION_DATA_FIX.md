# TLS Application Data Fix

## 🎉 Breakthrough: TLS Handshake Complete!

The TLS handshake is now **fully working**:
- ✅ ClientHello received and processed
- ✅ ServerHello + Certificate sent
- ✅ Client Finished received
- ✅ **TLS 1.3 handshake complete**
- ✅ HTTP/2 (h2) ALPN negotiated

## 🐛 Bug: Application Data Not Being Decrypted

### Symptoms

After successful TLS handshake, encrypted application data (HTTP/2 request) arrives but isn't processed:

```
[19:31:50.040] rustls: 📥 read 191 encrypted bytes from network
[19:31:50.040] rustls: readTls() consumed 0 bytes from slice (len: 191)  ❌
```

The `readTls()` function returns 0, meaning no bytes were consumed, so no decrypted data becomes available.

### Root Cause

In `rustls_connection_read_tls` (lib.rs:422), we were calling `read_tls()` but **never calling `process_new_packets()`**!

The rustls API requires this 3-step flow:
1. `read_tls(&mut reader)` - Read encrypted bytes from network into internal buffer
2. **`process_new_packets()`** - **Decrypt and process those bytes** ⚠️ **THIS WAS MISSING!**
3. `reader().read(&mut buf)` - Read decrypted application data

### The Fix

**Before** (lib.rs:431-452):
```rust
let rustls_conn = &mut *(conn as *mut RustlsConnection);
let input = std::slice::from_raw_parts(buf, len);

let result = match &mut rustls_conn.connection {
    Connection::Client(client_conn) => {
        let mut cursor = std::io::Cursor::new(input);
        match client_conn.read_tls(&mut cursor) {
            Ok(n) => n as isize,
            Err(_) => RUSTLS_ERR_IO as isize,
        }
    }
    Connection::Server(server_conn) => {
        let mut cursor = std::io::Cursor::new(input);
        match server_conn.read_tls(&mut cursor) {
            Ok(n) => n as isize,
            Err(_) => RUSTLS_ERR_IO as isize,
        }
    }
    Connection::KtlsEnabled => 0,
};

result  // ❌ Returns immediately without processing!
```

**After**:
```rust
let rustls_conn = &mut *(conn as *mut RustlsConnection);
let input = std::slice::from_raw_parts(buf, len);

let bytes_read = match &mut rustls_conn.connection {
    Connection::Client(client_conn) => {
        let mut cursor = std::io::Cursor::new(input);
        match client_conn.read_tls(&mut cursor) {
            Ok(n) => n,
            Err(_) => return RUSTLS_ERR_IO as isize,
        }
    }
    Connection::Server(server_conn) => {
        let mut cursor = std::io::Cursor::new(input);
        match server_conn.read_tls(&mut cursor) {
            Ok(n) => n,
            Err(_) => return RUSTLS_ERR_IO as isize,
        }
    }
    Connection::KtlsEnabled => return 0,
};

// CRITICAL: Process the TLS packets we just read to decrypt them. ✅
match &mut rustls_conn.connection {
    Connection::Client(client_conn) => {
        if let Err(_) = client_conn.process_new_packets() {
            return RUSTLS_ERR_IO as isize;
        }
    }
    Connection::Server(server_conn) => {
        if let Err(_) = server_conn.process_new_packets() {
            return RUSTLS_ERR_IO as isize;
        }
    }
    Connection::KtlsEnabled => {}
}

bytes_read as isize  // ✅ Returns after processing!
```

## Expected Behavior After Fix

1. Client sends encrypted HTTP/2 request
2. `readTls()` ingests 191 encrypted bytes → returns 191
3. **`process_new_packets()` decrypts them** ✅
4. `rustls_connection_read()` extracts decrypted HTTP/2 frames
5. Envoy HTTP/2 codec processes the request
6. Request forwarded to upstream backend
7. Response returned to client

## Testing

Rebuild and test:

```bash
# On Linux build machine:
cd ~/envoy-fork/source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

cd ~/envoy-fork
bazel build //source/exe:envoy-static --define=wasm=disabled --copt=-Wno-nullability-completeness

# Run Envoy
./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml

# Test from client
curl -vvv https://localhost:10000/ -k
```

Expected result: **Full HTTP response from backend server!** 🎉

## Files Modified

1. `source/extensions/transport_sockets/rustls/rustls_ffi/src/lib.rs`
   - Fixed `rustls_connection_read_tls` to call `process_new_packets()`
   
2. `source/extensions/transport_sockets/rustls/rustls_ffi/src/new_functions.rs`
   - **DELETED** - unused duplicate file

## Status

- ✅ TLS 1.3 handshake working
- ✅ ALPN negotiation working
- 🔨 Application data processing **fixed** (needs rebuild)
- ⏳ End-to-end HTTP proxying (next test after rebuild)
- ⏳ kTLS offload (requires kernel support)

