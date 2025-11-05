# TLS Handshake Fix - Critical Architecture Issue

## Problem

The handshake is hanging because there's no data flow between the network and rustls. The current implementation:

1. ✅ Starts the handshake in `onConnected()`
2. ❌ But then has no mechanism to:
   - Feed encrypted TLS data from network → rustls
   - Get encrypted TLS responses from rustls → network

## Root Cause

The original `rustls_connection_handshake()` function attempted direct socket I/O using file descriptors, which doesn't work with Envoy's buffer-based transport socket model. When we removed the FD-based I/O, we broke the data flow entirely.

## Solution

We need to implement proper TLS I/O orchestration in the socket layer:

### During Handshake (`doRead`)
```
Network → RawRead → Encrypted TLS Buffer
                 ↓
            readTls() → rustls internal buffer
                 ↓
          process_new_packets() → process handshake
                 ↓
            writeTls() → Encrypted TLS Response Buffer
                 ↓
           RawWrite → Network
```

### After Handshake (`doRead`)
```
Network → RawRead → Encrypted TLS Buffer
                 ↓
            readTls() → rustls internal buffer
                 ↓
              read() → Decrypted App Data
                 ↓
            Application Buffer
```

### After Handshake (`doWrite`)
```
Application Buffer
      ↓
   write() → rustls (encrypts)
      ↓
  writeTls() → Encrypted TLS Buffer
      ↓
  RawWrite → Network
```

## Implementation Status

### ✅ Completed
1. Added buffer-based TLS I/O functions to Rust FFI:
   - `rustls_connection_read_tls()` - Feed encrypted TLS data to rustls
   - `rustls_connection_write_tls()` - Get encrypted TLS data from rustls
   - `rustls_connection_wants_write()` - Check if rustls has pending TLS data
   - `rustls_connection_wants_read()` - Check if rustls needs TLS data

2. Added C++ wrapper methods to `RustlsConnection`:
   - `readTls()`
   - `writeTls()`
   - `wantsWrite()`
   - `wantsRead()`

### ❌ TODO - Critical
Modify `RustlsSocket` to properly orchestrate TLS I/O:

1. **`onConnected()`**: After starting handshake, write initial TLS data (e.g., ClientHello for client)
   ```cpp
   void RustlsSocket::onConnected() {
     ENVOY_CONN_LOG(debug, "rustls: connection established, starting TLS handshake",
                    callbacks_->connection());
     
     // For client connections, rustls generates ClientHello immediately
     // We need to send it to the network
     flushPendingTlsData();
   }
   ```

2. **`doRead()`**: Feed encrypted TLS data to rustls and handle responses
   ```cpp
   Network::IoResult RustlsSocket::doRead(Buffer::Instance& buffer) {
     // Read encrypted TLS data from network
     Network::PostIoAction action = Network::PostIoAction::KeepOpen;
     uint64_t bytes_read = 0;
     
     // Allocate temporary buffer for raw network data
     constexpr uint64_t TLS_BUFFER_SIZE = 16384;
     uint8_t tls_buffer[TLS_BUFFER_SIZE];
     
     // Read from network into temporary buffer
     Api::IoCallUint64Result result = callbacks_->ioHandle().read(
         Buffer::RawSlice{tls_buffer, TLS_BUFFER_SIZE});
     
     if (result.ok()) {
       bytes_read = result.return_value_;
       
       // Feed encrypted TLS data to rustls
       ssize_t consumed = rustls_conn_->readTls(tls_buffer, bytes_read);
       
       if (consumed < 0) {
         return {action, 0, false};
       }
       
       // Process TLS packets (handshake or application data)
       int process_result = rustls_conn_->handshake();
       if (process_result != RustlsConnection::OK) {
         return {action, 0, false};
       }
       
       // If handshaking, write any pending TLS responses
       if (rustls_conn_->isHandshaking()) {
         flushPendingTlsData();
       } else {
         // Handshake complete, read application data
         if (!handshake_complete_) {
           handshake_complete_ = true;
           onHandshakeComplete();
         }
         
         // Read decrypted application data from rustls
         uint8_t app_buffer[TLS_BUFFER_SIZE];
         ssize_t app_bytes = rustls_conn_->read(app_buffer, TLS_BUFFER_SIZE);
         if (app_bytes > 0) {
           buffer.add(app_buffer, app_bytes);
         }
       }
     }
     
     return {action, bytes_read, false};
   }
   ```

3. **`doWrite()`**: Encrypt application data and send TLS data to network
   ```cpp
   Network::IoResult RustlsSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
     if (!handshake_complete_) {
       // During handshake, just flush pending TLS data
       flushPendingTlsData();
       return {Network::PostIoAction::KeepOpen, 0, false};
     }
     
     // Write application data to rustls for encryption
     const auto slices = buffer.getRawSlices();
     uint64_t bytes_written = 0;
     
     for (const auto& slice : slices) {
       if (slice.len_ == 0) continue;
       
       ssize_t result = rustls_conn_->write(
           static_cast<const uint8_t*>(slice.mem_), slice.len_);
       
       if (result < 0) {
         return {Network::PostIoAction::KeepOpen, 0, false};
       }
       
       bytes_written += result;
       buffer.drain(result);
     }
     
     // Flush encrypted TLS data to network
     flushPendingTlsData();
     
     return {Network::PostIoAction::KeepOpen, bytes_written, false};
   }
   ```

4. **Add helper method** `flushPendingTlsData()`:
   ```cpp
   void RustlsSocket::flushPendingTlsData() {
     if (!rustls_conn_->wantsWrite()) {
       return;
     }
     
     constexpr uint64_t TLS_BUFFER_SIZE = 16384;
     uint8_t tls_buffer[TLS_BUFFER_SIZE];
     
     while (rustls_conn_->wantsWrite()) {
       ssize_t written = rustls_conn_->writeTls(tls_buffer, TLS_BUFFER_SIZE);
       if (written <= 0) {
         break;
       }
       
       // Write encrypted TLS data to network
       Buffer::OwnedImpl tls_data(tls_buffer, written);
       callbacks_->connection().write(tls_data, false);
     }
   }
   ```

## Next Steps

1. Install Rust (if not done):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. Rebuild Rust FFI with new TLS I/O functions:
   ```bash
   cd source/extensions/transport_sockets/rustls/rustls_ffi
   cargo build --release
   ```

3. Implement the socket layer changes above in `rustls_socket.cc`

4. Rebuild Envoy and test

## References

- Rustls documentation: https://docs.rs/rustls/
- Similar implementation: https://github.com/rustls/ktls


