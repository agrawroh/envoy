# Rebuild and Test with Diagnostic Logging

## Changes Made

Added extensive Rust-side logging to `rustls_connection_read_tls` to diagnose why `read_tls()` returns 0 after handshake:

1. Log `wants_read()` status before calling `read_tls()`
2. Log `is_handshaking()` status  
3. Log what `read_tls()` returns (with errors)
4. Log `process_new_packets()` call and result
5. Log final return value

## Rebuild Instructions

```bash
# On Linux machine - Rebuild Rust FFI library
cd ~/envoy-fork/source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

# Verify new timestamp
ls -lh target/release/libenvoy_rustls_ffi.a

# Rebuild Envoy (your current build system)
cd ~/envoy-fork
# Use whatever build command you normally use
# The binary should link against the new Rust library

# Run Envoy
./your-envoy-binary -c examples/rustls/envoy.yaml -l debug
```

## Test

```bash
curl -vvv -k https://localhost:10000/
```

## What to Look For

In the Envoy logs, you should now see Rust-side logging like:

```
rustls_connection_read_tls: len=191, wants_read=<true/false>, handshaking=<true/false>
Server read_tls returned: <0 or 191>
About to call process_new_packets() with bytes_read=<value>
Server process_new_packets() succeeded/failed
rustls_connection_read_tls returning: <value>
```

This will tell us **exactly** why `read_tls()` returns 0!

## Expected Scenarios

**Scenario A: wants_read() returns false**
```
rustls_connection_read_tls: len=191, wants_read=false, handshaking=false
Server read_tls returned: 0
```
→ rustls doesn't want more data (buffer full?)

**Scenario B: read_tls() has an issue**
```
rustls_connection_read_tls: len=191, wants_read=true, handshaking=false  
Server read_tls returned: 0
```
→ rustls wants to read but `read_tls()` returns 0 anyway (API issue?)

**Scenario C: Everything works!**
```
rustls_connection_read_tls: len=191, wants_read=true, handshaking=false
Server read_tls returned: 191
About to call process_new_packets() with bytes_read=191
Server process_new_packets() succeeded
rustls_connection_read_tls returning: 191
```
→ The fix works!

Share the logs and we'll know exactly what's wrong! 🔍

