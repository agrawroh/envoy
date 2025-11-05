# Rebuild and Test - Final Fix

## What Was Fixed

The application data flow issue where `read_tls()` returned 0 after handshake completion. See `APPLICATION_DATA_FLOW_FIX.md` for full details.

**TL;DR:** Rustls buffers decrypted application data and refuses to accept more encrypted data until the buffered data is consumed. We now check for buffered data BEFORE reading from the network.

## Rebuild (Bazel Only)

Since we only changed C++ code (`rustls_socket.cc`), no need to rebuild the Rust library:

```bash
cd /Users/rohit.agrawal/envoy-fork

# Build Envoy
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

## Test Locally

```bash
# Terminal 1: Start test HTTPS server
cd examples/rustls
python3 test_server.py

# Terminal 2: Start Envoy
cd /Users/rohit.agrawal/envoy-fork
./bazel-bin/source/exe/envoy-static \
  -c examples/rustls/envoy.yaml \
  -l debug

# Terminal 3: Test with curl
curl -k --http1.1 -v https://localhost:10000/
```

## Expected Success Logs

You should see:
```
[debug] rustls: doRead() called (handshake_complete: 1)
[info] rustls: 📖 read 123 buffered application bytes (before network read)
```

Then Envoy should process the HTTP request normally.

## If Testing in Docker

If you're running Envoy via `./ci/run_envoy_docker.sh`:

```bash
# The Docker build will automatically pick up the changed C++ file
# Just rebuild the Docker image
./ci/run_envoy_docker.sh ... your usual docker build command ...
```

## What to Look For

**Success indicators:**
1. ✅ "read N buffered application bytes (before network read)" - shows we're consuming buffered data first
2. ✅ Curl receives HTTP response
3. ✅ No "readTls() consumed 0 bytes" messages after handshake

**Failure indicators:**
1. ❌ "readTls() consumed 0 bytes from slice (len: 191)" - means rustls still refusing data
2. ❌ Connection hangs or times out
3. ❌ "no application data available" warnings

## Next Steps After Successful Test

Once this works:
1. Remove excessive debug logging (keep only key info/error logs)
2. Test kTLS offload functionality
3. Write integration tests
4. Prepare PR for Envoy upstream

