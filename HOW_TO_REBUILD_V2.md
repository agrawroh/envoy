# How to Rebuild V2_BUFFERED_READ_FIX

## What Changed

Added version markers and buffered data check to fix application data flow. The new code has these distinctive log markers:

- `🔵 V2_BUFFERED_READ_FIX socket callbacks set`
- `🔵 V2_BUFFERED_READ_FIX doRead() called`
- `🔵 V2_FIX: Checking for buffered application data BEFORE network read`
- `🔵 V2_FIX: rustls_conn_->read() returned N bytes`

**If you DON'T see these markers in your logs, you're running the OLD binary.**

## Your Build Environment

Based on your logs showing paths like `/source/source/extensions/...`, you're building **inside Docker**.

## How to Rebuild

### Method 1: Using Docker CI Script (Recommended)

```bash
cd /Users/rohit.agrawal/envoy-fork

# Build inside Docker (this is what you've been using)
./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release'
```

The Docker build will:
1. Mount your source code into the container
2. Build the Rust FFI library inside the container
3. Build Envoy with Bazel inside the container
4. Output the binary to `./linux/amd64/build_release/envoy` or similar

### Method 2: Manual Docker Build

If you have a custom Docker setup:

```bash
# Start your Docker container with the envoy-fork mounted
# Inside the container, run:

cd /path/to/envoy-fork

# Build Rust FFI
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

# Verify library was built
ls -lh target/release/libenvoy_rustls_ffi.a

# Build Envoy
cd ../../../..
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
```

### Method 3: If You Can Run test_rustls.sh in Docker

```bash
# Inside your Docker container:
cd /path/to/envoy-fork
./test_rustls.sh
```

## Finding the Built Binary

After building, find your binary:

**Docker builds typically output to:**
- `./linux/amd64/build_release/envoy`
- `./linux/amd64/build_envoy_debug/envoy`
- `./bazel-bin/source/exe/envoy-static`

Check which one you're actually running:

```bash
# In your logs, you'll see file paths like:
# [source/extensions/transport_sockets/rustls/rustls_socket.cc:21]
# This tells you which binary you're using
```

## How to Verify You're Running the New Version

When you start Envoy, the **FIRST** connection should show:

```
[info] rustls: 🔵 V2_BUFFERED_READ_FIX socket callbacks set
```

When reading data after handshake:

```
[info] rustls: 🔵 V2_BUFFERED_READ_FIX doRead() called (handshake_complete: true)
[info] rustls: 🔵 V2_FIX: Checking for buffered application data BEFORE network read
[info] rustls: 🔵 V2_FIX: rustls_conn_->read() returned N bytes
```

**If you see the OLD logs instead:**
```
[debug] rustls: socket callbacks set               ← OLD (missing 🔵 V2_BUFFERED_READ_FIX)
[debug] rustls: doRead() called (handshake_complete: true)  ← OLD
```

Then you're running the **wrong binary**. Find and use the newly built one.

## Testing After Rebuild

```bash
# Terminal 1: Start test server
cd examples/rustls
python3 test_server.py

# Terminal 2: Start Envoy (use the correct binary path!)
./bazel-bin/source/exe/envoy-static \
  -c examples/rustls/envoy.yaml \
  -l info 2>&1 | grep -E "(V2_|rustls:)"

# Terminal 3: Test
curl -k --http1.1 -v https://localhost:10000/
```

## Common Mistakes

1. **Running the wrong binary** - You have multiple Envoy binaries. Make sure you're running the one you just built.

2. **Docker cache** - Docker might use cached layers. Ensure the Docker build actually rebuilds the changed C++ files.

3. **Not rebuilding Rust** - If you're missing the Rust library (`libenvoy_rustls_ffi.a`), the build will fail.

## Quick Verification Command

Run this to check if your binary has the new code:

```bash
strings ./bazel-bin/source/exe/envoy-static | grep "V2_BUFFERED_READ_FIX"
```

If this returns matches, your binary has the new code.

