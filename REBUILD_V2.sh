#!/bin/bash

set -e

echo "========================================"
echo "🔵 REBUILDING V2_BUFFERED_READ_FIX"
echo "========================================"

cd "$(dirname "$0")"

# Check if running on macOS (host) or Linux (Docker)
if [[ "$OSTYPE" == "darwin"* ]]; then
  echo "❌ ERROR: You're on macOS but building Envoy requires Docker/Linux"
  echo ""
  echo "Please use one of these methods:"
  echo ""
  echo "Method 1: Use test_rustls.sh (recommended)"
  echo "  ./test_rustls.sh"
  echo ""
  echo "Method 2: Use Docker CI script"
  echo "  ./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release'"
  echo ""
  exit 1
fi

echo ""
echo "Step 1: Building Rust FFI library..."
echo ""
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

if [ ! -f "target/release/libenvoy_rustls_ffi.a" ]; then
  echo "❌ ERROR: Rust library not built"
  exit 1
fi

echo "✅ Rust library built: $(ls -lh target/release/libenvoy_rustls_ffi.a | awk '{print $5}')"

echo ""
echo "Step 2: Building Envoy with Bazel..."
echo ""
cd ../../../..
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

echo ""
echo "========================================"
echo "✅ BUILD COMPLETE - V2_BUFFERED_READ_FIX"
echo "========================================"
echo ""
echo "Binary location:"
echo "  ./bazel-bin/source/exe/envoy-static"
echo ""
echo "To verify the new version is running, look for these log markers:"
echo "  🔵 V2_BUFFERED_READ_FIX socket callbacks set"
echo "  🔵 V2_BUFFERED_READ_FIX doRead() called"
echo "  🔵 V2_FIX: Checking for buffered application data"
echo ""
echo "Test with:"
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l info"
echo ""

