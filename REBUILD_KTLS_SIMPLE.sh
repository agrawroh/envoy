#!/bin/bash
# Simple rebuild script for kTLS FD fix
# Run this on your Linux build machine

set -e

echo "=============================================="
echo "  Rebuilding with kTLS FD Fix"
echo "=============================================="

cd "$(dirname "$0")"

echo ""
echo "Step 1: Rebuilding Rust FFI..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

if [ ! -f "target/release/libenvoy_rustls_ffi.a" ]; then
    echo "❌ Rust library failed to build!"
    exit 1
fi

echo "✓ Rust FFI library rebuilt"
ls -lh target/release/libenvoy_rustls_ffi.a

cd ../../../../

echo ""
echo "Step 2: Rebuilding Envoy..."
bazel clean --expunge
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

echo ""
echo "✓ Build complete!"
echo ""
echo "Envoy binary location:"
ls -lh ./bazel-bin/source/exe/envoy-static

echo ""
echo "=============================================="
echo "Now run Envoy to test kTLS:"
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l debug"
echo "=============================================="

