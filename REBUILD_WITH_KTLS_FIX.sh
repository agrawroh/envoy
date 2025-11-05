#!/bin/bash
set -e

echo "=============================================="
echo "  kTLS FD Fix - Full Rebuild"
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "Step 1: Kill existing Envoy processes..."
pkill -f "envoy-static" || true
pkill -f "envoy" || true
sleep 1
echo "✓ Envoy processes killed."

echo ""
echo "Step 2: Rebuilding Rust FFI library..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
rm -rf target/
echo "  Building release version..."
cargo build --release

if [ ! -f "target/release/libenvoy_rustls_ffi.a" ]; then
    echo "❌ ERROR: Rust library not built!"
    exit 1
fi

echo "  ✓ Rust FFI library built successfully:"
ls -lh target/release/libenvoy_rustls_ffi.a

cd "$SCRIPT_DIR"

echo ""
echo "Step 3: Cleaning Bazel cache..."
bazel clean --expunge
echo "  ✓ Bazel cache cleaned."

echo ""
echo "Step 4: Rebuilding Envoy with kTLS FD fix..."
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

if [ ! -f "./bazel-bin/source/exe/envoy-static" ]; then
    echo "❌ ERROR: Envoy binary not built!"
    exit 1
fi

echo "  ✓ Envoy built successfully:"
ls -lh ./bazel-bin/source/exe/envoy-static

echo ""
echo "Step 5: Verifying symbols in binary..."
nm ./bazel-bin/source/exe/envoy-static | grep -E "(rustls_connection_set_fd|rustls_enable_ktls)" || echo "  ⚠ Warning: Some symbols not found"

echo ""
echo "=============================================="
echo "  Build Complete!"
echo "=============================================="
echo ""
echo "To test kTLS:"
echo ""
echo "1. Start backend server:"
echo "   cd examples/rustls && python3 test_server.py"
echo ""
echo "2. In another terminal, start Envoy:"
echo "   ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l debug"
echo ""
echo "3. In another terminal, test the connection:"
echo "   curl -k --http1.1 https://localhost:10000/"
echo ""
echo "4. Check logs for kTLS enablement:"
echo "   - Look for 'Setting file descriptor for kTLS: fd=X'"
echo "   - Look for '[RUST FFI] ✅ kTLS TX enabled successfully'"
echo ""

