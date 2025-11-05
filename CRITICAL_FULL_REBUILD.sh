#!/bin/bash

set -e

echo "========================================"
echo "🟢 CRITICAL FULL REBUILD"
echo "========================================"
echo ""
echo "This will:"
echo "1. Clean ALL Rust artifacts"
echo "2. Rebuild Rust library"
echo "3. Clean ALL Bazel artifacts"
echo "4. Rebuild Envoy"
echo "5. Kill any running Envoy processes"
echo ""

cd "$(dirname "$0")"

# Step 1: Kill any running Envoy
echo "Step 1: Killing any running Envoy processes..."
pkill -9 envoy-static || true
pkill -9 envoy || true
sleep 2

# Step 2: Clean Rust
echo ""
echo "Step 2: Cleaning Rust artifacts..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
rm -rf target/
echo "✓ Rust cleaned"

# Step 3: Rebuild Rust
echo ""
echo "Step 3: Building Rust library..."
cargo build --release

if [ ! -f "target/release/libenvoy_rustls_ffi.a" ]; then
  echo "❌ ERROR: Rust library not built!"
  exit 1
fi

echo "✓ Rust library built: $(ls -lh target/release/libenvoy_rustls_ffi.a | awk '{print $5}')"
echo "✓ Timestamp: $(date -r target/release/libenvoy_rustls_ffi.a)"

# Step 4: Clean Bazel
echo ""
echo "Step 4: Cleaning Bazel artifacts..."
cd ../../../../
bazel clean --expunge
echo "✓ Bazel cleaned"

# Step 5: Rebuild Envoy
echo ""
echo "Step 5: Building Envoy..."
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

echo ""
echo "========================================"
echo "✅ REBUILD COMPLETE"
echo "========================================"
echo ""
echo "Binary: ./bazel-bin/source/exe/envoy-static"
echo "Timestamp: $(date -r ./bazel-bin/source/exe/envoy-static)"
echo ""
echo "To verify new code is running, look for:"
echo "  [RUST FFI] 🟢 ABOUT TO ENTER MATCH STATEMENT"
echo ""
echo "Start Envoy with:"
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l info 2>&1 | grep -E '(V2_|RUST FFI|rustls:)'"
echo ""

