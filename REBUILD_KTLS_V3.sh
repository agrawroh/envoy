#!/bin/bash
# Rebuild script for kTLS V3 (Comprehensive Logging Fix)

set -e  # Exit on error

echo "=========================================="
echo "kTLS V3 Rebuild - Comprehensive Logging"
echo "=========================================="
echo

# Determine if we're on Linux or macOS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ENVOY_ROOT="/home/rohit.agrawal/envoy-fork"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    ENVOY_ROOT="/Users/rohit.agrawal/envoy-fork"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

echo "📂 Envoy root: $ENVOY_ROOT"
echo

# Step 1: Rebuild Rust FFI
echo "🦀 Step 1: Rebuilding Rust FFI library..."
cd "$ENVOY_ROOT/source/extensions/transport_sockets/rustls/rustls_ffi"

echo "  🧹 Cleaning previous build..."
cargo clean

echo "  🔨 Building release version..."
cargo build --release

echo "  ✅ Rust FFI build complete!"
echo

# Step 2: Rebuild Envoy
echo "🏗️  Step 2: Rebuilding Envoy..."
cd "$ENVOY_ROOT"

echo "  🔨 Building envoy-static..."
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness

echo "  ✅ Envoy build complete!"
echo

# Step 3: Summary
echo "=========================================="
echo "✅ Build Complete!"
echo "=========================================="
echo
echo "Binary location:"
echo "  $ENVOY_ROOT/bazel-bin/source/exe/envoy-static"
echo
echo "Test commands:"
echo "  # Terminal 1: Backend"
echo "  cd $ENVOY_ROOT/examples/rustls && python3 test_server.py"
echo
echo "  # Terminal 2: Envoy"
echo "  $ENVOY_ROOT/bazel-bin/source/exe/envoy-static \\"
echo "    -c $ENVOY_ROOT/examples/rustls/envoy.yaml -l debug"
echo
echo "  # Terminal 3: Test"
echo "  curl -k --http1.1 https://localhost:10000/"
echo
echo "Look for these success indicators in logs:"
echo "  ✅ rustls: 📤 UNCONDITIONALLY flushing pending TLS data before kTLS"
echo "  ✅ [RUST FFI] 📤 write_tls (server): extracted N bytes"
echo "  ✅ rustls: 🏁 flush complete: X iterations, Y total bytes"
echo "  ✅ [KEY EXTRACT] ✅ Successfully extracted secrets"
echo "  ✅ [KTLS] ✅ setsockopt SUCCESS: kTLS TX enabled"
echo "  ✅ rustls: ✅ kTLS offload enabled (TX and RX)"
echo


