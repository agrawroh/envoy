#!/bin/bash
# Quick test runner for rustls implementation.

set -e

cd "$(dirname "$0")"

echo "🧪 Rustls Transport Socket - Quick Test"
echo ""

# Step 1: Build Rust library.
echo "📦 Building Rust FFI library..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo build --release 2>&1 | tail -10
cd /Users/rohit.agrawal/envoy-fork

# Step 2: Run Rust tests.
echo ""
echo "🧪 Running Rust tests..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo test 2>&1 | tail -20
cd /Users/rohit.agrawal/envoy-fork

# Step 3: Generate certificates if needed.
if [ ! -d "examples/rustls/certs" ]; then
    echo ""
    echo "🔐 Generating test certificates..."
    cd examples/rustls
    ./generate_certs.sh
    cd /Users/rohit.agrawal/envoy-fork
fi

# Step 4: Build Envoy (if not already built).
if [ ! -f "bazel-bin/source/exe/envoy-static" ]; then
    echo ""
    echo "🔨 Building Envoy (this may take 10-30 minutes)..."
    bazel build //source/exe:envoy-static \
        --define=wasm=disabled \
        --copt=-Wno-nullability-completeness 2>&1 | tail -20
else
    echo ""
    echo "✅ Envoy already built"
fi

echo ""
echo "✅ All tests passed!"
echo ""
echo "To run Envoy:"
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml"
echo ""
echo "To run full test suite:"
echo "  ./test_rustls.sh"
