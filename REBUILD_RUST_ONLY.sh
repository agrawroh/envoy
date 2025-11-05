#!/bin/bash
# Quick rebuild script for Rust FFI changes only

set -e

echo "🦀 Rebuilding Rust FFI library..."
cd source/extensions/transport_sockets/rustls/rustls_ffi

echo "  🧹 Cleaning..."
cargo clean

echo "  🔨 Building release..."
cargo build --release

echo "  ✅ Rust FFI rebuild complete!"
echo ""
echo "Now rebuild Envoy to link the new library:"
echo "  cd /Users/rohit.agrawal/envoy-fork"
echo "  bazel build //source/exe:envoy-static --define=wasm=disabled --copt=-Wno-nullability-completeness"

