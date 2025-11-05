#!/bin/bash
# Final kTLS rebuild with TCP ULP fix

set -e

echo "=========================================="
echo "kTLS Final Fix - TCP ULP + Fallback"
echo "=========================================="
echo

# Step 1: Rebuild Rust FFI
echo "🦀 Rebuilding Rust FFI library..."
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release
echo "✅ Rust FFI build complete!"
echo

# Step 2: Rebuild Envoy
echo "🏗️  Rebuilding Envoy..."
cd /Users/rohit.agrawal/envoy-fork
bazel build //source/exe:envoy-static \
  --define=wasm=disabled \
  --copt=-Wno-nullability-completeness
echo "✅ Envoy build complete!"
echo

echo "=========================================="
echo "✅ Build Complete!"
echo "=========================================="
echo
echo "📝 Next Steps:"
echo
echo "1. Check if kTLS kernel module is loaded:"
echo "   lsmod | grep tls"
echo
echo "2. If not loaded, load it:"
echo "   sudo modprobe tls"
echo
echo "3. Test:"
echo "   # Terminal 1: cd examples/rustls && python3 test_server.py"
echo "   # Terminal 2: ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml -l debug"
echo "   # Terminal 3: curl -vvv -k https://localhost:10000/"
echo
echo "Expected Results:"
echo "  - If tls module loaded: kTLS will work (kernel offload)"
echo "  - If tls module NOT loaded: Userspace TLS will work (no hang!)"
echo
echo "See KTLS_TCP_ULP_FIX.md for complete details!"
echo

