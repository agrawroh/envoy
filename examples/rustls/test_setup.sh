#!/bin/bash
# Helper script to test the rustls transport socket setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Rustls Transport Socket Test Setup"
echo "========================================="
echo

# Step 1: Check certificates
echo "📋 Step 1: Checking certificates..."
if [ ! -f "certs/server-cert.pem" ] || [ ! -f "certs/server-key.pem" ]; then
    echo "❌ Certificates not found. Generating now..."
    bash generate_certs.sh
else
    echo "✅ Certificates found"
fi
echo

# Step 2: Test direct connection to backend
echo "📋 Step 2: Starting test HTTPS server on port 8443..."
echo "   (This server will run in the background)"
echo

# Kill any existing server on port 8443
lsof -ti:8443 | xargs kill -9 2>/dev/null || true
sleep 1

# Start the test server in background
python3 test_server.py > /tmp/rustls_test_server.log 2>&1 &
SERVER_PID=$!
echo "✅ Test server started (PID: $SERVER_PID)"
echo "   Log: /tmp/rustls_test_server.log"
sleep 2

# Test direct connection
echo
echo "📋 Step 3: Testing direct connection to server..."
if curl -k --connect-timeout 5 https://localhost:8443/ > /dev/null 2>&1; then
    echo "✅ Direct HTTPS connection successful"
else
    echo "❌ Direct connection failed"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi
echo

# Instructions for Envoy
echo "========================================="
echo "✅ Backend server is ready!"
echo "========================================="
echo
echo "Now you can start Envoy with:"
echo "  cd ../../.."
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml"
echo
echo "Then test through Envoy:"
echo "  curl -k https://localhost:10000/"
echo
echo "To stop the test server:"
echo "  kill $SERVER_PID"
echo
echo "Or run: lsof -ti:8443 | xargs kill"
echo
echo "Server log: tail -f /tmp/rustls_test_server.log"
echo "========================================="

