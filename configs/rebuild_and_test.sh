#!/bin/bash

set -e

echo "================================================================"
echo "🔧 REBUILDING ENVOY WITH REVERSE CONNECTION FILTER"
echo "================================================================"

# Navigate to build directory
cd "$(dirname "$0")/.."

echo "[INFO] Step 1: Cleaning previous build..."
if [ -d "bazel-bin" ]; then
    rm -rf bazel-bin/source/exe/envoy-static 2>/dev/null || true
fi

echo "[INFO] Step 2: Building Envoy with our reverse connection filter..."
bazel build //source/exe:envoy-static \
    --define=wasm=disabled \
    --define=hot_restart=disabled \
    --config=libc++ \
    --verbose_failures

echo "[INFO] Step 3: Verifying our filter is registered..."
./bazel-bin/source/exe/envoy-static --help-hidden | grep reverse_connection || echo "Filter may not be built in"

echo "[INFO] Step 4: Starting test with rebuilt Envoy..."
cd configs

# Kill any existing processes
pkill -f "envoy-static" 2>/dev/null || true
pkill -f "python3 -m http.server" 2>/dev/null || true
sleep 2

echo "[INFO] Starting backend HTTP server..."
python3 -m http.server 8081 > backend.log 2>&1 &
BACKEND_PID=$!
sleep 2

echo "[INFO] Starting downstream Envoy (with our filter)..."
../bazel-bin/source/exe/envoy-static -c reverse_connection_downstream.yaml -l debug > downstream.log 2>&1 &
DOWNSTREAM_PID=$!
sleep 3

echo "[INFO] Starting upstream Envoy (with terminal filter)..."
../bazel-bin/source/exe/envoy-static -c reverse_connection_upstream.yaml -l debug > upstream.log 2>&1 &
UPSTREAM_PID=$!
sleep 3

echo "[INFO] Testing connection..."
echo "Testing direct backend: $(curl -s -m 5 http://localhost:8081/ | head -c 50)..."
echo "Testing upstream Envoy: $(curl -s -m 5 http://localhost:8080/ | head -c 50)..."

echo "[INFO] Testing reverse tunnel..."
timeout 10 bash -c '
exec 3<>/dev/tcp/localhost/10000
echo "upstream_service" >&3
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3
sleep 1
read -t 5 response <&3
echo "Response: $response"
exec 3<&-
' || echo "Tunnel test failed or timed out"

echo "[INFO] Cleanup..."
kill $BACKEND_PID $DOWNSTREAM_PID $UPSTREAM_PID 2>/dev/null || true

echo "================================================================"
echo "✅ TEST COMPLETE - Check logs for details"
echo "================================================================" 