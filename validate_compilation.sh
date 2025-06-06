#!/bin/bash

echo "=== Reverse Connection Compilation Validation ==="

# Navigate to envoy root
cd /Users/rohit.agrawal/envoy-fork

echo "1. Testing downstream socket interface library..."
bazel build //source/extensions/network/socket_interface/reverse_connection:downstream_reverse_socket_interface_lib --verbose_failures

if [ $? -eq 0 ]; then
    echo "✅ Downstream socket interface library compiled successfully"
else
    echo "❌ Downstream socket interface library compilation failed"
fi

echo ""
echo "2. Testing listen socket factory library..."
bazel build //source/extensions/network/socket_interface/reverse_connection:reverse_connection_listen_socket_factory_lib --verbose_failures

if [ $? -eq 0 ]; then
    echo "✅ Listen socket factory library compiled successfully"
else
    echo "❌ Listen socket factory library compilation failed"
fi

echo ""
echo "3. Testing integration test..."
bazel build //source/extensions/network/socket_interface/reverse_connection:reverse_connection_integration_test --verbose_failures

if [ $? -eq 0 ]; then
    echo "✅ Integration test compiled successfully"
    echo "Running integration test..."
    bazel test //source/extensions/network/socket_interface/reverse_connection:reverse_connection_integration_test --test_output=summary
    if [ $? -eq 0 ]; then
        echo "✅ Integration test passed"
    else
        echo "❌ Integration test failed"
    fi
else
    echo "❌ Integration test compilation failed"
fi

echo ""
echo "=== Compilation Validation Complete ===" 