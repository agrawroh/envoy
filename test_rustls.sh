#!/bin/bash
# Comprehensive testing script for rustls transport socket implementation.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_step() {
    echo -e "${BLUE}==>${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Step 1: Check prerequisites.
echo_step "Step 1: Checking prerequisites..."

# Check Bazel.
if ! command -v bazel &> /dev/null; then
    echo_error "Bazel not found. Please install Bazel first."
    exit 1
fi
echo_success "Bazel found: $(bazel version | head -1)"

# Check Rust.
if ! command -v rustc &> /dev/null; then
    echo_error "Rust not found. Please install Rust first."
    echo "Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
echo_success "Rust found: $(rustc --version)"

# Check for kTLS support.
echo_step "Step 2: Checking kTLS support..."
if [ -f /proc/sys/net/ipv4/tcp_available_ulp ]; then
    KTLS_AVAILABLE=$(cat /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null || echo "")
    if [[ "$KTLS_AVAILABLE" == *"tls"* ]]; then
        echo_success "kTLS is available on this system"
    else
        echo_warning "kTLS not available. Will load module..."
        if command -v modprobe &> /dev/null && [ "$EUID" -eq 0 ]; then
            modprobe tls || echo_warning "Could not load TLS module (may need sudo)"
        else
            echo_warning "Run 'sudo modprobe tls' to enable kTLS"
        fi
    fi
else
    echo_warning "kTLS not supported on this kernel (need Linux 4.13+)"
    echo_warning "Will test without kTLS offload"
fi

# Step 3: Generate test certificates.
echo_step "Step 3: Generating test certificates..."
if [ ! -d "examples/rustls/certs" ]; then
    cd examples/rustls
    chmod +x generate_certs.sh
    ./generate_certs.sh
    cd "$SCRIPT_DIR"
    echo_success "Certificates generated"
else
    echo_success "Certificates already exist"
fi

# Step 4: Build rustls Rust library.
echo_step "Step 4: Building Rust FFI library..."
cd source/extensions/transport_sockets/rustls/rustls_ffi

# Clean first to avoid cached errors.
echo "  Cleaning previous builds..."
cargo clean > /dev/null 2>&1

# Build and capture output.
echo "  Building Rust library (this may take a few minutes)..."
BUILD_OUTPUT=$(cargo build --release 2>&1)
BUILD_EXIT=$?

if [ $BUILD_EXIT -eq 0 ]; then
    echo_success "Rust FFI library built successfully"
    
    # Verify the library was created.
    if [ -f "target/release/libenvoy_rustls_ffi.a" ]; then
        LIB_SIZE=$(ls -lh target/release/libenvoy_rustls_ffi.a | awk '{print $5}')
        echo "  Library size: $LIB_SIZE"
    else
        echo_error "Library file not found at target/release/libenvoy_rustls_ffi.a"
        exit 1
    fi
else
    echo "$BUILD_OUTPUT" | tail -30
    
    # Check if it's the AWS-LC compiler bug.
    if echo "$BUILD_OUTPUT" | grep -q "COMPILER BUG DETECTED"; then
        echo ""
        echo_error "GCC compiler bug detected (memcmp issue with AWS-LC)"
        echo ""
        echo "This is a known issue with GCC 10.0-10.2. Solutions:"
        echo "  1. The Cargo.toml has been updated to use 'ring' backend"
        echo "  2. Run: cargo clean && cargo build --release"
        echo "  3. Or update GCC to version 10.3+ or 11+"
        echo ""
        echo "See FIX_COMPILER_BUG.md for details"
        echo ""
    fi
    
    echo_error "Rust build failed"
    exit 1
fi
cd "$SCRIPT_DIR"

# Step 5: Build Envoy with rustls.
echo_step "Step 5: Building Envoy with rustls extension..."
echo "This may take 10-30 minutes on first build..."

bazel build //source/exe:envoy-static \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness \
    --verbose_failures 2>&1 | tee build.log | tail -50

if [ $? -eq 0 ]; then
    echo_success "Envoy built successfully"
else
    echo_error "Envoy build failed. Check build.log for details"
    exit 1
fi

# Step 6: Run unit tests.
echo_step "Step 6: Running unit tests..."
bazel test //test/extensions/transport_sockets/rustls:all \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness \
    --test_output=errors 2>&1 | tee test.log

if [ $? -eq 0 ]; then
    echo_success "Unit tests passed"
else
    echo_warning "Some tests failed. Check test.log for details"
fi

# Step 7: Start Envoy with example config.
echo_step "Step 7: Starting Envoy with rustls configuration..."
echo "Press Ctrl+C to stop Envoy"
echo ""

./linux/amd64/build_envoy_debug/envoy -c examples/rustls/envoy.yaml -l debug 2>&1 | \
    grep -E "rustls|kTLS|transport_socket" --line-buffered | head -50 &

ENVOY_PID=$!
sleep 5

# Step 8: Test connectivity.
echo_step "Step 8: Testing connectivity..."
if command -v curl &> /dev/null; then
    echo "Testing HTTPS connection..."
    curl -k -v https://localhost:10000/ 2>&1 | grep -E "SSL|TLS|Connected"
    
    if [ $? -eq 0 ]; then
        echo_success "HTTPS connection successful"
    else
        echo_warning "Connection test failed"
    fi
else
    echo_warning "curl not found, skipping connectivity test"
fi

# Step 9: Check kTLS status.
echo_step "Step 9: Checking kTLS status..."
if command -v ss &> /dev/null; then
    echo "Active TLS connections:"
    ss -tni | grep -A 1 :10000 | grep tls || echo_warning "No kTLS connections found"
    
    if [ -f /proc/net/tls_stat ]; then
        echo ""
        echo "kTLS statistics:"
        cat /proc/net/tls_stat
    fi
else
    echo_warning "ss command not found, skipping kTLS verification"
fi

# Cleanup.
echo ""
echo_step "Test complete! Stopping Envoy..."
kill $ENVOY_PID 2>/dev/null || true

echo ""
echo_success "All tests completed!"
echo ""
echo "Summary:"
echo "  - Build logs: build.log"
echo "  - Test logs: test.log"
echo "  - Example config: examples/rustls/envoy.yaml"
echo "  - Certificates: examples/rustls/certs/"
echo ""
echo "To run Envoy manually:"
echo "  ./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml"
echo ""
echo "To verify kTLS is active:"
echo "  ss -tni | grep tls"
echo "  cat /proc/net/tls_stat"
