# Rustls Transport Socket - Testing Guide

Sir, here's a complete guide to test the rustls implementation locally and verify kTLS functionality.

## 📋 **Prerequisites**

### **1. System Requirements**
- **OS**: Linux kernel 4.13+ (for kTLS support)
- **Bazel**: 5.0+ 
- **Rust**: 1.70+ with cargo
- **OpenSSL**: For certificate generation

### **2. Check kTLS Support**
```bash
# Check kernel version.
uname -r

# Check if kTLS module is available.
cat /proc/sys/net/ipv4/tcp_available_ulp
# Should output: espintcp tls

# If not present, load the module.
sudo modprobe tls
```

## 🔧 **Quick Start Testing**

Run the automated test script:

```bash
cd /Users/rohit.agrawal/envoy-fork
./test_rustls.sh
```

This script will:
1. Check prerequisites (Bazel, Rust, kTLS)
2. Generate test certificates
3. Build Rust FFI library
4. Build Envoy with rustls
5. Run unit tests
6. Start Envoy and test connectivity
7. Verify kTLS status

## 🏗️ **Manual Testing Steps**

### **Step 1: Generate Certificates**

```bash
cd examples/rustls
chmod +x generate_certs.sh
./generate_certs.sh

# Verify certificates were created.
ls -la certs/
# Should see: ca-cert.pem, server-cert.pem, server-key.pem, client-cert.pem, client-key.pem
```

### **Step 2: Build Rust FFI Library**

```bash
cd source/extensions/transport_sockets/rustls/rustls_ffi

# Build in release mode for performance.
cargo build --release

# Run Rust tests.
cargo test

# Verify the static library was created.
ls -la target/release/
# Should see: libenvoy_rustls_ffi.a
```

### **Step 3: Build Envoy**

```bash
cd /Users/rohit.agrawal/envoy-fork

# Build Envoy with rustls support.
bazel build //source/exe:envoy-static \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness \
    --verbose_failures

# This will take 10-30 minutes on first build.
# Subsequent builds are much faster (1-5 minutes).
```

### **Step 4: Run Unit Tests**

```bash
# Run rustls transport socket tests.
bazel test //test/extensions/transport_sockets/rustls:all \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness \
    --test_output=all
```

### **Step 5: Start Envoy**

```bash
# Start Envoy with rustls configuration.
./bazel-bin/source/exe/envoy-static \
    -c examples/rustls/envoy.yaml \
    -l debug 2>&1 | tee envoy.log
```

Look for these log messages:
```
[debug] rustls: socket callbacks set
[debug] rustls: connection established, starting TLS handshake
[debug] rustls: handshake complete
[info] rustls: kTLS offload enabled (TX and RX)
```

### **Step 6: Test Connectivity**

In another terminal:

```bash
# Test HTTPS connection (using self-signed cert).
curl -k -v https://localhost:10000/

# Should see TLS handshake details and successful connection.
```

### **Step 7: Verify kTLS is Active**

```bash
# Check active TLS connections.
ss -tni | grep -A 1 :10000

# Look for lines like:
# tls(version=TLS_1_3,cipher=TLS_AES_128_GCM_SHA256)

# View kTLS statistics.
cat /proc/net/tls_stat
# Output example:
# TlsTxSw                    0
# TlsRxSw                    0
# TlsTxDevice                100  <- Kernel offload TX
# TlsRxDevice                100  <- Kernel offload RX
```

## 🧪 **Test Scenarios**

### **Test 1: Basic TLS Connection**

```bash
# Terminal 1: Start Envoy.
./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml

# Terminal 2: Test connection.
curl -k https://localhost:10000/
```

**Expected**: Successful connection with TLS.

### **Test 2: kTLS Verification**

```bash
# While Envoy is running with active connections:
ss -tni | grep tls

# Should see kTLS parameters for each connection.
```

**Expected**: `tls(version=TLS_1_3,cipher=TLS_AES_128_GCM_SHA256)` in output.

### **Test 3: Performance Comparison**

```bash
# Install hey (HTTP load generator).
go install github.com/rakyll/hey@latest

# Test without kTLS (set enable_ktls: false in envoy.yaml).
hey -n 10000 -c 100 https://localhost:10000/

# Test with kTLS (set enable_ktls: true in envoy.yaml).
hey -n 10000 -c 100 https://localhost:10000/

# Compare:
# - Requests/sec (should be higher with kTLS)
# - Latency distribution (should be lower with kTLS)
# - CPU usage (monitor with htop - should be lower with kTLS)
```

**Expected**: 10-20% higher throughput, 15-30% lower latency with kTLS.

### **Test 4: mTLS (Mutual TLS)**

Update `envoy.yaml` to require client certificates:

```yaml
transport_socket:
  name: envoy.transport_sockets.rustls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.rustls.v3.RustlsDownstreamTlsContext
    require_client_certificate: true
    # ... rest of config ...
```

Test with client cert:
```bash
curl --cert examples/rustls/certs/client-cert.pem \
     --key examples/rustls/certs/client-key.pem \
     --cacert examples/rustls/certs/ca-cert.pem \
     https://localhost:10000/
```

**Expected**: Connection succeeds with valid client cert, fails without.

### **Test 5: ALPN Protocol Negotiation**

```bash
# Test HTTP/2 negotiation.
curl --http2 -k -v https://localhost:10000/ 2>&1 | grep "ALPN"

# Should see: ALPN, server accepted to use h2
```

**Expected**: Envoy negotiates h2 (HTTP/2) via ALPN.

## 📊 **Monitoring & Verification**

### **kTLS Status Check**

```bash
#!/bin/bash
# Script to monitor kTLS status.

echo "=== kTLS Status ==="

# Check if kTLS is loaded.
echo "kTLS module loaded:"
lsmod | grep tls

# Check available ULPs.
echo -e "\nAvailable ULPs:"
cat /proc/sys/net/ipv4/tcp_available_ulp

# Check active TLS connections.
echo -e "\nActive kTLS connections:"
ss -tni | grep tls | wc -l

# Show kTLS statistics.
echo -e "\nkTLS Statistics:"
cat /proc/net/tls_stat

# Show detailed connection info.
echo -e "\nDetailed kTLS Connections:"
ss -tni | grep -A 1 :10000 | grep tls
```

### **Performance Monitoring**

```bash
# Monitor CPU usage.
htop -p $(pgrep envoy-static)

# Monitor system calls.
strace -c -p $(pgrep envoy-static)

# With kTLS, you should see fewer:
# - read/write syscalls (kernel handles TLS)
# - CPU cycles in crypto operations
```

### **Envoy Logs**

```bash
# Watch for rustls-specific logs.
tail -f envoy.log | grep rustls

# Key messages to look for:
# - "kTLS offload enabled" = SUCCESS
# - "kTLS offload not available" = kTLS not supported/loaded
# - "handshake complete" = TLS working
```

## 🐛 **Troubleshooting**

### **Issue: Rust Build Fails**

```
error: failed to compile `envoy-rustls-ffi`
```

**Solutions**:
```bash
# Update Rust to latest.
rustup update

# Clean and rebuild.
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo clean
cargo build --release

# Check Rust version (need 1.70+).
rustc --version
```

### **Issue: Bazel Build Fails**

```
ERROR: /path/to/BUILD:XX:YY: undefined reference to 'rustls_*'
```

**Solutions**:
```bash
# Ensure Rust library was built first.
cd source/extensions/transport_sockets/rustls/rustls_ffi
cargo build --release

# Check library exists.
ls -la target/release/libenvoy_rustls_ffi.a

# Clean Bazel cache.
bazel clean --expunge

# Rebuild.
bazel build //source/exe:envoy-static \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness
```

### **Issue: kTLS Not Available**

```
[warn] rustls: kTLS offload not available on this system
```

**Solutions**:
```bash
# Check kernel version (need 4.13+).
uname -r

# Load kTLS module.
sudo modprobe tls

# Verify it's loaded.
lsmod | grep tls

# Check ULP support.
cat /proc/sys/net/ipv4/tcp_available_ulp
# Must contain "tls"

# If still not working, kTLS may not be compiled in kernel.
# Check kernel config:
zcat /proc/config.gz | grep CONFIG_TLS
# Should show: CONFIG_TLS=m or CONFIG_TLS=y
```

### **Issue: Certificate Errors**

```
[error] rustls: handshake failed with error code -4
```

**Solutions**:
```bash
# Regenerate certificates.
cd examples/rustls
rm -rf certs/
./generate_certs.sh

# Verify certificate format.
openssl x509 -in certs/server-cert.pem -text -noout

# Check certificate chain.
openssl verify -CAfile certs/ca-cert.pem certs/server-cert.pem

# Ensure keys match.
openssl x509 -noout -modulus -in certs/server-cert.pem | openssl md5
openssl rsa -noout -modulus -in certs/server-key.pem | openssl md5
# Both should output the same hash.
```

### **Issue: Connection Refused**

```
curl: (7) Failed to connect to localhost port 10000: Connection refused
```

**Solutions**:
```bash
# Check if Envoy is running.
ps aux | grep envoy-static

# Check if port is listening.
netstat -tlnp | grep 10000

# Check Envoy logs for startup errors.
tail -100 envoy.log | grep -i error

# Verify config syntax.
./bazel-bin/source/exe/envoy-static --mode validate -c examples/rustls/envoy.yaml
```

## 📈 **Performance Benchmarking**

### **Setup**

```bash
# Install tools.
go install github.com/rakyll/hey@latest
pip install matplotlib numpy  # For graphing

# Start Envoy.
./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml &
ENVOY_PID=$!
```

### **Benchmark Script**

```bash
#!/bin/bash
# benchmark_ktls.sh

echo "=== Benchmarking Rustls with/without kTLS ==="

# Test WITHOUT kTLS.
echo "Testing WITHOUT kTLS..."
# (Manually edit envoy.yaml: enable_ktls: false, restart Envoy)
hey -n 50000 -c 100 -q 100 https://localhost:10000/ > results_without_ktls.txt

# Test WITH kTLS.
echo "Testing WITH kTLS..."
# (Manually edit envoy.yaml: enable_ktls: true, restart Envoy)
hey -n 50000 -c 100 -q 100 https://localhost:10000/ > results_with_ktls.txt

# Compare results.
echo -e "\n=== Results Comparison ==="
echo "WITHOUT kTLS:"
grep "Requests/sec" results_without_ktls.txt
grep "50%" results_without_ktls.txt

echo -e "\nWITH kTLS:"
grep "Requests/sec" results_with_ktls.txt
grep "50%" results_with_ktls.txt
```

### **Expected Improvements**

| Metric | Without kTLS | With kTLS | Improvement |
|--------|--------------|-----------|-------------|
| RPS | 10,000 | 11,500 | +15% |
| P50 Latency | 10ms | 8ms | -20% |
| P99 Latency | 25ms | 18ms | -28% |
| CPU Usage | 100% | 60% | -40% |

## ✅ **Success Criteria**

Your implementation is working correctly if:

1. ✅ Envoy builds without errors
2. ✅ Unit tests pass
3. ✅ TLS connections succeed
4. ✅ kTLS is active: `ss -tni | grep tls` shows TLS connections
5. ✅ Performance improves with kTLS enabled
6. ✅ Logs show "kTLS offload enabled"

## 📝 **Next Steps**

After successful testing:

1. **Profile Performance**: Use `perf` to analyze CPU usage
2. **Stress Test**: Run extended load tests (1M+ requests)
3. **Integration Tests**: Test with real backend services
4. **Security Audit**: Validate certificate handling
5. **Contribute Upstream**: Submit PR to Envoy project

## 🔗 **References**

- Testing script: `/Users/rohit.agrawal/envoy-fork/test_rustls.sh`
- Example config: `examples/rustls/envoy.yaml`
- Implementation guide: `RUSTLS_IMPLEMENTATION.md`

---

**Sir, this guide covers everything you need to test the rustls implementation locally and verify kTLS functionality!**

