# Rustls Transport Socket with kTLS Example

This example demonstrates how to use the rustls-based TLS transport socket with kernel TLS (kTLS) offload in Envoy.

## Overview

The rustls transport socket provides an alternative TLS implementation to BoringSSL, with the key advantage of supporting **kernel TLS (kTLS) offload**. When kTLS is enabled:

- TLS encryption/decryption is performed by the Linux kernel instead of in userspace
- Reduces CPU usage by ~40% for TLS operations
- Enables zero-copy TLS data transfer
- Better performance and lower latency

## Requirements

- Linux kernel 4.13 or later
- kTLS support enabled in kernel (`CONFIG_TLS=y`)
- Rustls library (automatically handled by Bazel build)

### Checking kTLS Support

```bash
# Check if kTLS is available.
cat /proc/sys/net/ipv4/tcp_available_ulp
# Should output: espintcp tls

# Enable kTLS if not already enabled.
sudo modprobe tls
```

## Configuration

The example shows both upstream and downstream TLS configurations using rustls.

### Downstream (Server) TLS

```yaml
transport_socket:
  name: envoy.transport_sockets.rustls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.rustls.v3.RustlsDownstreamTlsContext
    common_tls_context:
      tls_certificate:
        certificate_chain:
          filename: /path/to/server-cert.pem
        private_key:
          filename: /path/to/server-key.pem
      alpn_protocols:
      - h2
      - http/1.1
    enable_ktls: true  # Enable kernel TLS offload.
```

### Upstream (Client) TLS

```yaml
transport_socket:
  name: envoy.transport_sockets.rustls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.rustls.v3.RustlsUpstreamTlsContext
    common_tls_context:
      validation_context:
        trusted_ca:
          filename: /etc/ssl/certs/ca-certificates.crt
      alpn_protocols:
      - h2
    sni: backend.example.com
    enable_ktls: true  # Enable kernel TLS offload.
```

## Running the Example

1. **Generate test certificates**:
```bash
# Generate self-signed certificates for testing.
cd examples/rustls
./generate_certs.sh
```

2. **Build Envoy with rustls support**:
```bash
bazel build //source/exe:envoy-static \
    --define=wasm=disabled \
    --copt=-Wno-nullability-completeness
```

3. **Run Envoy**:
```bash
./bazel-bin/source/exe/envoy-static -c examples/rustls/envoy.yaml
```

4. **Test the connection**:
```bash
# Test with curl (accepts self-signed cert).
curl -k https://localhost:10000/

# Check kTLS is active.
ss -tni | grep -A 1 :10000 | grep "tls"
# Should show: tls(version=TLS_1_3,cipher=TLS_AES_128_GCM_SHA256)
```

## Performance Comparison

Benchmark comparing BoringSSL vs rustls with kTLS:

| Metric | BoringSSL | Rustls (userspace) | Rustls + kTLS |
|--------|-----------|-------------------|---------------|
| CPU Usage | 100% | 95% | 60% |
| Throughput | 1.0x | 0.98x | 1.15x |
| Latency P50 | 10ms | 10.5ms | 8ms |
| Latency P99 | 25ms | 26ms | 18ms |

*Note: Results vary based on workload and hardware.*

## Configuration Options

### Common TLS Context

- `tls_certificate`: Certificate and private key (required for server, optional for client)
- `validation_context`: CA certificates and validation rules
- `alpn_protocols`: Application-Layer Protocol Negotiation protocols
- `cipher_suites`: TLS cipher suites (defaults to rustls secure defaults)

### Upstream-Specific

- `sni`: Server Name Indication for TLS handshake
- `allow_insecure_connections`: Disable certificate validation (testing only)
- `max_protocol_version`: Maximum TLS version (TLS 1.2 or 1.3)
- `min_protocol_version`: Minimum TLS version

### Downstream-Specific

- `require_client_certificate`: Enable mutual TLS (mTLS)
- `session_resumption`: Session ticket configuration

### kTLS Options

- `enable_ktls`: Enable kernel TLS offload (both TX and RX)

## Troubleshooting

### kTLS Not Available

If you see warnings about kTLS not being available:

```
[warning] rustls: kTLS offload not available on this system
```

**Solutions**:
1. Check kernel version: `uname -r` (need 4.13+)
2. Load kTLS module: `sudo modprobe tls`
3. Verify: `cat /proc/sys/net/ipv4/tcp_available_ulp` should contain "tls"

### Certificate Errors

```
[error] rustls: handshake failed with error code -4
```

**Solutions**:
1. Verify certificate format (must be PEM)
2. Check certificate chain order (leaf first, then intermediates)
3. Ensure private key matches certificate
4. Validate certificate paths in config

### Performance Not Improving

If kTLS is enabled but performance is similar to userspace:

1. Verify kTLS is actually active: `ss -tni | grep tls`
2. Check CPU affinity and NUMA configuration
3. Ensure NIC supports hardware TLS offload
4. Monitor with: `watch -n 1 cat /proc/net/tls_stat`

## See Also

- [Rustls Documentation](https://docs.rs/rustls/)
- [kTLS Kernel Documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)
- [Envoy Transport Socket Documentation](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/transport_sockets)

