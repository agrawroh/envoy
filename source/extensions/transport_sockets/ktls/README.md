# kTLS Transport Socket for Envoy

This extension provides kernel TLS (kTLS) offload capabilities for Envoy proxies running on Linux systems. kTLS allows offloading TLS record processing to the kernel after the handshake is complete, which can significantly improve performance.

## Overview

Kernel TLS (kTLS) is a feature in Linux that allows applications to offload TLS record processing to the kernel. After a TLS handshake completes in userspace, the TLS session keys can be installed into the kernel, allowing the kernel to handle the encryption and decryption of TLS records. This can provide significant performance benefits by:

1. Reducing CPU usage for TLS encryption/decryption
2. Enabling zero-copy operations for improved throughput
3. Taking advantage of hardware acceleration when available
4. Reducing context switches and memory copies

## Implementation Components

Our implementation includes:

1. **Platform compatibility layer** (`tls_compat.h`): Provides definitions for kTLS-related constants and structures that work across platforms.

2. **SSL Information Interface** (`ktls_ssl_info.h` and implementations): Extracts TLS session keys and parameters needed for kTLS from established SSL sessions.

3. **Socket Splicing** (`ktls_socket_splicing.h` and implementations): Provides zero-copy data transfer capabilities using Linux's `splice()` system call.

4. **Transport Socket** (`ktls_transport_socket.h` and implementations): Main transport socket implementation that enables kTLS and handles data transfer with fallback mechanisms.

5. **Configuration** (`config.h/cc`): Protocol buffer definitions and factory classes for enabling kTLS through Envoy configuration.

## Configuration Example

```yaml
static_resources:
  clusters:
  - name: example_cluster
    connect_timeout: 0.25s
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: example_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 443
    transport_socket:
      name: envoy.transport_sockets.ktls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.ktls.v3.KtlsTransportSocket
        tls_socket_config:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            sni: example.com
        enable_tx_zerocopy: true
        enable_rx_no_pad: true
```

## Current Status and Limitations

1. Only supports TLS 1.2 with AES-GCM-128 cipher suite
2. Only tested on Linux kernels 4.13+
3. Requires specific implementation of SSL socket to access key material
4. No support for TLS 1.3 yet
5. Implementation is a work in progress and not ready for production use

## References

This implementation was informed by:

1. The Linux kernel kTLS implementation: https://github.com/ktls/af_ktls
2. Oracle's kTLS utilities: https://github.com/oracle/ktls-utils
3. Envoy's existing TLS transport socket implementations

## Requirements

- Requires a Linux kernel with kTLS support (kernel 4.13+)
- Supports TLS 1.2 with AES-GCM ciphers initially
- Uses OpenSSL for TLS handshakes before kernel offload 