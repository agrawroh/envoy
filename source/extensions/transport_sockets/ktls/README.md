# kTLS Transport Socket

This extension provides kernel TLS (kTLS) offload capability for TLS connections in Envoy.

## Overview

The kTLS transport socket offloads TLS encryption and decryption to the kernel after handshake completion. This can significantly improve performance by leveraging hardware offload capabilities (where available) and reducing user-space <-> kernel-space data copies.

## Architecture

The kTLS transport socket is a passthrough transport socket that wraps another TLS transport socket (typically BoringSSL). It performs the following key functions:

1. Delegates the TLS handshake to the wrapped TLS transport socket
2. Once the handshake is complete, configures the kernel to perform TLS encryption/decryption on the socket
3. Manages the lifecycle of the kTLS-enabled socket, including handling lazy handshakes

## Lazy Handshake Handling

TLS handshakes in Envoy happen lazily, typically during the first data exchange rather than immediately after connection establishment. The kTLS socket handles this through:

1. A sophisticated handshake detection system that examines multiple indicators:
   - Checking cipher and TLS version information
   - Looking for peer certificate status
   - Examining session ID and SSL state
   - Verifying SSL crypto parameters

2. A progressive retry mechanism with exponential backoff:
   - Starting at 10ms delay and doubling with each attempt (capped at reasonable maximum)
   - Using Envoy's timer system for proper scheduling
   - Adaptive delays based on connection lifecycle
   - Limited maximum retry attempts (5 by default)

3. Operation buffering during handshake:
   - Pausing read/write operations until kTLS readiness is determined
   - Initiating handshake operations during reads/writes
   - Handling completion events during buffered operations
   - Processing buffered operations once kTLS status is determined

## Key Material Extraction

For kTLS to work properly, the implementation needs to extract key material from the TLS connection and configure the kernel to use it. This is done through:

1. Obtaining the TLS session object from OpenSSL
2. Extracting master key, client random, and server random
3. Deriving key block material using TLS 1.2 PRF (Pseudorandom Function)
4. Separating keys, IVs, and salts for both client and server directions
5. Configuring the socket with the appropriate crypto information

## Supported Ciphers and Versions

Currently, the kTLS implementation supports:
- TLS 1.2 only
- AES-128-GCM cipher suites only

This is a limitation of the kernel's kTLS implementation and most hardware offload capabilities.

## Usage

To enable kTLS in your Envoy configuration, use the "ktls" transport socket with appropriate options. Here's an example configuration:

```yaml
transport_socket:
  name: ktls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.ktls.v3.KtlsSocket
    transport_socket:
      name: tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          tls_certificates:
            - certificate_chain: { filename: "cert.pem" }
              private_key: { filename: "key.pem" }
        sni: example.com
    enable_tx_zerocopy: true
    enable_rx_no_pad: true
```

## Troubleshooting

If kTLS is not being enabled as expected, check for the following:

1. Ensure the cipher suite negotiated is supported (check logs for "Unsupported cipher suite for kTLS")
2. Verify TLS version is 1.2 (check logs for "Unsupported TLS version for kTLS")
3. Check if the handshake is actually completing (debug logs will show handshake state details)
4. Verify the platform has kTLS support in the kernel (required Linux 5.3+ for TX, 5.9+ for RX)
5. Examine the retry attempts and their frequency in debug logs
6. Check for cryptographic material extraction errors in debug logs

## Debugging Tips

Set the logging level to DEBUG or TRACE for the `connection` tag to see detailed information about:
- Handshake state detection
- Key material extraction
- Retry scheduling and state transitions
- Buffer operation handling
- kTLS enablement status

## Hardware Offload

On platforms with compatible NICs (like Mellanox/NVIDIA ConnectX-6 Dx or newer), kTLS can leverage hardware offload for even better performance. Ensure the appropriate NIC drivers are installed and properly configured.

## Implementation Components

Our implementation includes:

1. **Platform compatibility layer** (`tls_compat.h`): Provides definitions for kTLS-related constants and structures that work across platforms.

2. **SSL Information Interface** (`ktls_ssl_info.h` and implementations): Extracts TLS session keys and parameters needed for kTLS from established SSL sessions.

3. **Socket Splicing** (`ktls_socket_splicing.h` and implementations): Provides zero-copy data transfer capabilities using Linux's `splice()` system call.

4. **Transport Socket** (`ktls_transport_socket.h` and implementations): Main transport socket implementation that enables kTLS and handles data transfer with fallback mechanisms.

5. **Socket Interface** (`ktls_socket_interface.h` and implementations): Provides a custom socket interface with kTLS support. This should be used through the bootstrap extensions.

6. **Configuration** (`config.h/cc`): Protocol buffer definitions and factory classes for enabling kTLS through Envoy configuration.

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

# Enable kTLS socket interface via bootstrap extension
bootstrap_extensions:
  - name: envoy.extensions.network.socket_interface.ktls_socket_interface
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.network.socket_interface.v3.KTlsSocketInterface
      enabled: true
      enable_tx_zerocopy: true
      enable_rx_no_pad: true
```

## Current Status and Limitations

1. Only supports TLS 1.2 with AES-GCM-128 cipher suite
2. Only tested on Linux kernels 4.13+
3. Requires specific implementation of SSL socket to access key material
4. No support for TLS 1.3 yet

## Implementation Notes

1. The kTLS socket interface implementation has been consolidated in the `source/extensions/transport_sockets/ktls` directory. The duplicate implementation in `source/common/network/ktls` is deprecated and will be removed.
2. Socket interface and transport socket are configured separately but work together. The socket interface creates socket handles that are kTLS-capable, while the transport socket handles the TLS handshake and offloading.

## References

This implementation was informed by:

1. The Linux kernel kTLS implementation: https://github.com/ktls/af_ktls
2. Oracle's kTLS utilities: https://github.com/oracle/ktls-utils
3. Envoy's existing TLS transport socket implementations

## Requirements

- Requires a Linux kernel with kTLS support (kernel 4.13+)
- Supports TLS 1.2 with AES-GCM ciphers initially
- Uses OpenSSL for TLS handshakes before kernel offload 