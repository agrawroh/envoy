# kTLS Example

This example demonstrates how to use Linux Kernel TLS (kTLS) offloading with Envoy.

## What is kTLS?

kTLS allows TLS encryption and decryption to be offloaded to the Linux kernel instead of handling it in userspace. 
This can improve performance by:
- Reducing CPU usage by leveraging hardware cryptographic acceleration
- Enabling zero-copy writes for encrypted data
- Reducing context switches between kernel and userspace

## Requirements

- Linux kernel 4.13+ (for basic kTLS support)
- Linux kernel 5.4+ (for advanced features like zero-copy)
- A compatible network interface card that supports hardware TLS offloading (optional but recommended)

## Setup and Usage

1. Generate SSL certificates for the example:
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:2048 -keyout certs/serverkey.pem -out certs/servercert.pem -days 365 -nodes -subj '/CN=example.com'
   ```

2. Run Envoy with the provided configuration:
   ```bash
   envoy -c envoy-config.yaml --log-level debug
   ```

3. Test your configuration:
   ```bash
   curl -k https://localhost:10000/
   ```

## Configuration Details

The key parts of the configuration for kTLS are:

1. Using the kTLS transport socket:
   ```yaml
   transport_socket:
     name: envoy.transport_sockets.ktls
     typed_config:
       "@type": type.googleapis.com/envoy.extensions.transport_sockets.ktls.v3.KtlsTransportSocket
       tls_socket_config:
         # Your TLS configuration goes here
   ```

2. Enable optional kTLS features:
   ```yaml
   enable_tx_zerocopy: true  # Enable TX zero-copy if supported by your kernel
   enable_rx_no_pad: true    # Enable RX no-padding optimization for TLSv1.3
   ```

3. **CRITICAL**: Strictly enforce the kTLS-compatible cipher suite:
   ```yaml
   common_tls_context:
     tls_params:
       tls_minimum_protocol_version: TLSv1_2
       tls_maximum_protocol_version: TLSv1_2
       cipher_suites:
         - ECDHE-RSA-AES128-GCM-SHA256  # Only specify the one we want
   ```

4. Using the default socket interface:
   ```yaml
   bootstrap_extensions:
     - name: envoy.extensions.network.socket_interface.default_socket_interface
       typed_config:
         "@type": type.googleapis.com/envoy.extensions.network.socket_interface.v3.DefaultSocketInterface
   ```

   > **Note**: Some Envoy builds might support a custom kTLS socket interface, but the standard socket 
   > interface works for most kTLS deployments.

5. Enable runtime features for kTLS:
   ```yaml
   layered_runtime:
     layers:
       - name: static_layer
         static_layer:
           envoy:
             reloadable_features:
               ktls_socket: true
   ```

## Limitations

- kTLS currently only supports TLS 1.2 with AES-GCM ciphers
  - The only well-supported cipher is ECDHE-RSA-AES128-GCM-SHA256
  - Other ciphers will fall back to userspace TLS
- Hardware offloading depends on NIC support
- Only works on Linux kernels that support kTLS
- Requires explicit cipher configuration

## Common Issues

1. **"Unsupported cipher suite for kTLS"**: This is the most common issue. Even if you specify the supported cipher in your configuration, the actual cipher negotiated during the TLS handshake might be different:
   - For downstream (server) connections, ensure clients support ECDHE-RSA-AES128-GCM-SHA256
   - For upstream (client) connections, the remote server must support and prioritize ECDHE-RSA-AES128-GCM-SHA256
   - Try narrowing down to just one cipher in your configuration to force the negotiation
   - Some servers may override Envoy's cipher preferences during negotiation

2. **kTLS not being enabled**: Check logs for "kTLS enabled successfully". If you don't see this, kTLS is not being activated.

3. **Connection issues**: If you see "Network is unreachable" errors, try using:
   ```yaml
   dns_lookup_family: V4_ONLY  # Force IPv4 resolution
   ```

4. **Configuration errors**: If you see errors about unknown extensions or types, ensure your Envoy build has the features you're trying to use. When in doubt, use the standard configurations as shown in this README.

## Troubleshooting

1. Check if your kernel supports kTLS:
   ```bash
   modprobe tls  # Should load without errors if supported
   ```

2. Monitor TLS handshakes to see which cipher is being used:
   ```bash
   # Start Envoy with debug logging
   envoy -c envoy-config.yaml --log-level debug
   ```

3. Check kernel messages for kTLS activity:
   ```bash
   dmesg | grep -i tls
   ```

4. Verify a secure connection but test if kTLS is actually being used:
   ```bash
   # Look for log messages like:
   # [info][connection] kTLS enabled successfully
   # If you don't see this, kTLS is not being activated despite TLS working
   ```

5. For upstream connections to other servers, test their cipher support:
   ```bash
   # Check what ciphers a server supports
   openssl s_client -connect www.google.com:443 -cipher AES128-GCM-SHA256
   ```

6. If nothing works, try a self-to-self test with a controlled environment:
   - Use Envoy as both client and server
   - Configure both sides with the exact same cipher suite
   - This eliminates external variables in cipher negotiation 