# Kernel TLS (kTLS) Example

This example demonstrates how to use Envoy's kTLS (kernel TLS) support for offloading TLS processing to the Linux kernel.

## Requirements

- Linux kernel 4.13+ for basic kTLS support
- Linux kernel 5.0+ for TX zero-copy
- Linux kernel 5.17+ for RX no-padding and zero-copy receive

## Building

```bash
bazel build -c opt //source/exe:envoy
```

## Running

```bash
./bazel-bin/source/exe/envoy -c examples/ktls/envoy-config.yaml
```

## Testing

You can use a simple client like `curl` to test the kTLS setup:

```bash
curl -k https://localhost:10000/
```

## How It Works

The kTLS implementation in Envoy follows these steps:

1. First, a normal TLS handshake is completed using Envoy's regular TLS stack
2. After the handshake is complete, the kTLS transport socket attempts to enable kernel TLS offload
3. If successful, subsequent data transfer operations use the kernel's TLS implementation

Our implementation uses a sophisticated handshake detection system that:
- Uses multiple indicators to detect when the TLS handshake is truly complete
- Buffers read/write operations until we can determine if kTLS can be enabled
- Uses progressive retry delays to allow the handshake to complete
- Hooks into data operations to detect when handshake is complete

## Troubleshooting

### Common Issues

1. **"Unsupported cipher suite for kTLS"**: This is the most common issue. Even if you specify the supported cipher in your configuration, the actual cipher negotiated during the TLS handshake might be different. Only ECDHE-RSA-AES128-GCM-SHA256 and AES128-GCM-SHA256 are currently supported.

2. **"SSL handshake not complete"**: This indicates that the kTLS enablement code is trying to access TLS information before the handshake has completed. Our implementation will retry with progressive delays.

3. **"Failed to set TCP_ULP for kTLS"**: This typically means the kernel doesn't support kTLS or the required kernel module isn't loaded.

### Checking for kTLS Support

You can check if your kernel supports kTLS by running:

```bash
cat /proc/crypto | grep -A 1 -B 1 aes
```

You should see `gcm(aes)` in the output.

## Configuration

The kTLS transport socket is configured as a wrapper around the normal TLS transport socket. See the `envoy-config.yaml` file for an example configuration. 