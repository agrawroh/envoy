Added an experimental, dark-by-default HTTP/1.1 kernel-TLS body-splice fast path, guarded by
runtime feature ``envoy.reloadable_features.http1_ktls_body_splice``. When enabled and both the
upstream and downstream legs are single, non-multiplexed HTTP/1.1 sockets, a Content-Length body
is relayed with an in-kernel ``splice()`` that bypasses Envoy's userspace buffers and the codec
filter chains, in either direction: a response body from a kernel-TLS upstream to the downstream
socket (download), or a request body from the downstream socket to a kernel-TLS-TX upstream
(upload). The fast path only engages when the upstream has kernel TLS installed and is a trusted
peer, the other leg is plaintext or kernel TLS, and the body is Content-Length framed and at
least 64 KiB; otherwise the connection stays on the normal buffered path. For the upload the
request body is held in the kernel (the source is read-disabled) until the upstream connects and
installs kernel-TLS-TX. The non-kernel-TLS leg must be plaintext or installed-kernel-TLS, never
userspace TLS, since writing raw bytes into a userspace-TLS socket would bypass its encryption.
Because the spliced body bypasses the filter chains, the fast path must not be enabled alongside
filters that transform the body or rewrite ``Content-Length``. Engagement is observable per
cluster via the ``cluster.<name>.http1_ktls_splice.{engaged,abandoned,completed,truncated}``
counters. The spliced bytes do not pass the connection-level
``downstream_cx_*``/``upstream_cx_*`` byte counters (per-stream access-log bytes remain accurate),
so those counters under-report on flag ramp. Defaults off.
