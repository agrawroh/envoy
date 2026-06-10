Added ``tls_minimum_protocol_version`` and ``tls_maximum_protocol_version`` (TLS 1.2 / TLS 1.3
bounds) to the alpha :ref:`rustls
<envoy_v3_api_msg_extensions.transport_sockets.rustls.v3.RustlsUpstreamTlsContext>` upstream and
downstream transport sockets, and ``crl`` (a PEM certificate revocation list) to the downstream
socket for client-certificate revocation during mTLS and to the upstream socket for
server-certificate revocation. The CRL is read once at config load and is not refreshed.
