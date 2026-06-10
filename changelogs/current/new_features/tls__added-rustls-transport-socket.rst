Added :ref:`RustlsUpstreamTlsContext
<envoy_v3_api_msg_extensions.transport_sockets.rustls.v3.RustlsUpstreamTlsContext>` and
:ref:`RustlsDownstreamTlsContext
<envoy_v3_api_msg_extensions.transport_sockets.rustls.v3.RustlsDownstreamTlsContext>`, a new TLS
transport socket using the `rustls <https://github.com/rustls/rustls>`_ library with optional
kernel TLS (``kTLS``) offload on Linux. This extension is **alpha**; per-connection
SNI / ALPN / SAN overrides (e.g. cluster ``auto_sni: true``), SDS-managed certificate
rotation, certificate revocation (CRL / OCSP), and fine-grained ``TlsParameters`` are not yet
supported. Additionally, ``Network::Connection::ssl()`` returns ``nullptr`` for this socket,
so RBAC ``AuthenticatedMatcher`` / URI-SAN / DNS-SAN principals, ext_authz peer-cert
propagation, and access-log operators ``%DOWNSTREAM_TLS_*%`` / ``%UPSTREAM_TLS_*%`` /
``%DOWNSTREAM_PEER_CERT*%`` will behave as if the connection were plaintext. Do not route
through this socket from a listener whose filter chain depends on TLS-derived principals or
audit fields. Use ``envoy.transport_sockets.tls`` for any of the above.
