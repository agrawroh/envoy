Added support for a per-connection server name (SNI) override on the ``rustls`` upstream transport
socket, so a cluster with :ref:`auto_sni
<envoy_v3_api_field_extensions.upstreams.http.v3.HttpProtocolOptions.UpstreamHttpProtocolOptions.auto_sni>`
(or any per-connection ``serverNameOverride``) now handshakes with the override server name while
sharing the one configured ``rustls`` ``ClientConfig``. The override is threaded through a new
optional dynamic-module transport-socket ABI hook; modules that do not export it are unaffected.
Per-connection ALPN and SAN match-list overrides remain unsupported.
