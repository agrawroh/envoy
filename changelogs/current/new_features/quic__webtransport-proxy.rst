Added WebTransport over HTTP/3 proxying. A negotiated WebTransport ``CONNECT`` is forwarded to an
HTTP/3 upstream, the upstream ``200`` flows back to the downstream, and datagrams and data streams
are relayed in both directions. Subprotocol negotiation headers pass through transparently, and
relayed traffic resets the downstream stream idle timer so a busy proxied session is not reaped. The
upstream ``CONNECT`` waits for the upstream HTTP/3 SETTINGS so the session is negotiated, and
sessions are bounded per connection. A route opts in with an
``upgrade_configs`` entry of type ``webtransport`` carrying a ``connect_config`` and a cluster that
enables ``web_transport_options``. This is gated behind the runtime guard
``envoy.reloadable_features.web_transport`` and is disabled by default.
