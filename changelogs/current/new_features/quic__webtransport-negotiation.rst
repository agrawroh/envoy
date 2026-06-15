Added advertisement of WebTransport over HTTP/3 support in the HTTP/3 ``SETTINGS``, gated behind
the runtime guard ``envoy.reloadable_features.web_transport``. When the guard is enabled and a
listener allows extended CONNECT, Envoy advertises the QUICHE default WebTransport versions. It is
disabled by default. This is the negotiation foundation for WebTransport over HTTP/3. Session
termination support follows in subsequent changes.
