Added a reference WebTransport over HTTP/3 termination filter that accepts a negotiated
WebTransport ``CONNECT`` with a 200 and echoes received datagrams back to the client. A route opts
in with an ``upgrade_configs`` entry of type ``webtransport`` and the listener enables it with the
``web_transport_options`` HTTP/3 protocol option. Sessions are bounded per connection and reported
under the ``webtransport`` stats sub-scope. This is gated behind the runtime guard
``envoy.reloadable_features.web_transport`` and is disabled by default.
