.. _config_http_filters_web_transport:

WebTransport
============

The WebTransport filter terminates WebTransport over HTTP/3 sessions and echoes received datagrams
back to the client. It is a reference handler for the WebTransport termination path.

A route opts into WebTransport termination with an ``upgrade_configs`` entry of type
``webtransport`` whose filter chain contains this filter. The listener must enable extended CONNECT
and set ``web_transport_options.enabled`` on its HTTP/3 options, and the
``envoy.reloadable_features.web_transport`` runtime guard must be enabled.

After the ``CONNECT`` is accepted no further request or response events occur on the stream, so the
route should set ``idle_timeout`` to ``0s`` to keep an idle session from being reset by the stream
idle timeout.

Configuration
-------------

Example configuration:

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.web_transport
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.web_transport.v3.WebTransport
