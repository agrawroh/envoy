The Hickory DNS resolver now applies the lookup family fallback. For a dual-stack name it returned
both address families, IPv4 first, under
:ref:`AUTO <envoy_v3_api_enum_value_config.cluster.v3.Cluster.DnsLookupFamily.AUTO>` and
:ref:`V4_PREFERRED <envoy_v3_api_enum_value_config.cluster.v3.Cluster.DnsLookupFamily.V4_PREFERRED>`.
``AUTO`` now returns only the IPv6 addresses, so ``localhost`` resolves to ``::1`` alone, and
``V4_PREFERRED`` only the IPv4 ones. ``AUTO`` falls back to the IPv4 addresses of such a name where
Envoy cannot open an IPv6 socket or the AAAA lookup fails, not on an IPv4-only network whose kernel
supports IPv6. Such hosts set the cluster's or the DNS cache's ``dns_lookup_family`` to
``V4_PREFERRED``.
:ref:`ALL <envoy_v3_api_enum_value_config.cluster.v3.Cluster.DnsLookupFamily.ALL>` keeps the old
result exactly.
