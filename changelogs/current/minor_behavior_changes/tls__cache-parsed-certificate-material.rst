Added caching of the parsed local certificate chain and private key, so material identical across TLS
contexts is parsed and held once instead of once per context. This cuts config apply time for a
cluster that carries a distinct certificate per endpoint, where every transport socket match builds
its own context over the same material. Guarded by
``envoy.reloadable_features.cache_parsed_tls_certificates``, which defaults to false, so behavior is
unchanged unless the guard is enabled.
