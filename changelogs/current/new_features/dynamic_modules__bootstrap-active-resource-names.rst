Added the ``envoy_dynamic_module_callback_bootstrap_extension_get_active_resource_names`` ABI
callback so a dynamic module bootstrap extension can enumerate the names of the config objects Envoy
currently has active, without scraping the admin ``/config_dump`` endpoint. The resource kind is an
input parameter, so filter chains, clusters, transport socket matches and dynamic TLS certificate
secrets are read through one callback and future kinds need no new one. Available in the Rust SDK as
``active_resource_names``.
