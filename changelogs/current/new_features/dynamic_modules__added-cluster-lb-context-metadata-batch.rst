Added ``envoy_dynamic_module_callback_cluster_lb_context_set_dynamic_metadata_string_batch`` ABI
callback so a dynamic module cluster writes several string-valued dynamic metadata entries on a
request under one namespace in a single ABI crossing, resolving the namespace and merging into the
metadata struct once. The HTTP, network and listener filters already had a batch setter and the
cluster load balancer context did not, so a cluster annotating a request with a multi-field selection
record paid the single-key setter once per field on every request. The Rust SDK exposes this as
``ClusterLbContext::set_dynamic_metadata_string_batch``.
