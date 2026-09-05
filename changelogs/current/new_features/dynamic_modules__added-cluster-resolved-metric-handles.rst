Added ``envoy_dynamic_module_callback_cluster_config_resolve_counter_vec``,
``..._resolve_gauge_vec`` and ``..._resolve_histogram_vec`` ABI callbacks, which resolve one
label-value tuple of a defined metric vec to an opaque handle, plus
``envoy_dynamic_module_callback_cluster_metric_counter_add``, ``..._gauge_set``, ``..._gauge_add``,
``..._gauge_sub`` and ``..._histogram_record`` to record through a handle. The existing
id-plus-label-values callbacks resolve the tuple on every call, which allocates per label value and
rebuilds the tagged stat name, and a module writing metrics on a per-request path pays that per
record. A handle allocates nothing and builds no name, and stays valid until the owning configuration
is destroyed. The Rust SDK exposes them as ``EnvoyClusterMetrics::resolve_counter_vec``,
``resolve_gauge_vec`` and ``resolve_histogram_vec`` returning ``EnvoyResolvedCounter``,
``EnvoyResolvedGauge`` and ``EnvoyResolvedHistogram``.
