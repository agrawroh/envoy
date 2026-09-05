Added ``envoy_dynamic_module_callback_cluster_lb_get_healthy_hosts`` ABI callback so a dynamic
module cluster reads a whole healthy partition in one ABI crossing instead of one crossing per host
with ``envoy_dynamic_module_callback_cluster_lb_get_healthy_host``. This matters because Envoy
reports a health only transition, an active health check flip, an outlier ejection, or an EDS health
status change, as a membership update with no added and no removed hosts, so a module cannot apply a
delta and has to re-read the partition on every such update. Nothing is written when the buffer is
too small, so a caller sizes the retry from the reported count rather than acting on a partial
healthy set. The Rust SDK exposes this as ``EnvoyClusterLoadBalancer::get_healthy_hosts``.
