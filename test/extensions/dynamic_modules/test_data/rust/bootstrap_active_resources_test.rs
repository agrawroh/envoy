//! Test module for the bootstrap active-resource-name accessors.
//!
//! An admin request enumerates each resource kind via `active_resource_names(kind)` and returns the
//! observed names, so the integration test can assert what Envoy reports as active.

use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::collections::BTreeSet;

declare_bootstrap_init_functions!(my_program_init, my_new_bootstrap_extension_config_fn);

fn my_program_init() -> bool {
  true
}

fn my_new_bootstrap_extension_config_fn(
  envoy_extension_config: &mut dyn EnvoyBootstrapExtensionConfig,
  _name: &str,
  _config: &[u8],
) -> Option<Box<dyn BootstrapExtensionConfig>> {
  let registered = envoy_extension_config.register_admin_handler(
    "/active_resources",
    "Dump the names of the active config objects by kind.",
    true,
    false,
  );
  assert!(registered, "Admin handler registration should succeed");
  envoy_extension_config.signal_init_complete();
  Some(Box::new(ActiveResourcesTestConfig {}))
}

struct ActiveResourcesTestConfig {}

impl BootstrapExtensionConfig for ActiveResourcesTestConfig {
  fn new_bootstrap_extension(
    &self,
    _envoy_extension: &mut dyn EnvoyBootstrapExtension,
  ) -> Box<dyn BootstrapExtension> {
    Box::new(ActiveResourcesTestExtension {})
  }

  fn on_admin_request(
    &self,
    envoy_extension_config: &mut dyn EnvoyBootstrapExtensionConfig,
    _method: &str,
    _path: &str,
    _body: &[u8],
  ) -> (u32, String) {
    // A sorted set keeps the body stable and collapses the duplicates the ABI reports for objects
    // that share a name.
    let names = |kind| {
      envoy_extension_config
        .active_resource_names(kind)
        .into_iter()
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
    };
    (
      200,
      format!(
        "filter_chains=[{}] clusters=[{}] transport_socket_matches=[{}] secrets=[{}]",
        names(ActiveResourceKind::FilterChain),
        names(ActiveResourceKind::Cluster),
        names(ActiveResourceKind::TransportSocketMatch),
        names(ActiveResourceKind::Secret),
      ),
    )
  }
}

struct ActiveResourcesTestExtension {}

impl BootstrapExtension for ActiveResourcesTestExtension {
  fn on_server_initialized(&mut self, _envoy_extension: &mut dyn EnvoyBootstrapExtension) {
    envoy_log_info!("Active resources test bootstrap extension server initialized");
  }
}
