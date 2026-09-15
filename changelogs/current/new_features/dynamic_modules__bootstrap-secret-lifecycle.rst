Added dynamic module bootstrap ABI hooks for the secret lifecycle. A bootstrap extension opts in via
``envoy_dynamic_module_callback_bootstrap_extension_enable_secret_lifecycle`` and is then notified
when a dynamic TLS certificate secret becomes active, is rotated, or is removed. Secrets are
independent xDS resources, so the notifications fire without any cluster or listener being re-pushed,
and the secrets that are already active are replayed when the extension opts in. Available in the
Rust SDK as ``enable_secret_lifecycle`` with the ``on_secret_add_or_update`` and
``on_secret_removal`` callbacks.
