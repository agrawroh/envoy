#include <stddef.h>
#include <stdint.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// A cluster module whose choose_host always returns an async pending result so the C++ tests can
// drive the async host selection completion and cancellation paths. The module does not spawn a
// thread. The test invokes the completion callback directly.

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

envoy_dynamic_module_type_cluster_config_module_ptr envoy_dynamic_module_on_cluster_config_new(
    envoy_dynamic_module_type_cluster_config_envoy_ptr config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer config) {
  (void)config_envoy_ptr;
  (void)name;
  (void)config;
  return (envoy_dynamic_module_type_cluster_config_module_ptr)0x1;
}

void envoy_dynamic_module_on_cluster_config_destroy(
    envoy_dynamic_module_type_cluster_config_module_ptr config_module_ptr) {
  (void)config_module_ptr;
}

envoy_dynamic_module_type_cluster_module_ptr envoy_dynamic_module_on_cluster_new(
    envoy_dynamic_module_type_cluster_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_cluster_envoy_ptr cluster_envoy_ptr) {
  (void)config_module_ptr;
  (void)cluster_envoy_ptr;
  return (envoy_dynamic_module_type_cluster_module_ptr)0x2;
}

void envoy_dynamic_module_on_cluster_init(
    envoy_dynamic_module_type_cluster_envoy_ptr cluster_envoy_ptr,
    envoy_dynamic_module_type_cluster_module_ptr cluster_module_ptr) {
  (void)cluster_envoy_ptr;
  (void)cluster_module_ptr;
}

void envoy_dynamic_module_on_cluster_destroy(
    envoy_dynamic_module_type_cluster_module_ptr cluster_module_ptr) {
  (void)cluster_module_ptr;
}

envoy_dynamic_module_type_cluster_lb_module_ptr envoy_dynamic_module_on_cluster_lb_new(
    envoy_dynamic_module_type_cluster_module_ptr cluster_module_ptr,
    envoy_dynamic_module_type_cluster_lb_envoy_ptr lb_envoy_ptr) {
  (void)cluster_module_ptr;
  (void)lb_envoy_ptr;
  return (envoy_dynamic_module_type_cluster_lb_module_ptr)0x3;
}

void envoy_dynamic_module_on_cluster_lb_destroy(
    envoy_dynamic_module_type_cluster_lb_module_ptr lb_module_ptr) {
  (void)lb_module_ptr;
}

// Always returns an async pending result. The async handle value is a fixed non-null sentinel; the
// tests never dereference it.
void envoy_dynamic_module_on_cluster_lb_choose_host(
    envoy_dynamic_module_type_cluster_lb_module_ptr lb_module_ptr,
    envoy_dynamic_module_type_cluster_lb_context_envoy_ptr context_envoy_ptr,
    envoy_dynamic_module_type_cluster_host_envoy_ptr* host_out,
    envoy_dynamic_module_type_cluster_lb_async_handle_module_ptr* async_handle_out) {
  (void)lb_module_ptr;
  (void)context_envoy_ptr;
  *host_out = NULL;
  *async_handle_out = (envoy_dynamic_module_type_cluster_lb_async_handle_module_ptr)0x4;
}

void envoy_dynamic_module_on_cluster_lb_cancel_host_selection(
    envoy_dynamic_module_type_cluster_lb_module_ptr lb_module_ptr,
    envoy_dynamic_module_type_cluster_lb_async_handle_module_ptr async_handle_module_ptr) {
  (void)lb_module_ptr;
  (void)async_handle_module_ptr;
}
