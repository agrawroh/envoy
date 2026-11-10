#include <stdint.h>
#include <string.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This module opts in to answer virtual clusters but exports no hook, so that a configuration that
// sets a router answer is refused.

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

static char config;
static int on_route_count = 0;
static int router_answer_count = 0;

// Let tests observe how often route matching called the module and how often the router asked it.
int getOnRouteCount(void) { return on_route_count; }
int getRouterAnswerCount(void) { return router_answer_count; }

envoy_dynamic_module_type_route_specifier_config_module_ptr
envoy_dynamic_module_on_route_specifier_config_new(
    envoy_dynamic_module_type_route_specifier_config_envoy_ptr config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer value) {
  envoy_dynamic_module_callback_route_specifier_config_answers_virtual_clusters(config_envoy_ptr);
  return &config;
}

void envoy_dynamic_module_on_route_specifier_config_destroy(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr) {}

envoy_dynamic_module_type_route_specifier_on_route_status
envoy_dynamic_module_on_route_specifier_on_route(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx) {
  on_route_count++;
  return envoy_dynamic_module_type_route_specifier_on_route_status_Continue;
}

