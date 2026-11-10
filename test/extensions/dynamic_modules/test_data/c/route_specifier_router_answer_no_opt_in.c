#include <stdint.h>
#include <string.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This module exports the router answer hook like route_specifier_router_answer.c but does not opt
// in from its configuration constructor, so a configuration that sets a router answer is refused.
// Tests run it on one thread, so its scratch headers are static.

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
  (void)config_envoy_ptr;
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

#define MAX_HEADERS 64
static envoy_dynamic_module_type_envoy_http_header headers[MAX_HEADERS];
static const char kHeader[] = "x-router-virtual-cluster";

bool envoy_dynamic_module_on_route_specifier_virtual_cluster(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_virtual_cluster_context_envoy_ptr ctx,
    envoy_dynamic_module_type_module_buffer* virtual_cluster_name) {
  router_answer_count++;
  const size_t count =
      envoy_dynamic_module_callback_route_specifier_virtual_cluster_get_request_headers_size(ctx);
  if (count > MAX_HEADERS ||
      !envoy_dynamic_module_callback_route_specifier_virtual_cluster_get_request_headers(ctx,
                                                                                       headers)) {
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    if (headers[i].key_length == strlen(kHeader) &&
        memcmp(headers[i].key_ptr, kHeader, strlen(kHeader)) == 0) {
      virtual_cluster_name->ptr = headers[i].value_ptr;
      virtual_cluster_name->length = headers[i].value_length;
      return true;
    }
  }
  return false;
}
