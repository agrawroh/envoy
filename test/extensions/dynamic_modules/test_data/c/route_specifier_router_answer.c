#include <stdint.h>
#include <string.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This module answers the virtual cluster of a request at the router. It names the value of the
// x-router-virtual-cluster request header, and it opts in from its configuration constructor, so
// that a test can observe when the router asks for the answer and when route matching calls the
// module. The answer hook runs on several threads in the two thread test, so its scratch headers
// are thread local and its count is atomic. Route matching runs on one thread.

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

static char config;
static int on_route_count = 0;
static int router_answer_count = 0;

// Let tests observe how often route matching called the module and how often the router asked it.
int getOnRouteCount(void) { return on_route_count; }
// The result of set_virtual_cluster called from route matching, -1 before the module made the call.
static int set_virtual_cluster_result = -1;
int getSetVirtualClusterResult(void) { return set_virtual_cluster_result; }
int getRouterAnswerCount(void) { return __atomic_load_n(&router_answer_count, __ATOMIC_RELAXED); }

envoy_dynamic_module_type_route_specifier_config_module_ptr
envoy_dynamic_module_on_route_specifier_config_new(
    envoy_dynamic_module_type_route_specifier_config_envoy_ptr config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer value) {
  envoy_dynamic_module_callback_route_specifier_config_answers_virtual_clusters(config_envoy_ptr);
  return &config;
}

void envoy_dynamic_module_on_route_specifier_config_destroy(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr) {}

// Whether the request carries the header, whose value is then written to value.
static int header(envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx, const char* name,
                  envoy_dynamic_module_type_module_buffer* value) {
  envoy_dynamic_module_type_envoy_buffer found = {NULL, 0};
  envoy_dynamic_module_type_module_buffer key = {name, strlen(name)};
  if (!envoy_dynamic_module_callback_route_specifier_get_request_header_value(ctx, key, &found, 0,
                                                                             NULL)) {
    return 0;
  }
  value->ptr = found.ptr;
  value->length = found.length;
  return 1;
}

// The decimal number a header value holds, which names a built route cache key.
static uint64_t number(envoy_dynamic_module_type_module_buffer value) {
  uint64_t result = 0;
  for (size_t i = 0; i < value.length; i++) {
    result = result * 10 + (uint64_t)(value.ptr[i] - '0');
  }
  return result;
}

envoy_dynamic_module_type_route_specifier_on_route_status
envoy_dynamic_module_on_route_specifier_on_route(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx) {
  on_route_count++;
  envoy_dynamic_module_type_module_buffer value;
  // A request with a cache key selects the rerouted template on a miss, which the cache keeps. A
  // hit keeps the cached route, and the router answer is still asked for each request.
  if (header(ctx, "x-key", &value)) {
    // The template is selected before the lookup, as the cache module does, so a miss records it.
    const envoy_dynamic_module_type_module_buffer template_id = {"rerouted", 8};
    envoy_dynamic_module_callback_route_specifier_set_route_template(ctx, template_id);
    envoy_dynamic_module_callback_route_specifier_lookup_built_route(ctx, number(value));
    return envoy_dynamic_module_type_route_specifier_on_route_status_Continue;
  }
  // A router answer refuses the selection, so the call returns false and records nothing.
  const envoy_dynamic_module_type_module_buffer name = {"trips", 5};
  set_virtual_cluster_result =
      envoy_dynamic_module_callback_route_specifier_set_virtual_cluster(ctx, name);
  return envoy_dynamic_module_type_route_specifier_on_route_status_Continue;
}

#define MAX_HEADERS 64
static const char kHeader[] = "x-router-virtual-cluster";

bool envoy_dynamic_module_on_route_specifier_virtual_cluster(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_virtual_cluster_context_envoy_ptr ctx,
    envoy_dynamic_module_type_module_buffer* virtual_cluster_name) {
  __atomic_fetch_add(&router_answer_count, 1, __ATOMIC_RELAXED);
  static __thread envoy_dynamic_module_type_envoy_http_header headers[MAX_HEADERS];
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
      // The value null names a buffer with a length and no bytes, which Envoy counts as unknown.
      if (headers[i].value_length == 4 && memcmp(headers[i].value_ptr, "null", 4) == 0) {
        virtual_cluster_name->ptr = NULL;
      }
      return true;
    }
  }
  return false;
}
