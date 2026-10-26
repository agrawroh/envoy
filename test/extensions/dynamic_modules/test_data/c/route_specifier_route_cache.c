#include <stdint.h>
#include <string.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This module builds its routes through the route cache so that a test can observe what the cache
// does. The specifier config selects the mode, and the key is read from the x-key request header,
// defaulting to 1. On a hit the module records nothing, as a module that trusts the cache does.

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

enum mode {
  // Selects the template "only", records a cluster, metadata and user data on a miss.
  CACHED,
  // Like CACHED, but alternates the recorded cluster, so a verified hit finds a difference.
  INCONSISTENT,
  // Selects the template "weighted", whose cluster is picked per request.
  WEIGHTED,
  // Selects the direct response template "direct" and records a cluster, which fails the decision.
  DIRECT_ENTRY,
  // Selects the template "only" and records the route without a key.
  NO_KEY,
  // Sets a key without selecting a template.
  KEY_WITHOUT_TEMPLATE,
  // Selects the template again after the lookup, which discards the lookup.
  RESELECT,
  // Selects the template "only" and records nothing, so the cached route is the template itself.
  BARE,
  // Select the templates "header" and "plugin", whose cluster is resolved per request.
  HEADER,
  PLUGIN,
  // Records a path with set_prefix_rewrite, which is specific to the request.
  LEGACY_REWRITE,
  // Records the field the x-vary header names with the value of the x-value header.
  VARY,
  // Record a decision, or return a status, that wins over a hit.
  HIT_THEN_NO_ROUTE,
  HIT_THEN_PASS_THROUGH,
  HIT_THEN_ERROR,
  HIT_THEN_SKIP,
  MODE_COUNT,
};

static const char* const mode_names[MODE_COUNT] = {
    "cached",
    "inconsistent",
    "weighted",
    "direct-entry",
    "no-key",
    "key-without-template",
    "reselect",
    "bare",
    "header",
    "plugin",
    "legacy-rewrite",
    "vary",
    "hit-then-no-route",
    "hit-then-pass-through",
    "hit-then-error",
    "hit-then-skip",
};

static char modes[MODE_COUNT];

static int last_cache_result = -1;
static int route_destroy_count = 0;
static int config_destroy_count = 0;
static int inconsistent_calls = 0;

// Let tests observe what the cache returned and which hooks Envoy invoked.
int getLastCacheResult(void) { return last_cache_result; }
int getRouteDestroyCount(void) { return route_destroy_count; }
int getConfigDestroyCount(void) { return config_destroy_count; }

envoy_dynamic_module_type_route_specifier_config_module_ptr
envoy_dynamic_module_on_route_specifier_config_new(
    envoy_dynamic_module_type_route_specifier_config_envoy_ptr config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer config) {
  for (int i = 0; i < MODE_COUNT; i++) {
    const size_t length = strlen(mode_names[i]);
    if (config.length == length && memcmp(config.ptr, mode_names[i], length) == 0) {
      return &modes[i];
    }
  }
  return NULL;
}

void envoy_dynamic_module_on_route_specifier_config_destroy(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr) {
  config_destroy_count++;
}

void envoy_dynamic_module_on_route_specifier_route_destroy(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    uint64_t user_data) {
  route_destroy_count++;
}

static envoy_dynamic_module_type_module_buffer buffer(const char* value) {
  envoy_dynamic_module_type_module_buffer result = {value, strlen(value)};
  return result;
}

// The value of a request header, or an empty buffer when the request does not carry it.
static envoy_dynamic_module_type_envoy_buffer
requestHeader(envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx, const char* name) {
  envoy_dynamic_module_type_envoy_buffer value = {NULL, 0};
  if (!envoy_dynamic_module_callback_route_specifier_get_request_header_value(ctx, buffer(name),
                                                                              &value, 0, NULL)) {
    value.ptr = NULL;
    value.length = 0;
  }
  return value;
}

static uint64_t parseNumber(envoy_dynamic_module_type_envoy_buffer value, uint64_t missing) {
  if (value.ptr == NULL) {
    return missing;
  }
  uint64_t number = 0;
  for (size_t i = 0; i < value.length; i++) {
    number = number * 10 + (uint64_t)(value.ptr[i] - '0');
  }
  return number;
}

static uint64_t requestKey(envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx) {
  return parseNumber(requestHeader(ctx, "x-key"), 1);
}

static int headerIs(envoy_dynamic_module_type_envoy_buffer value, const char* expected) {
  const size_t length = strlen(expected);
  return value.ptr != NULL && value.length == length && memcmp(value.ptr, expected, length) == 0;
}

// Records cached_cluster and the one field x-vary names, set from x-value, so two requests that
// carry different values record different routes for one key.
static void recordVaried(envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx) {
  envoy_dynamic_module_callback_route_specifier_set_cluster_name(ctx, buffer("cached_cluster"));
  const envoy_dynamic_module_type_envoy_buffer field = requestHeader(ctx, "x-vary");
  const envoy_dynamic_module_type_envoy_buffer value = requestHeader(ctx, "x-value");
  const envoy_dynamic_module_type_module_buffer value_buffer = {value.ptr, value.length};
  if (headerIs(field, "timeout")) {
    envoy_dynamic_module_callback_route_specifier_set_timeout(ctx, parseNumber(value, 0));
  } else if (headerIs(field, "metadata")) {
    envoy_dynamic_module_callback_route_specifier_set_route_metadata_string(
        ctx, buffer("envoy.test.cache"), buffer("vary"), value_buffer);
  } else if (headerIs(field, "header")) {
    envoy_dynamic_module_callback_route_specifier_add_request_header(
        ctx, buffer("x-varied"), value_buffer,
        envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExistsOrAdd);
  } else if (headerIs(field, "rule")) {
    char replacement[64] = "/r";
    if (value.length < sizeof(replacement) - 3) {
      memcpy(replacement + 2, value.ptr, value.length);
      replacement[2 + value.length] = '\0';
    }
    envoy_dynamic_module_callback_route_specifier_set_prefix_rewrite_rule(
        ctx, envoy_dynamic_module_type_route_specifier_rewrite_span_Literal, buffer("/api"),
        buffer(replacement));
  } else if (headerIs(field, "user-data")) {
    envoy_dynamic_module_callback_route_specifier_set_route_user_data(ctx, parseNumber(value, 0));
  }
}

static void recordRoute(envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx,
                        const char* cluster) {
  envoy_dynamic_module_callback_route_specifier_set_cluster_name(ctx, buffer(cluster));
  envoy_dynamic_module_callback_route_specifier_set_route_metadata_string(
      ctx, buffer("envoy.test.cache"), buffer("built"), buffer("true"));
  envoy_dynamic_module_callback_route_specifier_set_route_user_data(ctx, 7);
}

envoy_dynamic_module_type_route_specifier_on_route_status
envoy_dynamic_module_on_route_specifier_on_route(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_context_envoy_ptr ctx) {
  const enum mode mode = (enum mode)((const char*)config_module_ptr - modes);
  const envoy_dynamic_module_type_route_specifier_on_route_status stop =
      envoy_dynamic_module_type_route_specifier_on_route_status_StopIteration;
  if (mode == KEY_WITHOUT_TEMPLATE) {
    last_cache_result =
        envoy_dynamic_module_callback_route_specifier_set_route_cache_key(ctx, requestKey(ctx));
    envoy_dynamic_module_callback_route_specifier_set_cluster_name(ctx, buffer("uncached"));
    return stop;
  }
  const char* template_id = "only";
  if (mode == WEIGHTED) {
    template_id = "weighted";
  } else if (mode == DIRECT_ENTRY) {
    template_id = "direct";
  } else if (mode == HEADER) {
    template_id = "header";
  } else if (mode == PLUGIN) {
    template_id = "plugin";
  }
  envoy_dynamic_module_callback_route_specifier_set_route_template(ctx, buffer(template_id));
  if (mode == NO_KEY) {
    recordRoute(ctx, "cached_cluster");
    return stop;
  }
  last_cache_result =
      envoy_dynamic_module_callback_route_specifier_set_route_cache_key(ctx, requestKey(ctx));
  if (mode == RESELECT) {
    envoy_dynamic_module_callback_route_specifier_set_route_template(ctx, buffer(template_id));
  }
  if (last_cache_result == envoy_dynamic_module_type_route_specifier_route_cache_result_Hit) {
    switch (mode) {
    case HIT_THEN_NO_ROUTE:
      envoy_dynamic_module_callback_route_specifier_set_decision(
          ctx, envoy_dynamic_module_type_route_specifier_decision_NoRoute);
      break;
    case HIT_THEN_PASS_THROUGH:
      envoy_dynamic_module_callback_route_specifier_set_decision(
          ctx, envoy_dynamic_module_type_route_specifier_decision_PassThrough);
      break;
    case HIT_THEN_ERROR:
      envoy_dynamic_module_callback_route_specifier_set_decision(
          ctx, envoy_dynamic_module_type_route_specifier_decision_Error);
      break;
    case HIT_THEN_SKIP:
      return envoy_dynamic_module_type_route_specifier_on_route_status_StopIterationAndSkipRoute;
    default:
      break;
    }
    return stop;
  }
  if (mode == INCONSISTENT) {
    recordRoute(ctx, inconsistent_calls++ % 2 == 0 ? "cluster_a" : "cluster_b");
    return stop;
  }
  if (mode == BARE) {
    return stop;
  }
  if (mode == LEGACY_REWRITE) {
    recordRoute(ctx, "cached_cluster");
    envoy_dynamic_module_callback_route_specifier_set_prefix_rewrite(ctx, buffer("/api"),
                                                                     buffer("/legacy"));
    return stop;
  }
  if (mode == VARY) {
    recordVaried(ctx);
    return stop;
  }
  if (mode == WEIGHTED || mode == HEADER || mode == PLUGIN) {
    envoy_dynamic_module_callback_route_specifier_set_route_metadata_string(
        ctx, buffer("envoy.test.cache"), buffer("built"), buffer("true"));
    return stop;
  }
  recordRoute(ctx, "cached_cluster");
  return stop;
}
