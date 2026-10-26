#include <string.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This module records prefix rewrite rules so that a test can read how the produced route rewrites
// a request it was not built for. The specifier config selects what is recorded, and every mode
// records whether its last rule was accepted as the route metadata envoy.test.rule.accepted.

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

// The modes, in the order of the names below.
enum mode {
  LITERAL,
  WHOLE_PATH,
  NOT_PREFIX,
  WHOLE_PATH_WITH_MATCHED,
  EMPTY_REPLACEMENT,
  INVALID_REPLACEMENT,
  UNKNOWN_SPAN,
  TOO_LONG,
  PATH_WINS,
  RULE_OVER_OVERRIDE,
  OVERRIDE_ONLY,
  REPLACED,
  RECORDS_ORIGINAL_PATH,
  MODE_COUNT,
};

static const char* const mode_names[MODE_COUNT] = {
    "literal",           "whole-path",          "not-prefix",    "whole-path-with-matched",
    "empty-replacement", "invalid-replacement", "unknown-span",  "too-long",
    "path-wins",         "rule-over-override",  "override-only", "replaced",
    "records-original-path",
};

// Distinct addresses used as the config handle that selects the mode.
static char modes[MODE_COUNT];

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
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr) {}

static envoy_dynamic_module_type_module_buffer buffer(const char* value) {
  envoy_dynamic_module_type_module_buffer result = {value, strlen(value)};
  return result;
}

static bool rule(envoy_dynamic_module_type_route_specifier_context_envoy_ptr context_envoy_ptr,
                 envoy_dynamic_module_type_route_specifier_rewrite_span span, const char* matched,
                 const char* replacement) {
  return envoy_dynamic_module_callback_route_specifier_set_prefix_rewrite_rule(
      context_envoy_ptr, span, buffer(matched), buffer(replacement));
}

envoy_dynamic_module_type_route_specifier_on_route_status
envoy_dynamic_module_on_route_specifier_on_route(
    envoy_dynamic_module_type_route_specifier_config_module_ptr config_module_ptr,
    envoy_dynamic_module_type_route_specifier_context_envoy_ptr context_envoy_ptr) {
  const enum mode mode = (enum mode)((const char*)config_module_ptr - modes);
  const envoy_dynamic_module_type_route_specifier_rewrite_span literal =
      envoy_dynamic_module_type_route_specifier_rewrite_span_Literal;
  bool accepted = false;
  switch (mode) {
  case LITERAL:
    accepted = rule(context_envoy_ptr, literal, "/api", "/internal");
    break;
  case WHOLE_PATH:
    accepted = rule(context_envoy_ptr,
                    envoy_dynamic_module_type_route_specifier_rewrite_span_WholePath, "", "/fixed");
    break;
  case NOT_PREFIX:
    accepted = rule(context_envoy_ptr, literal, "/nope", "/internal");
    break;
  case WHOLE_PATH_WITH_MATCHED:
    accepted =
        rule(context_envoy_ptr, envoy_dynamic_module_type_route_specifier_rewrite_span_WholePath,
             "/api", "/fixed");
    break;
  case EMPTY_REPLACEMENT:
    accepted = rule(context_envoy_ptr, literal, "/api", "");
    break;
  case INVALID_REPLACEMENT:
    accepted = rule(context_envoy_ptr, literal, "/api", "/in\nternal");
    break;
  case UNKNOWN_SPAN:
    accepted = rule(context_envoy_ptr, (envoy_dynamic_module_type_route_specifier_rewrite_span)7,
                    "/api", "/internal");
    break;
  case TOO_LONG:
    accepted = rule(context_envoy_ptr, literal, "/api", "/a-replacement-longer-than-the-bound");
    break;
  case PATH_WINS:
    envoy_dynamic_module_callback_route_specifier_set_path(context_envoy_ptr, buffer("/literal"));
    accepted = rule(context_envoy_ptr, literal, "/api", "/internal");
    break;
  case RULE_OVER_OVERRIDE:
    envoy_dynamic_module_callback_route_specifier_set_route_override(context_envoy_ptr,
                                                                     buffer("rewrite"));
    accepted = rule(context_envoy_ptr, literal, "/api", "/internal");
    break;
  case OVERRIDE_ONLY:
    accepted = envoy_dynamic_module_callback_route_specifier_set_route_override(context_envoy_ptr,
                                                                                buffer("rewrite"));
    break;
  case REPLACED:
    rule(context_envoy_ptr, literal, "/api", "/first");
    accepted = rule(context_envoy_ptr, literal, "/api", "/second");
    break;
  case RECORDS_ORIGINAL_PATH:
    envoy_dynamic_module_callback_route_specifier_add_request_header(
        context_envoy_ptr, buffer("x-envoy-original-path"), buffer("/module"),
        envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExistsOrAdd);
    accepted = rule(context_envoy_ptr, literal, "/api", "/internal");
    break;
  case MODE_COUNT:
    break;
  }
  envoy_dynamic_module_callback_route_specifier_set_route_metadata_string(
      context_envoy_ptr, buffer("envoy.test.rule"), buffer("accepted"),
      buffer(accepted ? "true" : "false"));
  return envoy_dynamic_module_type_route_specifier_on_route_status_Continue;
}
