// Sentinels guarding the wire-level layout of every ABI struct declared in abi.h.
// Bumping a struct without bumping `ENVOY_DYNAMIC_MODULES_ABI_VERSION` (in abi.h)
// and updating these asserts is a build error. Pairs with the version check in
// dynamic_modules.cc.
//
// Coverage: every struct has both `sizeof` and `alignof` sentinels. Structs that
// gate security decisions (cert_validator_validation_result) or whose fields are
// accessed directly across the FFI boundary (envoy_http_header, module_http_header,
// socket_option) additionally have `offsetof` sentinels on every field, because a
// same-sized field reordering would otherwise silently shift the field readers see
// (worst case: cert_validator_validation_result reorder = TLS auth bypass).
//
// Enums are intentionally NOT pinned here: the C language gives them
// implementation-defined width, so a `sizeof` check would be platform-dependent
// and would not protect against the failure mode we care about (a foreign
// discriminant flowing through bindgen-generated `match`). That class of bug is
// mitigated on the Rust SDK side by `non_exhaustive` enums in sdk/rust/build.rs.

#include <cstddef>  // offsetof

#include "source/extensions/dynamic_modules/abi/abi.h"

// Common types.
static_assert(sizeof(envoy_dynamic_module_type_envoy_buffer) == 16,
              "ABI drift: envoy_dynamic_module_type_envoy_buffer");
static_assert(alignof(envoy_dynamic_module_type_envoy_buffer) == 8,
              "ABI drift: envoy_dynamic_module_type_envoy_buffer");

static_assert(sizeof(envoy_dynamic_module_type_module_buffer) == 16,
              "ABI drift: envoy_dynamic_module_type_module_buffer");
static_assert(alignof(envoy_dynamic_module_type_module_buffer) == 8,
              "ABI drift: envoy_dynamic_module_type_module_buffer");

// HTTP header pairs are walked field-by-field by the Rust SDK on every
// request, so any field reorder (even at the same total size) silently
// corrupts header parsing.
static_assert(sizeof(envoy_dynamic_module_type_module_http_header) == 32,
              "ABI drift: envoy_dynamic_module_type_module_http_header");
static_assert(alignof(envoy_dynamic_module_type_module_http_header) == 8,
              "ABI drift: envoy_dynamic_module_type_module_http_header");
static_assert(offsetof(envoy_dynamic_module_type_module_http_header, key_ptr) == 0,
              "ABI drift: module_http_header.key_ptr offset");
static_assert(offsetof(envoy_dynamic_module_type_module_http_header, key_length) == 8,
              "ABI drift: module_http_header.key_length offset");
static_assert(offsetof(envoy_dynamic_module_type_module_http_header, value_ptr) == 16,
              "ABI drift: module_http_header.value_ptr offset");
static_assert(offsetof(envoy_dynamic_module_type_module_http_header, value_length) == 24,
              "ABI drift: module_http_header.value_length offset");

static_assert(sizeof(envoy_dynamic_module_type_envoy_http_header) == 32,
              "ABI drift: envoy_dynamic_module_type_envoy_http_header");
static_assert(alignof(envoy_dynamic_module_type_envoy_http_header) == 8,
              "ABI drift: envoy_dynamic_module_type_envoy_http_header");
static_assert(offsetof(envoy_dynamic_module_type_envoy_http_header, key_ptr) == 0,
              "ABI drift: envoy_http_header.key_ptr offset");
static_assert(offsetof(envoy_dynamic_module_type_envoy_http_header, key_length) == 8,
              "ABI drift: envoy_http_header.key_length offset");
static_assert(offsetof(envoy_dynamic_module_type_envoy_http_header, value_ptr) == 16,
              "ABI drift: envoy_http_header.value_ptr offset");
static_assert(offsetof(envoy_dynamic_module_type_envoy_http_header, value_length) == 24,
              "ABI drift: envoy_http_header.value_length offset");

// Network types. socket_option carries int_value at a load-bearing offset:
// modules construct sockopt(2)-shaped payloads from this, so a reorder that
// keeps the size at 48 would silently bind the wrong field to the syscall.
static_assert(sizeof(envoy_dynamic_module_type_socket_option) == 48,
              "ABI drift: envoy_dynamic_module_type_socket_option");
static_assert(alignof(envoy_dynamic_module_type_socket_option) == 8,
              "ABI drift: envoy_dynamic_module_type_socket_option");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, level) == 0,
              "ABI drift: socket_option.level offset");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, name) == 8,
              "ABI drift: socket_option.name offset");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, state) == 16,
              "ABI drift: socket_option.state offset");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, value_type) == 20,
              "ABI drift: socket_option.value_type offset");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, int_value) == 24,
              "ABI drift: socket_option.int_value offset");
static_assert(offsetof(envoy_dynamic_module_type_socket_option, byte_value) == 32,
              "ABI drift: socket_option.byte_value offset");

// Access logger / stream info types.
static_assert(sizeof(envoy_dynamic_module_type_timing_info) == 64,
              "ABI drift: envoy_dynamic_module_type_timing_info");
static_assert(alignof(envoy_dynamic_module_type_timing_info) == 8,
              "ABI drift: envoy_dynamic_module_type_timing_info");

static_assert(sizeof(envoy_dynamic_module_type_bytes_info) == 32,
              "ABI drift: envoy_dynamic_module_type_bytes_info");
static_assert(alignof(envoy_dynamic_module_type_bytes_info) == 8,
              "ABI drift: envoy_dynamic_module_type_bytes_info");

// Cert validator. Highest-leverage struct: a same-sized reorder of `status` and
// the trailing fields would silently flip TLS authentication decisions (the
// Rust SDK reads `status` at a fixed offset and compares against `Successful`).
// Every field gets an `offsetof` sentinel — `sizeof` alone is insufficient.
static_assert(sizeof(envoy_dynamic_module_type_cert_validator_validation_result) == 12,
              "ABI drift: envoy_dynamic_module_type_cert_validator_validation_result");
static_assert(alignof(envoy_dynamic_module_type_cert_validator_validation_result) == 4,
              "ABI drift: envoy_dynamic_module_type_cert_validator_validation_result");
static_assert(offsetof(envoy_dynamic_module_type_cert_validator_validation_result, status) == 0,
              "ABI drift: cert_validator_validation_result.status offset (TLS auth decision)");
static_assert(
    offsetof(envoy_dynamic_module_type_cert_validator_validation_result, detailed_status) == 4,
    "ABI drift: cert_validator_validation_result.detailed_status offset");
static_assert(offsetof(envoy_dynamic_module_type_cert_validator_validation_result, tls_alert) == 8,
              "ABI drift: cert_validator_validation_result.tls_alert offset");
static_assert(
    offsetof(envoy_dynamic_module_type_cert_validator_validation_result, has_tls_alert) == 9,
    "ABI drift: cert_validator_validation_result.has_tls_alert offset");

// DNS resolver types.
static_assert(sizeof(envoy_dynamic_module_type_dns_address) == 24,
              "ABI drift: envoy_dynamic_module_type_dns_address");
static_assert(alignof(envoy_dynamic_module_type_dns_address) == 8,
              "ABI drift: envoy_dynamic_module_type_dns_address");

// Transport socket types.
static_assert(sizeof(envoy_dynamic_module_type_transport_socket_io_result) == 24,
              "ABI drift: envoy_dynamic_module_type_transport_socket_io_result");
static_assert(alignof(envoy_dynamic_module_type_transport_socket_io_result) == 8,
              "ABI drift: envoy_dynamic_module_type_transport_socket_io_result");
