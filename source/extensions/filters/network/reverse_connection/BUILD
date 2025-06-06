load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# Reverse Connection L4 network filter for HTTP tunneling
# Provides reverse connection capability with HTTP traffic forwarding

envoy_extension_package()

envoy_cc_library(
    name = "reverse_connection_filter_lib",
    srcs = ["reverse_connection_filter.cc"],
    hdrs = ["reverse_connection_filter.h"],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/event:dispatcher_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:filter_interface",
        "//envoy/stats:stats_macros",
        "//envoy/thread:thread_interface",
        "//envoy/thread_local:thread_local_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/network:raw_buffer_socket_lib",
        "//source/extensions/network/socket_interface/reverse_connection:upstream_reverse_socket_interface_lib",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "//source/extensions/filters/network/common:factory_base_lib",
        "//source/extensions/filters/network/reverse_connection:reverse_connection_filter_lib",
        "@envoy_api//envoy/extensions/filters/network/reverse_connection/v3:pkg_cc_proto",
    ],
)
