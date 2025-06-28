load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "reverse_connection_address_lib",
    srcs = [
        "reverse_connection_address.cc",
    ],
    hdrs = [
        "reverse_connection_address.h",
    ],
    deps = [
        "//envoy/network:address_interface",
        "//source/common/network:address_lib",
        "//source/common/common:fmt_lib",
        "//source/common/network:socket_interface_lib",
    ],
)

envoy_cc_library(
    name = "reverse_connection_resolver_lib",
    srcs = [
        "reverse_connection_resolver.cc",
    ],
    hdrs = [
        "reverse_connection_resolver.h",
    ],
    deps = [
        ":reverse_connection_address_lib",
        "//envoy/network:resolver_interface",
        "//envoy/registry",
        "//source/common/common:statusor_lib",
    ],
    visibility = ["//visibility:public"],
)

envoy_cc_extension(
    name = "downstream_reverse_socket_interface_lib",
    srcs = [
        "downstream_reverse_socket_interface.cc",
    ],
    hdrs = [
        "downstream_reverse_socket_interface.h",
    ],
    deps = [
        ":reverse_connection_resolver_lib",
        ":reverse_connection_address_lib",
        "//envoy/api:io_error_interface",
        "//envoy/network:io_handle_interface",
        "//envoy/network:socket_interface",
        "//envoy/network:address_interface",
        "//envoy/registry",
        "//envoy/server:bootstrap_extension_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/http:headers_lib",
        "//source/common/network:address_lib",
        "//source/common/network:filter_lib",
        "//source/common/protobuf",
        "//source/common/network:default_socket_interface_lib",
        "//source/common/upstream:load_balancer_context_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/http/reverse_conn/v3alpha:pkg_cc_proto",
        "@envoy_api//contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha:pkg_cc_proto",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)

envoy_cc_extension(
    name = "upstream_reverse_socket_interface_lib",
    srcs = [
        "upstream_reverse_socket_interface.cc",
    ],
    hdrs = [
        "upstream_reverse_socket_interface.h",
    ],
    deps = [
        "//envoy/common:random_generator_interface",
        "//envoy/network:io_handle_interface",
        "//envoy/network:socket_interface",
        "//envoy/network:address_interface",
        "//envoy/registry",
        "//envoy/server:bootstrap_extension_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//envoy/thread_local:thread_local_object",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/common:logger_lib",
        "//source/common/common:random_generator_lib",
        "//source/common/network:address_lib",
        "//source/common/network:default_socket_interface_lib",
        "//source/common/protobuf",
        "@envoy_api//contrib/envoy/extensions/bootstrap/reverse_connection_socket_interface/v3alpha:pkg_cc_proto",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)