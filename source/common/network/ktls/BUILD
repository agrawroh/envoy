load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "ktls_socket_handle_lib",
    srcs = ["ktls_socket_handle_impl.cc"],
    hdrs = ["ktls_socket_handle_impl.h"],
    deps = [
        "//envoy/network:io_handle_interface",
        "//source/common/common:logger_lib",
        "//source/common/network:default_socket_interface_lib",
    ],
)

envoy_cc_library(
    name = "ktls_socket_interface_lib",
    srcs = ["ktls_socket_interface.cc"],
    hdrs = ["ktls_socket_interface.h"],
    deps = [
        ":ktls_socket_handle_lib",
        "//envoy/registry",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/common:assert_lib",
        "//source/common/network:address_lib",
        "//source/common/network:socket_interface_lib",
        "//source/common/network:socket_lib",
        "@com_google_protobuf//:protobuf",
    ],
)

# Add the extension library target with proper visibility
envoy_cc_library(
    name = "ktls_socket_interface_lib_envoy_extension",
    visibility = ["//visibility:public"],
    deps = [
        ":ktls_socket_interface_lib",
        "//envoy/registry",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/common:assert_lib",
        "//source/common/network:address_lib",
        "//source/common/network:socket_interface_lib",
        "//source/common/network:socket_lib",
        "@com_google_protobuf//:protobuf",
    ],
    alwayslink = 1,
)
