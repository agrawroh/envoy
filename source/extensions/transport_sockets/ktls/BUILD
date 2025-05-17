load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
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
    name = "ktls_ssl_info_lib",
    srcs = ["ktls_ssl_info_impl.cc"],
    hdrs = [
        "ktls_ssl_info.h",
        "ktls_ssl_info_impl.h",
        "tls_compat.h",
    ],
    external_deps = ["ssl"],
    deps = [
        "//envoy/ssl:connection_interface",
        "//source/common/common:assert_lib",
        "//source/common/network:utility_lib",
        "//source/common/tls:utility_lib",
        "//source/common/tls:ssl_socket_base",
    ],
)

envoy_cc_library(
    name = "ktls_socket_splicing_lib",
    srcs = ["ktls_socket_splicing.cc"],
    hdrs = ["ktls_socket_splicing.h"],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/network:io_handle_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
        "//source/common/network:io_socket_error_lib",
    ],
)

envoy_cc_library(
    name = "ktls_transport_socket_lib",
    srcs = ["ktls_transport_socket.cc"],
    hdrs = ["ktls_transport_socket.h"],
    external_deps = ["ssl"],
    deps = [
        ":ktls_socket_splicing_lib",
        ":ktls_ssl_info_lib",
        "//envoy/network:transport_socket_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/network:transport_socket_options_lib",
        "//source/extensions/transport_sockets/common:passthrough_lib",
    ],
)

envoy_cc_library(
    name = "ktls_socket_interface_lib",
    srcs = ["ktls_socket_interface.cc"],
    hdrs = ["ktls_socket_interface.h"],
    deps = [
        ":ktls_socket_handle_lib",
        "//envoy/registry:registry",
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
        "//envoy/registry:registry",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/common:assert_lib",
        "//source/common/network:address_lib",
        "//source/common/network:socket_interface_lib",
        "//source/common/network:socket_lib",
        "@com_google_protobuf//:protobuf",
        "@envoy_api//envoy/extensions/network/socket_interface/v3:pkg_cc_proto",
        "@com_github_cncf_xds//udpa/annotations:pkg_cc_proto",
    ],
    alwayslink = 1,
)

# Add combined config_envoy_extension that includes both regular config and socket interface
envoy_cc_extension(
    name = "config_envoy_extension",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":ktls_transport_socket_lib",
        "//envoy/registry:registry",
        "//envoy/server:transport_socket_config_interface",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/extensions/transport_sockets/ktls/v3:pkg_cc_proto",
        "@com_github_cncf_xds//udpa/annotations:pkg_cc_proto",
    ],
) 