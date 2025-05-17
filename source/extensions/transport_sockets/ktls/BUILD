load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "ktls_ssl_info_lib",
    srcs = ["ktls_ssl_info_impl.cc"],
    hdrs = [
        "ktls_ssl_info.h",
        "ktls_ssl_info_impl.h",
        "tls_compat.h",
    ],
    deps = [
        "//envoy/network:connection_interface",
        "//envoy/ssl:ssl_socket_extended_info_interface",
        "//envoy/ssl:ssl_socket_state_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
        "//source/common/network:io_socket_error_lib",
        "//source/common/tls:connection_info_lib",
    ],
)

envoy_cc_library(
    name = "ktls_socket_splicing_lib",
    srcs = ["ktls_socket_splicing.cc"],
    hdrs = ["ktls_socket_splicing.h"],
    deps = [
        "//envoy/network:io_handle_interface",
        "//source/common/common:logger_lib",
    ],
)

envoy_cc_library(
    name = "ktls_transport_socket_lib",
    srcs = ["ktls_transport_socket.cc"],
    hdrs = ["ktls_transport_socket.h"],
    deps = [
        ":ktls_socket_splicing_lib",
        ":ktls_ssl_info_lib",
        "//envoy/network:connection_interface",
        "//envoy/network:transport_socket_interface",
        "//envoy/ssl:ssl_socket_extended_info_interface",
        "//envoy/ssl:ssl_socket_state_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:logger_lib",
        "//source/common/network:io_socket_error_lib",
        "//source/common/network:io_socket_handle_impl_lib",
        "@com_github_openssl_openssl//:openssl",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":ktls_ssl_info_lib",
        ":ktls_transport_socket_lib",
        "//envoy/registry:registry",
        "//envoy/server:transport_socket_config_interface",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:utility_lib",
        "@com_google_protobuf//:protobuf",
    ],
) 