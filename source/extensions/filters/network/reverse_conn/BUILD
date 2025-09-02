load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "reverse_conn_config_lib",
    srcs = ["reverse_conn_filter_factory.cc"],
    hdrs = ["reverse_conn_filter_factory.h"],
    deps = [
        "//source/extensions/filters/network/generic_proxy/interface:filter_lib",
        "//source/extensions/filters/network/reverse_conn:reverse_conn_lib",
        "//source/extensions/filters/network/reverse_conn/v3:reverse_conn_proto",
    ],
)

envoy_cc_library(
    name = "reverse_conn_lib",
    srcs = [
        "reverse_conn_filter.cc",
    ],
    hdrs = [
        "reverse_conn_filter.h",
    ],
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/network:filter_impl_lib",
        "//source/common/protobuf:protobuf_lib",
        "//source/extensions/bootstrap/reverse_tunnel/downstream_socket_interface:reverse_connection_handshake_cc_proto",
        "//source/extensions/bootstrap/reverse_tunnel:reverse_tunnel_acceptor_lib",
        "//source/extensions/filters/network/generic_proxy/interface:filter_lib",
        "//source/extensions/filters/network/generic_proxy/interface:stream_lib",
        "//source/extensions/filters/network/reverse_conn/v3:reverse_conn_proto",
        "//source/extensions/bootstrap/reverse_tunnel/downstream_socket_interface:reverse_connection_handshake_cc_proto",
    ],
)
