load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "reverse_connection_test",
    srcs = ["reverse_connection_test.cc"],
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/network:address_lib",
        "//source/extensions/network/socket_interface/reverse_connection:downstream_reverse_socket_interface_lib",
        "//source/extensions/network/socket_interface/reverse_connection:protocol_lib",
        "//source/extensions/network/socket_interface/reverse_connection:reverse_connection_listen_socket_factory_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/upstream:upstream_mocks",
        "@envoy_api//envoy/config/listener/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "protocol_test",
    srcs = ["protocol_test.cc"],
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/extensions/network/socket_interface/reverse_connection:protocol_lib",
    ],
)

envoy_cc_test(
    name = "basic_architecture_test",
    srcs = ["basic_architecture_test.cc"],
    deps = [
        "//source/extensions/network/socket_interface/reverse_connection:downstream_reverse_socket_interface_lib",
        "//source/extensions/network/socket_interface/reverse_connection:reverse_connection_listen_socket_factory_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/upstream:upstream_mocks",
    ],
)
