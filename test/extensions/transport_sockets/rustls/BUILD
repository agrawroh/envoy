load(
    "//bazel:envoy_build_system.bzl",
    "envoy_extension_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_extension_cc_test(
    name = "rustls_socket_test",
    srcs = ["rustls_socket_test.cc"],
    extension_names = ["envoy.transport_sockets.rustls"],
    deps = [
        "//source/extensions/transport_sockets/rustls:rustls_socket_lib",
        "//test/mocks/network:network_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    extension_names = ["envoy.transport_sockets.rustls"],
    deps = [
        "//source/extensions/transport_sockets/rustls:config",
        "//test/mocks/server:transport_socket_factory_context_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:utility_lib",
    ],
)

