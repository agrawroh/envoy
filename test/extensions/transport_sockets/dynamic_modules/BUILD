load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    data = [
        "//test/extensions/dynamic_modules/test_data/c:transport_socket_config_new_fail",
        "//test/extensions/dynamic_modules/test_data/c:transport_socket_no_op",
    ],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/transport_sockets/dynamic_modules:config",
        "//test/extensions/dynamic_modules:util",
        "//test/mocks/server:server_factory_context_mocks",
        "@envoy_api//envoy/extensions/transport_sockets/dynamic_modules/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "integration_test",
    srcs = ["integration_test.cc"],
    data = [
        "//test/extensions/dynamic_modules/test_data/c:transport_socket_no_op",
    ],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/dynamic_modules:abi_impl",
        "//source/extensions/filters/network/tcp_proxy:config",
        "//source/extensions/transport_sockets/dynamic_modules:config",
        "//test/integration:integration_lib",
        "@envoy_api//envoy/extensions/transport_sockets/dynamic_modules/v3:pkg_cc_proto",
    ],
)
