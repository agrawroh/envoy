load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_fuzz_test",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

# PostgreSQL inspector filter for examining PostgreSQL protocol messages before routing to a FilterChain.
# Public docs: https://envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/postgres_inspector

envoy_cc_library(
    name = "postgres_inspector_lib",
    srcs = ["postgres_inspector.cc"],
    hdrs = [
        "postgres_inspector.h",
        "postgres_inspector_metadata.h",
    ],
    deps = [
        "//contrib/postgres_common",
        "//envoy/network:filter_interface",
        "//envoy/network:listen_socket_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//envoy/stream_info:filter_state_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:fmt_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/router:string_accessor_lib",
        "//source/common/stream_info:bool_accessor_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        ":postgres_inspector_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//contrib/envoy/extensions/filters/listener/postgres_inspector/v3alpha:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "postgres_inspector_test",
    srcs = ["postgres_inspector_test.cc"],
    deps = [
        ":postgres_inspector_lib",
        "//contrib/postgres_common:postgres_constants",
        "//source/common/buffer:buffer_lib",
        "//source/common/stats:isolated_store_lib",
        "//source/common/stream_info:filter_state_lib",
        "//test/mocks/network:network_mocks",
        "//test/mocks/stats:stats_mocks",
        "//test/test_common:utility_lib",
        "@com_google_googletest//:gtest_main",
    ],
)

envoy_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    deps = [
        ":config",
        "//test/mocks/server:listener_factory_context_mocks",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//contrib/envoy/extensions/filters/listener/postgres_inspector/v3alpha:pkg_cc_proto",
    ],
)

envoy_cc_fuzz_test(
    name = "postgres_inspector_fuzz_test",
    srcs = ["postgres_inspector_fuzz_test.cc"],
    corpus = "postgres_inspector_corpus",
    deps = [
        ":postgres_inspector_lib",
        "//test/extensions/filters/listener/common/fuzz:listener_filter_fuzzer_lib",
    ],
)

# Integration test for postgres_inspector
envoy_cc_test(
    name = "postgres_inspector_integration_test",
    srcs = ["postgres_inspector_integration_test.cc"],
    data = [
        "//test/common/tls/test_data:certs",
        "//test/config/integration/certs",
    ],
    deps = [
        ":config",
        ":postgres_inspector_lib",
        "//contrib/postgres_proxy/filters/network/source:config",
        "//contrib/postgres_proxy/filters/network/source:filter",
        "//contrib/postgres_proxy/filters/network/test:postgres_test_utils_lib",
        "//source/common/tcp_proxy",
        "//source/common/tls:context_lib",
        "//source/extensions/filters/listener/tls_inspector:config",
        "//source/extensions/filters/network/sni_cluster:config",
        "//source/extensions/filters/network/tcp_proxy:config",
        "//source/extensions/transport_sockets/starttls:config",
        "//source/extensions/transport_sockets/tls:config",
        "//test/config:utility_lib",
        "//test/integration:integration_lib",
        "//test/integration:utility_lib",
        "//test/test_common:registry_lib",
        "@envoy_api//envoy/extensions/access_loggers/file/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
    ],
)
