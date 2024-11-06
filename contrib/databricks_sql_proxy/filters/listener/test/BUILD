load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_fuzz_test",
    "envoy_cc_test",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_test(
    name = "postgres_inspector_test",
    srcs = ["postgres_inspector_test.cc"],
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//contrib/databricks_sql_proxy/filters/listener/source:databricks_sql_inspector_lib",
        "//source/common/network:listener_filter_buffer_lib",
        "//test/mocks/api:api_mocks",
        "//test/mocks/network:io_handle_mocks",
        "//test/mocks/network:network_mocks",
    ],
)

envoy_cc_test(
    name = "mysql_inspector_test",
    srcs = ["mysql_inspector_test.cc"],
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:mysql_constants_lib",
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//contrib/databricks_sql_proxy/filters/listener/source:databricks_sql_inspector_lib",
        "//source/common/network:listener_filter_buffer_lib",
        "//test/mocks/api:api_mocks",
        "//test/mocks/network:io_handle_mocks",
        "//test/mocks/network:network_mocks",
    ],
)

envoy_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    rbe_pool = "2core",
    deps = [
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//test/mocks/server:factory_context_mocks",
        "@envoy_api//contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "postgres_inspector_integration_test",
    size = "large",
    srcs = ["postgres_inspector_integration_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//contrib/databricks_sql_proxy/filters/listener/source:databricks_sql_inspector_lib",
        "//source/extensions/filters/network/echo:config",
        "//test/integration:integration_lib",
    ],
)

envoy_cc_test(
    name = "postgres_inspector_proxy_protocol_integration_test",
    size = "large",
    srcs = ["postgres_inspector_proxy_protocol_integration_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//contrib/databricks_sql_proxy/filters/listener/source:databricks_sql_inspector_lib",
        "//source/extensions/filters/listener/proxy_protocol:config",
        "//source/extensions/filters/network/echo:config",
        "//test/integration:integration_lib",
        "@envoy_api//envoy/extensions/filters/listener/proxy_protocol/v3:pkg_cc_proto",
    ],
)

envoy_cc_fuzz_test(
    name = "postgres_inspector_fuzz_test",
    srcs = ["postgres_inspector_fuzz_test.cc"],
    corpus = "postgres_inspector_corpus",
    rbe_pool = "6gig",
    deps = [
        "//contrib/databricks_sql_proxy/filters/listener/source:databricks_sql_inspector_lib",
        "//test/extensions/filters/listener/common/fuzz:listener_filter_fuzzer_lib",
    ],
)
