load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_fuzz_test",
    "envoy_contrib_package",
    "envoy_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_proto_library(
    name = "postgres_proxy_readfilter_fuzz_test_proto",
    srcs = ["postgres_proxy_readfilter_fuzz_test.proto"],
    deps = [
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg",
    ],
)

envoy_cc_fuzz_test(
    name = "postgres_proxy_readfilter_fuzz_test",
    srcs = ["postgres_proxy_readfilter_fuzz_test.cc"],
    corpus = "postgres_proxy_readfilter_corpus",
    rbe_pool = "6gig",
    deps = [
        ":postgres_proxy_readfilter_fuzz_test_proto_cc_proto",
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//source/common/buffer:buffer_lib",
        "//test/extensions/filters/common/ext_authz:ext_authz_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/runtime:runtime_mocks",
        "//test/mocks/server:factory_context_mocks",
    ],
)

envoy_proto_library(
    name = "postgres_proxy_writefilter_fuzz_test_proto",
    srcs = ["postgres_proxy_writefilter_fuzz_test.proto"],
    deps = [
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg",
    ],
)

envoy_cc_fuzz_test(
    name = "postgres_proxy_writefilter_fuzz_test",
    srcs = ["postgres_proxy_writefilter_fuzz_test.cc"],
    corpus = "postgres_proxy_writefilter_corpus",
    rbe_pool = "6gig",
    deps = [
        ":postgres_proxy_writefilter_fuzz_test_proto_cc_proto",
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//source/common/buffer:buffer_lib",
        "//test/extensions/filters/common/ext_authz:ext_authz_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/runtime:runtime_mocks",
        "//test/mocks/server:factory_context_mocks",
    ],
)
