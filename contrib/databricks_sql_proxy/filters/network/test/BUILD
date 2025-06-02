load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_contrib_package",
    "envoy_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    rbe_pool = "2core",
    deps = [
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//test/mocks/server:factory_context_mocks",
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "postgres_proxy_test",
    srcs = ["postgres_proxy_test.cc"],
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//test/extensions/filters/common/ext_authz:ext_authz_mocks",
        "//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "mysql_proxy_test",
    srcs = ["mysql_proxy_test.cc"],
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:mysql_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_helper_lib",
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//test/extensions/filters/common/ext_authz:ext_authz_mocks",
        "//test/mocks/server:factory_context_mocks",
    ],
)

envoy_proto_library(
    name = "sync_write_filter_proto",
    srcs = [":sync_write_filter.proto"],
)

envoy_cc_library(
    name = "sync_write_filter_lib",
    hdrs = ["sync_write_filter.h"],
    deps = [
        ":sync_write_filter_proto_cc_proto",
        "//envoy/network:filter_interface",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
    ],
)

envoy_cc_test(
    name = "postgres_proxy_integration_test",
    size = "large",
    srcs = ["postgres_proxy_integration_test.cc"],
    data = [
        "postgres_integration_test_config.yaml",
        "//test/config/integration/certs",
    ],
    rbe_pool = "6gig",
    deps = [
        ":sync_write_filter_lib",
        ":sync_write_filter_proto_cc_proto",
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/listener/source:config",
        "//contrib/databricks_sql_proxy/filters/network/source:config",
        "//source/common/tcp_proxy",
        "//source/extensions/access_loggers/file:config",
        "//source/extensions/filters/listener/proxy_protocol:config",
        "//source/extensions/filters/network/tcp_proxy:config",
        "//source/extensions/transport_sockets/raw_buffer:config",
        "//source/extensions/transport_sockets/starttls:config",
        "//test/common/grpc:grpc_client_integration_lib",
        "//test/integration:integration_lib",
        "//test/test_common:registry_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/access_loggers/file/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/tcp_proxy/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/raw_buffer/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_proto",
    ],
)
