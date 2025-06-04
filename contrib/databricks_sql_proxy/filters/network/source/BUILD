load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "databricks_sql_proxy_lib",
    srcs = [
        "databricks_mysql_proxy.cc",
        "databricks_postgres_proxy.cc",
        "databricks_sql_proxy.cc",
    ],
    hdrs = [
        "databricks_mysql_proxy.h",
        "databricks_postgres_proxy.h",
        "databricks_sql_errors.h",
        "databricks_sql_proxy.h",
    ],
    repository = "@envoy",
    deps = [
        "//contrib/common/sqlutils/source:sqlutils_lib",
        "//contrib/databricks_sql_proxy/filters/helper:common_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_auth_helper_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_helper_lib",
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:postgres_helper_lib",
        "//envoy/common:time_interface",
        "//envoy/network:filter_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:random_generator_lib",
        "//source/common/router:string_accessor_lib",
        "//source/common/tcp_proxy",
        "//source/extensions/filters/common/ext_authz:ext_authz_grpc_lib",
        "//source/extensions/filters/common/set_filter_state:filter_config_lib",
        "//source/extensions/filters/network:well_known_names",
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        ":databricks_sql_proxy_lib",
        "//envoy/registry",
        "//source/extensions/filters/common/ext_authz:ext_authz_grpc_lib",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3:pkg_cc_proto",
    ],
)
