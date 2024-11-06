load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

# Databricks SQL inspector filter for sniffing Postgres or MySQL protocol
envoy_cc_library(
    name = "databricks_sql_inspector_lib",
    srcs = [
        "databricks_sql_inspector.cc",
        "mysql_inspector.cc",
        "postgres_inspector.cc",
    ],
    hdrs = [
        "databricks_sql_inspector.h",
        "mysql_inspector.h",
        "postgres_inspector.h",
    ],
    deps = [
        "//contrib/databricks_sql_proxy/filters/helper:common_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:mysql_helper_lib",
        "//contrib/databricks_sql_proxy/filters/helper:postgres_constants_lib",
        "//contrib/databricks_sql_proxy/filters/helper:postgres_helper_lib",
        "//envoy/network:filter_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/extensions/filters/network:well_known_names",
        "@envoy_api//contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":databricks_sql_inspector_lib",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3:pkg_cc_proto",
    ],
)
