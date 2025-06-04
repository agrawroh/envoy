load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "common_constants_lib",
    hdrs = ["common_constants.h"],
)

envoy_cc_library(
    name = "postgres_constants_lib",
    hdrs = ["postgres_constants.h"],
)

envoy_cc_library(
    name = "postgres_helper_lib",
    srcs = ["postgres_helper.cc"],
    hdrs = ["postgres_helper.h"],
    deps = [
        ":postgres_constants_lib",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_library(
    name = "mysql_constants_lib",
    hdrs = ["mysql_constants.h"],
)

envoy_cc_library(
    name = "mysql_helper_lib",
    srcs = ["mysql_packet_utils.cc"],
    hdrs = ["mysql_packet_utils.h"],
    deps = [
        ":mysql_constants_lib",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_library(
    name = "mysql_auth_helper_lib",
    srcs = ["mysql_auth_helper.cc"],
    hdrs = ["mysql_auth_helper.h"],
    deps = [
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "@boringssl//:ssl",
    ],
)
