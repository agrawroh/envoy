load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "postgres_constants",
    hdrs = [
        "postgres_constants.h",
    ],
    deps = [
        "//source/common/common:assert_lib",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
    ],
)

envoy_cc_library(
    name = "postgres_utils",
    srcs = [
        "postgres_utils.cc",
    ],
    hdrs = [
        "postgres_utils.h",
    ],
    deps = [
        ":postgres_constants",
        "//source/common/buffer:buffer_lib",
        "@com_google_absl//absl/strings",
    ],
)

envoy_cc_library(
    name = "postgres_common",
    deps = [
        ":postgres_constants",
        ":postgres_utils",
    ],
)
