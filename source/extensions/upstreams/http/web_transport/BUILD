load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "web_transport_relay_lib",
    srcs = [
        "web_transport_relay.cc",
    ],
    hdrs = [
        "web_transport_relay.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//envoy/http:web_transport_interface",
        "//source/common/common:minimal_logger_lib",
    ],
)
