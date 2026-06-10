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

envoy_cc_library(
    name = "upstream_request_lib",
    srcs = [
        "upstream_request.cc",
    ],
    hdrs = [
        "upstream_request.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":web_transport_relay_lib",
        "//envoy/http:codec_interface",
        "//envoy/http:conn_pool_interface",
        "//envoy/upstream:thread_local_cluster_interface",
        "//envoy/upstream:upstream_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/router:router_lib",
    ],
)
