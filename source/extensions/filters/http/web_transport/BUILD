load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "web_transport_filter_lib",
    srcs = ["web_transport_filter.cc"],
    hdrs = ["web_transport_filter.h"],
    deps = [
        "//envoy/http:filter_interface",
        "//envoy/http:web_transport_interface",
        "//source/common/common:logger_lib",
        "//source/common/http:header_map_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@quiche//:quiche_web_transport_web_transport_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    # The integration test drives the filter over a real HTTP/3 connection.
    extra_visibility = [
        "//test:__subpackages__",
    ],
    deps = [
        ":web_transport_filter_lib",
        "//envoy/registry",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/web_transport/v3:pkg_cc_proto",
    ],
)
