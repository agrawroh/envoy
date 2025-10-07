load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "matching_data_lib",
    hdrs = ["matching_data.h"],
    deps = [
        "//envoy/http:header_map_interface",
        "//envoy/matcher:matcher_interface",
        "//envoy/router:router_interface",
        "//envoy/stream_info:stream_info_interface",
        "//source/common/common:logger_lib",
        "//source/common/matcher:matcher_lib",
        "@com_google_absl//absl/status",
    ],
)

envoy_cc_library(
    name = "inputs_lib",
    srcs = ["inputs.cc"],
    hdrs = ["inputs.h"],
    deps = [
        ":matching_data_lib",
        "//envoy/config:typed_config_interface",
        "//envoy/matcher:matcher_interface",
        "//envoy/registry",
        "//source/common/config:metadata_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "action_lib",
    srcs = ["action.cc"],
    hdrs = ["action.h"],
    deps = [
        ":matching_data_lib",
        "//envoy/matcher:matcher_interface",
        "//envoy/registry",
        "//envoy/server:factory_context_interface",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)
