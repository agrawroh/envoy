load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "inputs_test",
    srcs = ["inputs_test.cc"],
    deps = [
        "//source/common/http/filter_chain_matcher:inputs_lib",
        "//test/mocks/http:http_mocks",
        "//test/mocks/router:router_mocks",
        "//test/mocks/stream_info:stream_info_mocks",
        "//test/test_common:utility_lib",
        "@com_google_protobuf//:protobuf",
    ],
)

envoy_cc_test(
    name = "action_test",
    srcs = ["action_test.cc"],
    deps = [
        "//source/common/http/filter_chain_matcher:action_lib",
        "//test/mocks/server:factory_context_mocks",
        "//test/test_common:utility_lib",
    ],
)
