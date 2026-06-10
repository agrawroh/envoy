load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "web_transport_relay_test",
    srcs = ["web_transport_relay_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/upstreams/http/web_transport:web_transport_relay_lib",
    ],
)

envoy_cc_test(
    name = "upstream_request_test",
    srcs = ["upstream_request_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/stats:isolated_store_lib",
        "//source/extensions/upstreams/http/web_transport:upstream_request_lib",
        "//test/mocks/http:http_mocks",
        "//test/mocks/router:router_mocks",
        "//test/test_common:utility_lib",
    ],
)
