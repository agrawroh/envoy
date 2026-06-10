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
