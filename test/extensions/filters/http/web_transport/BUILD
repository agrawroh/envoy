load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "web_transport_filter_test",
    srcs = ["web_transport_filter_test.cc"],
    extension_names = ["envoy.filters.http.web_transport"],
    rbe_pool = "6gig",
    deps = [
        "//envoy/http:web_transport_interface",
        "//source/extensions/filters/http/web_transport:web_transport_filter_lib",
        "//test/mocks/http:http_mocks",
    ],
)
