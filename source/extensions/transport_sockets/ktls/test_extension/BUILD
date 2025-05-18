load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_binary(
    name = "ktls_test",
    srcs = ["main.cc"],
    deps = [
        "//source/exe:envoy_main_common_lib",
        "//source/extensions/transport_sockets/ktls:config_envoy_extension",
    ],
)
