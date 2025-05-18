load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

# Placeholder for QUIC transport socket
# This is a dummy target to satisfy dependencies
envoy_cc_extension(
    name = "config",
    srcs = [],
    hdrs = [],
    deps = [
        "//envoy/registry",
    ],
)
