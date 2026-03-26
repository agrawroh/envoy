load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    deps = [
        "//source/extensions/transport_sockets/dynamic_modules:config",
        "//source/extensions/transport_sockets/rustls/rust:rustls_ktls_static",
    ],
)
