load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "//envoy/registry",
        "//envoy/server:factory_context_interface",
        "//envoy/ssl:handshaker_interface",
        "//source/common/tls:context_lib",
        "//source/common/tls:server_context_lib",
        "//source/common/tls:utility_lib",
        "@envoy_api//envoy/extensions/transport_sockets/tls/cert_selectors/sni_with_default/v3:pkg_cc_proto",
    ],
)
