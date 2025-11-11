load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "rustls_wrapper_lib",
    srcs = ["rustls_wrapper.cc"],
    hdrs = ["rustls_wrapper.h"],
    deps = [
        ":rustls_ffi",
    ],
)

envoy_cc_library(
    name = "rustls_socket_lib",
    srcs = ["rustls_socket.cc"],
    hdrs = ["rustls_socket.h"],
    deps = [
        ":rustls_wrapper_lib",
        "//envoy/buffer:buffer_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:transport_socket_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":rustls_socket_lib",
        "//envoy/registry",
        "//envoy/server:transport_socket_config_interface",
        "//source/common/config:datasource_lib",
        "//source/common/config:utility_lib",
        "//source/common/network:transport_socket_options_lib",
        "//source/common/protobuf:message_validator_lib",
        "@envoy_api//envoy/extensions/transport_sockets/rustls/v3:pkg_cc_proto",
    ],
)

# Rust FFI library - pre-built static library from Cargo.
# Build it first with: cd source/extensions/transport_sockets/rustls/rustls_ffi && cargo build --release
cc_library(
    name = "rustls_ffi",
    srcs = select({
        "//bazel:linux_x86_64": ["rustls_ffi/target/release/libenvoy_rustls_ffi.a"],
        "//bazel:linux_aarch64": ["rustls_ffi/target/release/libenvoy_rustls_ffi.a"],
        "//conditions:default": ["rustls_ffi/target/release/libenvoy_rustls_ffi.a"],
    }),
    hdrs = [],
    linkstatic = True,
    alwayslink = True,
    # Link required Rust standard library dependencies.
    linkopts = select({
        "//bazel:linux_x86_64": ["-lpthread", "-ldl", "-lm"],
        "//bazel:linux_aarch64": ["-lpthread", "-ldl", "-lm"],
        "//conditions:default": ["-lpthread", "-ldl", "-lm"],
    }),
)

