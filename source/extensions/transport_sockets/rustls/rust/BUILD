load("@envoy_rust_crate_index//:defs.bzl", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_static_library", "rust_test", "rustfmt_test")
load("//bazel:envoy_build_system.bzl", "envoy_extension_package")
load("//source/extensions/dynamic_modules:dynamic_modules.bzl", "envoy_dynamic_module_prefix_symbols")

licenses(["notice"])  # Apache 2

envoy_extension_package()

exports_files(["Cargo.toml"])

rust_static_library(
    name = "rustls_ktls_static_lib",
    srcs = ["rustls_ktls.rs"],
    edition = "2021",
    deps = [
        "//source/extensions/dynamic_modules/sdk/rust:envoy_proxy_dynamic_modules_rust_sdk",
    ] + all_crate_deps(
        normal = True,
    ),
)

envoy_dynamic_module_prefix_symbols(
    name = "rustls_ktls_static",
    archive = ":rustls_ktls_static_lib",
    module_name = "rustls_ktls_static",
    visibility = [
        "//source/extensions/transport_sockets/rustls:__pkg__",
    ],
)

# Unit tests for the pure-Rust helpers (record tracking, IV split, errno mapping, backpressure
# constants). These run without Envoy ABI dependencies.
#
# `no_tsan`/`nocoverage`: matches the convention in test/extensions/dynamic_modules/BUILD —
# the Rust toolchain has known false positives under TSAN
# (https://github.com/rust-lang/rust/issues/39608) and coverage instrumentation of Rust
# artifacts is unsupported.
rust_test(
    name = "rustls_ktls_unit_tests",
    crate = ":rustls_ktls_static_lib",
    edition = "2021",
    tags = [
        "no_tsan",
        "nocoverage",
    ],
)

rustfmt_test(
    name = "fmt_rustls_ktls",
    testonly = True,
    tags = ["nocoverage"],
    targets = [":rustls_ktls_static_lib"],
)

rust_clippy(
    name = "clippy_rustls_ktls",
    testonly = True,
    tags = ["nocoverage"],
    deps = [":rustls_ktls_static_lib"],
)
