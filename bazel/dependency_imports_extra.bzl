load("@dynamic_modules_rust_sdk_crate_index//:defs.bzl", "crate_repositories")
load("@llvm_toolchain//:toolchains.bzl", "llvm_register_toolchains")
load("@rustls_ktls_crate_index//:defs.bzl", rustls_ktls_crate_repositories = "crate_repositories")

# Dependencies that rely on a first stage of envoy_dependency_imports() in dependency_imports.bzl.
def envoy_dependency_imports_extra():
    crate_repositories()
    rustls_ktls_crate_repositories()
    llvm_register_toolchains()
