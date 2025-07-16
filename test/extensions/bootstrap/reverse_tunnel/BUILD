load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "reverse_tunnel_test",
    srcs = ["reverse_tunnel_test.cc"],
    deps = [
        "//source/extensions/bootstrap/reverse_tunnel:reverse_tunnel_acceptor_lib",
        "//source/extensions/bootstrap/reverse_tunnel:reverse_tunnel_initiator_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/server:server_mocks",
        "//test/mocks/stats:stats_mocks",
        "//test/mocks/thread_local:thread_local_mocks",
        "//test/mocks/upstream:upstream_mocks",
        "//test/test_common:environment_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/bootstrap/reverse_connection_socket_interface/v3:pkg_cc_proto",
    ],
) 