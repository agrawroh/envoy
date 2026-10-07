load("@rules_rust//rust:defs.bzl", "rust_static_library")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_benchmark_binary",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

# The Tokio half of the pipeline under evaluation. It is linked into the benchmark directly rather
# than loaded as a dynamic module, as only its cost matters here.
rust_static_library(
    name = "offload",
    srcs = ["offload.rs"],
    crate_root = "offload.rs",
    edition = "2021",
    deps = ["@envoy_rust_crate_index//:tokio"],
)

envoy_cc_benchmark_binary(
    name = "xds_offload_speed_test",
    srcs = ["xds_offload_speed_test.cc"],
    deps = [
        ":offload",
        "//envoy/config:xds_config_tracker_interface",
        "//source/common/common:backoff_lib",
        "//source/common/config:decoded_resource_lib",
        "//source/common/config:null_grpc_mux_lib",
        "//source/common/config:opaque_resource_decoder_lib",
        "//source/common/config:protobuf_link_hacks",
        "//source/common/config:resource_name_lib",
        "//source/common/config:type_to_endpoint_lib",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:message_validator_lib",
        "//source/common/upstream:cds_api_lib",
        "//source/extensions/clusters/static:static_cluster_lib",
        "//source/extensions/config_subscription/grpc:grpc_subscription_impl_lib",
        "//source/extensions/config_subscription/grpc:new_grpc_mux_lib",
        "//source/extensions/load_balancing_policies/round_robin:config",
        "//source/extensions/transport_sockets/raw_buffer:config",
        "//test/common/upstream:cluster_manager_impl_test_common",
        "//test/mocks:common_lib",
        "//test/mocks/config:custom_config_validators_mocks",
        "//test/mocks/grpc:grpc_mocks",
        "//test/mocks/local_info:local_info_mocks",
        "@benchmark",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
    ],
)

envoy_cc_benchmark_binary(
    name = "cluster_shape_speed_test",
    srcs = ["cluster_shape_speed_test.cc"],
    deps = [
        "//source/common/config:null_grpc_mux_lib",
        "//source/common/upstream:cds_api_helper_lib",
        "//source/extensions/clusters/static:static_cluster_lib",
        "//source/extensions/load_balancing_policies/round_robin:config",
        "//source/extensions/transport_sockets/raw_buffer:config",
        "//test/common/upstream:cluster_manager_impl_test_common",
        "//test/test_common:utility_lib",
        "@benchmark",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
    ],
)

# Drives a real server with a fake management server, so it is an integration test rather than a
# benchmark binary. It only runs on demand and prints what it measures.
envoy_cc_test(
    name = "xds_burst_benchmark",
    size = "enormous",
    srcs = ["xds_burst_benchmark.cc"],
    tags = ["manual"],
    deps = [
        "//source/common/common:thread_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/matching/network/common:inputs_lib",
        "//test/common/grpc:grpc_client_integration_lib",
        "//test/integration:ads_integration_lib",
        "//test/integration:http_integration_lib",
        "//test/test_common:network_utility_lib",
        "//test/test_common:resources_lib",
        "@abseil-cpp//absl/strings",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/listener/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/router/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/matching/common_inputs/network/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
    ],
)
