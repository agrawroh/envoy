load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_extension_package",
    "envoy_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_proto_library(
    name = "reverse_connection_config_proto",
    srcs = ["reverse_connection_config.proto"],
)

# Remove dependency on external proto for now
# envoy_cc_library(
#     name = "reverse_connection_listener_config_cc_proto",
#     deps = [
#         "//api/envoy/extensions/reverse_connection/reverse_connection_listener_config/v3alpha:pkg_cc_proto",
#     ],
# )

envoy_cc_library(
    name = "protocol_lib",
    srcs = ["protocol.cc"],
    hdrs = ["protocol.h"],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/common:time_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:byte_order_lib",
        "//source/common/common:logger_lib",
        "@com_google_absl//absl/status:statusor",
    ],
)

envoy_cc_library(
    name = "downstream_reverse_socket_interface_lib",
    srcs = ["downstream_reverse_socket_interface.cc"],
    hdrs = ["downstream_reverse_socket_interface.h"],
    deps = [
        ":protocol_lib",
        # ":reverse_connection_listener_config_cc_proto",  # Temporarily removed
        "//envoy/api:io_error_interface",
        "//envoy/network:io_handle_interface",
        "//envoy/network:socket_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/network:address_lib",
        "//source/common/network:socket_interface_lib",
        "//source/common/network:default_socket_interface_lib",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/synchronization",
    ],
)

envoy_cc_library(
    name = "upstream_reverse_socket_interface_lib",
    srcs = ["upstream_reverse_socket_interface.cc"],
    hdrs = ["upstream_reverse_socket_interface.h"],
    deps = [
        "//envoy/api:io_error_interface",
        "//envoy/network:io_handle_interface",
        "//envoy/network:socket_interface",
        "//source/common/common:logger_lib",
        "//source/common/network:default_socket_interface_lib",
        "//source/common/network:socket_interface_lib",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/synchronization",
    ],
)

# Address resolver temporarily excluded due to API compatibility issues
# Core reverse connection functionality works without this optional component
# envoy_cc_library(
#     name = "reverse_connection_address_resolver_lib",
#     srcs = ["reverse_connection_address_resolver.cc"],
#     hdrs = ["reverse_connection_address_resolver.h"],
#     deps = [
#         ":downstream_reverse_socket_interface_lib",
#         "//envoy/network:address_interface",
#         "//envoy/network:resolver_interface",
#         "//envoy/registry",
#         "//source/common/common:logger_lib",
#         "//source/common/network:resolver_lib",
#     ],
# )

envoy_cc_library(
    name = "reverse_connection_listen_socket_factory_lib",
    srcs = ["reverse_connection_listen_socket_factory.cc"],
    hdrs = ["reverse_connection_listen_socket_factory.h"],
    deps = [
        ":downstream_reverse_socket_interface_lib",
        # ":reverse_connection_listener_config_cc_proto",  # Temporarily removed
        "//envoy/network:listen_socket_interface",
        "//envoy/server:listener_manager_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/common:logger_lib",
        "//source/common/network:listen_socket_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/listener/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "reverse_connection_terminal_filter_lib",
    srcs = ["reverse_connection_terminal_filter.cc"],
    hdrs = ["reverse_connection_terminal_filter.h"],
    deps = [
        ":upstream_reverse_socket_interface_lib",
        "//envoy/network:filter_interface",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/common/common:logger_lib",
        "//source/common/network:utility_lib",
        "//source/common/protobuf",
    ],
)

envoy_cc_extension(
    name = "reverse_connection_terminal_filter_config_lib",
    srcs = ["reverse_connection_terminal_filter_config.cc"],
    hdrs = ["reverse_connection_terminal_filter_config.h"],
    deps = [
        ":reverse_connection_config_proto_cc_proto",
        ":reverse_connection_terminal_filter_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/network/common:factory_base_lib",
    ],
)

envoy_cc_test(
    name = "reverse_connection_integration_test",
    srcs = ["test/reverse_connection_integration_test.cc"],
    deps = [
        ":downstream_reverse_socket_interface_lib",
        ":reverse_connection_terminal_filter_lib",
        ":upstream_reverse_socket_interface_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/upstream:upstream_mocks",
        "//test/test_common:utility_lib",
    ],
)
