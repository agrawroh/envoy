load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

# MySQL proxy L7 network filter.
# Public docs: https://envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/mysql_proxy_filter

envoy_cc_library(
    name = "filter_lib",
    srcs = [
        "mysql_filter.cc",
    ],
    hdrs = [
        "mysql_filter.h",
    ],
    deps = [
        ":codec_lib",
        ":decoder_lib",
        "//envoy/network:filter_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/network:filter_lib",
        "//source/extensions/filters/network:well_known_names",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "codec_lib",
    srcs = [
        "mysql_codec_clogin.cc",
        "mysql_codec_clogin_resp.cc",
        "mysql_codec_command.cc",
        "mysql_codec_greeting.cc",
        "mysql_codec_switch_resp.cc",
    ],
    hdrs = [
        "mysql_codec_clogin.h",
        "mysql_codec_clogin_resp.h",
        "mysql_codec_command.h",
        "mysql_codec_greeting.h",
        "mysql_codec_switch_resp.h",
        "mysql_session.h",
    ],
    deps = [
        ":codec_interface",
        ":util_lib",
        "//contrib/common/sqlutils/source:sqlutils_lib",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_library(
    name = "decoder_interface",
    hdrs = ["mysql_decoder.h"],
    deps = [
        ":codec_lib",
    ],
)

envoy_cc_library(
    name = "codec_interface",
    hdrs = ["mysql_codec.h"],
    deps = [
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_library(
    name = "util_lib",
    srcs = ["mysql_utils.cc"],
    hdrs = ["mysql_utils.h"],
    deps = [
        ":codec_interface",
        "//source/common/buffer:buffer_lib",
    ],
)

envoy_cc_library(
    name = "config_interface",
    hdrs = ["mysql_config.h"],
    deps = [
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/mysql_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "decoder_lib",
    srcs = ["mysql_decoder_impl.cc"],
    hdrs = ["mysql_decoder_impl.h"],
    deps = [
        ":decoder_interface",
    ],
)

envoy_cc_library(
    name = "mysql_connect_proxy",
    srcs = [
        "mysql_connect_proxy.cc",
    ],
    hdrs = [
        "mysql_connect_proxy.h",
    ],
    deps = [
        "//envoy/access_log:access_log_interface",
        "//envoy/buffer:buffer_interface",
        "//envoy/common:time_interface",
        "//envoy/event:dispatcher_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:filter_interface",
        "//envoy/registry",
        "//envoy/router:router_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//envoy/stats:timespan_interface",
        "//envoy/stream_info:filter_state_interface",
        "//envoy/tcp:conn_pool_interface",
        "//envoy/tcp:upstream_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//envoy/upstream:upstream_interface",
        "//source/common/access_log:access_log_lib",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/common/common:hex_lib",
        "//source/common/common:macros",
        "//source/common/common:minimal_logger_lib",
        "//source/common/formatter:substitution_format_string_lib",
        "//source/common/http:codec_client_lib",
        "//source/common/network:application_protocol_lib",
        "//source/common/network:cidr_range_lib",
        "//source/common/network:filter_lib",
        "//source/common/network:hash_policy_lib",
        "//source/common/network:proxy_protocol_filter_state_lib",
        "//source/common/network:socket_option_factory_lib",
        "//source/common/network:transport_socket_options_lib",
        "//source/common/network:upstream_server_name_lib",
        "//source/common/network:upstream_socket_options_filter_state_lib",
        "//source/common/network:utility_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/router:metadatamatchcriteria_lib",
        "//source/common/stream_info:stream_id_provider_lib",
        "//source/common/stream_info:stream_info_lib",
        "//source/common/tcp_proxy:upstream_lib",
        "//source/common/upstream:load_balancer_lib",
        "//source/extensions/upstreams/tcp/generic:config",
        "@envoy_api//envoy/config/accesslog/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/mysql_connect_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "connect_proxy_config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":mysql_connect_proxy",
        "//envoy/registry",
        "//source/common/tcp_proxy",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/network/mysql_connect_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["mysql_config.cc"],
    hdrs = ["mysql_config.h"],
    deps = [
        ":filter_lib",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/mysql_proxy/v3:pkg_cc_proto",
    ],
)
