#include "contrib/postgres_proxy/filters/network/source/config.h"

#include "envoy/common/exception.h"

#include "source/common/common/utility.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

/**
 * Config registration for the Postgres proxy filter. @see NamedNetworkFilterConfigFactory.
 */
Network::FilterFactoryCb
NetworkFilters::PostgresProxy::PostgresConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy& proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  PostgresFilterConfig::PostgresFilterConfigOptions config_options;
  config_options.stats_prefix_ = fmt::format("postgres.{}", proto_config.stat_prefix());
  config_options.enable_sql_parsing_ =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, enable_sql_parsing, true);
  config_options.terminate_ssl_ = proto_config.terminate_ssl();
  if (config_options.terminate_ssl_) {
    ENVOY_LOG(info,
              "postgres_proxy: terminate_ssl is deprecated, please use downstream_ssl instead.");
  }
  config_options.upstream_ssl_ = proto_config.upstream_ssl();
  config_options.downstream_ssl_ = proto_config.downstream_ssl();

  // Handle downstream SSL configuration options
  if (proto_config.has_downstream_ssl_options()) {
    // Validate that downstream_ssl_options is only set when downstream SSL is enabled
    if (config_options.downstream_ssl_ ==
        envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE) {
      throw EnvoyException(
          "downstream_ssl_options can only be set when downstream_ssl is ALLOW or REQUIRE");
    }

    const auto& downstream_options = proto_config.downstream_ssl_options();
    config_options.downstream_ssl_options_ = downstream_options;

    // Extract individual options for backward compatibility
    config_options.ssl_response_override_ = downstream_options.ssl_response_override();
    if (downstream_options.has_ssl_handshake_timeout_ms()) {
      config_options.ssl_handshake_timeout_ms_ =
          downstream_options.ssl_handshake_timeout_ms().value();
    }

    ENVOY_LOG(info, "Using downstream SSL configuration options");
  }

  // Handle upstream SSL configuration options
  if (proto_config.has_upstream_ssl_options()) {
    // Validate that upstream_ssl_options is only set when upstream SSL is enabled
    if (config_options.upstream_ssl_ ==
        envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE) {
      throw EnvoyException(
          "upstream_ssl_options can only be set when upstream_ssl is ALLOW or REQUIRE");
    }

    const auto& upstream_options = proto_config.upstream_ssl_options();
    config_options.upstream_ssl_options_ = upstream_options;

    // Extract upstream-specific options
    config_options.force_upstream_renegotiation_ = upstream_options.force_upstream_renegotiation();
    if (upstream_options.has_ssl_handshake_timeout_ms()) {
      // Upstream timeout takes precedence if both are set
      config_options.ssl_handshake_timeout_ms_ =
          upstream_options.ssl_handshake_timeout_ms().value();
    }

    ENVOY_LOG(info, "Using upstream SSL configuration options - renegotiation: {}",
              upstream_options.force_upstream_renegotiation());
  }

  PostgresFilterConfigSharedPtr filter_config(
      std::make_shared<PostgresFilterConfig>(config_options, context.scope()));
  return [filter_config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addFilter(std::make_shared<PostgresFilter>(filter_config));
  };
}

/**
 * Static registration for the Postgres proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(PostgresConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
