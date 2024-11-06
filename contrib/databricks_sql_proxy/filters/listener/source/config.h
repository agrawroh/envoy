#pragma once

#include "envoy/server/filter_config.h"

#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.h"

using DatabricksSqlInspectorProto =
    envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

/**
 * Config registration for the Databricks sql inspector filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class DatabricksSqlInspectorConfigFactory
    : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message&,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override { return "envoy.filters.listener.databricks_sql_inspector"; }

  static void validateProto(const DatabricksSqlInspectorProto& proto_config);
};

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
