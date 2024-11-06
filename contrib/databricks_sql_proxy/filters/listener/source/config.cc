#include "contrib/databricks_sql_proxy/filters/listener/source/config.h"

#include "source/extensions/filters/network/common/factory_base.h"

#include "contrib/databricks_sql_proxy/filters/listener/source/databricks_sql_inspector.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/postgres_inspector.h"
#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.h"
#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

// NamedListenerFilterConfigFactory
Network::ListenerFilterFactoryCb
DatabricksSqlInspectorConfigFactory::createListenerFilterFactoryFromProto(
    const Protobuf::Message& message,
    const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
    Server::Configuration::ListenerFactoryContext& context) {

  // Get raw proto config
  const envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector&
      proto_config = MessageUtil::downcastAndValidate<
          const envoy::extensions::filters::listener::databricks_sql_inspector::v3::
              DatabricksSqlInspector&>(message, context.messageValidationVisitor());

  DatabricksSqlInspectorConfigFactory::validateProto(proto_config);

  const std::string stat_prefix =
      fmt::format("databricks_sql_inspector.{}", proto_config.stat_prefix());

  // Create config
  DatabricksSqlInspector::ConfigSharedPtr config(
      std::make_shared<DatabricksSqlInspector::Config>(context.scope(), proto_config, stat_prefix));

  // Create filter
  return [listener_filter_matcher, config](Network::ListenerFilterManager& filter_manager) -> void {
    filter_manager.addAcceptFilter(listener_filter_matcher,
                                   std::make_unique<DatabricksSqlInspector::Filter>(config));
  };
}

void DatabricksSqlInspectorConfigFactory::validateProto(
    const DatabricksSqlInspectorProto& proto_config) {
  if (proto_config.stat_prefix().empty()) {
    throw EnvoyException("stat_prefix is required");
  }

  if (proto_config.protocol() == DatabricksSqlInspectorProto::UNSPECIFIED) {
    throw EnvoyException("Protocol must be specified");
  }

  // If this is a mysql protocol, mysql config must be specified
  if (proto_config.protocol() == DatabricksSqlInspectorProto::MYSQL &&
      !proto_config.has_mysql_config()) {
    throw EnvoyException("MySQL configuration is required when protocol is MYSQL");
  }
}

ProtobufTypes::MessagePtr DatabricksSqlInspectorConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector>();
}

/**
 * Static registration for the MySQL inspector filter. @see RegisterFactory.
 */
REGISTER_FACTORY(DatabricksSqlInspectorConfigFactory,
                 Server::Configuration::NamedListenerFilterConfigFactory){
    "envoy.listener.databricks_sql_inspector"};
} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
