#include "contrib/databricks_sql_proxy/filters/listener/source/databricks_sql_inspector.h"

#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/mysql_inspector.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/postgres_inspector.h"

using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

Config::Config(Stats::Scope& scope, const DatabricksSqlInspectorProto& proto_config,
               const std::string& stat_prefix)
    : stats_{ALL_DATABRICKS_SQL_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, stat_prefix))},
      protocol_(proto_config.protocol()) {

  // Store protocol-specific configuration if present
  if (protocol_ == envoy::extensions::filters::listener::databricks_sql_inspector::v3::
                       DatabricksSqlInspector::MYSQL) {
    mysql_config_ = proto_config.mysql_config();
    mysql_config_has_value_ = true;
  }
}

std::string Filter::name() { return "envoy.filters.listener.databricks_sql_proxy"; }

Filter::Filter(const ConfigSharedPtr config) : config_(config) {
  // Create inspector based on protocol
  switch (config_->protocol()) {
    PANIC_ON_PROTO_ENUM_SENTINEL_VALUES;
  case envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector::
      POSTGRES:
    inspector_ = std::make_unique<DatabricksSqlInspector::PostgresInspector>(config);
    break;
  case envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector::
      MYSQL:
    inspector_ = std::make_unique<DatabricksSqlInspector::MySQLInspector>(config);
    break;
  default:
    throw EnvoyException("Unsupported databricks_sql_inspector protocol.");
  }
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "databricks_sql_inspector: onAccept");

  std::string metadata_key = Filter::name();
  ProtobufWkt::Struct metadata((*cb.dynamicMetadata().mutable_filter_metadata())[metadata_key]);
  ProtobufWkt::Value protocol_val;
  protocol_val.set_string_value(envoy::extensions::filters::listener::databricks_sql_inspector::v3::
                                    DatabricksSqlInspector::Protocol_Name(config_->protocol()));
  (*metadata.mutable_fields())[CommonConstants::PROTOCOL_KEY] = protocol_val;
  cb.setDynamicMetadata(metadata_key, metadata);

  // Delegate to the protocol-specific inspector
  return inspector_->onAccept(cb);
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  ENVOY_LOG(trace, "databricks_sql_inspector: onData");

  // Delegate to the protocol-specific inspector
  return inspector_->onData(buffer);
}

/**
 * Stores error messages in the connection's dynamic metadata for logging and debugging. Error
 * messages are stored under the filter's namespace with the key "error_message". This allows error
 * conditions to be tracked in access logs and metrics.
 *
 * @param cb The listener filter callbacks to access connection metadata
 * @param error_msg The error message to store
 */
void Filter::setErrorMsgInDynamicMetadata(Network::ListenerFilterCallbacks& cb,
                                          const std::string& error_msg) {
  std::string metadata_key = Filter::name();
  ProtobufWkt::Struct metadata((*cb.dynamicMetadata().mutable_filter_metadata())[metadata_key]);
  ProtobufWkt::Value error_msg_val;
  error_msg_val.set_string_value(error_msg);
  (*metadata.mutable_fields())[CommonConstants::ERROR_MESSAGE_KEY] = error_msg_val;
  cb.setDynamicMetadata(metadata_key, metadata);
}

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
