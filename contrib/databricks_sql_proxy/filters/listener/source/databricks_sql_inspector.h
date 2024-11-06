#pragma once

#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.h"
#include "contrib/envoy/extensions/filters/listener/databricks_sql_inspector/v3/databricks_sql_inspector.pb.validate.h"

using DatabricksSqlInspectorProto =
    envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

/**
 * All stats for the SQL protocol inspector.
 * @see stats_macros.h
 */
#define ALL_DATABRICKS_SQL_INSPECTOR_STATS(COUNTER)                                                \
  COUNTER(error)                                                                                   \
  COUNTER(need_more_data)                                                                          \
  COUNTER(cancel_request_received)                                                                 \
  COUNTER(handshake_received)                                                                      \
  COUNTER(invalid_message_length)                                                                  \
  COUNTER(invalid_protocol_version)                                                                \
  COUNTER(protocol_violation)                                                                      \
  COUNTER(handshake_response_failed)                                                               \
  COUNTER(handshake_success)                                                                       \
  COUNTER(client_using_ssl)                                                                        \
  COUNTER(client_not_using_ssl)                                                                    \
  COUNTER(server_greeting_sent)                                                                    \
  COUNTER(ssl_mismatch)

/**
 * Definition of all stats for the SQL protocol inspector.
 * @see stats_macros.h
 */
struct DatabricksSqlInspectorStats {
  ALL_DATABRICKS_SQL_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Interface for the SQL protocol inspector.
 */
class SqlProtocolInspector {
public:
  virtual ~SqlProtocolInspector() = default;

  virtual Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) PURE;
  virtual Network::FilterStatus onData(Network::ListenerFilterBuffer&) PURE;
};
using SqlProtocolInspectorUniquePtr = std::unique_ptr<SqlProtocolInspector>;

/**
 * Global configuration for Databricks SQL inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope, const DatabricksSqlInspectorProto& proto_config,
         const std::string& stat_prefix);

  const DatabricksSqlInspectorStats& stats() const { return stats_; }
  envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector::
      Protocol
      protocol() const {
    return protocol_;
  }

  // MySQL-specific configuration accessor
  const envoy::extensions::filters::listener::databricks_sql_inspector::v3::MySQLConfig&
  mysqlConfig() const {
    ASSERT(protocol_ == envoy::extensions::filters::listener::databricks_sql_inspector::v3::
                            DatabricksSqlInspector::MYSQL);
    ASSERT(mysql_config_has_value_);
    return mysql_config_;
  }

  /*
   * Maximum packet length for both protocols.
   * For Postgres: Used for startup packet length limit
   * https://github.com/postgres/postgres/search?q=MAX_STARTUP_PACKET_LENGTH&type=code
   *
   * For MySQL: Used for initial handshake packet
   * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html#sect_protocol_connection_phase_initial_handshake
   */
  static constexpr uint32_t MAX_STARTUP_PACKET_LENGTH_BYTES = 10000;

private:
  DatabricksSqlInspectorStats stats_;
  envoy::extensions::filters::listener::databricks_sql_inspector::v3::DatabricksSqlInspector::
      Protocol protocol_;
  envoy::extensions::filters::listener::databricks_sql_inspector::v3::MySQLConfig mysql_config_;
  bool mysql_config_has_value_{false};
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Databricks SQL inspector listener filter.
 */
class Filter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr config);

  // These functions are needed to implement Network::ListenerFilter
  // For what each function does, see the comments in Network::ListenerFilter in
  // envoy/network/filter.h.
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer&) override;
  size_t maxReadBytes() const override { return Config::MAX_STARTUP_PACKET_LENGTH_BYTES; }

  /**
   * Sets error message in connection metadata.
   * @param cb Listener callback
   * @param error_msg Error message
   */
  static void setErrorMsgInDynamicMetadata(Network::ListenerFilterCallbacks& cb,
                                           const std::string& error_msg);

  static std::string name();

private:
  ConfigSharedPtr config_;
  SqlProtocolInspectorUniquePtr inspector_;
};

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
