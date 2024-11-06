#pragma once

#include "source/common/common/logger.h"

#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/databricks_sql_inspector.h"

using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

class PostgresInspector : public SqlProtocolInspector, Logger::Loggable<Logger::Id::filter> {
public:
  PostgresInspector(ConfigSharedPtr config) : config_(config) {}

  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;

private:
  Network::FilterStatus processCancelRequestMessage(int32_t message_len);
  Network::FilterStatus processSslRequestMessage(Network::ListenerFilterBuffer& buffer,
                                                 int32_t message_len);

  void sendErrorResponseToDownstream(PostgresConstants::PostgresErrorCode error_code,
                                     absl::string_view sql_state, absl::string_view error_message,
                                     absl::string_view detail_message);

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{nullptr};
};

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
