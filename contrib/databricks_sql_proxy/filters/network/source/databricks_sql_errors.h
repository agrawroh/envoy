#pragma once

#include <cstdint>
#include <unordered_map>

#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"

using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

enum class CommonErrors : int16_t {
  DownstreamNoTls,
  DownstreamNoSni,
  ExtAuthzFailed,
  InvalidUpstreamHandshakeState,
  HandshakeTimeout,
};

struct ErrorInfo {
  int16_t error_code;
  absl::string_view sql_state;
  absl::string_view error_message;
  absl::string_view detail_message;
};

static inline const absl::flat_hash_map<CommonErrors, ErrorInfo> PostgresCommonErrorInfo = {
    // 08006 = connection_failure code.
    {CommonErrors::DownstreamNoTls,
     {static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL), "08006",
      "Insecure connection. Ensure that connection is using SSL. Try using `sslmode=require` in "
      "the connection string.",
      ""}},
    {CommonErrors::DownstreamNoSni,
     {static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL), "08006",
      "Connection does not have SNI.", "Please upgrade your client to support SNI."}},
    // 28000 = invalid_authorization_specification code.
    {CommonErrors::ExtAuthzFailed,
     {static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL), "28000",
      "External authorization failed.",
      "This could be due to paused instances, disabling readable secondaries, IP ACLs or private "
      "link configuration."}},
    // XX000 = internal_error code.
    {CommonErrors::InvalidUpstreamHandshakeState,
     {static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
      PostgresConstants::INTERNAL_ERROR, "Invalid upstream handshake state.", ""}},
    // 08006 = connection_failure code.
    {CommonErrors::HandshakeTimeout,
     {static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL), "08006",
      "Client handshake timeout.", ""}},
};

/**
 * Common error information for MySQL protocol.
 * https://dev.mysql.com/doc/mysql-errors/5.7/en/server-error-reference.html
 */
static inline const absl::flat_hash_map<CommonErrors, ErrorInfo> MySqlCommonErrorInfo = {
    // MySQL error code 1275 (ER_SERVER_IS_IN_SECURE_AUTH_MODE)
    // SQL state 28000 indicates "Invalid authorization specification"
    {CommonErrors::DownstreamNoTls,
     {1275, "28000", "Secure connection is required. Please use SSL/TLS.", ""}},

    // MySQL error code 1105 (ER_UNKNOWN_ERROR)
    // SQL state 08001 indicates "Connection to SQL Server failed"
    {CommonErrors::DownstreamNoSni,
     {1105, "08001", "Server name indication (SNI) required.",
      "Please upgrade your client to support SNI."}},

    // MySQL error code 1045 (ER_ACCESS_DENIED_ERROR)
    // SQL state 28000 indicates "Invalid authorization specification"
    {CommonErrors::ExtAuthzFailed,
     {1045, "28000", "Access denied. External authorization failed.",
      "This could be due to IP ACL or private link configuration."}},

    // MySQL error code 1053 (ER_SERVER_SHUTDOWN)
    // SQL state HY000 is the general error state
    {CommonErrors::InvalidUpstreamHandshakeState, {1053, "HY000", "Server handshake error.", ""}},

    // MySQL error code 1079 (ER_LOCKING_SERVICE_TIMEOUT)
    // SQL state HY000 is the general error state
    {CommonErrors::HandshakeTimeout, {1079, "HY000", "Handshake timeout.", ""}},
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
