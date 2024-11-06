#pragma once

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace DatabricksSqlProxy {
namespace Helper {

class CommonConstants {

public:
  // These are the key names used in dynamic metadata.
  static inline constexpr absl::string_view PROTOCOL_KEY{"protocol"};
  static inline constexpr absl::string_view TARGET_CLUSTER_KEY{"target_cluster"};
  static inline constexpr absl::string_view OVERRIDE_UPSTREAM_SNI_KEY{
      "override_upstream_sni_value"};
  static inline constexpr absl::string_view HANDSHAKE_STATE_KEY{"handshake_state"};
  static inline constexpr absl::string_view UPSTREAM_HANDSHAKE_STATE_KEY{
      "upstream_handshake_state"};
  static inline constexpr absl::string_view EXT_AUTHZ_DURATION_MS_KEY{
      "ext_authz_duration_micro_seconds"};
  static inline constexpr absl::string_view CLIENT_CAPABILITIES_KEY{"client_capabilities"};
  static inline constexpr absl::string_view USERNAME_KEY{"user"};
  static inline constexpr absl::string_view ORG_ID_KEY{"org_id"};
  static inline constexpr absl::string_view HOSTNAME_KEY{"database_hostname"};
  static inline constexpr absl::string_view CONNECTION_STRING_OPTIONS_KEY{
      "connection_string_options"};
  static inline constexpr absl::string_view ERROR_MESSAGE_KEY{"error_message"};
  static inline constexpr absl::string_view SHORT_HANDSHAKE_KEY{"short_handshake"};
  static inline constexpr absl::string_view PARAMETER_STATUS_UPSTREAM_IP_KEY{"upstream_ip"};
  static inline constexpr absl::string_view OPERATION_KEY{"operation"};
  static inline constexpr absl::string_view CANCELLATION_ID_KEY{"cancellation_id"};
  static inline constexpr absl::string_view CANCELLATION_PROCESS_ID_KEY{"cancellation_process_id"};
  static inline constexpr absl::string_view CANCELLATION_SECRET_KEY_KEY{"cancellation_secret_key"};
  static inline constexpr absl::string_view FIRST_CLIENT_MESSAGE_TYPE{"first_client_message"};
  static inline constexpr absl::string_view DATABASE_KEY{"database"};
  static inline constexpr absl::string_view ADDITIONAL_CONNECTION_ATTRS_KEY{
      "additional_connection_attributes"};
  static inline constexpr absl::string_view DYNAMIC_FORWARD_PROXY_KEY{"DYNAMIC_FORWARD_PROXY"};
  static inline constexpr absl::string_view REASON_PHRASE_KEY{"reason_phrase"};

  // Databricks SQL Inspector Filter Name
  static inline constexpr absl::string_view DATABRICKS_SQL_INSPECTOR_FILTER_NAMESPACE{
      "envoy.filters.listener.databricks_sql_proxy"};
};

} // namespace Helper
} // namespace DatabricksSqlProxy
} // namespace Extensions
} // namespace Envoy
