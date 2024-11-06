#pragma once

#include <cstdint>
#include <string_view>
#include <unordered_map>

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace DatabricksSqlProxy {
namespace Helper {

class PostgresConstants {
public:
  // SSL request message length is 8 bytes.
  // SSL REQUEST message format is
  // 4 bytes: message length = 8 (including these 4 bytes)
  // 4 bytes: protocol version = 80877103
  // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-SSLREQUEST
  static constexpr int32_t SSL_REQUEST_MESSAGE_LENGTH = 8;
  // Cancel request message length is 16 bytes.
  static constexpr int32_t CANCEL_REQUEST_MESSAGE_LENGTH = 16;
  // Backend key data message length is 13 bytes (1 byte message type, 4 bytes message length, 4
  // bytes process_id, 4 bytes secret_key).
  static constexpr int32_t BACKEND_KEY_DATA_MESSAGE_LENGTH = 13;
  // Protocol version size is 4 bytes.
  static constexpr int32_t PROTOCOL_VERSION_LENGTH = 4;

  // Minimum message size of a startup message that we can process.
  // This is the size of the message length field and protocol version field.
  static constexpr int32_t MIN_STARTUP_MESSAGE_LENGTH = 8;
  // Maximum start up message. Same as what postgres server uses.
  static constexpr int32_t MAX_POSTGRES_MESSAGE_LENGTH = 10000;

  // The protocol version must be 80877102 (0x4D2162E) for cancel request.
  static constexpr uint32_t CANCEL_REQUEST_PROTOCOL_VERSION = 0x4D2162E;
  // The protocol version must be 80877103 (0x04d2162f) for SSL request.
  static constexpr uint32_t SSL_REQUEST_PROTOCOL_VERSION = 0x04d2162f;

  // Postgres protocol version
  static constexpr uint32_t MAJOR_VERSION = 3;
  static constexpr uint32_t MINOR_VERSION = 0;
  static constexpr uint32_t PROTOCOL_VERSION = (MAJOR_VERSION << 16) | MINOR_VERSION;

  // The SSL response if the server support SSL.
  static constexpr char POSTGRES_SUPPORT_SSL = 'S';

  // Postgres message type
  static constexpr char BACKEND_KEY_DATA_MESSAGE_TYPE = 'K';
  static constexpr char PARAMETER_STATUS_MESSAGE_TYPE = 'S';

  static inline constexpr absl::string_view POSTGRES_SSL_REQUEST_MESSAGE{
      "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8};

  // This is use in Severity field.
  // See this spec https://www.postgresql.org/docs/current/protocol-error-fields.html
  enum class PostgresErrorCode : int16_t {
    ERROR = 1,
    FATAL = 2,
    PANIC = 3,
    WARNING = 4,
    NOTICE = 5,
    DEBUG = 6,
    INFO = 7,
    LOG = 8
  };

  static inline const absl::flat_hash_map<PostgresErrorCode, absl::string_view>
      PostgresErrorCodeToString = {
          {PostgresErrorCode::ERROR, "ERROR"},   {PostgresErrorCode::FATAL, "FATAL"},
          {PostgresErrorCode::PANIC, "PANIC"},   {PostgresErrorCode::WARNING, "WARNING"},
          {PostgresErrorCode::NOTICE, "NOTICE"}, {PostgresErrorCode::DEBUG, "DEBUG"},
          {PostgresErrorCode::INFO, "INFO"},     {PostgresErrorCode::LOG, "LOG"}};

  // List of postgres error code defined in
  // https://www.postgresql.org/docs/current/errcodes-appendix.html
  static inline absl::string_view CONNECTION_FAILURE = "08006";
  static inline absl::string_view PROTOCOL_VIOLATION = "08P01";
  static inline absl::string_view FEATURE_NOT_SUPPORT = "0A000";
  static inline absl::string_view INTERNAL_ERROR = "XX000";
};

} // namespace Helper
} // namespace DatabricksSqlProxy
} // namespace Extensions
} // namespace Envoy
