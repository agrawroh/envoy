#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Constants used in MySQL protocol implementation.
 * These values are based on the MySQL protocol specification:
 * https://dev.mysql.com/doc/internals/en/client-server-protocol.html
 */
struct MySQLConstants {
  // Protocol sizing and version constants
  // https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html
  static constexpr uint32_t MAX_PACKET_SIZE = 0x00ffffff; // 16MB maximum packet size
  /**
   * This represents the minimum size of the initial handshake packet sent from server to client in
   * MySQL protocol.
   * https://dev.mysql.com/doc/dev/mysql-server/9.1.0/page_protocol_connection_phase_packets_protocol_handshake_v10.html
   *
   * The fixed 32 bytes consist of:
   * 1 byte protocol version
   * [Variable] NUL-terminated server version string (minimum of 1 byte + 1 byte NUL)
   * 4 byte thread ID
   * 8 bytes of auth plugin data for first part (auth-plugin-data-part-1)
   * 1 byte filler
   * 2 bytes lower capability flags
   * 1 byte character set
   * 2 bytes server status flags
   * 2 bytes upper capability flags
   * 1 byte auth plugin data length
   * 10 bytes reserved (filler)
   * [Variable] Rest of the plugin provided data (scramble), $len=MAX(13, length of auth-plugin-data
   * - 8)
   */
  static constexpr size_t MIN_HANDSHAKE_SIZE = 32;        // Minimum handshake packet size
  static constexpr uint8_t PROTOCOL_VERSION = 0x0a;       // Protocol version 10
  static constexpr uint32_t MIN_PACKET_LENGTH = 4;        // Length + sequence number
  static constexpr uint32_t AUTH_PLUGIN_DATA_LENGTH = 20; // Authentication plugin data length
  /**
   * Initial SSL request sent by the client to the MySQL server before establishing an SSL
   * connection. The structure of this SSL handshake message includes SSL support flags and a
   * sequence number.
   * https://dev.mysql.com/doc/dev/mysql-server/9.1.0/page_protocol_connection_phase_packets_protocol_ssl_request.html
   *
   * The 36 bytes consist of:
   * 4 bytes for the packet header: This includes the packet length (3 bytes) and the sequence
   * number (1 byte). 32 bytes for the payload: This payload is structured as follows: 4 bytes for
   * the client capability flags, 4 bytes for the maximum packet size, 1 byte for the character set,
   *  23 bytes of reserved filler (typically all set to zero).
   */
  static constexpr uint32_t SSL_HANDSHAKE_PACKET_LENGTH = 36; // SSL handshake packet length
  static constexpr uint32_t CAPABILITIES_FLAGS_OFFSET = 4; // Offset for capabilities in handshake
  static constexpr uint32_t MIN_CAPABILITIES_PACKET_SIZE =
      MIN_PACKET_LENGTH + CAPABILITIES_FLAGS_OFFSET;

  // Client capability flags - must match MySQL server capabilities
  // https://dev.mysql.com/doc/dev/mysql-server/8.4.3/group__group__cs__capabilities__flags.html
  static constexpr uint32_t CLIENT_SSL = 0x00000800; // Support SSL

  // Server status flags
  static constexpr uint32_t SERVER_STATUS_AUTOCOMMIT = 0xFFDF;

  // Required capability combinations
  static constexpr uint32_t REQUIRED_CAPABILITIES = 0xFFFFFFFF;

  // Client capability flags - must match MySQL server capabilities
  static constexpr uint32_t CLIENT_PROTOCOL_41 = 0x00000200;     // Use 4.1 protocol
  static constexpr uint32_t CLIENT_PLUGIN_AUTH = 0x00080000;     // Support plugins
  static constexpr uint32_t CLIENT_CONNECT_WITH_DB = 0x00000008; // Database name in handshake
  static constexpr uint32_t CLIENT_COMPRESS = 0x00000020;        // Support compression
  static constexpr uint32_t CLIENT_TRANSACTIONS = 0x00002000;    // Support transactions
  static constexpr uint32_t CLIENT_CONNECT_ATTRS = 0x00100000;   // Support connection attributes
  static constexpr uint32_t CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000; // Auth data length

  // Timeouts and retry settings
  static constexpr std::chrono::milliseconds HANDSHAKE_TIMEOUT{1000};
  static constexpr std::chrono::milliseconds RETRY_INTERVAL{1};
  static constexpr uint32_t MAX_HANDSHAKE_ATTEMPTS = 10;
  static constexpr uint32_t MAX_AUTH_ATTEMPTS = 3;

  // Default values for MySQL protocol
  static constexpr uint8_t DEFAULT_CHARSET_ID = 2;   // UTF-8
  static constexpr size_t MAX_USERNAME_LENGTH = 255; // Maximum MySQL username length

  // Error codes
  // Authentication and permission errors
  static constexpr uint16_t ER_ACCESS_DENIED_ERROR = 1045;   // Access denied for user
  static constexpr uint16_t ER_DBACCESS_DENIED_ERROR = 1044; // Access denied for database
  static constexpr uint16_t ER_HOST_NOT_PRIVILEGED = 1130;   // Host not allowed to connect

  // Connection errors
  static constexpr uint16_t ER_CON_COUNT_ERROR = 1040;      // Too many connections
  static constexpr uint16_t ER_SERVER_SHUTDOWN = 1053;      // Server shutdown in progress
  static constexpr uint16_t ER_NET_PACKET_TOO_LARGE = 1153; // Packet too large
  static constexpr uint16_t ER_NET_READ_ERROR = 1158;       // Network read error
  static constexpr uint16_t ER_NET_WRITE_ERROR = 1160;      // Network write error

  // Protocol errors
  static constexpr uint16_t ER_HANDSHAKE_ERROR = 1043;        // Bad handshake
  static constexpr uint16_t ER_UNKNOWN_COM_ERROR = 1047;      // Unknown command
  static constexpr uint16_t ER_MALFORMED_PACKET = 1835;       // Malformed packet
  static constexpr uint16_t ER_INVALID_SSL_PARAMETERS = 1617; // SSL parameters are invalid

  // Feature not supported errors
  static constexpr uint16_t ER_NOT_SUPPORTED_AUTH_MODE = 1251; // Authentication mode not supported
  static constexpr uint16_t ER_FEATURE_DISABLED = 1289;        // Feature disabled

  // General server errors
  static constexpr uint16_t ER_YES = 1003;              // No error
  static constexpr uint16_t ER_UNKNOWN_ERROR = 1105;    // Unknown error
  static constexpr uint16_t ER_INTERNAL_ERROR = 1815;   // Internal server error
  static constexpr uint16_t ER_OUT_OF_RESOURCES = 1041; // Out of memory

  // Common SQL state values
  static constexpr absl::string_view SQL_STATE_ACCESS_DENIED = "28000"; // Access denied
  static constexpr absl::string_view SQL_STATE_SYNTAX_ERROR = "42000";  // Syntax error
  static constexpr absl::string_view SQL_STATE_CONNECTION_ERROR =
      "08S01"; // Communication link failure
  static constexpr absl::string_view SQL_STATE_SERVER_SHUTDOWN = "08006"; // Server shutdown
  static constexpr absl::string_view SQL_STATE_HANDSHAKE_ERROR = "08004"; // Handshake error
  static constexpr absl::string_view SQL_STATE_INTERNAL_ERROR = "HY000";  // Internal server error
  static constexpr absl::string_view SQL_STATE_FEATURE_NOT_SUPPORTED =
      "0A000"; // Feature not supported
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
