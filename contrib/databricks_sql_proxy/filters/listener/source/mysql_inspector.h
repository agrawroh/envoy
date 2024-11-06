#pragma once

#include "source/common/common/logger.h"

#include "contrib/databricks_sql_proxy/filters/helper/mysql_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/mysql_packet_utils.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/databricks_sql_inspector.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

/**
 * MySQL listener filter that handles initial protocol validation and SSL setup.
 */
class MySQLInspector : public SqlProtocolInspector, Logger::Loggable<Logger::Id::filter> {
public:
  explicit MySQLInspector(ConfigSharedPtr config) : config_(config) {}

  // Implementation of SqlProtocolInspector interface
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;

private:
  // Error types for MySQL inspector
  enum class ErrorType {
    General,
    InvalidMessageLength,
    ProtocolViolation,
    HandshakeResponseFailed,
    SSLMismatch
  };

  /**
   * Generates random authentication plugin data for handshake.
   * @throws EnvoyException if random generation fails
   */
  void generateAuthPluginData();

  /**
   * Sends initial handshake packet to client.
   * @throws EnvoyException if packet creation or send fails
   */
  void sendInitialHandshake();

  /**
   * Validates a client handshake response packet.
   * @param data Buffer containing handshake response
   * @return true if valid, false if invalid
   */
  bool isValidHandshakeResponse(const Buffer::Instance& data);

  /**
   * Sets connection metadata for MySQL protocol.
   */
  void setConnectionMetadata();

  /**
   * Closes connection with error message.
   * @param error_msg Description of the error that caused the connection close
   * @param error_type Specific error type to increment the appropriate counter
   */
  void closeConnection(const std::string& error_msg, ErrorType error_type);

  /**
   * Handles SSL request from client.
   * @param data Buffer containing SSL request
   * @param packet_length Length of the packet
   */
  void handleSSLRequest(const Buffer::Instance& data, uint32_t packet_length);

  /**
   * Stores truncated handshake data in connection metadata.
   * @param data Source buffer
   * @param length Length to store
   */
  void setShortHandshakeData(const Buffer::Instance& data, uint32_t length);

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{nullptr};
  std::array<uint8_t, NetworkFilters::DatabricksSqlProxy::MySQLConstants::AUTH_PLUGIN_DATA_LENGTH>
      auth_plugin_data_;
};

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
