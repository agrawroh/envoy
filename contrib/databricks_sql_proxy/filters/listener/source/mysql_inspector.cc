#include "mysql_inspector.h"

#include "source/common/common/base64.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"

using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

Network::FilterStatus MySQLInspector::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "mysql_inspector: onAccept");
  cb_ = &cb;

  try {
    sendInitialHandshake();
  } catch (const EnvoyException& e) {
    ENVOY_LOG(error, "mysql_inspector: failed during accept: {}", e.what());
    closeConnection(e.what(), ErrorType::General);
    return Network::FilterStatus::StopIteration;
  }

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus MySQLInspector::onData(Network::ListenerFilterBuffer& buffer) {
  ENVOY_LOG(trace, "mysql_inspector: onData");
  const auto& mysql_config = config_->mysqlConfig();

  try {
    auto raw_slice = buffer.rawSlice();
    Buffer::OwnedImpl data{
        raw_slice.mem_,
        std::min(raw_slice.len_,
                 static_cast<size_t>(
                     NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_HANDSHAKE_SIZE))};

    if (data.length() < NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_HANDSHAKE_SIZE) {
      ENVOY_LOG(debug, "mysql_inspector: need more data, current length: {}", data.length());
      config_->stats().need_more_data_.inc();
      return Network::FilterStatus::StopIteration;
    }

    // Increment handshake received counter
    config_->stats().handshake_received_.inc();

    if (!isValidHandshakeResponse(data)) {
      closeConnection("Invalid MySQL handshake response", ErrorType::InvalidMessageLength);
      return Network::FilterStatus::StopIteration;
    }

    uint32_t capabilities = data.peekLEInt<uint32_t>(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::CAPABILITIES_FLAGS_OFFSET);
    bool ssl_requested =
        (capabilities & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL) != 0;

    if (!ssl_requested && mysql_config.require_tls().value()) {
      closeConnection("SSL required but not requested by client", ErrorType::SSLMismatch);
      return Network::FilterStatus::StopIteration;
    }

    // Check if SSL is requested or required
    if (ssl_requested || mysql_config.require_tls().value()) {
      config_->stats().client_using_ssl_.inc();
    } else {
      config_->stats().client_not_using_ssl_.inc();
    }

    // Drain the handshake packet
    uint32_t packet_length = data.peekLEInt<uint32_t>(0) & 0x00FFFFFF;
    buffer.drain(packet_length +
                 NetworkFilters::DatabricksSqlProxy::MySQLConstants::CAPABILITIES_FLAGS_OFFSET);

    config_->stats().handshake_success_.inc();
    return Network::FilterStatus::Continue;
  } catch (const EnvoyException& e) {
    ENVOY_LOG(error, "mysql_inspector: error processing data: {}", e.what());
    closeConnection(e.what(), ErrorType::ProtocolViolation);
    return Network::FilterStatus::StopIteration;
  }
}

/**
 * Handles the SSL request packet from the MySQL client. This packet is sent by the client to
 * request an SSL connection with the server. The packet is validated according to the MySQL
 * protocol specification for Protocol::SSLRequest.
 */
void MySQLInspector::handleSSLRequest(const Buffer::Instance& data, uint32_t packet_length) {
  ENVOY_LOG(debug, "mysql_inspector: client requested SSL");
  setShortHandshakeData(data, packet_length);
}

/**
 * Generates random authentication plugin data to be used in the MySQL handshake. This data serves
 * as a challenge sent to the client during authentication. The random data is generated using a
 * cryptographically secure random number generator.
 * @see
 * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
 */
void MySQLInspector::generateAuthPluginData() {
  // Use a single random device initialization and generate all bytes at once
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint8_t> dis(0, 255);

  std::generate(auth_plugin_data_.begin(), auth_plugin_data_.end(),
                [&dis, &gen]() { return dis(gen); });
}

/**
 * Sends the initial handshake packet from server to client during the MySQL connection phase. This
 * is the first packet sent by the server when a client connects, containing:
 * - Protocol version
 * - Server version
 * - Connection ID
 * - Authentication plugin data (challenge)
 * - Server capabilities
 * - Character set
 * - Server status
 * - Authentication plugin name
 *
 * The packet follows the MySQL protocol specification for Protocol::HandshakeV10.
 * @throws EnvoyException if writing the handshake packet to the socket fails
 * @see
 * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
 */
void MySQLInspector::sendInitialHandshake() {
  Buffer::OwnedImpl packet;  // Payload buffer
  Buffer::OwnedImpl encoded; // Final buffer with header

  // Generate random auth plugin data for authentication
  generateAuthPluginData();

  // Protocol version (1 byte)
  packet.writeByte(NetworkFilters::DatabricksSqlProxy::MySQLConstants::PROTOCOL_VERSION);

  // Server version string + NULL terminator (string[255] + 1 byte)
  packet.add(config_->mysqlConfig().server_version());
  packet.writeByte(0);

  // Connection ID (4 bytes, little-endian)
  uint32_t conn_id = static_cast<uint32_t>(cb_->socket().ioHandle().fdDoNotUse());
  packet.writeLEInt<uint32_t>(conn_id);

  // Auth plugin data part 1 (8 bytes) + filler (1 byte)
  packet.add(auth_plugin_data_.data(), 8);

  // `0` is a filler to terminate the first part of the scramble string.
  packet.writeByte(0);

  // Lower 2 bytes of capabilities (2 bytes, little-endian)
  packet.writeLEInt<uint16_t>(
      std::stoul(config_->mysqlConfig().server_capabilities(), nullptr, 16));

  // Character set (1 byte)
  packet.writeByte(config_->mysqlConfig().character_set_id());

  // Server status (2 bytes, little-endian)
  packet.writeLEInt<uint16_t>(
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::SERVER_STATUS_AUTOCOMMIT);

  // Upper 2 bytes of capabilities (2 bytes, little-endian)
  packet.writeLEInt<uint16_t>(
      std::stoul(config_->mysqlConfig().extended_server_capabilities(), nullptr, 16));

  // Auth plugin data length (including NULL terminator)
  packet.writeByte(NetworkFilters::DatabricksSqlProxy::MySQLConstants::AUTH_PLUGIN_DATA_LENGTH + 1);

  // Reserved bytes (10 bytes)
  packet.add(std::string(10, 0));

  // Auth plugin data part 2 (12 bytes)
  packet.add(auth_plugin_data_.data() + 8, 12);

  // Auth plugin name + NULL terminator
  packet.add(config_->mysqlConfig().auth_plugin_name());
  packet.writeByte(0);

  // Add packet length to encoded buffer
  const uint32_t payload_len = packet.length();

  // Write the payload header to the encoded buffer. Since this is the first packet, the sequence ID
  // is 0
  NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::writePayloadHeader(encoded, payload_len, 0);

  // Add and flush payload
  encoded.add(packet);

  ENVOY_LOG(debug, "mysql_inspector: sending initial handshake server greeting");
  NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::debugPacket(encoded, encoded.length());

  Api::IoCallUint64Result result = cb_->socket().ioHandle().write(encoded);
  if (!result.ok()) {
    throw EnvoyException(fmt::format("Failed to send initial handshake server greeting: {}",
                                     result.err_->getErrorDetails()));
  }

  // Increment the server greeting sent counter
  config_->stats().server_greeting_sent_.inc();
}

/**
 * Validates the handshake response packet received from the MySQL client. The handshake response
 * contains the client's capabilities, including SSL support, and is used to determine if the client
 * requested SSL. The packet is validated according to the MySQL protocol specification for
 * Protocol::HandshakeResponse41.
 *
 * Protocol Specs:
 * https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_connection_phase_packets_protocol_ssl_request.html
 */
bool MySQLInspector::isValidHandshakeResponse(const Buffer::Instance& data) {
  // Use the packet header struct to parse the packet
  NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::MySQLPacketHeader header =
      NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::MySQLPacketHeader::parseFromBuffer(
          data);

  ENVOY_LOG(debug, "mysql_inspector: received handshake response - length: {}, seq: {}",
            header.length, header.sequence_id);

  if (!NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::validatePacketHeader(data,
                                                                                  header.length)) {
    return false;
  }

  uint32_t capabilities = data.peekLEInt<uint32_t>(4);
  ENVOY_LOG(debug, "mysql_inspector: client capabilities: 0x{:x}", capabilities);

  if (capabilities & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL) {
    handleSSLRequest(data, header.length);

    // Dump packet data for debugging if debug logging is enabled
    NetworkFilters::DatabricksSqlProxy::MySQLPacketUtils::debugPacket(data, header.length);
  } else {
    ENVOY_LOG(debug, "mysql_inspector: client did not request SSL");
  }

  return true;
}

/**
 * Closes the MySQL connection due to an error condition. This method:
 * 1. Logs the error message
 * 2. Stores the error in dynamic metadata for monitoring
 * 3. Increments error statistics
 * 4. Closes the underlying socket connection
 *
 * @param error_msg Description of the error that caused the connection close
 * @param error_type Specific error type to increment the appropriate counter
 */
void MySQLInspector::closeConnection(const std::string& error_msg, ErrorType error_type) {
  ENVOY_LOG(error, "mysql_inspector: closing connection - {}", error_msg);

  Filter::setErrorMsgInDynamicMetadata(*cb_, error_msg);

  // Always increment the general error counter
  config_->stats().error_.inc();

  // Increment the specific error counter based on type
  switch (error_type) {
  case ErrorType::InvalidMessageLength:
    config_->stats().invalid_message_length_.inc();
    break;
  case ErrorType::ProtocolViolation:
    config_->stats().protocol_violation_.inc();
    break;
  case ErrorType::HandshakeResponseFailed:
    config_->stats().handshake_response_failed_.inc();
    break;
  case ErrorType::SSLMismatch:
    config_->stats().ssl_mismatch_.inc();
    break;
  case ErrorType::General:
    // Only the general error counter was incremented above
    break;
  }

  cb_->socket().ioHandle().close();
}

/**
 * Stores the first 36 bytes of the handshake response in dynamic metadata for later use. This data
 * is needed when establishing an SSL connection with the upstream server. The stored data will be
 * decoded and replayed during the upstream SSL handshake process.
 *
 * @param data The buffer containing the handshake response
 * @param length The total length of the handshake response
 */
void MySQLInspector::setShortHandshakeData(const Buffer::Instance& data, uint32_t length) {
  try {
    std::vector<uint8_t> binary_data(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH, 0);
    data.copyOut(
        0,
        std::min(length,
                 NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH),
        binary_data.data());

    // Base64 encoding is used because:
    // 1. The handshake data contains binary values that may not be safely stored as strings
    // 2. Protobuf's string fields expect valid UTF-8, which binary data may not be
    // 3. Base64 encoding provides a safe way to store binary data as ASCII text
    std::string base64_data =
        Envoy::Base64::encode(reinterpret_cast<const char*>(binary_data.data()), binary_data.size(),
                              /*add_padding=*/true);

    ProtobufWkt::Struct metadata;
    (*metadata.mutable_fields())[CommonConstants::SHORT_HANDSHAKE_KEY].set_string_value(
        base64_data);

    // Store the handshake data in dynamic metadata for later use under the inspector filter's
    // namespace
    cb_->setDynamicMetadata(Filter::name(), metadata);
  } catch (const EnvoyException& e) {
    ENVOY_LOG(error, "mysql_inspector: failed to set short handshake data: {}", e.what());
    closeConnection(e.what(), ErrorType::HandshakeResponseFailed);
  }
}

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
