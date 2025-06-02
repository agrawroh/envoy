#include "databricks_mysql_proxy.h"

#include "source/common/common/base64.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/protobuf/utility.h"
#include "source/common/router/string_accessor_impl.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;
using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Processes the first message received from a MySQL client. This function validates packet
 * structure, extracts sequence numbers and capabilities, and initiates handshake parsing.
 *
 * The MySQL protocol requires packets to begin with a 3-byte length field followed by
 * a 1-byte sequence number, then the payload data.
 *
 * @param data The buffer containing the client message
 * @return true if message processing was successful, false if invalid or incomplete
 */
bool MySQLProxy::processClientFirstMessage(Buffer::Instance& data) {
  if (!read_callbacks_ || !write_callbacks_) {
    ENVOY_LOG(error, "mysql_proxy: callbacks not initialized");
    return false;
  }

  if (data.length() < NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH) {
    ENVOY_CONN_LOG(debug, "mysql_proxy: insufficient data: {}", read_callbacks_->connection(),
                   data.length());
    return false;
  }

  // Peek at the packet length without consuming it from the buffer. The packet length is encoded in
  // the first 3 bytes of the packet. See https://dev.mysql.com/doc/internals/en/mysql-packet.html
  uint32_t packet_length = data.peekLEInt<uint32_t>(0) & 0x00FFFFFF;
  uint8_t seq = data.peekLEInt<uint8_t>(3);

  // Validate the packet
  if (packet_length > NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_PACKET_SIZE) {
    ENVOY_CONN_LOG(error, "mysql_proxy: packet too large: {}", read_callbacks_->connection(),
                   packet_length);
    config_->stats().malformed_packet_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_NET_PACKET_TOO_LARGE,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
        "Packet too large.", "Maximum allowed packet size exceeded");
    closeWithError("Packet size exceeds maximum allowed",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Check for complete packet (includes header + payload)
  const uint64_t required_size =
      static_cast<uint64_t>(packet_length) +
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH;
  if (required_size > data.length() ||
      required_size > NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_PACKET_SIZE +
                          NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH) {
    if (required_size > NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_PACKET_SIZE +
                            NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH) {
      ENVOY_CONN_LOG(error, "mysql_proxy: packet size overflow: {} + {}",
                     read_callbacks_->connection(), packet_length,
                     NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH);
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_NET_PACKET_TOO_LARGE,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Packet too large.", "Packet size calculation overflow");
      closeWithError("Packet size overflow", StreamInfo::CoreResponseFlag::DownstreamProtocolError);
      return false;
    }
    ENVOY_CONN_LOG(debug, "mysql_proxy: incomplete packet, waiting for more data",
                   read_callbacks_->connection());
    return false;
  }

  // Dump packet data for debugging if debug logging is enabled
  MySQLPacketUtils::debugPacket(data, data.length());

  // Store the raw sequence number for later validation
  const uint8_t raw_seq = seq;

  // This will drain the header from the copied packet
  uint32_t payload_length;
  uint8_t sequence;
  if (!MySQLPacketUtils::decode(data, payload_length, sequence)) {
    config_->stats().malformed_packet_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
        "Malformed packet.", "Invalid packet structure");
    closeWithError("Malformed MySQL packet", StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Verify sequence numbers match
  if (sequence != raw_seq) {
    ENVOY_CONN_LOG(error, "mysql_proxy: sequence number mismatch after decode: {} vs {}",
                   read_callbacks_->connection(), raw_seq, sequence);
    config_->stats().protocol_violation_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_HANDSHAKE_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_HANDSHAKE_ERROR,
        "Protocol violation.", "Sequence number mismatch");
    closeWithError("Sequence number mismatch",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Determine expected sequence number based on SSL capability
  // 1. For non-SSL connections: The first packet from client is the handshake response with seq=1
  // 2. For SSL connections: Client first sends short handshake (seq=1), then after SSL handshake
  //    the client sends long handshake with seq=2
  bool is_ssl_established = read_callbacks_->connection().ssl() != nullptr;
  ENVOY_CONN_LOG(debug, "mysql_proxy: SSL established: {}", read_callbacks_->connection(),
                 is_ssl_established);
  const uint8_t expected_seq = (is_ssl_established) ? 2 : 1;

  if (seq != expected_seq) {
    ENVOY_CONN_LOG(error, "mysql_proxy: invalid sequence number: {} expected: {}",
                   read_callbacks_->connection(), seq, expected_seq);
    config_->stats().protocol_violation_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_HANDSHAKE_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_HANDSHAKE_ERROR,
        "Protocol violation.", "Invalid sequence number in handshake");
    closeWithError("Invalid sequence number in handshake",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  return parseHandshakeResponse(data);
}

/**
 * Handles data received from the upstream MySQL server. This function processes server greeting
 * packets during initial connection setup and transitions the proxy to SSL mode if configured.
 *
 * @param data The buffer containing data from the upstream server
 * @param end_stream Flag indicating if this is the final data chunk
 * @return FilterStatus determining whether to continue filter chain processing
 */
Network::FilterStatus MySQLProxy::handleUpstreamData(Buffer::Instance& data, bool) {
  ENVOY_LOG(debug, "mysql_proxy: handleUpstreamData: {} bytes", data.length());
  if (!read_callbacks_ || !write_callbacks_) {
    ENVOY_LOG(error, "mysql_proxy: callbacks not initialized");
    return Network::FilterStatus::StopIteration;
  }

  if (upstream_handshake_state_ == UpstreamHandshakeState::Error) {
    return Network::FilterStatus::StopIteration;
  }

  if (upstream_handshake_state_ == UpstreamHandshakeState::Init) {
    if (data.length() < NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH) {
      ENVOY_CONN_LOG(error, "mysql_proxy: server greeting too short",
                     read_callbacks_->connection());
      config_->stats().malformed_packet_.inc();
      return Network::FilterStatus::StopIteration;
    }

    uint32_t packet_length;
    uint8_t seq;

    if (!MySQLPacketUtils::decode(data, packet_length, seq)) {
      config_->stats().malformed_packet_.inc();
      return Network::FilterStatus::StopIteration;
    }

    // Validate server capabilities
    if (data.length() < packet_length || packet_length < 4) {
      ENVOY_CONN_LOG(error, "mysql_proxy: incomplete server greeting",
                     read_callbacks_->connection());
      config_->stats().malformed_packet_.inc();
      return Network::FilterStatus::StopIteration;
    }

    // Store server capabilities
    server_capabilities_ = data.peekLEInt<uint32_t>(4);
    data.drain(packet_length);

    ENVOY_CONN_LOG(debug, "mysql_proxy: server greeting received", read_callbacks_->connection());
    if (config_->enableUpstreamTls()) {
      sendSslRequest();
      return Network::FilterStatus::StopIteration;
    } else {
      ENVOY_CONN_LOG(debug, "mysql_proxy: no SSL requested, continuing with rest of the workflow",
                     read_callbacks_->connection());

      Buffer::OwnedImpl complete_packet;
      MySQLPacketUtils::encode(complete_packet, temp_handshake_packet_, HANDSHAKE_NO_SSL_SEQ_ID);
      MySQLPacketUtils::debugPacket(complete_packet, complete_packet.length());

      ENVOY_CONN_LOG(debug, "mysql_proxy: sending modified handshake packet",
                     read_callbacks_->connection());
      read_callbacks_->injectReadDataToFilterChain(complete_packet, false);
    }

    ENVOY_CONN_LOG(debug, "mysql_proxy: upstream handshake complete. setting SentHandshakeResponse",
                   read_callbacks_->connection());
    setUpstreamHandshakeState(UpstreamHandshakeState::SentHandshakeResponse);
  }

  return Network::FilterStatus::Continue;
}

/**
 * Parses the MySQL client handshake response packet. This function extracts and validates the
 * username, auth data, and other fields from the client handshake response according to the MySQL
 * protocol specification:
 * https://dev.mysql.com/doc/dev/mysql-server/9.1.0/page_protocol_connection_phase_packets_protocol_handshake_response.html
 *
 * It also handles the extraction of workspace ID and hostname from the username for routing
 * purposes.
 *
 * @param data The buffer containing the handshake response packet
 * @return true if parsing was successful, false if validation failed
 */
bool MySQLProxy::parseHandshakeResponse(Buffer::Instance& data) {
  const size_t len = data.length();
  if (len < NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_HANDSHAKE_SIZE) {
    ENVOY_CONN_LOG(error, "mysql_proxy: handshake packet too small", read_callbacks_->connection());
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_HANDSHAKE_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_HANDSHAKE_ERROR,
        "Invalid handshake packet.", "Packet too small");
    closeWithError("Handshake packet too small",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  const uint8_t* raw = static_cast<const uint8_t*>(data.linearize(len));
  if (!raw) {
    ENVOY_CONN_LOG(error, "mysql_proxy: failed to linearize buffer", read_callbacks_->connection());
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_INTERNAL_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
        "Internal server error.", "Failed to process handshake packet");
    closeWithError("Failed to linearize handshake buffer",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Extract client capabilities using our utility method
  if (!MySQLPacketUtils::extractClientCapabilities(data, client_capabilities_)) {
    ENVOY_CONN_LOG(error, "mysql_proxy: failed to extract client capabilities",
                   read_callbacks_->connection());
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
        "Malformed packet.", "Invalid packet structure");
    closeWithError("Failed to extract client capabilities",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Log client capabilities for debugging
  ENVOY_CONN_LOG(debug, "mysql_proxy: client capabilities: 0x{:08x}", read_callbacks_->connection(),
                 client_capabilities_);

  // Log specific capabilities relevant to authentication
  if (ENVOY_LOG_CHECK_LEVEL(debug)) {
    if (client_capabilities_ &
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH) {
      ENVOY_CONN_LOG(debug, "mysql_proxy: client supports plugin auth (CLIENT_PLUGIN_AUTH)",
                     read_callbacks_->connection());
    }
    if (client_capabilities_ &
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
      ENVOY_CONN_LOG(debug,
                     "mysql_proxy: client supports length-encoded auth data "
                     "(CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)",
                     read_callbacks_->connection());
    }
    if (client_capabilities_ &
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_WITH_DB) {
      ENVOY_CONN_LOG(debug, "mysql_proxy: client specifies database (CLIENT_CONNECT_WITH_DB)",
                     read_callbacks_->connection());
    }
    if (client_capabilities_ & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL) {
      ENVOY_CONN_LOG(debug, "mysql_proxy: client supports SSL (CLIENT_SSL)",
                     read_callbacks_->connection());
    }
  }

  // Create a modified capabilities flag if needed
  uint32_t modified_caps = client_capabilities_;
  if (config_->enableUpstreamTls()) {
    // Only add SSL capability if upstream requires TLS and client doesn't already have it
    if (!(modified_caps & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL)) {
      ENVOY_CONN_LOG(debug, "mysql_proxy: adding CLIENT_SSL capability flag (0x{:08x} -> 0x{:08x})",
                     read_callbacks_->connection(), modified_caps,
                     modified_caps |
                         NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL);
      modified_caps |= NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL;
    }
  } else if (modified_caps & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL) {
    // If upstream doesn't support TLS but client requested it, we need to remove the flag
    ENVOY_CONN_LOG(debug, "mysql_proxy: removing CLIENT_SSL capability flag (0x{:08x} -> 0x{:08x})",
                   read_callbacks_->connection(), modified_caps,
                   modified_caps & ~NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL);
    modified_caps &= ~NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL;
  }

  // Skip capabilities (4 bytes), max packet size (4 bytes), charset (1 byte),
  // and reserved bytes (23 bytes) to get to the username
  size_t offset = 4 + 4 + 1 + 23;

  // Find username boundaries
  size_t username_start = offset;
  size_t username_end = offset;
  while (username_end < len && raw[username_end] != 0) {
    username_end++;
  }

  if (username_end >= len) {
    ENVOY_CONN_LOG(error, "mysql_proxy: missing null terminator for username",
                   read_callbacks_->connection());
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
        "Malformed packet.", "Invalid username format");
    closeWithError("Missing null terminator for username",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Extract username string
  std::string full_username(reinterpret_cast<const char*>(raw + username_start),
                            username_end - username_start);

  // Process username after validation
  if (!validateUsername(full_username)) {
    closeWithError("Invalid username format",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  std::string extracted_username, workspace_id, hostname;
  if (!extractUserDetails(full_username, extracted_username, workspace_id, hostname)) {
    closeWithError("Failed to extract username parts",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Move past username (including null terminator)
  size_t current_pos = username_end + 1;

  // Extract authentication data
  AuthData auth_data;
  if (!extractAuthenticationData(data, current_pos, auth_data)) {
    closeWithError("Failed to extract authentication data",
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Store the auth data for later use
  client_auth_data_ = auth_data;

  // Log auth plugin details for debugging
  ENVOY_CONN_LOG(debug,
                 "mysql_proxy: auth plugin '{}' detected, native_password={}, auth_data_size={}",
                 read_callbacks_->connection(), auth_data.auth_plugin_name,
                 auth_data.is_native_password ? "true" : "false", auth_data.auth_response.size());

  // Extract database name if CLIENT_CONNECT_WITH_DB is set
  std::string database_name;
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_WITH_DB) {
    // Database name is a null-terminated string
    size_t db_start = current_pos;
    while (current_pos < len && raw[current_pos] != 0) {
      current_pos++;
    }

    // Check for malformed packets which might not have the null terminator
    if (current_pos < len) {
      database_name.assign(reinterpret_cast<const char*>(raw + db_start), current_pos - db_start);
      current_pos++; // Skip null terminator
      ENVOY_CONN_LOG(debug, "mysql_proxy: database name: '{}'", read_callbacks_->connection(),
                     database_name);
    } else {
      ENVOY_CONN_LOG(warn, "mysql_proxy: missing null terminator for database name",
                     read_callbacks_->connection());
    }
  }

  // Extract connection attributes if CLIENT_CONNECT_ATTRS is set
  std::vector<MySQLPacketUtils::MySQLConnectionAttribute> connection_attributes;
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_ATTRS) {
    // Reserve capacity based on typical number of attributes to avoid reallocations
    connection_attributes.reserve(8);
    connection_attributes =
        MySQLPacketUtils::extractConnectionAttributes(data, current_pos, client_capabilities_);
  }

  // Now we can build the modified packet in a single pass
  Buffer::OwnedImpl new_packet;

  // 1. Write capabilities (modified if needed)
  new_packet.writeLEInt<uint16_t>(modified_caps & 0xFFFF);         // Lower capability bytes
  new_packet.writeLEInt<uint16_t>((modified_caps >> 16) & 0xFFFF); // Upper capability bytes

  // 2. Copy max packet size, charset, and reserved bytes (4+1+23 bytes)
  new_packet.add(raw + 4, 28);

  // 3. Write modified username
  new_packet.add(extracted_username);
  new_packet.writeByte(0); // Null terminator

  // 4. Add authentication data with proper preservation
  preserveAuthData(new_packet, auth_data, modified_caps);

  // 5. Add database name if present
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_WITH_DB) {
    new_packet.add(database_name);
    new_packet.writeByte(0); // Null terminator
  }

  // 6. Add auth plugin name if CLIENT_PLUGIN_AUTH is set
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH) {
    new_packet.add(auth_data.auth_plugin_name);
    new_packet.writeByte(0); // Null terminator
  }

  // 7. Add connection attributes if present
  if (client_capabilities_ &
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_ATTRS &&
      !connection_attributes.empty()) {

    // Calculate total length of all attributes
    size_t total_length = 0;
    for (const auto& attr : connection_attributes) {
      // Length of key length + key + value length + value
      total_length +=
          MySQLPacketUtils::getLengthEncodedIntegerSize(attr.key.length()) + attr.key.length() +
          MySQLPacketUtils::getLengthEncodedIntegerSize(attr.value.length()) + attr.value.length();
    }

    // Write total length as length-encoded integer
    MySQLPacketUtils::writeLengthEncodedInteger(new_packet, total_length);

    // Write each attribute
    for (const auto& attr : connection_attributes) {
      // Write key
      MySQLPacketUtils::writeLengthEncodedInteger(new_packet, attr.key.length());
      new_packet.add(attr.key);

      // Write value
      MySQLPacketUtils::writeLengthEncodedInteger(new_packet, attr.value.length());
      new_packet.add(attr.value);
    }
  }

  // Store finalized packet
  ENVOY_CONN_LOG(debug, "mysql_proxy: storing modified packet (size: {})",
                 read_callbacks_->connection(), new_packet.length());
  temp_handshake_packet_ = std::move(new_packet);

  // Set metadata and routing info
  setConnectionMetadata(extracted_username, workspace_id, hostname);
  setAuthMetadata(auth_data);

  // Add the database to metadata if it's present
  if (!database_name.empty()) {
    // Get the existing metadata
    auto& stream_info = read_callbacks_->connection().streamInfo();
    const auto& existing_metadata = stream_info.dynamicMetadata().filter_metadata();

    // Create a new metadata struct
    ProtobufWkt::Struct metadata;

    // Copy existing metadata if it exists
    auto it = existing_metadata.find(NetworkFilterNames::get().DatabricksSqlProxy);
    if (it != existing_metadata.end()) {
      metadata = it->second;
    }

    // Get or create connection_string_options
    ProtobufWkt::Struct connection_string_options;
    if (metadata.fields().contains(CommonConstants::CONNECTION_STRING_OPTIONS_KEY)) {
      connection_string_options =
          metadata.fields().at(CommonConstants::CONNECTION_STRING_OPTIONS_KEY).struct_value();
    }

    // Add database name
    (*connection_string_options.mutable_fields())[CommonConstants::DATABASE_KEY].set_string_value(
        database_name);

    // Update connection_string_options in metadata
    (*metadata.mutable_fields())[CommonConstants::CONNECTION_STRING_OPTIONS_KEY]
        .mutable_struct_value()
        ->CopyFrom(connection_string_options);

    // Set the updated metadata
    stream_info.setDynamicMetadata(NetworkFilterNames::get().DatabricksSqlProxy, metadata);

    ENVOY_CONN_LOG(debug, "mysql_proxy: extracted database name: '{}'",
                   read_callbacks_->connection(), database_name);
  }

  // Add connection attributes to metadata if present
  if (!connection_attributes.empty()) {
    // Get the existing metadata
    auto& stream_info = read_callbacks_->connection().streamInfo();
    const auto& existing_metadata = stream_info.dynamicMetadata().filter_metadata();

    // Create a new metadata struct
    ProtobufWkt::Struct metadata;

    // Copy existing metadata if it exists
    auto it = existing_metadata.find(NetworkFilterNames::get().DatabricksSqlProxy);
    if (it != existing_metadata.end()) {
      metadata = it->second;
    }

    // Create a ListValue to hold the attributes
    ProtobufWkt::ListValue attributes_list;

    for (const auto& attr : connection_attributes) {
      // For each attribute, create a Struct with "key" and "value" fields
      ProtobufWkt::Struct attr_struct;
      (*attr_struct.mutable_fields())["key"].set_string_value(attr.key);
      (*attr_struct.mutable_fields())["value"].set_string_value(attr.value);

      // Add the Struct to the ListValue
      *attributes_list.add_values()->mutable_struct_value() = attr_struct;
    }

    // Add the ListValue to the metadata
    (*metadata.mutable_fields())[CommonConstants::ADDITIONAL_CONNECTION_ATTRS_KEY]
        .mutable_list_value()
        ->MergeFrom(attributes_list);

    // Set the updated metadata
    stream_info.setDynamicMetadata(NetworkFilterNames::get().DatabricksSqlProxy, metadata);

    ENVOY_CONN_LOG(debug, "mysql_proxy: stored {} connection attributes",
                   read_callbacks_->connection(), connection_attributes.size());
  }

  // Drain original data
  data.drain(len);

  // Check if hostname is allowed to connect
  if (!isHostnameAllowed(hostname)) {
    config_->stats().access_denied_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for hostname.", "Connection to this hostname is not in the allowed list");
    closeWithError("Connection to non-allowed hostname: " + hostname,
                   StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    return false;
  }

  // Increment successful login stats
  config_->stats().successful_login_.inc();
  return true;
}

/**
 * Unimplemented. This function is not used in the MySQL proxy.
 */
void MySQLProxy::onUpstreamConnected() { throw EnvoyException("Unimplemented."); }

/**
 * Sends an SSL request packet to the upstream MySQL server. The packet includes the client
 * capabilities, maximum packet size, and character set. It either replays a captured SSL request
 * from the client or constructs a new one based on capabilities.
 */
void MySQLProxy::sendSslRequest() {
  ENVOY_CONN_LOG(debug, "mysql_proxy: sending SSL request", read_callbacks_->connection());
  Buffer::OwnedImpl ssl_request;

  if (read_callbacks_->connection().ssl()) {
    // Replay stored handshake from metadata if available. It comes from the MySQL Inspector which
    // is installed as a listener filter.
    const auto& metadata =
        read_callbacks_->connection().streamInfo().dynamicMetadata().filter_metadata();

    auto it = metadata.find(CommonConstants::DATABRICKS_SQL_INSPECTOR_FILTER_NAMESPACE);
    if (it == metadata.end()) {
      closeWithError("Missing proxy metadata",
                     StreamInfo::CoreResponseFlag::DownstreamProtocolError);
      return;
    }

    const auto& fields = it->second.fields();
    auto handshake_it = fields.find(CommonConstants::SHORT_HANDSHAKE_KEY);
    if (handshake_it == fields.end()) {
      closeWithError("Missing handshake data",
                     StreamInfo::CoreResponseFlag::DownstreamProtocolError);
      return;
    }

    std::string base64_data = handshake_it->second.string_value();
    auto binary_data = Base64::decode(base64_data);
    if (binary_data.empty()) {
      closeWithError("Invalid handshake data",
                     StreamInfo::CoreResponseFlag::DownstreamProtocolError);
      return;
    }

    ssl_request.add(binary_data.data(), binary_data.size());
  } else {
    // Build new SSL request
    Buffer::OwnedImpl packet;
    buildSslRequestPacket(packet);
    MySQLPacketUtils::encode(ssl_request, packet, 1);
  }
  // Dump packet data for debugging if debug logging is enabled
  MySQLPacketUtils::debugPacket(ssl_request, ssl_request.length());

  read_callbacks_->injectReadDataToFilterChain(ssl_request, false);
  setUpstreamHandshakeState(UpstreamHandshakeState::SentSslRequest);

  upstream_handshake_timer_ = read_callbacks_->connection().dispatcher().createTimer(
      [this]() -> void { checkUpstreamHandshakeProgress(); });
  upstream_handshake_timer_->enableTimer(
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::RETRY_INTERVAL);
}

/**
 * Periodically checks the progress of the upstream TLS handshake. If the handshake is not yet
 * complete, it will retry the handshake up to MAX_HANDSHAKE_ATTEMPTS times before giving up. If the
 * handshake is successful, it will modify the client capabilities to enable SSL and send the
 * modified handshake response to the upstream server.
 */
void MySQLProxy::checkUpstreamHandshakeProgress() {
  ENVOY_CONN_LOG(debug, "mysql_proxy: checking upstream handshake progress",
                 read_callbacks_->connection());
  if (upstream_handshake_state_ == UpstreamHandshakeState::SentSslRequest) {
    // Attempt to start TLS
    ENVOY_CONN_LOG(debug, "mysql_proxy: starting upstream secure transport",
                   read_callbacks_->connection());
    if (!read_callbacks_->startUpstreamSecureTransport()) {
      if (++handshake_attempts_ >=
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_HANDSHAKE_ATTEMPTS) {
        setUpstreamHandshakeState(UpstreamHandshakeState::Error);
        sendErrorResponseToDownstream(
            NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_NET_READ_ERROR,
            NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
            "Cannot establish secure connection to server.", "TLS handshake failed");
        closeWithError("TLS handshake failed", StreamInfo::CoreResponseFlag::UpstreamProtocolError);
        return;
      }
      // Retry
      upstream_handshake_timer_->enableTimer(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::RETRY_INTERVAL);
      return;
    }
    setUpstreamHandshakeState(UpstreamHandshakeState::WaitingForTls);
    handshake_attempts_ = 0;
  }

  if (upstream_handshake_state_ == UpstreamHandshakeState::WaitingForTls) {
    ENVOY_CONN_LOG(debug, "mysql_proxy: waiting for upstream TLS handshake",
                   read_callbacks_->connection());
    auto upstream_ssl = read_callbacks_->connection().streamInfo().upstreamInfo();
    if (!upstream_ssl || !upstream_ssl->upstreamSslConnection()) {
      upstream_handshake_timer_->enableTimer(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::RETRY_INTERVAL);
      return;
    }

    Buffer::OwnedImpl complete_packet;
    MySQLPacketUtils::encode(complete_packet, temp_handshake_packet_, HANDSHAKE_AFTER_SSL_SEQ_ID);

    ENVOY_CONN_LOG(debug, "mysql_proxy: sending modified handshake packet",
                   read_callbacks_->connection());
    MySQLPacketUtils::debugPacket(complete_packet, complete_packet.length());

    read_callbacks_->injectReadDataToFilterChain(complete_packet, false);
    setUpstreamHandshakeState(UpstreamHandshakeState::SentHandshakeResponse);
    upstream_handshake_timer_->disableTimer();
  }
}

/**
 * Constructs an SSL request packet according to MySQL protocol. Constructed packet has necessary
 * capabilities flags, max packet size, charset, and reserved bytes for initiating SSL with the
 * MySQL server.
 *
 * @param packet The buffer to populate with the SSL request
 */
void MySQLProxy::buildSslRequestPacket(Buffer::Instance& packet) {
  uint32_t capabilities =
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::REQUIRED_CAPABILITIES |
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_SSL |
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_WITH_DB;

  packet.writeLEInt<uint32_t>(capabilities);
  packet.writeLEInt<uint32_t>(NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_PACKET_SIZE);
  packet.writeByte(NetworkFilters::DatabricksSqlProxy::MySQLConstants::DEFAULT_CHARSET_ID);
  packet.add(std::string(23, 0)); // Reserved bytes

  if (packet.length() != NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_HANDSHAKE_SIZE) {
    ENVOY_LOG(error, "mysql_proxy: invalid SSL request packet size: {}", packet.length());
  }
}

/**
 * Validates MySQL usernames according to security and protocol requirements.
 * Performs the following checks:
 * 1. Username must not be empty
 * 2. Username length must not exceed MAX_USERNAME_LENGTH
 * 3. Username must not contain special characters that could be used for SQL injection
 *    or path traversal (<, >, ", ', /, \)
 *
 * @param username The username to validate
 * @return true if username is valid, false otherwise
 */
bool MySQLProxy::validateUsername(const std::string& username) {
  // Length validation (4-32 characters typical)
  if (username.empty() ||
      username.length() > NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_USERNAME_LENGTH) {
    ENVOY_CONN_LOG(error, "mysql_proxy: invalid username length: {}", read_callbacks_->connection(),
                   username.length());
    config_->stats().invalid_username_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for user.", "Username length invalid");
    return false;
  }

  // SQL injection prevention through character blacklisting
  // See: https://wiki.sei.cmu.edu/confluence/display/java/IDS00-J.+Prevent+SQL+injection
  // Blocks characters that could enable injection attacks or path traversal
  static const std::string invalid_chars = "<>\"'/\\";
  if (username.find_first_of(invalid_chars) != std::string::npos) {
    ENVOY_CONN_LOG(error, "mysql_proxy: username contains invalid characters",
                   read_callbacks_->connection());
    config_->stats().invalid_username_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for user.", "Username contains invalid characters");
    return false;
  }

  return true;
}

/**
 * Validates authentication data within a packet and verifies that auth data:
 * 1. Does not exceed packet bounds
 * 2. Does not contain null bytes (which are not allowed in auth data)
 *
 * @param data The buffer containing auth data
 * @param offset Starting position of auth data
 * @param length Length of auth data
 * @return true if auth data is valid, false otherwise
 */
bool MySQLProxy::validateAuthData(const Buffer::Instance& data, size_t offset, uint8_t length) {
  if (offset + length > data.length()) {
    ENVOY_CONN_LOG(error, "mysql_proxy: auth data exceeds packet bounds",
                   read_callbacks_->connection());
    config_->stats().malformed_packet_.inc();
    return false;
  }

  // Verify auth data contains only valid bytes
  for (size_t i = 0; i < length; i++) {
    uint8_t byte = data.peekBEInt<uint8_t>(offset + i);
    if (byte == 0) {
      ENVOY_CONN_LOG(error, "mysql_proxy: auth data contains null byte",
                     read_callbacks_->connection());
      config_->stats().protocol_violation_.inc();
      return false;
    }
  }

  return true;
}

/**
 * Extracts username, workspace ID, and hostname from the full username string. It parses the
 * username string using a regex pattern (typically in format "username@workspaceId_hostname") to
 * extract individual components needed for routing and authentication.
 *
 * @param username_string The full username from client handshake
 * @param extracted_username Output parameter for the actual username
 * @param workspace_id Output parameter for the workspace ID
 * @param hostname Output parameter for the hostname
 * @return true if extraction succeeded, false otherwise
 */
bool MySQLProxy::extractUserDetails(const std::string& username_string,
                                    std::string& extracted_username, std::string& workspace_id,
                                    std::string& hostname) {
  if (!regex_pattern_) {
    ENVOY_CONN_LOG(error, "mysql_proxy: regex pattern not initialized",
                   read_callbacks_->connection());
    config_->stats().username_extraction_failed_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_INTERNAL_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
        "Internal server error.", "Username extraction failed");
    return false;
  }

  if (!regex_pattern_->match(username_string)) {
    ENVOY_CONN_LOG(error, "mysql_proxy: username: '{}' does not match defined RegEx pattern",
                   read_callbacks_->connection(), username_string);
    config_->stats().username_extraction_failed_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for user.", "Invalid username format");
    return false;
  }

  // Reserve capacity for extracted strings to avoid reallocations
  extracted_username.reserve(username_string.length());
  workspace_id.reserve(32); // Typical workspace ID length
  hostname.reserve(64);     // Typical hostname length

  // Pattern should be something like "^([^@]+)@([^_]+)_(.+)$" as expect it to have 3 things in this
  // format: username@workspaceId_hostname
  const std::string& pattern = config_->protoConfig().mysql_config().username_pattern();
  re2::RE2 re2_pattern(pattern);
  if (!re2_pattern.ok() || !re2::RE2::FullMatch(username_string, re2_pattern, &extracted_username,
                                                &workspace_id, &hostname)) {
    ENVOY_CONN_LOG(error,
                   "mysql_proxy: failed to extract username parts from username string: '{}'",
                   read_callbacks_->connection(), username_string);
    config_->stats().username_extraction_failed_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for user.", "Invalid username format. Failed to extract username parts");
    return false;
  }

  if (extracted_username.empty() || workspace_id.empty() || hostname.empty()) {
    ENVOY_CONN_LOG(error,
                   "mysql_proxy: empty username parts after extraction. username: '{}', workspace: "
                   "'{}', hostname: '{}'",
                   read_callbacks_->connection(), extracted_username, workspace_id, hostname);
    config_->stats().username_extraction_failed_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_ACCESS_DENIED_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_ACCESS_DENIED,
        "Access denied for user.", "Invalid username format");
    return false;
  }

  ENVOY_CONN_LOG(debug, "mysql_proxy: extracted username='{}', workspace='{}', hostname='{}'",
                 read_callbacks_->connection(), extracted_username, workspace_id, hostname);

  return true;
}

/**
 * Sets dynamic metadata in the connection's stream info with the extracted username, workspace ID,
 * and hostname, which can be used by other filters and for logging. It also sets routing
 * information based on the configured destination cluster source.
 *
 * @param username The extracted username
 * @param workspace_id The extracted workspace ID
 * @param hostname The extracted hostname for routing
 */
void MySQLProxy::setConnectionMetadata(const std::string& username, const std::string& workspace_id,
                                       const std::string& hostname) {
  ENVOY_CONN_LOG(
      debug, "mysql_proxy: setting connection metadata username: {}, workspace: {}, hostname: {}",
      read_callbacks_->connection(), username, workspace_id, hostname);

  ProtobufWkt::Struct connection_string_options;
  (*connection_string_options.mutable_fields())[CommonConstants::USERNAME_KEY].set_string_value(
      username);

  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::CONNECTION_STRING_OPTIONS_KEY]
      .mutable_struct_value()
      ->MergeFrom(connection_string_options);

  (*metadata.mutable_fields())[CommonConstants::ORG_ID_KEY].set_string_value(workspace_id);
  (*metadata.mutable_fields())[CommonConstants::HOSTNAME_KEY].set_string_value(hostname);

  // Set routing information based on config
  setRoutingMetadata(Network::UpstreamServerName::key(),
                     std::make_unique<Network::UpstreamServerName>(hostname));
  if (config_->destinationClusterSource() == DatabricksSqlProxyProto::SNI) {
    setRoutingMetadata(TcpProxy::PerConnectionCluster::key(),
                       std::make_unique<TcpProxy::PerConnectionCluster>(hostname));
  } else if (config_->destinationClusterSource() ==
             DatabricksSqlProxyProto::DYNAMIC_FORWARD_PROXY) {
    (*metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY].set_string_value(
        CommonConstants::DYNAMIC_FORWARD_PROXY_KEY);
    setRoutingMetadata("envoy.upstream.dynamic_host",
                       std::make_unique<Router::StringAccessorImpl>(hostname));
  }

  // Set the metadata in the connection's stream info
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);
}

/**
 * This method stores routing information in the connection's filter state, which will be used by
 * the TCP proxy filter to route the connection to the appropriate upstream cluster.
 *
 * @param key The filter state key
 * @param value The filter state value object
 */
void MySQLProxy::setRoutingMetadata(const std::string& key,
                                    std::shared_ptr<Envoy::StreamInfo::FilterState::Object> value) {
  read_callbacks_->connection().streamInfo().filterState()->setData(
      key, value, StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Connection);
}

/**
 * Closes the connection with an error message. It sets appropriate error details and response flags
 * in the connection's stream info before closing the connection.
 *
 * @param message The error message to log
 * @param response_flag The response flag to set in stream info
 */
void MySQLProxy::closeWithError(const std::string& message,
                                StreamInfo::CoreResponseFlag response_flag) {
  if (!read_callbacks_ || connection_closed_) {
    return;
  }

  ENVOY_CONN_LOG(error, "mysql_proxy: {}", read_callbacks_->connection(), message);
  parent_.closeConnection(message, response_flag);
  connection_closed_ = true;
  config_->stats().errors_.inc();
}

/**
 * Tracks the current state of the upstream handshake process and makes it available in connection
 * metadata for debugging and logging.
 *
 * @param state The new upstream handshake state
 */
void MySQLProxy::setUpstreamHandshakeState(UpstreamHandshakeState state) {
  upstream_handshake_state_ = state;

  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::UPSTREAM_HANDSHAKE_STATE_KEY].set_number_value(
      static_cast<int>(state));
  (*metadata.mutable_fields())[CommonConstants::CLIENT_CAPABILITIES_KEY].set_number_value(
      client_capabilities_);

  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);
}

/**
 * Constructs and sends a MySQL protocol error packet to inform the client about an error condition.
 * The packet contains an error code, SQL state, and human-readable error message.
 *
 * @param error_code The MySQL error code
 * @param sql_state The SQL state string (5 characters)
 * @param error_message The human-readable error message
 * @param detail_message Optional detailed error information
 */
void MySQLProxy::sendErrorResponseToDownstream(int16_t error_code, absl::string_view sql_state,
                                               absl::string_view error_message,
                                               absl::string_view detail_message) {
  ENVOY_CONN_LOG(debug, "mysql_proxy: sending error to downstream - code: {}, message: {}",
                 read_callbacks_->connection(), error_code, error_message);

  if (connection_closed_) {
    ENVOY_CONN_LOG(error, "mysql_proxy: cannot send error, connection already closed",
                   read_callbacks_->connection());
    return;
  }

  // Create a buffer for the error response
  Buffer::OwnedImpl error_packet;

  // Error packet contents
  Buffer::OwnedImpl payload;

  // Header byte for error packet
  payload.writeByte(0xFF); // Error packet indicator

  // Error code (2 bytes)
  payload.writeLEInt<uint16_t>(error_code);

  // SQL state marker '#' and SQL state code (6 bytes total)
  payload.writeByte('#');
  payload.add(sql_state.data(), sql_state.size());

  // Error message
  payload.add(error_message.data(), error_message.size());

  // Detail message (MySQL doesn't have a separate detail field,
  // but we can append it to the error message if provided)
  if (!detail_message.empty()) {
    payload.writeByte(' '); // Space separator
    payload.add(detail_message.data(), detail_message.size());
  }

  // Encode the packet with header (sequence ID 1 for error response)
  MySQLPacketUtils::encode(error_packet, payload, 1);

  // Log the packet for debugging
  MySQLPacketUtils::debugPacket(error_packet, error_packet.length());

  // Send to client
  if (write_callbacks_) {
    write_callbacks_->injectWriteDataToFilterChain(error_packet, false);

    // Instead of immediately closing the connection, mark it for delayed closure and allow the
    // client to process the error. If we don't do this then clients fail to drain the data from the
    // socket and the connection is closed before the clients get a chance to process the error
    // message.
    error_response_timer_ = read_callbacks_->connection().dispatcher().createTimer([this]() {
      if (!connection_closed_) {
        connection_closed_ = true; // Mark as closed to prevent multiple errors
        // Use FlushWrite to ensure the error message is sent before closing the connection
        read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
      }
    });
    error_response_timer_->enableTimer(std::chrono::milliseconds(25));
  } else {
    ENVOY_CONN_LOG(error, "mysql_proxy: cannot send error, write callbacks not initialized",
                   read_callbacks_->connection());
  }
}

/**
 * Checks if the given hostname matches any of the allowed hostname patterns.
 * If no patterns are specified, all hostnames are allowed.
 * If patterns are specified, at least one must match for the hostname to be allowed.
 *
 * @param hostname The hostname to check against allowed patterns
 * @return true if hostname is allowed, false if it doesn't match any allowed pattern
 */
bool MySQLProxy::isHostnameAllowed(const std::string& hostname) {
  const auto& mysql_config = config_->protoConfig().mysql_config();
  const auto& allowed_patterns = mysql_config.allowed_hostname_patterns();

  if (allowed_patterns.empty()) {
    // No allowed patterns defined, all hostnames will be allowed
    return true;
  }

  // Check each pattern against the hostname
  for (const auto& pattern : allowed_patterns) {
    try {
      envoy::type::matcher::v3::RegexMatcher regex_config;
      regex_config.set_regex(pattern);

      auto matcher_result = Regex::CompiledGoogleReMatcher::create(regex_config);
      if (!matcher_result.ok()) {
        ENVOY_CONN_LOG(warn, "mysql_proxy: invalid allowed hostname pattern: {}, error: {}",
                       read_callbacks_->connection(), pattern, matcher_result.status().message());
        continue;
      }

      auto matcher = std::move(*matcher_result);
      if (matcher->match(hostname)) {
        ENVOY_CONN_LOG(debug, "mysql_proxy: hostname '{}' matches allowed pattern '{}'",
                       read_callbacks_->connection(), hostname, pattern);
        return true;
      }
    } catch (const EnvoyException& e) {
      ENVOY_CONN_LOG(error, "mysql_proxy: error checking hostname pattern: {}",
                     read_callbacks_->connection(), e.what());
    }
  }

  // If we get here, the hostname didn't match any allowed pattern
  ENVOY_CONN_LOG(info, "mysql_proxy: hostname '{}' doesn't match any allowed pattern",
                 read_callbacks_->connection(), hostname);
  return false;
}

/**
 * Creates a compiled regex matcher based on the pattern provided in the filter configuration, used
 * for extracting username components. The compiled matcher is stored in the filter for use during
 * the connection lifecycle.
 *
 * @return A unique pointer to the compiled regex matcher or nullptr on failure
 */
std::unique_ptr<Regex::CompiledGoogleReMatcher> MySQLProxy::compileRegexPattern() {
  if (!config_ || !config_->protoConfig().has_mysql_config()) {
    ENVOY_LOG(error, "mysql_proxy: missing mysql config");
    return nullptr;
  }

  const std::string& pattern = config_->protoConfig().mysql_config().username_pattern();
  if (pattern.empty()) {
    ENVOY_LOG(error, "mysql_proxy: empty username pattern");
    return nullptr;
  }

  envoy::type::matcher::v3::RegexMatcher regex_config;
  regex_config.set_regex(pattern);

  auto matcher = Regex::CompiledGoogleReMatcher::create(regex_config);
  if (!matcher.ok()) {
    ENVOY_LOG(error, "mysql_proxy: invalid regex pattern: {}", matcher.status().message());
    return nullptr;
  }

  return std::move(*matcher);
}

/**
 * Extracts authentication data from the client handshake response packet.
 * This includes authentication plugin name and authentication response data.
 *
 * @param data The buffer containing the handshake response
 * @param current_pos Position in the buffer where auth data starts
 * @param auth_data Output structure to store extracted auth data
 * @return true if extraction was successful, false otherwise
 */
bool MySQLProxy::extractAuthenticationData(Buffer::Instance& data, size_t& current_pos,
                                           AuthData& auth_data) {
  const size_t len = data.length();
  if (current_pos >= len) {
    ENVOY_CONN_LOG(error, "mysql_proxy: invalid position for auth data: {} (buffer length: {})",
                   read_callbacks_->connection(), current_pos, len);
    config_->stats().malformed_packet_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
        "Malformed packet.", "Invalid auth data position");
    return false;
  }

  const uint8_t* raw = static_cast<const uint8_t*>(data.linearize(len));
  if (!raw) {
    ENVOY_CONN_LOG(error, "mysql_proxy: failed to linearize buffer for auth data",
                   read_callbacks_->connection());
    config_->stats().malformed_packet_.inc();
    sendErrorResponseToDownstream(
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_INTERNAL_ERROR,
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
        "Internal server error.", "Failed to process authentication data");
    return false;
  }

  // Extract auth data response
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
    // If CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA is set, auth length is a length-encoded integer
    uint64_t auth_len;
    size_t len_bytes;
    if (!MySQLPacketUtils::decodeVariableLengthInteger(data, current_pos, auth_len, len_bytes)) {
      ENVOY_CONN_LOG(error, "mysql_proxy: failed to decode auth data length",
                     read_callbacks_->connection());
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Malformed packet.", "Invalid auth data length encoding");
      return false;
    }

    // Validate auth data length
    if (current_pos + len_bytes + auth_len > len) {
      ENVOY_CONN_LOG(error,
                     "mysql_proxy: auth data length exceeds packet bounds (pos: {}, len_bytes: {}, "
                     "auth_len: {}, buffer_len: {})",
                     read_callbacks_->connection(), current_pos, len_bytes, auth_len, len);
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Malformed packet.", "Auth data exceeds packet bounds");
      return false;
    }

    // Enforce a reasonable maximum size for auth data to prevent memory issues
    static constexpr uint64_t MAX_AUTH_DATA_LENGTH = 1024 * 64; // 64KB should be more than enough
    if (auth_len > MAX_AUTH_DATA_LENGTH) {
      ENVOY_CONN_LOG(error, "mysql_proxy: auth data length too large: {}",
                     read_callbacks_->connection(), auth_len);
      config_->stats().oversized_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_NET_PACKET_TOO_LARGE,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Auth data too large.", "Maximum allowed auth data size exceeded");
      return false;
    }

    // Skip length bytes
    current_pos += len_bytes;

    // Extract the auth data
    try {
      auth_data.auth_response.resize(auth_len);
      if (auth_len > 0) {
        if (current_pos + auth_len > len) {
          ENVOY_CONN_LOG(error, "mysql_proxy: auth data would read past buffer bounds",
                         read_callbacks_->connection());
          config_->stats().malformed_packet_.inc();
          sendErrorResponseToDownstream(
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
              "Malformed packet.", "Auth data extends beyond packet bounds");
          return false;
        }
        data.copyOut(current_pos, auth_len, auth_data.auth_response.data());
      }
      current_pos += auth_len;
    } catch (const std::bad_alloc& e) {
      ENVOY_CONN_LOG(error, "mysql_proxy: memory allocation failed for auth data: {}",
                     read_callbacks_->connection(), e.what());
      config_->stats().errors_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_OUT_OF_RESOURCES,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
          "Out of memory.", "Failed to allocate memory for auth data");
      return false;
    }
  } else {
    // Otherwise, it's a 1-byte length followed by data of that length
    if (current_pos >= len) {
      ENVOY_CONN_LOG(error, "mysql_proxy: missing auth data length byte",
                     read_callbacks_->connection());
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Malformed packet.", "Missing auth data length");
      return false;
    }

    uint8_t auth_len = raw[current_pos++];

    // Validate auth data length
    if (current_pos + auth_len > len) {
      ENVOY_CONN_LOG(error,
                     "mysql_proxy: auth data length exceeds packet bounds (pos: {}, auth_len: {}, "
                     "buffer_len: {})",
                     read_callbacks_->connection(), current_pos, auth_len, len);
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Malformed packet.", "Auth data exceeds packet bounds");
      return false;
    }

    // Extract the auth data
    try {
      auth_data.auth_response.resize(auth_len);
      if (auth_len > 0) {
        // Replace undefined safeMemcpy with proper bounds-checked copying
        // Ensure we don't read past the buffer
        if (current_pos + auth_len > len) {
          ENVOY_CONN_LOG(error, "mysql_proxy: auth data would read past buffer bounds",
                         read_callbacks_->connection());
          config_->stats().malformed_packet_.inc();
          sendErrorResponseToDownstream(
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
              "Malformed packet.", "Auth data extends beyond packet bounds");
          return false;
        }
        // Use Buffer::copyOut which is the preferred method in Envoy
        data.copyOut(current_pos, auth_len, auth_data.auth_response.data());
      }
      current_pos += auth_len;
    } catch (const std::bad_alloc& e) {
      ENVOY_CONN_LOG(error, "mysql_proxy: memory allocation failed for auth data: {}",
                     read_callbacks_->connection(), e.what());
      config_->stats().errors_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_OUT_OF_RESOURCES,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
          "Out of memory.", "Failed to allocate memory for auth data");
      return false;
    }
  }

  // Skip database name if present (we'll handle it in the main parsing function)
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_WITH_DB) {
    while (current_pos < len && raw[current_pos] != 0) {
      current_pos++;
    }
    if (current_pos < len) {
      current_pos++; // Skip null terminator
    }
  }

  // Extract auth plugin name if CLIENT_PLUGIN_AUTH is set
  if (client_capabilities_ &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH) {
    size_t plugin_start = current_pos;
    while (current_pos < len && raw[current_pos] != 0) {
      current_pos++;
    }

    if (current_pos >= len) {
      ENVOY_CONN_LOG(error, "mysql_proxy: missing null terminator for auth plugin name",
                     read_callbacks_->connection());
      config_->stats().malformed_packet_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
          "Malformed packet.", "Missing auth plugin name terminator");
      return false;
    }

    try {
      auth_data.auth_plugin_name.assign(reinterpret_cast<const char*>(raw + plugin_start),
                                        current_pos - plugin_start);
      current_pos++; // Skip null terminator

      // Validate auth plugin name length - MySQL plugin names should be reasonable
      if (auth_data.auth_plugin_name.length() > 64) {
        ENVOY_CONN_LOG(error, "mysql_proxy: auth plugin name too long: {} bytes",
                       read_callbacks_->connection(), auth_data.auth_plugin_name.length());
        config_->stats().malformed_packet_.inc();
        sendErrorResponseToDownstream(
            NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_MALFORMED_PACKET,
            NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_CONNECTION_ERROR,
            "Malformed packet.", "Auth plugin name too long");
        return false;
      }

      // Check if this is mysql_native_password
      auth_data.is_native_password = (auth_data.auth_plugin_name == "mysql_native_password");

      ENVOY_CONN_LOG(debug, "mysql_proxy: auth plugin: '{}', is_native_password: {}",
                     read_callbacks_->connection(), auth_data.auth_plugin_name,
                     auth_data.is_native_password ? "true" : "false");
    } catch (const std::exception& e) {
      ENVOY_CONN_LOG(error, "mysql_proxy: error processing auth plugin name: {}",
                     read_callbacks_->connection(), e.what());
      config_->stats().errors_.inc();
      sendErrorResponseToDownstream(
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::ER_INTERNAL_ERROR,
          NetworkFilters::DatabricksSqlProxy::MySQLConstants::SQL_STATE_INTERNAL_ERROR,
          "Internal error.", "Failed to process auth plugin name");
      return false;
    }
  } else {
    // If no plugin specified, default to mysql_native_password per MySQL protocol
    auth_data.auth_plugin_name = "mysql_native_password";
    auth_data.is_native_password = true;

    ENVOY_CONN_LOG(debug,
                   "mysql_proxy: no auth plugin specified, defaulting to mysql_native_password",
                   read_callbacks_->connection());
  }

  return true;
}

/**
 * Adds authentication data to the packet being built.
 * This properly formats the authentication data according to the client capabilities
 * and ensures compatibility with different auth plugins.
 *
 * @param new_packet The packet buffer being constructed
 * @param auth_data The authentication data to add
 * @param capabilities The client capabilities
 */
void MySQLProxy::preserveAuthData(Buffer::Instance& new_packet, const AuthData& auth_data,
                                  uint32_t capabilities) {
  const auto& auth_response = auth_data.auth_response;

  // Special handling for mysql_native_password which has fixed 20-byte length in protocol
  // See:
  // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods_native_password_authentication.html
  if (auth_data.is_native_password) {
    ENVOY_CONN_LOG(debug, "mysql_proxy: handling mysql_native_password auth data",
                   read_callbacks_->connection());

    if (capabilities &
        NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
      // When using length-encoded client data with mysql_native_password
      MySQLPacketUtils::writeLengthEncodedInteger(new_packet, auth_response.size());
      if (!auth_response.empty()) {
        new_packet.add(auth_response.data(), auth_response.size());
      }
    } else {
      // For mysql_native_password without CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
      // the auth data is always 20 bytes or 0 bytes (empty password)
      if (auth_response.empty()) {
        // Empty password case - write 0 length
        new_packet.writeByte(0);
      } else if (auth_response.size() == MySQLConstants::MYSQL_NATIVE_PASSWORD_LENGTH) {
        // Standard case - write length byte followed by 20 bytes
        new_packet.writeByte(MySQLConstants::MYSQL_NATIVE_PASSWORD_LENGTH);
        new_packet.add(auth_response.data(), MySQLConstants::MYSQL_NATIVE_PASSWORD_LENGTH);
      } else {
        // Non-standard size - this is an error for mysql_native_password
        ENVOY_CONN_LOG(
            error,
            "mysql_proxy: invalid mysql_native_password auth response size: {} (expected 0 or {})",
            read_callbacks_->connection(), auth_response.size(),
            MySQLConstants::MYSQL_NATIVE_PASSWORD_LENGTH);
        // Write the actual size and data anyway to preserve the client's intent
        new_packet.writeByte(
            static_cast<uint8_t>(std::min(auth_response.size(), static_cast<size_t>(255))));
        if (!auth_response.empty()) {
          new_packet.add(auth_response.data(),
                         std::min(auth_response.size(), static_cast<size_t>(255)));
        }
      }
    }

    ENVOY_CONN_LOG(debug, "mysql_proxy: wrote mysql_native_password auth data",
                   read_callbacks_->connection());
    return;
  }

  // For other auth plugins, use standard logic
  // Add auth response data according to capability flags
  if (capabilities &
      NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
    // Write auth data as length-encoded string
    MySQLPacketUtils::writeLengthEncodedInteger(new_packet, auth_response.size());
    if (!auth_response.empty()) {
      new_packet.add(auth_response.data(), auth_response.size());
    }

    ENVOY_CONN_LOG(debug, "mysql_proxy: wrote auth data as length-encoded string (length: {})",
                   read_callbacks_->connection(), auth_response.size());
  } else {
    // Write auth data as 1-byte length followed by data
    if (auth_response.size() > 255) {
      ENVOY_CONN_LOG(warn, "mysql_proxy: auth response truncated from {} to 255 bytes",
                     read_callbacks_->connection(), auth_response.size());
    }

    uint8_t auth_len =
        static_cast<uint8_t>(std::min(auth_response.size(), static_cast<size_t>(255)));
    new_packet.writeByte(auth_len);
    if (auth_len > 0) {
      new_packet.add(auth_response.data(), auth_len);
    }

    ENVOY_CONN_LOG(debug, "mysql_proxy: wrote auth data with 1-byte length: {}",
                   read_callbacks_->connection(), auth_len);
  }
}

/**
 * Stores authentication metadata in the connection's stream info.
 * This makes auth plugin information available to other filters and for logging.
 *
 * @param auth_data The authentication data to store in metadata
 */
void MySQLProxy::setAuthMetadata(const AuthData& auth_data) {
  auto& stream_info = read_callbacks_->connection().streamInfo();
  const auto& existing_metadata = stream_info.dynamicMetadata().filter_metadata();

  // Create a new metadata struct
  ProtobufWkt::Struct metadata;

  // Copy existing metadata if it exists
  auto it = existing_metadata.find(NetworkFilterNames::get().DatabricksSqlProxy);
  if (it != existing_metadata.end()) {
    metadata = it->second;
  }

  // Create auth data struct
  ProtobufWkt::Struct auth_data_struct;
  (*auth_data_struct.mutable_fields())[CommonConstants::AUTH_PLUGIN_KEY].set_string_value(
      auth_data.auth_plugin_name);

  // Convert binary auth response to Base64 for storage in metadata
  if (!auth_data.auth_response.empty()) {
    const std::string auth_response_b64 =
        Base64::encode(reinterpret_cast<const char*>(auth_data.auth_response.data()),
                       auth_data.auth_response.size());
    (*auth_data_struct.mutable_fields())[CommonConstants::AUTH_RESPONSE_B64_KEY].set_string_value(
        auth_response_b64);
  }

  (*auth_data_struct.mutable_fields())[CommonConstants::IS_NATIVE_PASSWORD_KEY].set_bool_value(
      auth_data.is_native_password);

  // Add auth data to metadata
  (*metadata.mutable_fields())[CommonConstants::AUTH_DATA_KEY].mutable_struct_value()->CopyFrom(
      auth_data_struct);

  // Set the updated metadata
  stream_info.setDynamicMetadata(NetworkFilterNames::get().DatabricksSqlProxy, metadata);

  ENVOY_CONN_LOG(debug, "mysql_proxy: stored auth metadata: plugin='{}', is_native={}",
                 read_callbacks_->connection(), auth_data.auth_plugin_name,
                 auth_data.is_native_password ? "true" : "false");
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
