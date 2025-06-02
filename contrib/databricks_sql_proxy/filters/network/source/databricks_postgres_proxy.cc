#include "contrib/databricks_sql_proxy/filters/network/source/databricks_postgres_proxy.h"

#include <cstddef>
#include <cstdint>

#include "source/common/common/random_generator.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/common/sqlutils/source/sqlutils.h"
#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_helper.h"

using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;
using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

// The "Filters" mentioned in the diagram include the Databricks SQL Inspector and the Databricks
// SQL Proxy.
// - Databricks SQL Inspector handles the initial TLS handshake from the client.
// - Databricks SQL Proxy (parent of this class) handles Postgres startup message and later step.
//
// Here are the general postgres protocol SSL handshake steps:
//
// Client                         Filters                   Upstream
// ----- Can I use SSL? ------------>
// <------- Yes---------------------
// <------- TLS handshake ---------->
// ------ Postgres startup msg ----->
//
//                           wait for upstream
//                        connection established
//
//                                    ------ Can I use SSL? ------>
//                                    <------- Yes ----------------
//                                    <------- TLS handshake ----->
//                                    --- Postgres startup msg --->
//
// ------ close connection --------->
//                                    ------ close connection ---->
//
// Here are the general postgres protocol steps without initiating SSL handshake with upstream:
//
// Client                         Filters                   Upstream
// ----- Can I use SSL? ------------>
// <------- Yes---------------------
// <------- TLS handshake ---------->
// ------ Postgres startup msg ----->
//
//                           wait for upstream
//                        connection established
//
//                                    --- Postgres startup msg --->
//
// ------ close connection --------->
//                                    ------ close connection ---->

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

void PostgresProxy::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: initializeReadFilterCallbacks",
                 callbacks.connection());
  read_callbacks_ = &callbacks;

  setUpstreamHandshakeState(UpstreamHandshakeState::Init);
}

void PostgresProxy::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: initializeWriteFilterCallbacks",
                 callbacks.connection());
  write_callbacks_ = &callbacks;
}

bool PostgresProxy::requireTls() const {
  // Only allow unecnrypted downstream connection if we are processing the cancel request message.
  return (first_client_message_type_ != PostgresMessageTypes::CANCELLATION);
}

/**
 * Process postgres client first message from downstream connection.
 * This message is expected to be postgres startup message.
 */
bool PostgresProxy::processClientFirstMessage(Buffer::Instance& data) {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: processClientFirstMessage",
                 read_callbacks_->connection());

  if (data.length() < PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH) {
    ENVOY_CONN_LOG(info, "databricks_sql_proxy: Need more data for startup packet. Data length: {}",
                   read_callbacks_->connection(), data.length());

    return false;
  }

  int32_t message_len = data.peekBEInt<int32_t>();
  if (message_len < PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH ||
      message_len >= PostgresConstants::MAX_POSTGRES_MESSAGE_LENGTH) {
    ENVOY_CONN_LOG(error, "databricks_sql_proxy: Invalid length of startup packet. message_len: {}",
                   read_callbacks_->connection(), message_len);

    sendErrorResponseToDownstream(static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
                                  PostgresConstants::CONNECTION_FAILURE,
                                  "Invalid length of startup packet.", "");

    parent_.closeConnection("Invalid length of startup packet.",
                            StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    config_->stats().invalid_message_length_.inc();
    config_->stats().errors_.inc();
    return false;
  }

  // Make sure that we have enough data to process the complete startup message.
  if (data.length() < static_cast<uint64_t>(message_len)) {
    ENVOY_CONN_LOG(
        info,
        "databricks_sql_proxy: Need more data for startup packet. Data length: {}, message_len: {}",
        read_callbacks_->connection(), data.length(), message_len);

    return false;
  }

  uint32_t protocol_version = data.peekBEInt<uint32_t>(4);

  if (protocol_version == PostgresConstants::CANCEL_REQUEST_PROTOCOL_VERSION) {
    first_client_message_type_ = PostgresMessageTypes::CANCELLATION;
    // Treat 8 bytes cancellation id as 64-bit integer,
    // as well as 4 bytes process id and 4 bytes secret key as 32-bit integers.
    //
    // This is because depending on where the proxy is executed (e.g. storage-gateway or dpapiproxy)
    // the way we handle the data in cancellation message can be different.
    // We will have to read 8 bytes as process id and secret key and save these values in dynamic
    // metadata. On storage gateway, the sidecar response will override process_id and secret_key to
    // the correct value and we will use the overriden value to construct the cancel request to the
    // upstream. On dpapiproxy, we will use the value we save here to construct the cancel request
    // to the upstream.
    //
    // Cancellation_id is only used in storage gateway when calling the sidecar for authorization.
    //
    // In all of these use cases, we use dynamic metadata to store the values and pass along
    // in different state of the filter.
    uint64_t cancellation_id = data.peekBEInt<uint64_t>(8);
    uint32_t process_id = cancellation_id >> 32;
    uint32_t secret_key = cancellation_id & 0x00000000FFFFFFFF;

    setDynamicMetadataNumber(CommonConstants::CANCELLATION_ID_KEY, cancellation_id);
    setDynamicMetadataNumber(CommonConstants::CANCELLATION_PROCESS_ID_KEY, process_id);
    setDynamicMetadataNumber(CommonConstants::CANCELLATION_SECRET_KEY_KEY, secret_key);
    setDynamicMetadataNumber(CommonConstants::FIRST_CLIENT_MESSAGE_TYPE,
                             enumToInt(first_client_message_type_));

    data.drain(PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);

    ENVOY_CONN_LOG(trace,
                   "databricks_sql_proxy: Received cancellation message. cancellation_id: {}, "
                   "process_id: {}, secret_key: {}",
                   read_callbacks_->connection(), cancellation_id, process_id, secret_key);

    // Return immediately as we do not need to process the cancel request message here.
    return true;
  } else {
    first_client_message_type_ = PostgresMessageTypes::START_UP;
    setDynamicMetadataNumber(CommonConstants::FIRST_CLIENT_MESSAGE_TYPE,
                             enumToInt(first_client_message_type_));
  }

  uint32_t protocol_major = protocol_version >> 16;
  uint32_t protocol_minor = protocol_version & 0x0000FFFF;
  ENVOY_CONN_LOG(debug, "Detected version {}.{} of Postgres", read_callbacks_->connection(),
                 protocol_major, protocol_minor);

  // We only support version 3.0 of the protocol.
  if (protocol_major != PostgresConstants::MAJOR_VERSION ||
      protocol_minor != PostgresConstants::MINOR_VERSION) {
    ENVOY_CONN_LOG(
        error, "databricks_sql_proxy: Unsupported version of the protocol. Major: {}, Minor: {}",
        read_callbacks_->connection(), protocol_major, protocol_minor);

    sendErrorResponseToDownstream(
        static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
        PostgresConstants::FEATURE_NOT_SUPPORT,
        fmt::format("Unsupported frontend protocol {}.{}. Server supports {}.0 to {}.{}",
                    protocol_major, protocol_minor, PostgresConstants::MAJOR_VERSION,
                    PostgresConstants::MAJOR_VERSION, PostgresConstants::MINOR_VERSION),
        "");

    parent_.closeConnection("Unsupported version of the protocol.",
                            StreamInfo::CoreResponseFlag::DownstreamProtocolError);
    config_->stats().invalid_protocol_version_.inc();
    config_->stats().errors_.inc();
    return false;
  }

  // Copy the received startup packet request.
  temp_startup_packet_.add(data.linearize(data.length()), data.length());
  config_->stats().buffered_first_message_.adjust(temp_startup_packet_.length(), 0);

  // Already processed message length (4 bytes) and protocol version (4 bytes).
  data.drain(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH);

  uint32_t bytes_to_read = message_len - PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH;
  outputConnectionStringToDynamicMetadata(data, bytes_to_read);

  // Drain the data as they all have been processed.
  data.drain(bytes_to_read);

  return true;
}

/**
 * Read connection string options from the startup message and set them to dynamic metadata.
 * Postgres connection string options are sent in pairs of <key> <value> pairs.
 *
 * We are only doing some basic checks here.
 * 1. The first byte should not be a null-terminator.
 * 2. The second last byte and the last byte should be null-terminators.
 *    The second last byte is because it should be a end of string null-terminator.
 *    The last byte must be a null-terminator after the last string terminates.
 * See:
 * https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
 *
 * The reason we are only doing this basic check is because absl::StrSplit() can handle most of the
 * parsing.
 */
void PostgresProxy::outputConnectionStringToDynamicMetadata(Buffer::Instance& data,
                                                            uint32_t bytes_to_read) {
  // We have at least bytes_to_read bytes in the buffer.
  if (data.length() >= bytes_to_read && bytes_to_read > 2) {
    uint8_t first_byte = data.peekBEInt<uint8_t>();
    if (first_byte == 0) {
      return;
    }

    uint8_t second_last_byte = data.peekBEInt<uint8_t>(bytes_to_read - 2);
    uint8_t last_byte = data.peekBEInt<uint8_t>(bytes_to_read - 1);
    if (second_last_byte != 0 || last_byte != 0) {
      ENVOY_CONN_LOG(error,
                     "databricks_sql_proxy: Invalid connection string. Second last byte and last "
                     "byte is not null terminator. Second Last byte: {}. Last byte: {}",
                     read_callbacks_->connection(), second_last_byte, last_byte);
      return;
    }

    const std::string message{static_cast<char*>(data.linearize(bytes_to_read)), bytes_to_read};
    const Extensions::Common::SQLUtils::SQLUtils::DecoderAttributes attributes_ =
        absl::StrSplit(message, absl::ByChar('\0'));
    // Read connection string and copy them to Struct.
    ProtobufWkt::Struct connection_string_options;
    for (const auto& [key, value] : attributes_) {
      ENVOY_CONN_LOG(debug, "Connection String: Key: {}, Value: {}", read_callbacks_->connection(),
                     key, value);
      (*connection_string_options.mutable_fields())[key].set_string_value(value);
    }
    // Create another struct to wrap the connection_string_options to make sure that
    // there is no collision with other fields under the same namespace
    // (NetworkFilterNames::get().DatabricksSqlProxy)
    ProtobufWkt::Struct metadata;
    (*metadata.mutable_fields())[CommonConstants::CONNECTION_STRING_OPTIONS_KEY]
        .mutable_struct_value()
        ->CopyFrom(connection_string_options);

    read_callbacks_->connection().streamInfo().setDynamicMetadata(
        NetworkFilterNames::get().DatabricksSqlProxy, metadata);
  } else {
    // We should have enough data to process the connection string because in
    // processClientFirstMessage(), we wait for the complete startup message to be received before
    // proceeding.
    ENVOY_CONN_LOG(error,
                   "databricks_sql_proxy: Not enough data to process the connection string. Data "
                   "length: {}, Expected connection string length: {}",
                   read_callbacks_->connection(), data.length(), bytes_to_read);
  }
}

/**
 * Only poll for upstream connection established when the upstream handshake state is Init.
 */
bool PostgresProxy::shouldPollForUpstreamConnected() const {
  return upstream_handshake_state_ == UpstreamHandshakeState::Init;
}

/**
 * Connected to upstream cluster.
 * For Postgres, this is where we initiate TLS with the upstream or
 * send the startup message to upstream if upstream TLS is not configured.
 */
void PostgresProxy::onUpstreamConnected() {
  // This should be called when the upstream connection is established.
  // At that point, read shouid be enabled.
  ASSERT(read_callbacks_->connection().readEnabled());

  if (first_client_message_type_ == PostgresMessageTypes::CANCELLATION) {
    sendPostgresCancelRequestToUpstream();
  } else {
    // Send the ssl request or startup message to upstream based on the configuration.
    // The response is handled in `PostgresProxy::onWrite()`.
    if (config_->enableUpstreamTls()) {
      sendPostgresSslRequestToUpstream();
    } else {
      sendPostgresStartupMessageToUpstream();
    }
  }
}

void PostgresProxy::sendPostgresCancelRequestToUpstream() {
  auto* dynamic_metadata = read_callbacks_->connection()
                               .streamInfo()
                               .dynamicMetadata()
                               .mutable_filter_metadata()
                               ->at(NetworkFilterNames::get().DatabricksSqlProxy)
                               .mutable_fields();
  uint32_t process_id =
      dynamic_metadata->at(CommonConstants::CANCELLATION_PROCESS_ID_KEY).number_value();
  uint32_t secret_key =
      dynamic_metadata->at(CommonConstants::CANCELLATION_SECRET_KEY_KEY).number_value();

  ENVOY_CONN_LOG(debug,
                 "databricks_sql_proxy: Sending cancel request to upstream with process_id: {}, "
                 "secret_key: {}",
                 read_callbacks_->connection(), process_id, secret_key);

  // Use cancellation PID and key returned from the sidecar.
  Buffer::OwnedImpl cancel_packet;
  cancel_packet.writeBEInt<uint32_t>(PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);
  cancel_packet.writeBEInt<uint32_t>(PostgresConstants::CANCEL_REQUEST_PROTOCOL_VERSION);
  cancel_packet.writeBEInt<uint32_t>(process_id);
  cancel_packet.writeBEInt<uint32_t>(secret_key);

  // Inject cancel packet to the upstream.
  read_callbacks_->injectReadDataToFilterChain(cancel_packet, false);

  setUpstreamHandshakeState(UpstreamHandshakeState::ProcessedCancellation);
  config_->stats().sent_cancel_request_.inc();
}

/**
 * Send the SSL request to the upstream.
 */
void PostgresProxy::sendPostgresSslRequestToUpstream() {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: Sending SSL Request to upstream",
                 read_callbacks_->connection());

  Buffer::OwnedImpl ssl_request;
  ssl_request.writeBEInt<uint32_t>(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);
  ssl_request.writeBEInt<uint32_t>(PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION);

  // This will call TcpProxy::onData to send the SSL request to the upstream.
  // We expect to process the SSL response in onWrite()
  read_callbacks_->injectReadDataToFilterChain(ssl_request, false);

  setUpstreamHandshakeState(UpstreamHandshakeState::SentSslRequestUpstream);
}

/*
 * Send the startup packet to the upstream.
 * Set the upstream handshake state to ProcessedUpstreamSslResponse.
 */
void PostgresProxy::sendPostgresStartupMessageToUpstream() {
  // Inject startup packet to the upstream.
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: Sending startup packet to upstream",
                 read_callbacks_->connection());

  // Remmeber the length of temp_startup_packet_. injectReadDataToFilterChain() will drain the
  // buffer.
  uint64_t len = temp_startup_packet_.length();
  read_callbacks_->injectReadDataToFilterChain(temp_startup_packet_, false);
  // Decrease the buffered_first_message_ stat with len.
  config_->stats().buffered_first_message_.adjust(0, len);

  setUpstreamHandshakeState(UpstreamHandshakeState::SentStartupMessage);
}

/**
 * Handle data from upstream. This will be called for every data packet received from the upstream.
 * So the SQL protocol proxy implementation should keep track of the state of the connection.
 *
 * For postgres, this is where we expect to receive the SSL response from the upstream.
 */
Network::FilterStatus PostgresProxy::handleUpstreamData(Buffer::Instance& data, bool end_stream) {
  // If upstream is ending and we have not processed the backend key data message nor processed the
  // cancellation message we should flush all buffered data to downstream by calling
  // Network::FilterStatus::Continue.
  if (end_stream && upstream_handshake_state_ < UpstreamHandshakeState::ProcessedBackendKeyData) {
    ENVOY_CONN_LOG(debug,
                   "databricks_sql_proxy: Upstream is closing TCP connection end_stream: {}. Flush "
                   "all buffered data to downstream. data.length: {}",
                   read_callbacks_->connection(), end_stream, data.length());
    return Network::FilterStatus::Continue;
  }

  if (upstream_handshake_state_ == UpstreamHandshakeState::Init) {
    std::string error_msg =
        "Received data from upstream before sending SSL request. This is a protocol violation.";
    ENVOY_CONN_LOG(error, "databricks_sql_proxy: {}", read_callbacks_->connection(), error_msg);

    sendErrorResponseToDownstream(static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
                                  PostgresConstants::INTERNAL_ERROR, error_msg, "");

    parent_.closeConnection(error_msg, StreamInfo::CoreResponseFlag::UpstreamProtocolError);
    config_->stats().incorrect_upstream_connection_state_.inc();
    config_->stats().errors_.inc();
    return Network::FilterStatus::StopIteration;
  } else if (upstream_handshake_state_ == UpstreamHandshakeState::SentSslRequestUpstream) {
    return handleUpstreamSslResponse(data);
  } else if (upstream_handshake_state_ == UpstreamHandshakeState::SentStartupMessage) {
    // Now we need to look for BackendKeyData message from the upstream.
    if (data.length() < (sizeof(char) + sizeof(int32_t))) {
      ENVOY_CONN_LOG(info,
                     "databricks_sql_proxy: Need more data before forwarding downstream. Data "
                     "length: {} end_stream: {}",
                     read_callbacks_->connection(), data.length(), end_stream);
      return Network::FilterStatus::StopIteration;
    }

    assert(data_to_forward_.length() == 0);
    while (data.length() > 0) {
      uint8_t message_type = data.peekBEInt<uint8_t>(0);
      uint32_t message_len = data.peekBEInt<uint32_t>(1);
      if ((data.length() < message_len + sizeof(char))) {
        ENVOY_CONN_LOG(info,
                       "databricks_sql_proxy: Need more data before forwarding downstream. Data "
                       "length: {}. Message length: {}",
                       read_callbacks_->connection(), data.length(), message_len);
        return Network::FilterStatus::StopIteration;
      }

      ENVOY_CONN_LOG(trace, "databricks_sql_proxy: Upstream sent message_type: {} message_len: {}",
                     read_callbacks_->connection(), static_cast<char>(message_type), message_len);

      if (message_type == PostgresConstants::PARAMETER_STATUS_MESSAGE_TYPE) {
        if (findAndProcessUpstreamIpParameterStatus(data, message_len)) {
          continue;
        }
      }

      // If this is a backend key data message and we need to extract cancellation key, we need to
      // remember the process id and secret key.
      if (message_type == PostgresConstants::BACKEND_KEY_DATA_MESSAGE_TYPE) {
        processBackendKeyDataMessage(data);
        setUpstreamHandshakeState(UpstreamHandshakeState::ProcessedBackendKeyData);
        // processBackendKeyDataMessage already drains the data so just continue.
        continue;
      }

      // Forward this message to the downstream.
      data_to_forward_.move(data, message_len + sizeof(char));

      ENVOY_CONN_LOG(trace, "databricks_sql_proxy: data.length: {} data_to_forward_.length: {}",
                     read_callbacks_->connection(), data.length(), data_to_forward_.length());
    }

    ENVOY_CONN_LOG(trace, "databricks_sql_proxy: Forwarding data.length: {}",
                   read_callbacks_->connection(), data_to_forward_.length());

    write_callbacks_->injectWriteDataToFilterChain(data_to_forward_, end_stream);

    if (upstream_handshake_state_ == UpstreamHandshakeState::ProcessedBackendKeyData) {
      // If we processed backend key data message and need to store the cancellation key, store it.
      if (config_->protoConfig().postgres_config().store_cancellation_key()) {
        ENVOY_CONN_LOG(debug, "databricks_sql_proxy: Storing cancellation key in sidecar.",
                       read_callbacks_->connection());
        parent_.storeMetadataInSidecar();
      }
      // Only increment successful login stats if we have processed backend key data message.
      // When we see backend key data, it means that the authentication is successful.
      // We will switch to forward mode.
      config_->stats().successful_login_.inc();
    }
  }

  return Network::FilterStatus::Continue;
}

/**
 * Handle the SSL response from the upstream by check if the upstream supports SSL.
 *
 * If the upstream supports SSL, we will start the SSL handshake with the upstream by switching
 * the transport socket to SSL. Then we will send the postgres startup message to the upstream.
 *
 * If the upstream does not support SSL, we will send an error response to the downstream.
 * We will not forward the SSL response to the downstream.
 */
Network::FilterStatus PostgresProxy::handleUpstreamSslResponse(Buffer::Instance& data) {
  // For the first onWrite call, we should have received the SSL response.
  if (data.length() < 1) {
    ENVOY_CONN_LOG(error,
                   "databricks_sql_proxy: Invalid length of SSL response packet. Data length: {}",
                   read_callbacks_->connection(), data.length());

    sendErrorResponseToDownstream(
        static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
        PostgresConstants::INTERNAL_ERROR,
        "Internal error. Invalid length of SSL response packet from upstream.", "");

    parent_.closeConnection("Invalid length of SSL response from upstream.",
                            StreamInfo::CoreResponseFlag::UpstreamProtocolError);
    config_->stats().invalid_upstream_response_.inc();
    config_->stats().errors_.inc();
    return Network::FilterStatus::StopIteration;
  }

  uint8_t response = data.drainBEInt<uint8_t>();
  if (response == PostgresConstants::POSTGRES_SUPPORT_SSL) {
    ENVOY_CONN_LOG(debug, "databricks_sql_proxy: Switching to SSL for upstream connection.",
                   read_callbacks_->connection());

    if (read_callbacks_->startUpstreamSecureTransport()) {
      ENVOY_CONN_LOG(debug, "databricks_sql_proxy: Upstream connection is now secure.",
                     read_callbacks_->connection());

      sendPostgresStartupMessageToUpstream();
    } else {
      ENVOY_CONN_LOG(error, "databricks_sql_proxy: Failed to start secure transport with upstream.",
                     read_callbacks_->connection());

      sendErrorResponseToDownstream(
          static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
          PostgresConstants::INTERNAL_ERROR,
          "Internal error. Failed to start secure transport with upstream.", "");

      parent_.closeConnection("Failed to start secure transport with upstream.",
                              StreamInfo::CoreResponseFlag::UpstreamProtocolError);
      config_->stats().failed_upstream_ssl_handshake_.inc();
      config_->stats().errors_.inc();
    }
  } else {
    ENVOY_CONN_LOG(error,
                   "databricks_sql_proxy: Upstream does not support SSL. If this is expected, "
                   "please configure the filter enable_upstream_tls to false.",
                   read_callbacks_->connection());

    sendErrorResponseToDownstream(static_cast<int16_t>(PostgresConstants::PostgresErrorCode::FATAL),
                                  PostgresConstants::INTERNAL_ERROR,
                                  "Internal error. Upstream does not support SSL.", "");

    parent_.closeConnection("Upstream does not support SSL.",
                            StreamInfo::CoreResponseFlag::UpstreamProtocolError);
    config_->stats().upstream_not_support_ssl_.inc();
    config_->stats().errors_.inc();
  }

  // Do not write SSL response to the downstream.
  return Network::FilterStatus::StopIteration;
}

/**
 * Find and process the upstream_ip parameter status message.
 * If this is an upstream_ip parameter status message, do not forward it to the downstream
 * because this is our special message.
 *
 * @return: The function will return true if the message is an upstream_ip parameter status message.
 *          And the data will be drained.
 *          Otherwise, the function will return false and data will not be drained.
 */
bool PostgresProxy::findAndProcessUpstreamIpParameterStatus(Buffer::Instance& data,
                                                            uint32_t message_len) {
  size_t value_len =
      message_len - sizeof(int32_t); // message_len includes the message length itself, so we need
                                     // to remove sizeof(int32_t) to get actual value length.
  std::vector<char> binary_data(value_len);
  data.copyOut(sizeof(char) + sizeof(int32_t), // Skip the message type and message length
               value_len, binary_data.data());

  // Find the position of the null terminator
  auto null_pos = std::find(binary_data.begin(), binary_data.end(), 0);
  std::string key(binary_data.begin(), null_pos);

  ENVOY_CONN_LOG(trace, "databricks_sql_proxy: Parsing parameter status message with key: {}.",
                 read_callbacks_->connection(), key);

  // If this is an upstream_ip parameter status message, do not forward it to the downstream
  // because this is our special message.
  if (key == CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY) {
    // Store the upstream IP in the dynamic metadata.
    if (config_->protoConfig().postgres_config().read_parameter_status_upstream_ip()) {
      auto second_null_pos = std::find(null_pos + 1, binary_data.end(), 0);
      std::string ip_str(null_pos + 1, second_null_pos);

      setDynamicMetadataString(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY, ip_str);

      ENVOY_CONN_LOG(trace, "databricks_sql_proxy: Found upstream_ip: {}",
                     read_callbacks_->connection(), ip_str);
    }

    // Skip parameter status message and forward the rest of the data to the downstream.
    size_t len_to_skip = sizeof(char) + message_len;
    data.drain(len_to_skip);

    return true;
  }

  return false;
}

/**
 * Process the backend key data message from the upstream.
 * Store cancellation pid and key in the dynamic metadata.
 *
 * If send_parameter_status_upstream_ip is enabled, create the parameter status message
 * with the upstream IP and forward it to the downstream.
 */
void PostgresProxy::processBackendKeyDataMessage(Buffer::Instance& data) {
  uint32_t process_id =
      data.peekBEInt<uint32_t>(5); // skip message type (1 byte) and message length (4 bytes)
  uint32_t secret_key = data.peekBEInt<uint32_t>(9); // skip process id (4 bytes)

  setDynamicMetadataNumber(CommonConstants::CANCELLATION_PROCESS_ID_KEY, process_id);
  setDynamicMetadataNumber(CommonConstants::CANCELLATION_SECRET_KEY_KEY, secret_key);

  std::string ip = write_callbacks_->connection()
                       .streamInfo()
                       .upstreamInfo()
                       ->upstreamHost()
                       ->address()
                       ->ip()
                       ->addressAsString();
  // If we are not reading parameter status for upstream ip, then we should get it from the
  // underlying connection.
  if (!config_->protoConfig().postgres_config().read_parameter_status_upstream_ip()) {
    setDynamicMetadataString(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY, ip);
  }

  // After we have received backend key data message, we can send a special parameter status message
  // if needed. Parameter status message must be sent before BackendKeyData message.
  if (config_->protoConfig().postgres_config().send_parameter_status_upstream_ip()) {
    size_t message_len = sizeof(uint32_t) /* message_len field */
                         + CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY.size() +
                         1 /* null-terminator */
                         + ip.size() + 1 /* null-terminator */;

    Buffer::OwnedImpl parameter_status;
    parameter_status.writeByte(PostgresConstants::PARAMETER_STATUS_MESSAGE_TYPE);
    parameter_status.writeBEInt<int32_t>(message_len);
    parameter_status.add(CommonConstants::PARAMETER_STATUS_UPSTREAM_IP_KEY);
    parameter_status.writeByte(0); // null-terminator
    parameter_status.add(ip);
    parameter_status.writeByte(0); // null-terminator

    // Copy the parameter status message to the data_to_forward buffer.
    data_to_forward_.move(parameter_status, parameter_status.length());

    ENVOY_CONN_LOG(trace,
                   "databricks_sql_proxy: Injecting upstream_ip parameter status message, ip: {}.",
                   read_callbacks_->connection(), ip);
  }

  // Now we decide if we need to create a new backend key data message with a random cancellation
  // key, or forward the original backend key data message.
  if (config_->protoConfig().postgres_config().randomize_cancellation_key()) {
    uint64_t cancellation_id = Envoy::Random::RandomUtility::random();
    setDynamicMetadataNumber(CommonConstants::CANCELLATION_ID_KEY, cancellation_id);

    Buffer::OwnedImpl new_backend_key_data;
    new_backend_key_data.writeByte(PostgresConstants::BACKEND_KEY_DATA_MESSAGE_TYPE);
    new_backend_key_data.writeBEInt<int32_t>(PostgresConstants::BACKEND_KEY_DATA_MESSAGE_LENGTH -
                                             1); // message_len not including message type (1 byte)
    new_backend_key_data.writeBEInt<int64_t>(cancellation_id);

    data_to_forward_.move(new_backend_key_data, new_backend_key_data.length());
    // Drain the original backend key data message. It will not be forwarded to the downstream.
    data.drain(PostgresConstants::BACKEND_KEY_DATA_MESSAGE_LENGTH);

    ENVOY_CONN_LOG(trace,
                   "databricks_sql_proxy: Extract cancellation key, PID: {}, key: {}, id: {}",
                   read_callbacks_->connection(), process_id, secret_key, cancellation_id);
  } else {
    // Copy the original backend key data message to the data_to_forward buffer.
    data_to_forward_.move(data, PostgresConstants::BACKEND_KEY_DATA_MESSAGE_LENGTH);

    ENVOY_CONN_LOG(trace, "databricks_sql_proxy: Extract cancellation key, PID: {}, key: {}",
                   read_callbacks_->connection(), process_id, secret_key);
  }
}

void PostgresProxy::setDynamicMetadataNumber(const absl::string_view key, const int64_t value) {
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[key].set_number_value(value);
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);
}

void PostgresProxy::setDynamicMetadataString(const absl::string_view key, std::string& value) {
  ProtobufWkt::Value proto_value;
  proto_value.set_string_value(value);
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[key] = proto_value;
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);
}

/**
 * Set upstream handshake state and record it in the dynamic metadata.
 */
void PostgresProxy::setUpstreamHandshakeState(UpstreamHandshakeState state) {
  upstream_handshake_state_ = state;

  // Set dynamic metadata to keep track of the handshake state for access log debugging.
  setDynamicMetadataNumber(CommonConstants::UPSTREAM_HANDSHAKE_STATE_KEY, enumToInt(state));
}

void PostgresProxy::sendErrorResponseToDownstream(int16_t error_code, absl::string_view sql_state,
                                                  absl::string_view error_message,
                                                  absl::string_view detail_message) {
  Buffer::OwnedImpl unsupported_protocol_response =
      Envoy::Extensions::DatabricksSqlProxy::Helper::createPostgresErrorResponse(
          error_code, sql_state, error_message, detail_message);

  write_callbacks_->injectWriteDataToFilterChain(unsupported_protocol_response, false);
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
