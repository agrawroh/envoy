#include "contrib/databricks_sql_proxy/filters/listener/source/postgres_inspector.h"

#include <cstddef>

#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"

#include "source/common/buffer/buffer_impl.h"

#include "contrib/databricks_sql_proxy/filters/helper/postgres_helper.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {

Network::FilterStatus PostgresInspector::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "postgres_inspector: onAccept");
  cb_ = &cb;

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus PostgresInspector::onData(Network::ListenerFilterBuffer& buffer) {
  ENVOY_LOG(trace, "postgres_inspector: onData");

  auto raw_slice = buffer.rawSlice();
  Buffer::OwnedImpl data{raw_slice.mem_, raw_slice.len_};

  // SSL REQUEST message format is
  // 4 bytes: message length = 8 (including this 4 bytes)
  // 4 bytes: protocol version = 80877103
  // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-SSLREQUEST
  // Need to have at least 8 bytes (SSL_REQUEST_MESSAGE_LENGTH) to process the SSL request message.
  if (data.length() < PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH) {
    ENVOY_LOG(info, "postgres_inspector: Message is too small. Need more data. Data length: {}",
              data.length());
    // Not enough data in the buffer. Return StopIteration but do not close the connection to wait
    // for more data.
    config_->stats().need_more_data_.inc();
    return Network::FilterStatus::StopIteration;
  }

  // We have enough data to read the first 8 bytes.
  // Look at the first 4 bytes to determine the length of the message.
  uint32_t message_len = data.peekBEInt<uint32_t>(0);
  // Make sure that we have full message in the buffer.
  if (data.length() < message_len) {
    ENVOY_LOG(info,
              "postgres_inspector: Message is too small. Need more data. Data length: {}. "
              "message_len: {}",
              data.length(), message_len);
    // Not enough data in the buffer. Return StopIteration but do not close the connection to wait
    // for more data.
    config_->stats().need_more_data_.inc();
    return Network::FilterStatus::StopIteration;
  }

  // Look at the protocol version, which is the next 4 bytes.
  uint32_t protocol_version = data.peekBEInt<uint32_t>(4);

  // Check if this is a cancel request message.
  if (protocol_version == PostgresConstants::CANCEL_REQUEST_PROTOCOL_VERSION) {
    return processCancelRequestMessage(message_len);
  }
  // Or SSL request message
  else if (protocol_version == PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION) {
    return processSslRequestMessage(buffer, message_len);
  } else {
    // If not cancel request or ssl request, then it is an invalid protocol version.
    std::string error_msg =
        fmt::format("Invalid protocol version. Protocol version: {}", protocol_version);
    ENVOY_LOG(error, "postgres_inspector: {}", error_msg);

    sendErrorResponseToDownstream(PostgresConstants::PostgresErrorCode::FATAL,
                                  PostgresConstants::PROTOCOL_VIOLATION, error_msg,
                                  "Ensure that connection is using SSL. Try using "
                                  "`sslmode-require` in the connection string.");

    config_->stats().error_.inc();
    config_->stats().invalid_protocol_version_.inc();
    Filter::setErrorMsgInDynamicMetadata(*cb_, error_msg);
    cb_->socket().ioHandle().close();
    return Network::FilterStatus::StopIteration;
  }
}

/**
 * Process postgres cancel request message.
 * Checking that the message has the correct size. If not, send an error response to the client.
 * If the message is correct, just continue the filter chain.
 */
Network::FilterStatus PostgresInspector::processCancelRequestMessage(int32_t message_len) {
  // Check that message length is correct cancel request message length.
  if (message_len != PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH) {
    std::string error_msg = "Invalid cancel request message length.";
    ENVOY_LOG(error, "postgres_inspector: {} Message length: {}. Expected {} bytes.", error_msg,
              std::to_string(message_len), PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);

    // 08P01 is protocol_violation error code.
    sendErrorResponseToDownstream(PostgresConstants::PostgresErrorCode::FATAL,
                                  PostgresConstants::PROTOCOL_VIOLATION, error_msg, "");

    config_->stats().error_.inc();
    config_->stats().invalid_message_length_.inc();
    Filter::setErrorMsgInDynamicMetadata(
        *cb_,
        fmt::format("{} Message length: {}. Expected {} or {} bytes.", error_msg,
                    std::to_string(message_len), PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                    PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH));
    cb_->socket().ioHandle().close();
    return Network::FilterStatus::StopIteration;
  }

  config_->stats().cancel_request_received_.inc();

  // This is a cancel request message, just continue the filter chain because we do not need to
  // process any more data. We also do not drain this data because we need to forward this to the
  // upstream.
  return Network::FilterStatus::Continue;
}

/**
 * Process postgres SSL request message.
 * Checking that the message has the correct size. If not, send an error response to the client.
 * If the message is correct, drain the buffer and send a reply to the client
 * that SSL is enabled and continue the filter chain.
 */
Network::FilterStatus
PostgresInspector::processSslRequestMessage(Network::ListenerFilterBuffer& buffer,
                                            int32_t message_len) {
  Network::ConnectionSocket& socket = cb_->socket();

  // Check that message length is correct ssl request message length.
  if (message_len != PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH) {
    std::string error_msg = "Invalid SSL request message length.";
    ENVOY_LOG(error, "postgres_inspector: {} Message length: {}. Expected {} bytes.", error_msg,
              std::to_string(message_len), PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);

    sendErrorResponseToDownstream(PostgresConstants::PostgresErrorCode::FATAL,
                                  PostgresConstants::PROTOCOL_VIOLATION, error_msg,
                                  "Ensure that connection is using SSL. Try using "
                                  "`sslmode=require` in the connection string.");

    config_->stats().error_.inc();
    config_->stats().invalid_message_length_.inc();
    Filter::setErrorMsgInDynamicMetadata(
        *cb_,
        fmt::format("{} Message length: {}. Expected {} bytes.", error_msg,
                    std::to_string(message_len), PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH));
    socket.ioHandle().close();
    return Network::FilterStatus::StopIteration;
  }

  config_->stats().handshake_received_.inc();

  // Reply to the client that SSL is enabled.
  absl::string_view response(&PostgresConstants::POSTGRES_SUPPORT_SSL, 1);
  Buffer::OwnedImpl write_buffer{};
  write_buffer.add(response);
  Api::IoCallUint64Result result = socket.ioHandle().write(write_buffer);

  if (!result.ok()) {
    std::string error_msg =
        fmt::format("Failed to write reply to socket. code: {} error: {}",
                    static_cast<int>(result.err_->getErrorCode()), result.err_->getErrorDetails());

    ENVOY_LOG(error, "postgres_inspector: {}", error_msg);

    config_->stats().error_.inc();
    config_->stats().handshake_response_failed_.inc();
    Filter::setErrorMsgInDynamicMetadata(*cb_, error_msg);
    socket.ioHandle().close();
    return Network::FilterStatus::StopIteration;
  }

  // Drain the buffer as we have processed the SSL request.
  buffer.drain(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);

  // At this point we should have no data buffered. If we do,
  // it was received before we performed the SSL handshake, so it wasn't
  // encrypted and indeed may have been injected by a man-in-the-middle.
  if (buffer.rawSlice().len_ > 0) {
    absl::string_view error_msg = "Received unencrypted data after SSL request.";
    absl::string_view detail_msg = "This could be either a client-software bug or evidence of an "
                                   "attempted man-in-the-middle attack.";

    ENVOY_LOG(error, "postgres_inspector: {} {}", error_msg, detail_msg);

    sendErrorResponseToDownstream(PostgresConstants::PostgresErrorCode::FATAL,
                                  PostgresConstants::PROTOCOL_VIOLATION, error_msg, detail_msg);

    config_->stats().error_.inc();
    config_->stats().protocol_violation_.inc();

    Filter::setErrorMsgInDynamicMetadata(*cb_, fmt::format("{} {}", error_msg, detail_msg));

    socket.ioHandle().close();
    return Network::FilterStatus::StopIteration;
  }

  config_->stats().handshake_success_.inc();

  ENVOY_LOG(info, "postgres_inspector: Successfully processed SSL Request startup message");

  return Network::FilterStatus::Continue;
}

/**
 * Send postgres error response to the downstream client.
 */
void PostgresInspector::sendErrorResponseToDownstream(
    PostgresConstants::PostgresErrorCode error_code, absl::string_view sql_state,
    absl::string_view error_message, absl::string_view detail_message) {
  Buffer::OwnedImpl error_response = DatabricksSqlProxy::Helper::createPostgresErrorResponse(
      static_cast<int16_t>(error_code), sql_state, error_message, detail_message);

  Api::IoCallUint64Result result = cb_->socket().ioHandle().write(error_response);
  if (!result.ok()) {
    ENVOY_LOG(error,
              "postgres_inspector: failed to write error response to socket. code: {} error: {}",
              static_cast<int>(result.err_->getErrorCode()), result.err_->getErrorDetails());
  }
}

} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
