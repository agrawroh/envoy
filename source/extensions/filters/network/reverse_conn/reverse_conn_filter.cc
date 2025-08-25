#include "source/extensions/filters/network/reverse_conn/reverse_conn_filter.h"

#include "envoy/network/connection.h"
#include "envoy/network/connection_socket_impl.h"
#include "envoy/ssl/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/logger.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/common/network/socket_option_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConn {

// Static constants
const std::string ReverseConnFilter::REVERSE_CONNECTIONS_REQUEST_PATH =
    "/reverse_connections/request";
const std::string ReverseConnFilter::HTTP_POST_METHOD = "POST";

// ReverseConnFilter implementation

ReverseConnFilter::ReverseConnFilter(ReverseConnFilterConfigSharedPtr config) : config_(config) {
  // No custom codec needed - Generic Proxy handles all protocol parsing
}

Network::FilterStatus ReverseConnFilter::onNewConnection() {
  ENVOY_LOG(debug, "ReverseConnFilter: New connection established");
  return Network::FilterStatus::Continue;
}

Network::FilterStatus ReverseConnFilter::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(debug, "ReverseConnFilter: Received {} bytes, end_stream: {}", data.length(),
            end_stream);

  // Note: In a real Generic Proxy setup, this method would typically not be called
  // because the Generic Proxy filter would intercept the data and call our
  // decodeHeaderFrame/decodeCommonFrame methods directly.
  // This is kept for compatibility with the network filter interface.

  // For now, we'll just continue to let Generic Proxy handle the data
  return Network::FilterStatus::Continue;
}

Network::FilterStatus ReverseConnFilter::onWrite(Buffer::Instance&, bool) {
  return Network::FilterStatus::Continue;
}

void ReverseConnFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

void ReverseConnFilter::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
}

// GenericProxy::DecoderFilter implementation

void ReverseConnFilter::onDestroy() { ENVOY_LOG(debug, "ReverseConnFilter: Filter destroyed"); }

void ReverseConnFilter::setDecoderFilterCallbacks(GenericProxy::DecoderFilterCallback& callbacks) {
  decoder_callbacks_ = &callbacks;
  ENVOY_LOG(debug, "ReverseConnFilter: Decoder filter callbacks set");
}

GenericProxy::HeaderFilterStatus
ReverseConnFilter::decodeHeaderFrame(GenericProxy::RequestHeaderFrame& request) {
  ENVOY_LOG(debug, "ReverseConnFilter: Processing header frame - protocol: {}, host: {}, path: {}",
            request.protocol(), request.host(), request.path());

  // Check if this is a reverse connection request
  if (isReverseConnectionRequest(request)) {
    ENVOY_LOG(debug, "ReverseConnFilter: Detected reverse connection request");
    is_reverse_connection_request_ = true;

    // Continue to receive body frames
    return GenericProxy::HeaderFilterStatus::Continue;
  }

  // Not a reverse connection request, continue to next filter
  ENVOY_LOG(debug, "ReverseConnFilter: Not a reverse connection request, continuing");
  return GenericProxy::HeaderFilterStatus::Continue;
}

GenericProxy::CommonFilterStatus
ReverseConnFilter::decodeCommonFrame(GenericProxy::RequestCommonFrame& request) {
  if (!is_reverse_connection_request_) {
    // Not a reverse connection request, continue
    return GenericProxy::CommonFilterStatus::Continue;
  }

  ENVOY_LOG(debug, "ReverseConnFilter: Processing common frame for reverse connection request");

  // Extract body data from the common frame
  extractRequestBody(request);

  // Check if we have enough data to process
  if (!request_body_.empty()) {
    message_complete_ = true;
    processReverseConnectionRequest();

    // As a terminal filter, stop processing after handling the request
    return GenericProxy::CommonFilterStatus::StopIteration;
  }

  return GenericProxy::CommonFilterStatus::Continue;
}

// GenericProxy::EncoderFilter implementation

void ReverseConnFilter::setEncoderFilterCallbacks(GenericProxy::EncoderFilterCallback& callbacks) {
  encoder_callbacks_ = &callbacks;
  ENVOY_LOG(debug, "ReverseConnFilter: Encoder filter callbacks set");
}

GenericProxy::HeaderFilterStatus
ReverseConnFilter::encodeHeaderFrame(GenericProxy::ResponseHeaderFrame& response) {
  // We don't modify response headers for reverse connection requests
  // Just continue to the next filter
  return GenericProxy::HeaderFilterStatus::Continue;
}

GenericProxy::CommonFilterStatus
ReverseConnFilter::encodeCommonFrame(GenericProxy::ResponseCommonFrame& response) {
  // We don't modify response body for reverse connection requests
  // Just continue to the next filter
  return GenericProxy::CommonFilterStatus::Continue;
}

// Private methods

bool ReverseConnFilter::isReverseConnectionRequest(
    const GenericProxy::RequestHeaderFrame& request) const {
  // Check method (for HTTP, this would be "POST")
  auto method = request.get("method");
  if (!method.has_value() || method.value() != HTTP_POST_METHOD) {
    return false;
  }

  // Check path (for HTTP, this would be "/reverse_connections/request")
  auto path = request.path();
  if (path != REVERSE_CONNECTIONS_REQUEST_PATH) {
    return false;
  }

  ENVOY_LOG(debug, "ReverseConnFilter: Valid reverse connection request - method: {}, path: {}",
            method.value(), path);

  return true;
}

void ReverseConnFilter::extractRequestBody(GenericProxy::RequestCommonFrame& frame) {
  // In a real implementation, you would extract the body data from the common frame
  // This depends on how the Generic Proxy codec represents body data

  // For now, we'll use a placeholder approach
  // In practice, you might access frame.data() or similar methods

  ENVOY_LOG(debug, "ReverseConnFilter: Extracting request body from common frame");

  // This is a simplified approach - in reality, you'd get the actual body data
  // from the Generic Proxy frame structure
  // request_body_ = frame.bodyData(); // or similar method
}

bool ReverseConnFilter::parseProtobufPayload(const std::string& payload, std::string& node_uuid,
                                             std::string& cluster_uuid, std::string& tenant_uuid) {
  envoy::extensions::bootstrap::reverse_connection_handshake::v3::ReverseConnHandshakeArg arg;

  if (!arg.ParseFromString(payload)) {
    ENVOY_LOG(error, "ReverseConnFilter: Failed to parse protobuf from request body");
    return false;
  }

  ENVOY_LOG(debug, "ReverseConnFilter: Successfully parsed protobuf: {}", arg.DebugString());

  node_uuid = arg.node_uuid();
  cluster_uuid = arg.cluster_uuid();
  tenant_uuid = arg.tenant_uuid();

  ENVOY_LOG(debug, "ReverseConnFilter: Extracted values - tenant='{}', cluster='{}', node='{}'",
            tenant_uuid, cluster_uuid, node_uuid);

  return !node_uuid.empty();
}

void ReverseConnFilter::sendLocalReply(GenericProxy::Status status, const std::string& data) {
  if (!decoder_callbacks_) {
    ENVOY_LOG(error, "ReverseConnFilter: No decoder callbacks available for local reply");
    return;
  }

  // Send local reply using Generic Proxy callbacks
  // This will create a response frame and send it back to the client
  decoder_callbacks_->sendLocalReply(status, data);

  ENVOY_LOG(debug, "ReverseConnFilter: Sent local reply with status: {}, data: {}",
            static_cast<int>(status), data);
}

void ReverseConnFilter::saveDownstreamConnection(const std::string& node_id,
                                                 const std::string& cluster_id) {
  ENVOY_LOG(debug, "ReverseConnFilter: Adding connection to upstream socket manager");

  auto* socket_manager = getUpstreamSocketManager();
  if (!socket_manager) {
    ENVOY_LOG(error, "ReverseConnFilter: Failed to get upstream socket manager");
    return;
  }

  // Get connection from Generic Proxy callbacks if available, otherwise fall back to network
  // callbacks
  const Network::Connection* connection = nullptr;
  if (decoder_callbacks_) {
    connection = decoder_callbacks_->connection();
  } else if (read_callbacks_) {
    connection = &read_callbacks_->connection();
  }

  if (!connection) {
    ENVOY_LOG(error, "ReverseConnFilter: No connection available");
    return;
  }

  const Network::ConnectionSocketPtr& original_socket = connection->getSocket();

  if (!original_socket || !original_socket->isOpen()) {
    ENVOY_LOG(error, "ReverseConnFilter: Original socket is not available or not open");
    return;
  }

  // Duplicate the file descriptor
  Network::IoHandlePtr duplicated_handle = original_socket->ioHandle().duplicate();
  if (!duplicated_handle || !duplicated_handle->isOpen()) {
    ENVOY_LOG(error, "ReverseConnFilter: Failed to duplicate file descriptor");
    return;
  }

  ENVOY_LOG(debug,
            "ReverseConnFilter: Successfully duplicated file descriptor: original_fd={}, "
            "duplicated_fd={}",
            original_socket->ioHandle().fdDoNotUse(), duplicated_handle->fdDoNotUse());

  // Create a new socket with the duplicated handle
  Network::ConnectionSocketPtr duplicated_socket = std::make_unique<Network::ConnectionSocketImpl>(
      std::move(duplicated_handle), original_socket->connectionInfoProvider().localAddress(),
      original_socket->connectionSocket()->connectionInfoProvider().remoteAddress());

  // Reset file events on the duplicated socket
  duplicated_socket->ioHandle().resetFileEvents();

  // Add the duplicated socket to the manager
  socket_manager->addConnectionSocket(node_id, cluster_id, std::move(duplicated_socket),
                                      config_->pingInterval(), false /* rebalanced */);

  ENVOY_LOG(debug,
            "ReverseConnFilter: Successfully added duplicated socket to upstream socket manager");
}

void ReverseConnFilter::closeConnection() {
  if (connection_closed_) {
    return;
  }

  // Get connection from Generic Proxy callbacks if available, otherwise fall back to network
  // callbacks
  Network::Connection* connection = nullptr;
  if (decoder_callbacks_) {
    connection = const_cast<Network::Connection*>(decoder_callbacks_->connection());
  } else if (read_callbacks_) {
    connection = &read_callbacks_->connection();
  }

  if (connection) {
    ENVOY_LOG(debug,
              "ReverseConnFilter: Closing connection after processing reverse connection request");

    // Mark connection as reused
    connection->setSocketReused(true);

    // Reset file events on the connection socket
    if (connection->getSocket()) {
      connection->getSocket()->ioHandle().resetFileEvents();
    }

    // Close the connection
    connection->close(Network::ConnectionCloseType::NoFlush, "accepted_reverse_conn");
  }

  connection_closed_ = true;
}

ReverseConnection::UpstreamSocketManager* ReverseConnFilter::getUpstreamSocketManager() {
  auto* upstream_interface =
      Network::socketInterface("envoy.bootstrap.reverse_tunnel.upstream_socket_interface");
  if (!upstream_interface) {
    ENVOY_LOG(debug, "ReverseConnFilter: Upstream reverse socket interface not found");
    return nullptr;
  }

  auto* upstream_socket_interface =
      dynamic_cast<const ReverseConnection::ReverseTunnelAcceptor*>(upstream_interface);
  if (!upstream_socket_interface) {
    ENVOY_LOG(error, "ReverseConnFilter: Failed to cast to ReverseTunnelAcceptor");
    return nullptr;
  }

  auto* tls_registry = upstream_socket_interface->getLocalRegistry();
  if (!tls_registry) {
    ENVOY_LOG(error,
              "ReverseConnFilter: Thread local registry not found for upstream socket interface");
    return nullptr;
  }

  return tls_registry->socketManager();
}

void ReverseConnFilter::processReverseConnectionRequest() {
  ENVOY_LOG(info, "ReverseConnFilter: Processing reverse connection request");

  // Parse protobuf payload
  if (!parseProtobufPayload(request_body_, node_uuid_, cluster_uuid_, tenant_uuid_)) {
    // Send rejection response
    sendLocalReply(GenericProxy::Status::InvalidArgument,
                   "Failed to parse request message or required fields missing");

    // Close connection after rejection
    closeConnection();
    return;
  }

  // Check SSL certificate for additional tenant/cluster info
  const Network::Connection* connection = nullptr;
  if (decoder_callbacks_) {
    connection = decoder_callbacks_->connection();
  } else if (read_callbacks_) {
    connection = &read_callbacks_->connection();
  }

  if (connection) {
    Envoy::Ssl::ConnectionInfoConstSharedPtr ssl = connection->ssl();

    if (ssl && ssl->peerCertificatePresented()) {
      absl::Span<const std::string> dnsSans = ssl->dnsSansPeerCertificate();
      for (const std::string& dns : dnsSans) {
        auto parts = absl::StrSplit(dns, "=");
        if (parts.size() == 2) {
          if (parts[0] == "tenantId") {
            tenant_uuid_ = std::string(parts[1]);
          } else if (parts[0] == "clusterId") {
            cluster_uuid_ = std::string(parts[1]);
          }
        }
      }
    }
  }

  ENVOY_LOG(info,
            "ReverseConnFilter: Accepting reverse connection. tenant '{}', cluster '{}', node '{}'",
            tenant_uuid_, cluster_uuid_, node_uuid_);

  // Create acceptance response
  envoy::extensions::bootstrap::reverse_connection_handshake::v3::ReverseConnHandshakeRet ret;
  ret.set_status(envoy::extensions::bootstrap::reverse_connection_handshake::v3::
                     ReverseConnHandshakeRet::ACCEPTED);

  std::string response_body = ret.SerializeAsString();
  ENVOY_LOG(info, "ReverseConnFilter: Response body length: {}, content: '{}'",
            response_body.length(), response_body);

  // Send acceptance response
  sendLocalReply(GenericProxy::Status::Ok, response_body);

  // Save the connection
  saveDownstreamConnection(node_uuid_, cluster_uuid_);

  // Close the connection after processing (terminal filter behavior)
  closeConnection();

  ENVOY_LOG(info, "ReverseConnFilter: Reverse connection accepted and connection closed");
}

} // namespace ReverseConn
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
