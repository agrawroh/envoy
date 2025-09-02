#pragma once

#include "source/extensions/bootstrap/reverse_tunnel/downstream_socket_interface/reverse_connection_handshake.pb.h"
#include "envoy/network/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/network/filter_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/bootstrap/reverse_tunnel/reverse_tunnel_acceptor.h"
#include "source/extensions/filters/network/generic_proxy/interface/filter.h"
#include "source/extensions/filters/network/generic_proxy/interface/stream.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConn {

namespace ReverseConnection = Envoy::Extensions::Bootstrap::ReverseConnection;
namespace GenericProxy = Envoy::Extensions::NetworkFilters::GenericProxy;

/**
 * Configuration for the reverse connection network filter.
 */
class ReverseConnFilterConfig {
public:
  ReverseConnFilterConfig() : ping_interval_(std::chrono::seconds(2)) {}

  std::chrono::seconds pingInterval() const { return ping_interval_; }

private:
  const std::chrono::seconds ping_interval_;
};

using ReverseConnFilterConfigSharedPtr = std::shared_ptr<ReverseConnFilterConfig>;

/**
 * Network filter that handles reverse connection acceptance/rejection using the Generic Proxy
 * interface. This filter only processes POST requests to /reverse_connections/request and
 * accepts/rejects reverse connections based on protobuf payload.
 *
 * Uses the Generic Proxy StreamFilter interface for protocol-agnostic operation.
 * This is a TERMINAL filter that stops processing after handling reverse connection requests.
 */
class ReverseConnFilter : public Network::Filter,
                          public GenericProxy::StreamFilter,
                          public Logger::Loggable<Logger::Id::filter> {
public:
  ReverseConnFilter(ReverseConnFilterConfigSharedPtr config);

  // Network::Filter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override;

  // GenericProxy::DecoderFilter
  void onDestroy() override;
  void setDecoderFilterCallbacks(GenericProxy::DecoderFilterCallback& callbacks) override;
  GenericProxy::HeaderFilterStatus
  decodeHeaderFrame(GenericProxy::RequestHeaderFrame& request) override;
  GenericProxy::CommonFilterStatus
  decodeCommonFrame(GenericProxy::RequestCommonFrame& request) override;

  // GenericProxy::EncoderFilter
  void setEncoderFilterCallbacks(GenericProxy::EncoderFilterCallback& callbacks) override;
  GenericProxy::HeaderFilterStatus
  encodeHeaderFrame(GenericProxy::ResponseHeaderFrame& response) override;
  GenericProxy::CommonFilterStatus
  encodeCommonFrame(GenericProxy::ResponseCommonFrame& response) override;

  // Terminal filter behavior
  bool isTerminalFilter() const { return true; }

private:
  // Parse protobuf payload and extract cluster details
  bool parseProtobufPayload(const std::string& payload, std::string& node_uuid,
                            std::string& cluster_uuid, std::string& tenant_uuid);

  // Send local reply using Generic Proxy callbacks
  void sendLocalReply(GenericProxy::Status status, const std::string& data);

  // Save the connection to upstream socket manager
  void saveDownstreamConnection(const std::string& node_id, const std::string& cluster_id);

  // Get the upstream socket manager from the thread-local registry
  ReverseConnection::UpstreamSocketManager* getUpstreamSocketManager();

  // Process the reverse connection request
  void processReverseConnectionRequest();

  // Check if this is a reverse connection request
  bool isReverseConnectionRequest(const GenericProxy::RequestHeaderFrame& request) const;

  // Extract body from common frames
  void extractRequestBody(GenericProxy::RequestCommonFrame& frame);

  // Close the connection after processing
  void closeConnection();

  ReverseConnFilterConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  Network::WriteFilterCallbacks* write_callbacks_{nullptr};

  // Generic Proxy filter callbacks
  GenericProxy::DecoderFilterCallback* decoder_callbacks_{nullptr};
  GenericProxy::EncoderFilterCallback* encoder_callbacks_{nullptr};

  // Request data from Generic Proxy frames
  std::string request_body_;

  // Request state
  bool is_reverse_connection_request_{false};
  bool message_complete_{false};
  bool connection_closed_{false};

  // Reverse connection data
  std::string node_uuid_;
  std::string cluster_uuid_;
  std::string tenant_uuid_;

  // Constants
  static const std::string REVERSE_CONNECTIONS_REQUEST_PATH;
  static const std::string HTTP_POST_METHOD;
};

} // namespace ReverseConn
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
