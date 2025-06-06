#include "source/extensions/network/socket_interface/reverse_connection/protocol.h"

#include <chrono>

#include "envoy/common/time.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/byte_order.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {
namespace Protocol {

uint32_t ProtocolUtil::next_sequence_ = 1;

ProtocolHeader ProtocolUtil::createHeader(MessageType type, uint16_t payload_length,
                                          uint32_t sequence, uint32_t timestamp) {
  ProtocolHeader header;
  header.magic = htobe32(ProtocolHeader::MAGIC);
  header.version = ProtocolHeader::VERSION;
  header.type = type;
  header.length = htobe16(payload_length);
  header.sequence = htobe32(sequence == 0 ? getNextSequence() : sequence);
  header.timestamp = htobe32(timestamp == 0 ? getCurrentTimestampSec() : timestamp);
  return header;
}

void ProtocolUtil::serializeHeader(Buffer::Instance& buffer, const ProtocolHeader& header) {
  buffer.add(&header, ProtocolHeader::HEADER_SIZE);
}

absl::StatusOr<ProtocolHeader> ProtocolUtil::parseHeader(Buffer::Instance& buffer) {
  if (buffer.length() < ProtocolHeader::HEADER_SIZE) {
    return absl::InvalidArgumentError("Insufficient data for protocol header");
  }

  ProtocolHeader header;
  buffer.copyOut(0, ProtocolHeader::HEADER_SIZE, &header);

  // Convert from network byte order
  header.magic = be32toh(header.magic);
  header.length = be16toh(header.length);
  header.sequence = be32toh(header.sequence);
  header.timestamp = be32toh(header.timestamp);

  if (!isValidHeader(header)) {
    return absl::InvalidArgumentError("Invalid protocol header");
  }

  buffer.drain(ProtocolHeader::HEADER_SIZE);
  return header;
}

void ProtocolUtil::createConnectionRequest(Buffer::Instance& buffer,
                                           const std::string& src_cluster_id,
                                           const std::string& src_node_id,
                                           const std::string& src_tenant_id, uint32_t sequence) {
  // Calculate payload length
  uint16_t payload_length = sizeof(ConnectionRequest) + src_cluster_id.length() +
                            src_node_id.length() + src_tenant_id.length();

  // Create and serialize header
  auto header = createHeader(MessageType::CONN_REQ, payload_length, sequence);
  serializeHeader(buffer, header);

  // Create and serialize payload
  ConnectionRequest req;
  req.src_cluster_id_len = static_cast<uint8_t>(src_cluster_id.length());
  req.src_node_id_len = static_cast<uint8_t>(src_node_id.length());
  req.src_tenant_id_len = static_cast<uint8_t>(src_tenant_id.length());
  req.reserved = 0;

  buffer.add(&req, sizeof(ConnectionRequest));
  buffer.add(src_cluster_id.data(), src_cluster_id.length());
  buffer.add(src_node_id.data(), src_node_id.length());
  buffer.add(src_tenant_id.data(), src_tenant_id.length());

  ENVOY_LOG(debug, "Created connection request: cluster={}, node={}, tenant={}", src_cluster_id,
            src_node_id, src_tenant_id);
}

absl::StatusOr<ConnectionRequest> ProtocolUtil::parseConnectionRequest(Buffer::Instance& buffer,
                                                                       std::string& src_cluster_id,
                                                                       std::string& src_node_id,
                                                                       std::string& src_tenant_id) {
  if (buffer.length() < sizeof(ConnectionRequest)) {
    return absl::InvalidArgumentError("Insufficient data for connection request");
  }

  ConnectionRequest req;
  buffer.copyOut(0, sizeof(ConnectionRequest), &req);
  buffer.drain(sizeof(ConnectionRequest));

  // Calculate total string length
  size_t total_string_len = req.src_cluster_id_len + req.src_node_id_len + req.src_tenant_id_len;
  if (buffer.length() < total_string_len) {
    return absl::InvalidArgumentError("Insufficient data for connection request strings");
  }

  // Extract strings
  if (req.src_cluster_id_len > 0) {
    src_cluster_id.resize(req.src_cluster_id_len);
    buffer.copyOut(0, req.src_cluster_id_len, &src_cluster_id[0]);
    buffer.drain(req.src_cluster_id_len);
  }

  if (req.src_node_id_len > 0) {
    src_node_id.resize(req.src_node_id_len);
    buffer.copyOut(0, req.src_node_id_len, &src_node_id[0]);
    buffer.drain(req.src_node_id_len);
  }

  if (req.src_tenant_id_len > 0) {
    src_tenant_id.resize(req.src_tenant_id_len);
    buffer.copyOut(0, req.src_tenant_id_len, &src_tenant_id[0]);
    buffer.drain(req.src_tenant_id_len);
  }

  ENVOY_LOG(debug, "Parsed connection request: cluster={}, node={}, tenant={}", src_cluster_id,
            src_node_id, src_tenant_id);

  return req;
}

void ProtocolUtil::createConnectionAck(Buffer::Instance& buffer, uint32_t connection_id,
                                       uint32_t keepalive_interval, uint32_t max_data_size,
                                       uint32_t sequence) {
  auto header = createHeader(MessageType::CONN_ACK, sizeof(ConnectionAck), sequence);
  serializeHeader(buffer, header);

  ConnectionAck ack;
  ack.connection_id = htobe32(connection_id);
  ack.keepalive_interval = htobe32(keepalive_interval);
  ack.max_data_size = htobe32(max_data_size);
  ack.reserved = 0;

  buffer.add(&ack, sizeof(ConnectionAck));

  ENVOY_LOG(debug, "Created connection ack: id={}, keepalive={}s, max_data={}", connection_id,
            keepalive_interval, max_data_size);
}

absl::StatusOr<ConnectionAck> ProtocolUtil::parseConnectionAck(Buffer::Instance& buffer) {
  if (buffer.length() < sizeof(ConnectionAck)) {
    return absl::InvalidArgumentError("Insufficient data for connection ack");
  }

  ConnectionAck ack;
  buffer.copyOut(0, sizeof(ConnectionAck), &ack);
  buffer.drain(sizeof(ConnectionAck));

  // Convert from network byte order
  ack.connection_id = be32toh(ack.connection_id);
  ack.keepalive_interval = be32toh(ack.keepalive_interval);
  ack.max_data_size = be32toh(ack.max_data_size);

  ENVOY_LOG(debug, "Parsed connection ack: id={}, keepalive={}s, max_data={}", ack.connection_id,
            ack.keepalive_interval, ack.max_data_size);

  return ack;
}

void ProtocolUtil::createRPing(Buffer::Instance& buffer, uint32_t connection_id,
                               uint64_t timestamp_us, uint32_t sequence) {
  auto header = createHeader(MessageType::RPING, sizeof(RPingPayload), sequence);
  serializeHeader(buffer, header);

  RPingPayload ping;
  ping.timestamp_us = htobe64(timestamp_us == 0 ? getCurrentTimestampUs() : timestamp_us);
  ping.connection_id = htobe32(connection_id);
  ping.reserved = 0;

  buffer.add(&ping, sizeof(RPingPayload));

  ENVOY_LOG(trace, "Created RPING: connection_id={}, timestamp={}", connection_id,
            ping.timestamp_us);
}

absl::StatusOr<RPingPayload> ProtocolUtil::parseRPing(Buffer::Instance& buffer) {
  if (buffer.length() < sizeof(RPingPayload)) {
    return absl::InvalidArgumentError("Insufficient data for RPING payload");
  }

  RPingPayload ping;
  buffer.copyOut(0, sizeof(RPingPayload), &ping);
  buffer.drain(sizeof(RPingPayload));

  // Convert from network byte order
  ping.timestamp_us = be64toh(ping.timestamp_us);
  ping.connection_id = be32toh(ping.connection_id);

  ENVOY_LOG(trace, "Parsed RPING: connection_id={}, timestamp={}", ping.connection_id,
            ping.timestamp_us);

  return ping;
}

void ProtocolUtil::createRPingAck(Buffer::Instance& buffer, uint32_t connection_id,
                                  uint64_t timestamp_us, uint32_t sequence) {
  auto header = createHeader(MessageType::RPING_ACK, sizeof(RPingPayload), sequence);
  serializeHeader(buffer, header);

  RPingPayload ping_ack;
  ping_ack.timestamp_us = htobe64(timestamp_us);
  ping_ack.connection_id = htobe32(connection_id);
  ping_ack.reserved = 0;

  buffer.add(&ping_ack, sizeof(RPingPayload));

  ENVOY_LOG(trace, "Created RPING_ACK: connection_id={}, timestamp={}", connection_id,
            timestamp_us);
}

void ProtocolUtil::createDataMessage(Buffer::Instance& buffer, uint32_t connection_id,
                                     uint32_t stream_id, uint16_t flags, Buffer::Instance& payload,
                                     uint32_t sequence) {
  uint16_t payload_length = sizeof(DataHeader) + payload.length();
  auto header = createHeader(MessageType::DATA, payload_length, sequence);
  serializeHeader(buffer, header);

  DataHeader data_hdr;
  data_hdr.connection_id = htobe32(connection_id);
  data_hdr.stream_id = htobe32(stream_id);
  data_hdr.flags = htobe16(flags);
  data_hdr.reserved = 0;

  buffer.add(&data_hdr, sizeof(DataHeader));
  buffer.move(payload);

  ENVOY_LOG(trace, "Created data message: connection_id={}, stream_id={}, flags={}, len={}",
            connection_id, stream_id, flags, payload_length - sizeof(DataHeader));
}

absl::StatusOr<DataHeader> ProtocolUtil::parseDataHeader(Buffer::Instance& buffer) {
  if (buffer.length() < sizeof(DataHeader)) {
    return absl::InvalidArgumentError("Insufficient data for data header");
  }

  DataHeader data_hdr;
  buffer.copyOut(0, sizeof(DataHeader), &data_hdr);
  buffer.drain(sizeof(DataHeader));

  // Convert from network byte order
  data_hdr.connection_id = be32toh(data_hdr.connection_id);
  data_hdr.stream_id = be32toh(data_hdr.stream_id);
  data_hdr.flags = be16toh(data_hdr.flags);

  ENVOY_LOG(trace, "Parsed data header: connection_id={}, stream_id={}, flags={}",
            data_hdr.connection_id, data_hdr.stream_id, data_hdr.flags);

  return data_hdr;
}

void ProtocolUtil::createCloseMessage(Buffer::Instance& buffer, uint32_t connection_id,
                                      uint32_t sequence) {
  auto header = createHeader(MessageType::CLOSE, sizeof(uint32_t), sequence);
  serializeHeader(buffer, header);

  uint32_t conn_id_be = htobe32(connection_id);
  buffer.add(&conn_id_be, sizeof(uint32_t));

  ENVOY_LOG(debug, "Created close message: connection_id={}", connection_id);
}

uint64_t ProtocolUtil::getCurrentTimestampUs() {
  auto now = std::chrono::steady_clock::now();
  auto duration = now.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
}

uint32_t ProtocolUtil::getCurrentTimestampSec() {
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

bool ProtocolUtil::isValidHeader(const ProtocolHeader& header) {
  if (header.magic != ProtocolHeader::MAGIC) {
    ENVOY_LOG(warn, "Invalid magic number: expected={:08x}, got={:08x}", ProtocolHeader::MAGIC,
              header.magic);
    return false;
  }

  if (header.version != ProtocolHeader::VERSION) {
    ENVOY_LOG(warn, "Unsupported protocol version: expected={}, got={}", ProtocolHeader::VERSION,
              header.version);
    return false;
  }

  // Validate message type
  switch (header.type) {
  case MessageType::CONN_REQ:
  case MessageType::CONN_ACK:
  case MessageType::CONN_NACK:
  case MessageType::RPING:
  case MessageType::RPING_ACK:
  case MessageType::DATA:
  case MessageType::CLOSE:
    break;
  default:
    ENVOY_LOG(warn, "Invalid message type: {}", static_cast<uint8_t>(header.type));
    return false;
  }

  return true;
}

uint32_t ProtocolUtil::getNextSequence() { return next_sequence_++; }

} // namespace Protocol
} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
