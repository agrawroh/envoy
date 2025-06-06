#pragma once

#include <cstdint>
#include <string>

#include "envoy/buffer/buffer.h"

#include "source/common/common/byte_order.h"
#include "source/common/common/logger.h"

#include "absl/status/statusor.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {
namespace Protocol {

/**
 * Reverse connection protocol message types.
 */
enum class MessageType : uint8_t {
  // Connection establishment
  CONN_REQ = 0x01,  // Reverse connection request
  CONN_ACK = 0x02,  // Connection acknowledgment
  CONN_NACK = 0x03, // Connection negative acknowledgment

  // Keepalive messages
  RPING = 0x10,     // Reverse ping (keepalive request)
  RPING_ACK = 0x11, // Reverse ping acknowledgment

  // Data tunneling
  DATA = 0x20, // Tunneled data

  // Control messages
  CLOSE = 0xF0, // Connection close
};

/**
 * Reverse connection protocol header structure.
 * All fields in network byte order.
 */
struct ProtocolHeader {
  uint32_t magic;     // Magic number: 0x52434E4E ("RCNN")
  uint8_t version;    // Protocol version
  MessageType type;   // Message type
  uint16_t length;    // Payload length (excluding header)
  uint32_t sequence;  // Sequence number
  uint32_t timestamp; // Timestamp (seconds since epoch)

  static constexpr uint32_t MAGIC = 0x52434E4E; // "RCNN"
  static constexpr uint8_t VERSION = 1;
  static constexpr size_t HEADER_SIZE = 16;
} __attribute__((packed));

/**
 * Connection request payload.
 */
struct ConnectionRequest {
  uint8_t src_cluster_id_len;
  uint8_t src_node_id_len;
  uint8_t src_tenant_id_len;
  uint8_t reserved;
  // Variable length strings follow:
  // char src_cluster_id[src_cluster_id_len];
  // char src_node_id[src_node_id_len];
  // char src_tenant_id[src_tenant_id_len];
} __attribute__((packed));

/**
 * Connection acknowledgment payload.
 */
struct ConnectionAck {
  uint32_t connection_id;      // Assigned connection ID
  uint32_t keepalive_interval; // Keepalive interval in seconds
  uint32_t max_data_size;      // Maximum data payload size
  uint32_t reserved;
} __attribute__((packed));

/**
 * RPING payload.
 */
struct RPingPayload {
  uint64_t timestamp_us;  // Microsecond timestamp
  uint32_t connection_id; // Connection ID
  uint32_t reserved;
} __attribute__((packed));

/**
 * Data payload header.
 */
struct DataHeader {
  uint32_t connection_id; // Target connection ID
  uint32_t stream_id;     // Stream identifier
  uint16_t flags;         // Data flags
  uint16_t reserved;
  // Data follows
} __attribute__((packed));

/**
 * Protocol utility functions.
 */
class ProtocolUtil : public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Create a protocol header.
   */
  static ProtocolHeader createHeader(MessageType type, uint16_t payload_length,
                                     uint32_t sequence = 0, uint32_t timestamp = 0);

  /**
   * Serialize header to buffer.
   */
  static void serializeHeader(Buffer::Instance& buffer, const ProtocolHeader& header);

  /**
   * Parse header from buffer.
   */
  static absl::StatusOr<ProtocolHeader> parseHeader(Buffer::Instance& buffer);

  /**
   * Create connection request message.
   */
  static void createConnectionRequest(Buffer::Instance& buffer, const std::string& src_cluster_id,
                                      const std::string& src_node_id,
                                      const std::string& src_tenant_id, uint32_t sequence = 0);

  /**
   * Parse connection request message.
   */
  static absl::StatusOr<ConnectionRequest> parseConnectionRequest(Buffer::Instance& buffer,
                                                                  std::string& src_cluster_id,
                                                                  std::string& src_node_id,
                                                                  std::string& src_tenant_id);

  /**
   * Create connection acknowledgment message.
   */
  static void createConnectionAck(Buffer::Instance& buffer, uint32_t connection_id,
                                  uint32_t keepalive_interval, uint32_t max_data_size,
                                  uint32_t sequence = 0);

  /**
   * Parse connection acknowledgment message.
   */
  static absl::StatusOr<ConnectionAck> parseConnectionAck(Buffer::Instance& buffer);

  /**
   * Create RPING keepalive message.
   */
  static void createRPing(Buffer::Instance& buffer, uint32_t connection_id, uint64_t timestamp_us,
                          uint32_t sequence = 0);

  /**
   * Parse RPING message.
   */
  static absl::StatusOr<RPingPayload> parseRPing(Buffer::Instance& buffer);

  /**
   * Create RPING acknowledgment message.
   */
  static void createRPingAck(Buffer::Instance& buffer, uint32_t connection_id,
                             uint64_t timestamp_us, uint32_t sequence = 0);

  /**
   * Create data message.
   */
  static void createDataMessage(Buffer::Instance& buffer, uint32_t connection_id,
                                uint32_t stream_id, uint16_t flags, Buffer::Instance& payload,
                                uint32_t sequence = 0);

  /**
   * Parse data message.
   */
  static absl::StatusOr<DataHeader> parseDataHeader(Buffer::Instance& buffer);

  /**
   * Create close message.
   */
  static void createCloseMessage(Buffer::Instance& buffer, uint32_t connection_id,
                                 uint32_t sequence = 0);

  /**
   * Get current timestamp in microseconds.
   */
  static uint64_t getCurrentTimestampUs();

  /**
   * Get current timestamp in seconds.
   */
  static uint32_t getCurrentTimestampSec();

  /**
   * Validate protocol header.
   */
  static bool isValidHeader(const ProtocolHeader& header);

private:
  static uint32_t next_sequence_;
  static uint32_t getNextSequence();
};

} // namespace Protocol
} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
