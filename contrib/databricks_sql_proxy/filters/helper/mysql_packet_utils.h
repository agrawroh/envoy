#pragma once

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "mysql_constants.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Helper class for handling MySQL protocol packets.
 */
class MySQLPacketUtils : public Logger::Loggable<Logger::Id::filter> {
public:
  /**
   * MySQL packet header structure. It contains the payload length and sequence number.
   */
  struct MySQLPacketHeader {
    uint32_t length;
    uint8_t sequence_id;

    static MySQLPacketHeader parseFromBuffer(const Buffer::Instance& data) {
      MySQLPacketHeader header;
      header.length = data.peekLEInt<uint32_t>(0) & 0x00FFFFFF;
      header.sequence_id = data.peekLEInt<uint8_t>(3);
      return header;
    }
  };

  /**
   * MySQL connection attribute structure. It contains a key-value pair representing a connection
   * attribute.
   */
  struct MySQLConnectionAttribute {
    std::string key;
    std::string value;
  };

  /**
   * MySQL connection attributes structure. It contains a list of connection attributes.
   */
  struct MySQLConnectionAttributes {
    std::vector<MySQLConnectionAttribute> attributes;
  };

  /**
   * Validates a packet's basic structure and size.
   *
   * @param data Buffer containing packet
   * @param size Size of packet
   * @return true if valid, false if malformed
   */
  static bool validatePacketHeader(const Buffer::Instance& data, uint32_t size);

  /**
   * Encodes a MySQL packet.
   *
   * @param out Output buffer
   * @param payload Payload data
   * @param seq Sequence number
   * @throws EnvoyException if packet exceeds size limits
   */
  static void encode(Buffer::Instance& out, const Buffer::Instance& payload, uint8_t seq);

  /**
   * Decodes a MySQL packet header.
   *
   * @param data Input buffer
   * @param length Output parameter for payload length
   * @param seq Output parameter for sequence number
   * @return true if successful, false if invalid/incomplete
   */
  static bool decode(Buffer::Instance& data, uint32_t& length, uint8_t& seq);

  /**
   * Debug log packet contents if debug logging is enabled.
   *
   * @param data Packet data
   * @param length Packet length
   * @param log_hex Whether to include hex dump
   */
  static void debugPacket(const Buffer::Instance& data, uint32_t length, bool log_hex = true);

  /**
   * Extracts the packet header from the given data buffer. The packet header consists of the
   * payload length and the sequence number.
   *
   * @param data The buffer containing the packet
   * @param payload_length Output parameter for the payload length
   * @param seq Output parameter for the sequence number
   * @return true if successful, false if the buffer is too small
   */
  static bool extractPacketHeader(Buffer::Instance& data, uint32_t& payload_length, uint8_t& seq);

  /**
   * Writes the MySQL packet header to the given buffer. The MySQL packet header consists of a
   * 3-byte length field and a 1-byte sequence number.
   *
   * @param buffer The buffer to write the header to
   * @param length The length of the payload
   * @param sequence_id The sequence number
   */
  static void writePayloadHeader(Buffer::OwnedImpl& buffer, uint32_t length, uint8_t sequence_id);

  /**
   * Decodes a variable-length integer from MySQL packet format.
   *
   * @param data Buffer containing the encoded integer
   * @param offset Position in the buffer to start reading from
   * @param value Output parameter to store the decoded value
   * @param bytes_read Output parameter to store the number of bytes read
   * @return true if successful, false if the buffer is too small or invalid format
   */
  static bool decodeVariableLengthInteger(const Buffer::Instance& data, size_t offset,
                                          uint64_t& value, size_t& bytes_read);

  /**
   * Calculate the number of bytes needed to encode a length-encoded integer.
   *
   * @param value The integer value to encode
   * @return The number of bytes needed to encode the value
   */
  static size_t getLengthEncodedIntegerSize(uint64_t value);

  /**
   * Write a length-encoded integer to a buffer.
   *
   * @param buffer The buffer to write to
   * @param value The integer value to encode
   * @return The number of bytes written
   */
  static size_t writeLengthEncodedInteger(Buffer::Instance& buffer, uint64_t value);

  /**
   * Extracts client capabilities from a MySQL packet.
   *
   * @param data Buffer containing the packet data
   * @param client_caps Output parameter to store the capabilities flags
   * @return true if successful, false if the buffer is too small
   */
  static bool extractClientCapabilities(const Buffer::Instance& data, uint32_t& client_caps);

  /**
   * Extracts connection attributes from a MySQL packet. The connection attributes are sent by the
   * client in the initial handshake response.
   *
   * @param data The buffer containing the client message
   * @param offset Starting position for parsing connection attributes
   * @param client_caps The client capabilities flags
   * @param attributes Output parameter to store the connection attributes
   * @return vector of connection attributes if parsing was successful, empty vector otherwise
   */
  static std::vector<MySQLConnectionAttribute>
  extractConnectionAttributes(Buffer::Instance& data, size_t& offset, uint32_t client_caps);

private:
  static bool validateSize(uint32_t size) {
    return size > 0 && size <= NetworkFilters::DatabricksSqlProxy::MySQLConstants::MAX_PACKET_SIZE;
  }
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
