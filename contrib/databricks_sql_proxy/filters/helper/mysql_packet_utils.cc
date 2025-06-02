#include "mysql_packet_utils.h"

#include <iomanip>
#include <sstream>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * Validates the given packet size against the maximum allowed packet size.
 */
bool MySQLPacketUtils::validatePacketHeader(const Buffer::Instance&, uint32_t size) {
  if (!validateSize(size)) {
    ENVOY_LOG(debug, "mysql_utils: invalid packet size: {}", size);
    return false;
  }

  return true;
}

/**
 * Writes the MySQL packet header to the given buffer. The MySQL packet header consists of a 3-byte
 * length field and a 1-byte sequence number.
 */
void MySQLPacketUtils::writePayloadHeader(Buffer::OwnedImpl& buffer, uint32_t length,
                                          uint8_t sequence_id) {
  // Add packet length (3 bytes, little-endian)
  buffer.writeByte(static_cast<uint8_t>(length & 0xFF));
  buffer.writeByte(static_cast<uint8_t>((length >> 8) & 0xFF));
  buffer.writeByte(static_cast<uint8_t>((length >> 16) & 0xFF));

  // Add sequence ID (1 byte)
  buffer.writeByte(sequence_id);
}

/**
 * Encodes the given payload into a MySQL packet. The MySQL packet consists of a 3-byte length
 * field, a 1-byte sequence number, and the payload.
 */
void MySQLPacketUtils::encode(Buffer::Instance& out, const Buffer::Instance& payload, uint8_t seq) {
  const uint32_t length = payload.length();

  if (!validateSize(length)) {
    throw EnvoyException(fmt::format("Packet size {} exceeds maximum", length));
  }

  // Write 3-byte length in little-endian order
  out.writeByte(length & 0xFF);
  out.writeByte((length >> 8) & 0xFF);
  out.writeByte((length >> 16) & 0xFF);

  // Write sequence number
  out.writeByte(seq);

  // Write payload
  out.add(payload);
}

/**
 * Extracts the packet header from the given data buffer. The packet header consists of the payload
 * length and the sequence number.
 */
bool MySQLPacketUtils::extractPacketHeader(Buffer::Instance& data, uint32_t& payload_length,
                                           uint8_t& seq) {
  if (data.length() < MySQLConstants::MIN_PACKET_LENGTH) {
    return false;
  }

  // Length is first 3 bytes, little-endian
  payload_length = data.peekLEInt<uint32_t>(0) & 0x00FFFFFF;

  // Sequence number is 4th byte
  seq = data.peekLEInt<uint8_t>(3);

  return MySQLPacketUtils::validateSize(payload_length);
}

/**
 * Decodes the packet header from the given data buffer. The packet header consists of the payload
 * length and the sequence number.
 */
bool MySQLPacketUtils::decode(Buffer::Instance& data, uint32_t& length, uint8_t& seq) {
  if (!extractPacketHeader(data, length, seq)) {
    return false;
  }

  // Remove packet header
  data.drain(NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH);
  return true;
}

/**
 * Dump the MySQL packet in debug log with hex data and packet header information. This is useful
 * for debugging MySQL protocol issues.
 */
void MySQLPacketUtils::debugPacket(const Buffer::Instance& data, uint32_t length, bool log_hex) {
  if (!ENVOY_LOG_CHECK_LEVEL(debug)) {
    return;
  }

  ENVOY_LOG(debug, "mysql_utils: MySQL packet length: {}", length);

  if (log_hex && length > 0) {
    std::stringstream hex;
    for (uint32_t i = 0; i < length && i < data.length(); i++) {
      hex << std::setfill('0') << std::setw(2) << std::hex
          << static_cast<int>(data.peekLEInt<uint8_t>(i)) << " ";
      if ((i + 1) % 16 == 0) {
        ENVOY_LOG(debug, "mysql_utils: hex dump: {}", hex.str());
        hex.str("");
      }
    }
    if (!hex.str().empty()) {
      ENVOY_LOG(debug, "mysql_utils: hex dump: {}", hex.str());
    }
  }

  if (length >= NetworkFilters::DatabricksSqlProxy::MySQLConstants::MIN_PACKET_LENGTH) {
    uint32_t payload_length;
    uint8_t seq;
    if (extractPacketHeader(const_cast<Buffer::Instance&>(data), payload_length, seq)) {
      ENVOY_LOG(debug, "mysql_utils: packet header - Length: {}, Sequence ID: {}", payload_length,
                seq);
    }
  }

  if (length >= MySQLConstants::MIN_CAPABILITIES_PACKET_SIZE) {
    uint32_t capabilities = data.peekLEInt<uint32_t>(MySQLConstants::CAPABILITIES_FLAGS_OFFSET);
    ENVOY_LOG(debug, "mysql_utils: capabilities flags: 0x{:x}", capabilities);
  }
}

/**
 * Decodes a variable-length integer from MySQL packet format.
 * MySQL encodes integers in different formats depending on value:
 * - 1 byte for values 0-250
 * - 3 bytes for values 251-65535 (first byte = 0xFC)
 * - 4 bytes for values 65536-16777215 (first byte = 0xFD)
 * - 9 bytes for values 16777216+ (first byte = 0xFE)
 * Reference: "length encoded integer" in MySQL protocol documentation:
 *            https://github.com/siddontang/mixer/blob/master/doc/mysql-proxy/protocol.txt
 *
 * @param data Buffer containing the encoded integer
 * @param offset Position in the buffer to start reading from
 * @param value Output parameter to store the decoded value
 * @param bytes_read Output parameter to store the number of bytes read
 * @return true if successful, false if the buffer is too small or invalid format
 */
bool MySQLPacketUtils::decodeVariableLengthInteger(const Buffer::Instance& data, size_t offset,
                                                   uint64_t& value, size_t& bytes_read) {
  // Make sure we have at least one byte to read
  if (offset >= data.length()) {
    return false;
  }

  // Read the first byte to determine the encoding format
  uint8_t first_byte = data.peekLEInt<uint8_t>(offset);

  if (first_byte < 251) {
    // Format: 1 byte value (0-250)
    value = first_byte;
    bytes_read = 1;
    return true;
  } else if (first_byte == 251) {
    // Format: NULL value (not used for length encoding)
    // In length encoding context, this should not occur
    return false;
  } else if (first_byte == 252) {
    // Format: 2 bytes (251-65535)
    if (offset + 3 > data.length()) {
      return false;
    }
    value = data.peekLEInt<uint16_t>(offset + 1);
    bytes_read = 3;
    return true;
  } else if (first_byte == 253) {
    // Format: 3 bytes (65536-16777215)
    if (offset + 4 > data.length()) {
      return false;
    }
    // Need to read 3 bytes in little-endian order
    value = data.peekLEInt<uint8_t>(offset + 1) | (data.peekLEInt<uint8_t>(offset + 2) << 8) |
            (data.peekLEInt<uint8_t>(offset + 3) << 16);
    bytes_read = 4;
    return true;
  } else if (first_byte == 254) {
    // Format: 8 bytes (16777216-2^64-1)
    if (offset + 9 > data.length()) {
      return false;
    }
    value = data.peekLEInt<uint64_t>(offset + 1);
    bytes_read = 9;
    return true;
  } else {
    // Invalid format (255 is not used for length encoding)
    return false;
  }
}

/**
 * Extracts client capabilities from a MySQL packet. The client capabilities are sent by the client
 * in the initial handshake response.
 *
 * @param data The buffer containing the client message
 * @param client_caps Output parameter to store the capabilities flags
 * @return true if parsing was successful, false otherwise
 */
bool MySQLPacketUtils::extractClientCapabilities(const Buffer::Instance& data,
                                                 uint32_t& client_caps) {
  // Ensure we have enough data for the capabilities flags (4 bytes at the beginning)
  if (data.length() < 4) {
    return false;
  }

  uint16_t caps_lower = data.peekLEInt<uint16_t>(0);
  uint16_t caps_upper = data.peekLEInt<uint16_t>(2);
  client_caps = (caps_upper << 16) | caps_lower;

  return true;
}

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
std::vector<MySQLPacketUtils::MySQLConnectionAttribute>
MySQLPacketUtils::extractConnectionAttributes(Buffer::Instance& data, size_t& offset,
                                              uint32_t client_caps) {
  // Create a vector to hold the connection attributes
  std::vector<MySQLConnectionAttribute> attributes;

  // Ensure we're at the correct position to start reading attributes
  if (offset >= data.length() ||
      !(client_caps & NetworkFilters::DatabricksSqlProxy::MySQLConstants::CLIENT_CONNECT_ATTRS)) {
    ENVOY_LOG(debug,
              "mysql_proxy: client doesn't have CONNECTION_ATTRS capability or end of packet");
    return attributes; // Return empty vector
  }

  // The first byte at the connection attributes position should be a length-encoded integer
  // representing the total length of all key-value pairs
  uint64_t total_length;
  size_t bytes_read = 0;

  // Ease debugging by logging the data at the connection attributes position
  if (ENVOY_LOG_CHECK_LEVEL(debug) && offset < data.length()) {
    std::stringstream hex_dump;
    for (size_t i = offset; i < std::min(offset + size_t{16}, static_cast<size_t>(data.length()));
         i++) {
      hex_dump << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(data.peekBEInt<uint8_t>(i)) << " ";
    }
    ENVOY_LOG(debug, "mysql_proxy: data at connection attributes position: {}", hex_dump.str());
  }

  bool result =
      MySQLPacketUtils::decodeVariableLengthInteger(data, offset, total_length, bytes_read);
  if (!result) {
    ENVOY_LOG(error, "mysql_proxy: failed to decode connection attributes total length");
    return attributes; // Return empty vector
  }

  ENVOY_LOG(debug, "mysql_proxy: connection attributes total length: {}, bytes_read: {}",
            total_length, bytes_read);

  static constexpr uint64_t MAX_TOTAL_ATTRS_SIZE = 64 * 1024;
  static constexpr size_t MAX_ATTR_COUNT = 256;
  static constexpr uint64_t MAX_ATTR_KEY_SIZE = 1024;
  static constexpr uint64_t MAX_ATTR_VALUE_SIZE = 8192;

  if (total_length > MAX_TOTAL_ATTRS_SIZE) {
    ENVOY_LOG(error, "mysql_proxy: connection attributes total size too large: {} bytes (max: {})",
              total_length, MAX_TOTAL_ATTRS_SIZE);
    return attributes;
  }

  offset += bytes_read;

  size_t attrs_end = offset + total_length;
  if (attrs_end > data.length()) {
    ENVOY_LOG(error, "mysql_proxy: connection attributes length exceeds packet bounds");
    return attributes;
  }

  // Read key-value pairs until we reach the end of the attributes section
  while (offset < attrs_end) {
    if (attributes.size() >= MAX_ATTR_COUNT) {
      ENVOY_LOG(error, "mysql_proxy: too many connection attributes: {} (max: {})",
                attributes.size(), MAX_ATTR_COUNT);
      return attributes;
    }

    // Each key and value is a length-encoded string
    std::string key, value;

    // Read key length
    uint64_t key_len;
    size_t key_len_size = 0;
    if (!MySQLPacketUtils::decodeVariableLengthInteger(data, offset, key_len, key_len_size)) {
      ENVOY_LOG(error, "mysql_proxy: failed to decode connection attribute key length");
      return attributes;
    }

    // Validate key size to prevent DoS
    if (key_len > MAX_ATTR_KEY_SIZE) {
      ENVOY_LOG(error, "mysql_proxy: connection attribute key too large: {} bytes (max: {})",
                key_len, MAX_ATTR_KEY_SIZE);
      return attributes;
    }

    offset += key_len_size;

    if (offset + key_len > data.length()) {
      ENVOY_LOG(error, "mysql_proxy: connection attribute key length exceeds packet bounds");
      return attributes;
    }

    key.resize(key_len); // Pre-size the string to the exact length
    data.copyOut(offset, key_len, const_cast<char*>(key.data()));
    offset += key_len;

    // Read value length
    uint64_t value_len;
    size_t value_len_size = 0;
    if (!MySQLPacketUtils::decodeVariableLengthInteger(data, offset, value_len, value_len_size)) {
      ENVOY_LOG(error, "mysql_proxy: failed to decode connection attribute value length");
      return attributes;
    }

    if (value_len > MAX_ATTR_VALUE_SIZE) {
      ENVOY_LOG(error, "mysql_proxy: connection attribute value too large: {} bytes (max: {})",
                value_len, MAX_ATTR_VALUE_SIZE);
      return attributes;
    }

    offset += value_len_size;

    if (offset + value_len > data.length()) {
      ENVOY_LOG(error, "mysql_proxy: connection attribute value length exceeds packet bounds");
      return attributes;
    }

    value.resize(value_len); // Pre-size the string to the exact length
    data.copyOut(offset, value_len, const_cast<char*>(value.data()));
    offset += value_len;

    // Store the key-value pair in our vector
    attributes.push_back({key, value});

    ENVOY_LOG(debug, "mysql_proxy: connection attribute {}='{}'", key, value);
  }

  ENVOY_LOG(debug, "mysql_proxy: connection attributes extraction complete, found {} attributes",
            attributes.size());
  return attributes;
}

/**
 * Calculate the number of bytes needed to encode a length-encoded integer.
 * This follows the MySQL protocol specification for length-encoded integers:
 * - 1 byte for values 0-250
 * - 3 bytes for values 251-65535 (first byte = 0xFC)
 * - 4 bytes for values 65536-16777215 (first byte = 0xFD)
 * - 9 bytes for values 16777216+ (first byte = 0xFE)
 *
 * @param value The integer value to encode
 * @return The number of bytes needed to encode the value
 */
size_t MySQLPacketUtils::getLengthEncodedIntegerSize(uint64_t value) {
  if (value < 251) {
    return 1; // 1 byte (0-250)
  } else if (value < 65536) {
    return 3; // 1 byte prefix (0xFC) + 2 bytes value
  } else if (value < 16777216) {
    return 4; // 1 byte prefix (0xFD) + 3 bytes value
  } else {
    return 9; // 1 byte prefix (0xFE) + 8 bytes value
  }
}

/**
 * Write a length-encoded integer to a buffer according to MySQL protocol.
 * Length-encoded integers are used throughout the MySQL protocol for
 * representing string lengths and other numeric values.
 *
 * @param buffer The buffer to write to
 * @param value The integer value to encode
 * @return The number of bytes written
 */
size_t MySQLPacketUtils::writeLengthEncodedInteger(Buffer::Instance& buffer, uint64_t value) {
  if (value < 251) {
    // Format: 1 byte value (0-250)
    buffer.writeByte(static_cast<uint8_t>(value));
    return 1;
  } else if (value < 65536) {
    // Format: 3 bytes (251-65535): [0xFC][2 byte value in little-endian]
    buffer.writeByte(0xFC);
    buffer.writeLEInt<uint16_t>(static_cast<uint16_t>(value));
    return 3;
  } else if (value < 16777216) {
    // Format: 4 bytes (65536-16777215): [0xFD][3 byte value in little-endian]
    buffer.writeByte(0xFD);
    // Write 3 bytes in little-endian order
    buffer.writeByte(value & 0xFF);
    buffer.writeByte((value >> 8) & 0xFF);
    buffer.writeByte((value >> 16) & 0xFF);
    return 4;
  } else {
    // Format: 9 bytes (16777216+): [0xFE][8 byte value in little-endian]
    buffer.writeByte(0xFE);
    buffer.writeLEInt<uint64_t>(value);
    return 9;
  }
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
