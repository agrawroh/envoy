#pragma once

#include "envoy/stream_info/filter_state.h"

#include "source/common/common/macros.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

/**
 * Typed metadata object for PostgreSQL inspector results.
 * This carries information about detected PostgreSQL protocol messages
 * from the listener filter to the network filter.
 * Includes SNI hostname support for SSL connections.
 */
class PostgresInspectorMetadata : public StreamInfo::FilterState::Object {
public:
  /**
   * Constructor for PostgreSQL inspector metadata.
   * @param transport_protocol the detected transport protocol (always "postgres").
   * @param message_type the type of detected message ("ssl_request" or "startup_message").
   * @param ssl_requested whether SSL was requested by the client.
   * @param sni_hostname the SNI hostname extracted from SSL connection (optional).
   */
  PostgresInspectorMetadata(const std::string& transport_protocol, const std::string& message_type,
                            bool ssl_requested, const std::string& sni_hostname = "")
      : transport_protocol_(transport_protocol), message_type_(message_type),
        ssl_requested_(ssl_requested), sni_hostname_(sni_hostname) {}

  // StreamInfo::FilterState::Object
  ProtobufTypes::MessagePtr serializeAsProto() const override {
    // This metadata is not serializable as it's runtime-only information.
    return nullptr;
  }

  /**
   * Get the detected transport protocol.
   * @return the transport protocol ("postgres").
   */
  const std::string& transportProtocol() const { return transport_protocol_; }

  /**
   * Get the detected message type.
   * @return the message type ("ssl_request" or "startup_message").
   */
  const std::string& messageType() const { return message_type_; }

  /**
   * Check if SSL was requested by the client.
   * @return true if SSL was requested, false otherwise.
   */
  bool sslRequested() const { return ssl_requested_; }

  /**
   * Get the SNI hostname extracted from SSL connection.
   * @return the SNI hostname, empty string if not available.
   */
  const std::string& sniHostname() const { return sni_hostname_; }

  /**
   * Filter state key for PostgreSQL inspector metadata.
   * @return the filter state key.
   */
  static constexpr absl::string_view filterStateKey() {
    return "envoy.filters.listener.postgres_inspector";
  }

  /**
   * Factory function for creating PostgreSQL inspector metadata.
   * @param transport_protocol the detected transport protocol.
   * @param message_type the type of detected message.
   * @param ssl_requested whether SSL was requested.
   * @param sni_hostname the SNI hostname extracted from SSL connection (optional).
   * @return unique pointer to metadata object.
   */
  static std::unique_ptr<PostgresInspectorMetadata> create(const std::string& transport_protocol,
                                                           const std::string& message_type,
                                                           bool ssl_requested,
                                                           const std::string& sni_hostname = "") {
    return std::make_unique<PostgresInspectorMetadata>(transport_protocol, message_type,
                                                       ssl_requested, sni_hostname);
  }

private:
  const std::string transport_protocol_;
  const std::string message_type_;
  const bool ssl_requested_;
  const std::string sni_hostname_;
};

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
