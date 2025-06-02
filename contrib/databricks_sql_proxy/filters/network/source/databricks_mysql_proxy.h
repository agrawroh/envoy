#pragma once

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "contrib/databricks_sql_proxy/filters/helper/mysql_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/mysql_packet_utils.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * MySQL protocol implementation for SQL proxy filter.
 * Handles protocol negotiation, authentication, and message routing.
 */
class MySQLProxy : public SqlProtocolProxy, Logger::Loggable<Logger::Id::filter> {
public:
  MySQLProxy(ConfigSharedPtr config, Filter& parent)
      : config_(config), parent_(parent), regex_pattern_(compileRegexPattern()) {
    if (!config_->protoConfig().has_mysql_config()) {
      throw EnvoyException("MySQL configuration required");
    }
  }

  // Network filter callbacks with null checks
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
    ENVOY_LOG(debug, "mysql_proxy: initialized read callbacks");
  }

  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
    write_callbacks_ = &callbacks;
    ENVOY_LOG(debug, "mysql_proxy: initialized write callbacks");
  }

  // SqlProtocolProxy implementation
  bool processClientFirstMessage(Buffer::Instance& data) override;
  bool shouldPollForUpstreamConnected() const override { return false; }
  void onUpstreamConnected() override;
  Network::FilterStatus handleUpstreamData(Buffer::Instance& data, bool end_stream) override;
  bool isOnDataForwardingMode() const override {
    return upstream_handshake_state_ == UpstreamHandshakeState::SentHandshakeResponse;
  }
  bool isOnWriteForwardingMode() const override {
    return upstream_handshake_state_ == UpstreamHandshakeState::SentHandshakeResponse;
  }

  bool requireTls() const override { return false; }

  // Sequence ID for the handshake response packet when SSL is not requested.
  static constexpr uint8_t HANDSHAKE_NO_SSL_SEQ_ID = 1;
  // Sequence ID for the handshake response packet after SSL has been established.
  static constexpr uint8_t HANDSHAKE_AFTER_SSL_SEQ_ID = 2;

private:
  // Authentication data structure to track auth plugin and data
  struct AuthData {
    std::string auth_plugin_name;
    std::vector<uint8_t> auth_response;
    bool is_native_password{false};
  };

  // Handshake states with clear transitions
  enum class UpstreamHandshakeState {
    Init,                   // Initial state before handshake
    SentHandshakeResponse,  // Client handshake sent to upstream
    SentSslRequest,         // SSL request sent to upstream
    ReceivedServerGreeting, // Server greeting received
    WaitingForTls,          // TLS handshake in progress
    Error                   // Error state - connection should be closed
  };

  /**
   * Safe access to read callbacks with null check.
   * @throws EnvoyException if callbacks not initialized
   */
  Network::ReadFilterCallbacks* getReadCallbacks() {
    if (!read_callbacks_) {
      throw EnvoyException("Read callbacks not initialized");
    }
    return read_callbacks_;
  }

  // Packet processing methods with validation
  bool parseHandshakeResponse(Buffer::Instance& data);
  bool extractUserDetails(const std::string& username_string, std::string& extracted_username,
                          std::string& workspace_id, std::string& instance_url);
  void buildSslRequestPacket(Buffer::Instance& packet);
  void checkUpstreamHandshakeProgress();

  // Extract auth plugin and data from handshake response
  bool extractAuthenticationData(Buffer::Instance& data, size_t& current_pos, AuthData& auth_data);

  // Preserve auth data when rebuilding packets
  void preserveAuthData(Buffer::Instance& new_packet, const AuthData& auth_data,
                        uint32_t capabilities);

  void sendErrorResponseToDownstream(int16_t error_code, absl::string_view sql_state,
                                     absl::string_view error_message,
                                     absl::string_view detail_message) override;

  // Validation methods
  bool validateUsername(const std::string& username);
  bool validateAuthData(const Buffer::Instance& data, size_t offset, uint8_t length);

  // Safe error handling and state management
  void closeWithError(const std::string& message, StreamInfo::CoreResponseFlag response_flag);
  void setUpstreamHandshakeState(UpstreamHandshakeState state);

  // Connection metadata methods
  void setConnectionMetadata(const std::string& username, const std::string& workspace_id,
                             const std::string& instance_url);
  void setRoutingMetadata(const std::string& key,
                          std::shared_ptr<Envoy::StreamInfo::FilterState::Object> value);
  void setAuthMetadata(const AuthData& auth_data);

  // SSL/TLS handshake methods
  void sendSslRequest();

  // Hostname validation method
  bool isHostnameAllowed(const std::string& hostname);

  /**
   * Compiles regex pattern once for username validation.
   * @throws EnvoyException if pattern is invalid
   */
  std::unique_ptr<Regex::CompiledGoogleReMatcher> compileRegexPattern();

  // Class members with clear ownership
  ConfigSharedPtr config_;
  Filter& parent_;
  Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  Network::WriteFilterCallbacks* write_callbacks_{nullptr};
  Buffer::OwnedImpl temp_handshake_packet_{};
  UpstreamHandshakeState upstream_handshake_state_{UpstreamHandshakeState::Init};
  uint32_t client_capabilities_{0};
  uint32_t server_capabilities_{0};
  Event::TimerPtr upstream_handshake_timer_;
  std::unique_ptr<Regex::CompiledGoogleReMatcher> regex_pattern_;
  uint32_t handshake_attempts_{0};
  bool connection_closed_{false}; // Guard against multiple close attempts
  AuthData client_auth_data_;     // Store client authentication data
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
