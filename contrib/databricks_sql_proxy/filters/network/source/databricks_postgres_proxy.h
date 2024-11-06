#pragma once

#include "envoy/event/timer.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

class PostgresProxy : public SqlProtocolProxy, Logger::Loggable<Logger::Id::filter> {
public:
  PostgresProxy(ConfigSharedPtr config, Filter& parent) : config_(config), parent_(parent) {}

  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override;

  /**
   * Process postgres startup message from downstream connection.
   * @param data the handshake message.
   * @return true if the handshake message is processed successfully. false otherwise.
   */
  bool processClientFirstMessage(Buffer::Instance& data) override;

  bool shouldPollForUpstreamConnected() const override;
  /*
   * Connected to upstream cluster.
   * For Postgres, this is where we initiate SSL with the upstream.
   */
  void onUpstreamConnected() override;

  /*
   * Handle data from upstream. This will be called for every data packet received from the
   * upstream. So the SQL protocol proxy implementation should keep track of the state of the
   * connection.
   *
   * For postgres, this is where we expect to receive the SSL response from the upstream.
   */
  Network::FilterStatus handleUpstreamData(Buffer::Instance& data, bool end_stream) override;

  bool isOnDataForwardingMode() const override {
    return upstream_handshake_state_ >= UpstreamHandshakeState::SentStartupMessage;
  }
  bool isOnWriteForwardingMode() const override {
    return upstream_handshake_state_ >= UpstreamHandshakeState::ProcessedBackendKeyData;
  }

  bool requireTls() const override;

  void sendErrorResponseToDownstream(int16_t error_code, absl::string_view sql_state,
                                     absl::string_view error_message,
                                     absl::string_view detail_message) override;

  void outputConnectionStringToDynamicMetadata(Buffer::Instance& data, uint32_t bytes_to_read);

  enum class UpstreamHandshakeState {
    Init, // Initial state of the filter is to wait for start up packet from downstream.
    SentSslRequestUpstream,  // Wait for TcpProxy to establish the upstream connection.
    SentStartupMessage,      // Sent the buffered startup message to upstream. At this point, we are
                             // ready to forward the data from downstream to upstream.
    ProcessedBackendKeyData, // Processed the backend key data from the upstream.
    ProcessedCancellation,   // Processed the cancellation message from the downstream.
  };

  enum class PostgresMessageTypes {
    START_UP,
    CANCELLATION,
  };

private:
  void setUpstreamHandshakeState(UpstreamHandshakeState state);
  void sendPostgresCancelRequestToUpstream();
  void sendPostgresSslRequestToUpstream();
  void sendPostgresStartupMessageToUpstream();
  Network::FilterStatus handleUpstreamSslResponse(Buffer::Instance& data);
  bool findAndProcessUpstreamIpParameterStatus(Buffer::Instance& data, uint32_t message_len);
  void processBackendKeyDataMessage(Buffer::Instance& data);
  void setDynamicMetadataNumber(const absl::string_view key, const int64_t value);
  void setDynamicMetadataString(const absl::string_view key, std::string& value);

  ConfigSharedPtr config_;
  Filter& parent_;
  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
  Buffer::OwnedImpl temp_startup_packet_{};
  Buffer::OwnedImpl data_to_forward_{};
  UpstreamHandshakeState upstream_handshake_state_{UpstreamHandshakeState::Init};
  PostgresMessageTypes first_client_message_type_{PostgresMessageTypes::START_UP};
};

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
