#pragma once

#include <cstdint>

#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/runtime/runtime.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/common/ext_authz/ext_authz_grpc_impl.h"
#include "source/extensions/filters/common/set_filter_state/filter_config.h"

#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_errors.h"
#include "contrib/envoy/extensions/filters/network/databricks_sql_proxy/v3/databricks_sql_proxy.pb.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

/**
 * All proxy stats. @see stats_macros.h
 */
#define ALL_DATABRICKS_SQL_PROXY_STATS(COUNTER, GAUGE)                                             \
  COUNTER(errors)                                                                                  \
  COUNTER(invalid_message_length)                                                                  \
  COUNTER(invalid_upstream_response)                                                               \
  COUNTER(invalid_protocol_version)                                                                \
  COUNTER(protocol_violation)                                                                      \
  COUNTER(incorrect_upstream_connection_state)                                                     \
  COUNTER(failed_upstream_ssl_handshake)                                                           \
  COUNTER(upstream_not_support_ssl)                                                                \
  COUNTER(downstream_not_support_ssl)                                                              \
  COUNTER(downstream_no_sni)                                                                       \
  COUNTER(ext_authz_failed)                                                                        \
  COUNTER(handshake_timeout)                                                                       \
  COUNTER(malformed_packet)                                                                        \
  COUNTER(invalid_capability_flags)                                                                \
  COUNTER(username_extraction_failed)                                                              \
  COUNTER(oversized_packet)                                                                        \
  COUNTER(invalid_username)                                                                        \
  COUNTER(successful_login)                                                                        \
  COUNTER(access_denied)                                                                           \
  COUNTER(sent_cancel_request)                                                                     \
  GAUGE(buffered_first_message, Accumulate)                                                        \
  GAUGE(active_ext_authz_call, Accumulate)

/**
 * Struct definition for all proxy stats. @see stats_macros.h
 */
struct DatabricksSqlProxyStats {
  ALL_DATABRICKS_SQL_PROXY_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

/**
 * Filter configuration.
 */
class Config {
public:
  Config(const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy&
             config,
         Server::Configuration::FactoryContext& context, const std::string& stat_prefix);

  const DatabricksSqlProxyStats& stats() { return stats_; }
  envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy::Protocol
  protocol() {
    return protocol_;
  }
  envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy::
      DestinationClusterSource
      destinationClusterSource() {
    return destination_cluster_source_;
  }
  bool includePeerCertificate() { return include_peer_certificate_; }
  bool enableUpstreamTls() { return enable_upstream_tls_; }
  std::chrono::milliseconds handshakeTimeoutMs() { return handshake_timeout_ms_; }

  // Get full proto config
  const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy&
  protoConfig() const {
    return proto_config_;
  }

  // Get filter state propagation keys to ext_authz
  const std::vector<std::string>& filterStatePropagationKeysToExtAuthz() const {
    return filter_state_propagation_keys_to_ext_authz_;
  }

private:
  const DatabricksSqlProxyStats stats_;
  const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy
      proto_config_;
  const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy::Protocol
      protocol_;
  const envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy::
      DestinationClusterSource destination_cluster_source_;
  const bool include_peer_certificate_;
  const bool enable_upstream_tls_;
  std::chrono::milliseconds handshake_timeout_ms_;
  std::vector<std::string> filter_state_propagation_keys_to_ext_authz_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Interface for the SQL protocol inspector.
 */
class SqlProtocolProxy {
public:
  virtual ~SqlProtocolProxy() = default;

  virtual void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) PURE;
  virtual void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) PURE;

  /**
   * Process the first handshake message from downstream connection.
   * Regardless if there is an SSL or not, this is the first message that the client sends to the
   * server. If there is SSL, this message is sent after the SSL handshake is done.
   *
   * For Postgres, this expects to be a startup message.
   *
   * For MySQL, this expects to be a handshake response packet.
   *
   * @param data the handshake message.
   * @return true if the handshake message is processed successfully. false otherwise.
   */
  virtual bool processClientFirstMessage(Buffer::Instance& data) PURE;

  /**
   * Is TLS required for the downstream connection.
   *
   * For Postgres, this always return true because for Postgres, we need SNI for routing.
   * SNI is only available when the connection uses TLS.
   * The only exception is when the client sends a cancel request message. In that case, we allow
   * unencrypted downstream connection because cancel request is always sent unencrypted.
   *
   * For MySQL, this function return false because it uses the hostname in from the username to
   * determine the cluster and therefore can allow unencrypted downstream connection. Unencrypted
   * downstream connection is used in testing.
   */
  virtual bool requireTls() const PURE;

  /**
   * Should we poll for upstream connection established.
   *
   * For Postgres, this is needed because the client needs to send a SSL request to the upstream
   * after the connection is established.
   *
   * For MySQL, this is not needed because the client expects to receive the first message from the
   * upstream.
   */
  virtual bool shouldPollForUpstreamConnected() const PURE;

  /*
   * Connected to upstream cluster.
   * For Postgres, this is where we initiate SSL with the upstream.
   *
   * For MySQL, there is nothing to do here.
   * We expect to receive the SSL handshake from the upstream as soon as the connection is
   * established with upstream, so SSL handshake is done in handleUpstreamData().
   */
  virtual void onUpstreamConnected() PURE;

  /*
   * Handle data from upstream. This will be called for every data packet received from the
   * upstream. So the SQL protocol proxy implementation should keep track of the state of the
   * connection.
   *
   * For postgres, this is where we expect to receive the SSL response from the upstream.
   *
   * For MySQL, this is where we expect to receive the SSL handshake initiation from the upstream.
   */
  virtual Network::FilterStatus handleUpstreamData(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Is the SQL protocol proxy in forwarding mode where it will just forward the data from
   * downstream to upstream. and from upstream to downstream without any processing.
   *
   * For Postgres, this is after the filter sent startup message to the upstream.
   *
   * For MySQL, this is after the filter sent handshake response to the upstream.
   */
  virtual bool isOnDataForwardingMode() const PURE;
  virtual bool isOnWriteForwardingMode() const PURE;

  /**
   * Function to send error messages to the downstream.
   *
   * For postgres
   * - error_code is an ENUM value.
   * - sql_state is a string according to this spec
   * https://www.postgresql.org/docs/current/errcodes-appendix.html
   * - error_message is the error message.
   * - detail_message is optional and if not empty, it will be included in the error response.
   *
   *
   * For MySQL, this is the spec of the error message
   * https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_err_packet.html
   *
   * For error_code number and SQL State value, please refer to this spec
   * https://dev.mysql.com/doc/refman/8.0/en/error-message-elements.html#error-code-ranges
   * and this one https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
   *
   * - error_code is a number.
   * - sql_state is SQL State in MySQL.
   * - error_message is the error message.
   * - detail_message is not supported in MySQL spec and should be ignored.
   */
  virtual void sendErrorResponseToDownstream(int16_t error_code, absl::string_view sql_state,
                                             absl::string_view error_message,
                                             absl::string_view detail_message) PURE;
};
using SqlProtocolProxyUniquePtr = std::unique_ptr<SqlProtocolProxy>;
using ExtAuthzClientPtr = std::unique_ptr<Filters::Common::ExtAuthz::Client>;

/**
 * Databricks SQL proxy filter.
 */
class Filter : public Network::Filter,
               public Network::ConnectionCallbacks,
               public Filters::Common::ExtAuthz::RequestCallbacks,
               protected Logger::Loggable<Logger::Id::filter> {
public:
  Filter(ConfigSharedPtr config, ExtAuthzClientPtr&& ext_authz_client);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override;

  // Filters::Common::ExtAuthz::RequestCallbacks
  void onComplete(Filters::Common::ExtAuthz::ResponsePtr&& response) override;

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  void onHandshakeTimeout();
  void pollForUpstreamConnected();
  void closeConnection(
      const std::string& connection_termination_details,
      StreamInfo::CoreResponseFlag response_flag = StreamInfo::CoreResponseFlag::LastFlag);
  void storeMetadataInSidecar();

  enum class HandshakeState {
    Init, // Initial state of the filter is to wait for start up packet from downstream.
    WaitingForExtAuthzResponse, // Called the external authorization service and is waiting for the
                                // response.
    ExtAuthzResponseCompleted,  // External authorization service response received or timeout.
    CreatingUpstreamConnection, // Wait for TcpProxy to establish the upstream connection.
    UpstreamConnected,          // Upstream connection is established.
  };

  enum class SidecarOperation {
    CheckAuthorization, // Check authorization with external authorization service.
    StoreMetadata,      // Store additional metadata in the sidecar service.
  };

private:
  void setUpstreamSni(std::string& sni);
  void initiateUpstreamConnection();
  void initiateUpstreamConnectionUsingSni(std::string& target_cluster);
  bool shouldPollForUpstreamConnected();
  void callExternalAuthorizationService();
  void setHandshakeState(HandshakeState state);
  void maySendErrorResponseToDownstream(CommonErrors error_type,
                                        absl::string_view additional_detail_message = "");

  HandshakeState handshake_state_{HandshakeState::Init};
  ConfigSharedPtr config_;

  Event::TimerPtr handshake_timer_;

  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
  Buffer::OwnedImpl temp_startup_packet_{};
  Event::TimerPtr upstream_connect_check_timer_;
  SqlProtocolProxyUniquePtr sql_proxy_{};

  ExtAuthzClientPtr ext_authz_client_{};
  envoy::service::auth::v3::CheckRequest check_request_{};
  absl::optional<MonotonicTime> start_time_{};
  SidecarOperation sidecar_operation_{SidecarOperation::CheckAuthorization};
};

using FilterSharedPtr = std::shared_ptr<Filter>;

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
