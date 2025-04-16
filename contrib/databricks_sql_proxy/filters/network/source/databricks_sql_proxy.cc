#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"

#include <chrono>
#include <cstdint>
#include <string>

#include "envoy/network/connection.h"

#include "source/common/network/upstream_server_name.h"
#include "source/common/tcp_proxy/tcp_proxy.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/common/sqlutils/source/sqlutils.h"
#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_helper.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_mysql_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_postgres_proxy.h"

using namespace std::chrono_literals;
using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;
using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

Config::Config(const DatabricksSqlProxyProto& proto_config,
               Server::Configuration::FactoryContext& context, const std::string& stat_prefix)
    : stats_{ALL_DATABRICKS_SQL_PROXY_STATS(POOL_COUNTER_PREFIX(context.scope(), stat_prefix),
                                            POOL_GAUGE_PREFIX(context.scope(), stat_prefix))},
      proto_config_(proto_config), protocol_(proto_config.protocol()),
      destination_cluster_source_(proto_config.destination_cluster_source()),
      include_peer_certificate_(proto_config.include_peer_certificate()),
      enable_upstream_tls_(proto_config.enable_upstream_tls().value()),
      filter_state_propagation_keys_to_ext_authz_(
          {proto_config.filter_state_propagation_keys_to_ext_authz().begin(),
           proto_config.filter_state_propagation_keys_to_ext_authz().end()}) {
  // Validate MySQL config is present when needed
  if (protocol_ == envoy::extensions::filters::network::databricks_sql_proxy::v3::
                       DatabricksSqlProxy::MYSQL &&
      !proto_config.has_mysql_config()) {
    throw EnvoyException("MySQL routing config required when protocol is MYSQL");
  }

  if (proto_config.has_handshake_timeout()) {
    const uint64_t timeout = DurationUtil::durationToMilliseconds(proto_config.handshake_timeout());
    if (timeout > 0) {
      handshake_timeout_ms_ = std::chrono::milliseconds(timeout);
    }
  } else {
    handshake_timeout_ms_ = std::chrono::seconds(15);
  }
}

Filter::Filter(ConfigSharedPtr config, ExtAuthzClientPtr&& ext_authz_client)
    : config_(config), ext_authz_client_(std::move(ext_authz_client)) {
  if (config_->protocol() == DatabricksSqlProxyProto::POSTGRES) {
    sql_proxy_ = std::make_unique<PostgresProxy>(config, *this);
  } else if (config_->protocol() == DatabricksSqlProxyProto::MYSQL) {
    sql_proxy_ = std::make_unique<MySQLProxy>(config, *this);
  } else {
    throw EnvoyException("Unsupported databricks_sql_proxy protocol.");
  }
}

void Filter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;

  setHandshakeState(HandshakeState::Init);

  ProtobufWkt::Value protocol_val;
  protocol_val.set_string_value(DatabricksSqlProxyProto::Protocol_Name(config_->protocol()));
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::PROTOCOL_KEY] = protocol_val;
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);

  read_callbacks_->connection().addConnectionCallbacks(*this);

  sql_proxy_->initializeReadFilterCallbacks(callbacks);
}

void Filter::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
  sql_proxy_->initializeWriteFilterCallbacks(callbacks);
}

Network::FilterStatus Filter::onNewConnection() {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onNewConnection", read_callbacks_->connection());

  // TcpProxy disable read in TcpProxy::initializeReadFilterCallbacks()
  // TcpProxy::initializeReadFilterCallbacks() is called before onNewConnection().
  // However, we do want to enable read so that TLS handshake and a start-up message can be
  // processed. so we are re-enabling read here.
  read_callbacks_->connection().readDisable(false);

  handshake_timer_ = read_callbacks_->connection().dispatcher().createTimer(
      [this]() -> void { onHandshakeTimeout(); });
  handshake_timer_->enableTimer(config_->handshakeTimeoutMs());

  // Do not continue the filter chain until we have processed the start up message.
  return Network::FilterStatus::StopIteration;
}

void Filter::onHandshakeTimeout() {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: handshake timed out", read_callbacks_->connection());

  maySendErrorResponseToDownstream(CommonErrors::DownstreamNoTls);
  closeConnection("Protocol handshake timed out", StreamInfo::CoreResponseFlag::StreamIdleTimeout);
  config_->stats().handshake_timeout_.inc();
  config_->stats().errors_.inc();
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(
      debug, "databricks_sql_proxy: onData received {} handshake_state_: {} end_stream: {}",
      read_callbacks_->connection(), data.length(), static_cast<int>(handshake_state_), end_stream);

  if (sql_proxy_->isOnDataForwardingMode()) {
    ENVOY_CONN_LOG(trace, "databricks_sql_proxy: onData: Forwarding mode",
                   read_callbacks_->connection());
    return Network::FilterStatus::Continue;
  }

  if (handshake_state_ == HandshakeState::Init) {
    if (sql_proxy_->processClientFirstMessage(data) == false) {
      return Network::FilterStatus::StopIteration;
    }

    if (sql_proxy_->requireTls() && read_callbacks_->connection().ssl() == nullptr) {
      ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onData: Downstream does not support SSL",
                     read_callbacks_->connection());
      maySendErrorResponseToDownstream(CommonErrors::DownstreamNoTls);

      closeConnection("Downstream connection is not a TLS connection.",
                      StreamInfo::CoreResponseFlag::DownstreamProtocolError);
      config_->stats().downstream_not_support_ssl_.inc();
      config_->stats().errors_.inc();
      return Network::FilterStatus::StopIteration;
    }

    std::string sni = "";
    const auto* sni_fs =
        read_callbacks_->connection()
            .streamInfo()
            .filterState()
            ->getDataReadOnly<Network::UpstreamServerName>(Network::UpstreamServerName::key());

    if (sni_fs != nullptr) {
      // Use SNI from filter state if available
      sni = sni_fs->value();
    } else {
      // Try to get SNI from the connection
      if (read_callbacks_->connection().ssl() != nullptr) {
        sni = read_callbacks_->connection().ssl()->sni();
      }

      if (!sni.empty()) {
        setUpstreamSni(sni);
      } else if (sql_proxy_->requireTls()) {
        ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onData: SNI is empty",
                       read_callbacks_->connection());
        maySendErrorResponseToDownstream(CommonErrors::DownstreamNoSni);
        closeConnection("Downstream connection does not have SNI.",
                        StreamInfo::CoreResponseFlag::DownstreamProtocolError);
        config_->stats().downstream_no_sni_.inc();
        config_->stats().errors_.inc();
        return Network::FilterStatus::StopIteration;
      }
    }

    if (config_->destinationClusterSource() == DatabricksSqlProxyProto::SIDECAR_SERVICE) {
      callExternalAuthorizationService();
    } else if (config_->destinationClusterSource() == DatabricksSqlProxyProto::SNI) {
      initiateUpstreamConnectionUsingSni(sni);
    } else {
      ASSERT(config_->destinationClusterSource() == DatabricksSqlProxyProto::DYNAMIC_FORWARD_PROXY);
      initiateUpstreamConnection();
    }
  }

  // We are still waiting for the upstream handshake process to be completed and to be in a
  // forwarding mode. Do not continue the filter chain until then. We do not want to forward
  // downstream message to upstream yet.
  return Network::FilterStatus::StopIteration;
}

// Call external authorization service to get the target cluster.
// The call to external authorization service is asynchronous. When it completes, it will call
// onComplete().
void Filter::callExternalAuthorizationService() {
  Filters::Common::ExtAuthz::CheckRequestUtils::createTcpCheck(
      read_callbacks_, check_request_, config_->includePeerCertificate(),
      true,                                       // include_tls_session
      Protobuf::Map<std::string, std::string>()); // destination_labels

  sidecar_operation_ = SidecarOperation::CheckAuthorization;
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::OPERATION_KEY].set_number_value(
      enumToInt(sidecar_operation_));
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);

  // Add dynamic metadata to metadata_context in check_request_
  (*check_request_.mutable_attributes()
        ->mutable_metadata_context()
        ->mutable_filter_metadata())[NetworkFilterNames::get().DatabricksSqlProxy]
      .MergeFrom((*read_callbacks_->connection()
                       .streamInfo()
                       .dynamicMetadata()
                       .mutable_filter_metadata())[NetworkFilterNames::get().DatabricksSqlProxy]);

  // Propagate filter state keys to ext_authz request
  for (const auto& key : config_->filterStatePropagationKeysToExtAuthz()) {
    ENVOY_CONN_LOG(debug,
                   "databricks_sql_proxy: callExternalAuthorizationService: "
                   "Filter state key = {} , hasData<HashableStringObject>()? = {}",
                   read_callbacks_->connection(), key,
                   read_callbacks_->connection()
                       .streamInfo()
                       .filterState()
                       ->hasData<Filters::Common::SetFilterState::HashableStringObject>(key));
    const auto* data =
        read_callbacks_->connection()
            .streamInfo()
            .filterState()
            ->getDataReadOnly<Filters::Common::SetFilterState::HashableStringObject>(key);
    if (data != nullptr) {
      ProtobufWkt::Value value;
      value.set_string_value(data->asString());
      (*check_request_.mutable_attributes()
            ->mutable_metadata_context()
            ->mutable_filter_metadata())[NetworkFilterNames::get().DatabricksSqlProxy]
          .mutable_fields()
          ->insert({key, value});
    } else {
      ENVOY_CONN_LOG(debug,
                     "databricks_sql_proxy: callExternalAuthorizationService: "
                     "Filter state key {} not found",
                     read_callbacks_->connection(), key);
    }
  }

  // Store start time of ext_authz filter call
  start_time_ = read_callbacks_->connection().dispatcher().timeSource().monotonicTime();
  setHandshakeState(HandshakeState::WaitingForExtAuthzResponse);
  config_->stats().active_ext_authz_call_.inc();
  ext_authz_client_->check(*this, check_request_, Tracing::NullSpan::instance(),
                           read_callbacks_->connection().streamInfo());
}

/**
 * Call external authorization service (sidecar) to store filter dynamic metadata.
 * Depending on the sidecar implementation, metadata fields that will be stored will be different.
 */
void Filter::storeMetadataInSidecar() {
  Filters::Common::ExtAuthz::CheckRequestUtils::createTcpCheck(
      read_callbacks_, check_request_, config_->includePeerCertificate(),
      true,                                       // include_tls_session
      Protobuf::Map<std::string, std::string>()); // destination_labels

  sidecar_operation_ = SidecarOperation::StoreMetadata;
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::OPERATION_KEY].set_number_value(
      enumToInt(sidecar_operation_));
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);

  config_->stats().active_ext_authz_call_.inc();
  // Add dynamic metadata to metadata_context in check_request
  (*check_request_.mutable_attributes()
        ->mutable_metadata_context()
        ->mutable_filter_metadata())[NetworkFilterNames::get().DatabricksSqlProxy]
      .MergeFrom((*read_callbacks_->connection()
                       .streamInfo()
                       .dynamicMetadata()
                       .mutable_filter_metadata())[NetworkFilterNames::get().DatabricksSqlProxy]);

  ext_authz_client_->check(*this, check_request_, Tracing::NullSpan::instance(),
                           read_callbacks_->connection().streamInfo());
}

// Callback function when external authorization service (sidecar) call is completed.
//
// When sidecar operation is to check authorzation, if the call is successful,
// the response will contains the target cluster in a dynamic metadata.
// Then the function will set TcpProxy upstream cluster and initiate upstream
// connection.
//
// If external authorization service call is failed, it will close the connection.
//
// When sidecar operation is to store metadata, we only check for the response status.
// No additional action is taken.
void Filter::onComplete(Filters::Common::ExtAuthz::ResponsePtr&& response) {
  config_->stats().active_ext_authz_call_.dec();
  switch (response->status) {
  case Filters::Common::ExtAuthz::CheckStatus::OK: {

    // Add duration of call to dynamic metadata if applicable
    if (start_time_.has_value()) {
      ProtobufWkt::Value ext_authz_duration_value;
      auto duration = read_callbacks_->connection().dispatcher().timeSource().monotonicTime() -
                      start_time_.value();
      ext_authz_duration_value.set_number_value(
          std::chrono::duration_cast<std::chrono::microseconds>(duration).count());
      (*response->dynamic_metadata.mutable_fields())[CommonConstants::EXT_AUTHZ_DURATION_MS_KEY] =
          ext_authz_duration_value;
    }

    if (sidecar_operation_ == SidecarOperation::CheckAuthorization) {
      ASSERT(handshake_state_ == HandshakeState::WaitingForExtAuthzResponse,
             fmt::format("Expect handshake_state_ to be {}. Current handshake_state_={}.",
                         static_cast<int>(HandshakeState::WaitingForExtAuthzResponse),
                         static_cast<int>(handshake_state_)));

      setHandshakeState(HandshakeState::ExtAuthzResponseCompleted);

      // Check should return dynamic metadata for picking the upstream cluster.
      std::string target_cluster = response->dynamic_metadata.fields()
                                       .at(CommonConstants::TARGET_CLUSTER_KEY)
                                       .string_value();

      ENVOY_CONN_LOG(debug, "onComplete: target_cluster: {}", read_callbacks_->connection(),
                     target_cluster);

      // If sidecar configured to override upstream SNI, set it here.
      auto override_upstream_sni_entry =
          response->dynamic_metadata.fields().find(CommonConstants::OVERRIDE_UPSTREAM_SNI_KEY);
      if (override_upstream_sni_entry != response->dynamic_metadata.fields().end()) {
        std::string override_upstream_sni_value =
            override_upstream_sni_entry->second.string_value();
        ENVOY_CONN_LOG(debug, "onComplete: override_upstream_sni_value: {}",
                       read_callbacks_->connection(), override_upstream_sni_value);
        setUpstreamSni(override_upstream_sni_value);
      }

      // Copy all returned dynamic metadata to the filter dynamic metadata.
      read_callbacks_->connection().streamInfo().setDynamicMetadata(
          NetworkFilterNames::get().DatabricksSqlProxy, response->dynamic_metadata);

      // If we are using ExtAuthZ then the target cluster name must come from it.
      initiateUpstreamConnectionUsingSni(target_cluster);
    }
  } break;
  case Filters::Common::ExtAuthz::CheckStatus::Error:
  case Filters::Common::ExtAuthz::CheckStatus::Denied:
    std::string reason_phrase = "";
    if (!response->dynamic_metadata.fields().empty()) {
      read_callbacks_->connection().streamInfo().setDynamicMetadata(
          NetworkFilterNames::get().DatabricksSqlProxy, response->dynamic_metadata);

      reason_phrase =
          response->dynamic_metadata.fields().at(CommonConstants::REASON_PHRASE_KEY).string_value();
    }

    if (sidecar_operation_ == SidecarOperation::CheckAuthorization) {
      setHandshakeState(HandshakeState::ExtAuthzResponseCompleted);
      read_callbacks_->connection().streamInfo().setResponseCodeDetails(
          response->status == Filters::Common::ExtAuthz::CheckStatus::Denied
              ? Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzDenied
              : Filters::Common::ExtAuthz::ResponseCodeDetails::get().AuthzError);
      maySendErrorResponseToDownstream(CommonErrors::ExtAuthzFailed, reason_phrase);
      closeConnection("Ext Authz failed",
                      StreamInfo::CoreResponseFlag::UnauthorizedExternalService);
      config_->stats().errors_.inc();
      config_->stats().ext_authz_failed_.inc();
    }
    break;
  }
}

void Filter::onEvent(Network::ConnectionEvent event) {
  std::string response_flag_str = "";
  if (read_callbacks_->connection().streamInfo().hasAnyResponseFlag()) {
    response_flag_str = ::Envoy::StreamInfo::ResponseFlagUtils::toString(
        read_callbacks_->connection().streamInfo());
  }

  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onEvent: {} response_flag_str: {}",
                 read_callbacks_->connection(), enumToInt(event), response_flag_str);

  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    if (handshake_state_ == HandshakeState::WaitingForExtAuthzResponse) {
      ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onEvent: ext_authz call cancelled.",
                     read_callbacks_->connection());
      // Make sure that any pending request in the client is cancelled. This will be NOP if the
      // request already completed.
      ext_authz_client_->cancel();
      config_->stats().active_ext_authz_call_.dec();
      config_->stats().ext_authz_failed_.inc();
      config_->stats().errors_.inc();
    }
  }
}

void Filter::setUpstreamSni(std::string& sni) {
  ENVOY_CONN_LOG(info, "databricks_sql_proxy: SNI {}", read_callbacks_->connection(), sni);

  // Override upstream SNI with downstream SNI to keep the original target hostname.
  read_callbacks_->connection().streamInfo().filterState()->setData(
      Network::UpstreamServerName::key(), std::make_unique<Network::UpstreamServerName>(sni),
      StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
}

// Send empty buffer to TcpProxy to initiate the upstream connection.
void Filter::initiateUpstreamConnectionUsingSni(std::string& target_cluster) {
  // Set the target cluster in the connection filter state before calling TcpProxy::onNewConnection
  // as the function will try to establish the upstream connection.
  read_callbacks_->connection().streamInfo().filterState()->setData(
      TcpProxy::PerConnectionCluster::key(),
      std::make_unique<TcpProxy::PerConnectionCluster>(target_cluster),
      StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
  initiateUpstreamConnection();
}

// Send empty buffer to TcpProxy to initiate the upstream connection.
void Filter::initiateUpstreamConnection() {
  // Disable handshake timeout because we are about to establish the upstream connection.
  // We will rely on TCP_proxy filter to handle the upstream timeout.
  handshake_timer_->disableTimer();

  // Disable read until we established upstream connection.
  // Once TcpProxy established upstream connection, it will re-enable read.
  read_callbacks_->connection().readDisable(true);

  Buffer::OwnedImpl empty_buffer;
  // This will call TcpProxy::onNewConnection to establish upstream connection.
  read_callbacks_->injectReadDataToFilterChain(empty_buffer, false);

  setHandshakeState(HandshakeState::CreatingUpstreamConnection);

  if (shouldPollForUpstreamConnected()) {
    // Create a timer task to check if the upstream connection is established.
    // Need to do it like this because there is no callback function when the upstream connection is
    // established.
    upstream_connect_check_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { pollForUpstreamConnected(); });
    // Timer task runs every 1ms to check if the upstream connection is established.
    upstream_connect_check_timer_->enableTimer(std::chrono::milliseconds(1));
  }
}

bool Filter::shouldPollForUpstreamConnected() {
  return sql_proxy_->shouldPollForUpstreamConnected();
}

void Filter::pollForUpstreamConnected() {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: pollForUpstreamConnected.",
                 read_callbacks_->connection());

  ASSERT(handshake_state_ == HandshakeState::CreatingUpstreamConnection,
         fmt::format("Expect handshake_state to be '{}'. Current handshake_state is '{}'.",
                     static_cast<int>(HandshakeState::CreatingUpstreamConnection),
                     static_cast<int>(handshake_state_)));

  // If read is enabled, it means that TcpProxy established the upstream connection.
  if (read_callbacks_->connection().state() == Network::Connection::State::Open && read_callbacks_->connection().readEnabled()) {
    // Disable the timer task since we do not need it anymore.
    upstream_connect_check_timer_->disableTimer();
    sql_proxy_->onUpstreamConnected();
    // Set the handshake state to UpstreamConnected and call onUpstreamConnected on the sql_proxy.
    setHandshakeState(HandshakeState::UpstreamConnected);
  } else {
    if (read_callbacks_->connection().state() == Network::Connection::State::Open && shouldPollForUpstreamConnected()) {
      // Enable timer to try again.
      upstream_connect_check_timer_->enableTimer(std::chrono::milliseconds(1));
    } else {
      // Disable the timer task since we do not need it anymore.
      upstream_connect_check_timer_->disableTimer();
    }
  }
}

Network::FilterStatus Filter::onWrite(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(debug, "databricks_sql_proxy: onWrite data.length={}",
                 read_callbacks_->connection(), data.length());

  if (sql_proxy_->isOnWriteForwardingMode()) {
    ENVOY_CONN_LOG(trace, "databricks_sql_proxy: onWrite: Forwarding mode",
                   read_callbacks_->connection());
    return Network::FilterStatus::Continue;
  }

  if (config_->protocol() == DatabricksSqlProxyProto::POSTGRES) {
    // For Postgres, we are polling for the upstream connection establishment.
    // After the upstream connection is established, we will send the startup message to the
    // upstream. We should not receive any data from the upstream before that. Otherwise, it is a
    // protocol violation.
    if (handshake_state_ != HandshakeState::UpstreamConnected) {
      ENVOY_CONN_LOG(error,
                     "databricks_sql_proxy: Invalid state. Expect handshake_state to be '{}'. "
                     "Current handshake_state is '{}'.",
                     read_callbacks_->connection(),
                     static_cast<int>(HandshakeState::UpstreamConnected),
                     static_cast<int>(handshake_state_));
      maySendErrorResponseToDownstream(CommonErrors::InvalidUpstreamHandshakeState);
      closeConnection("Invalid state. Expect handshake_state to be UpstreamConnected.",
                      StreamInfo::CoreResponseFlag::UpstreamProtocolError);
      config_->stats().errors_.inc();
      config_->stats().protocol_violation_.inc();
      return Network::FilterStatus::StopIteration;
    }
  } else if (config_->protocol() == DatabricksSqlProxyProto::MYSQL) {
    // If we're receiving data from upstream, it means the connection has been established. We are
    // not polling for the upstream connection establishment in case of MySQL.
    if (handshake_state_ == HandshakeState::CreatingUpstreamConnection) {
      // Update the handshake state to UpstreamConnected
      setHandshakeState(HandshakeState::UpstreamConnected);
    } else {
      ENVOY_CONN_LOG(error,
                     "databricks_sql_proxy: Invalid state for MySQL. Expect handshake_state to be "
                     "'{}'. Current handshake_state is '{}'.",
                     read_callbacks_->connection(),
                     static_cast<int>(HandshakeState::CreatingUpstreamConnection),
                     static_cast<int>(handshake_state_));
      closeConnection("Invalid state for MySQL handshake.",
                      StreamInfo::CoreResponseFlag::UpstreamProtocolError);
      config_->stats().errors_.inc();
      config_->stats().protocol_violation_.inc();
      return Network::FilterStatus::StopIteration;
    }
  } else {
    // Unknown protocol
    closeConnection("Unsupported protocol", StreamInfo::CoreResponseFlag::UpstreamProtocolError);
    config_->stats().errors_.inc();
    return Network::FilterStatus::StopIteration;
  }

  return sql_proxy_->handleUpstreamData(data, end_stream);
}

void Filter::closeConnection(const std::string& connection_termination_details,
                             StreamInfo::CoreResponseFlag response_flag) {
  read_callbacks_->connection().streamInfo().setConnectionTerminationDetails(
      connection_termination_details);
  if (response_flag != StreamInfo::CoreResponseFlag::LastFlag) {
    read_callbacks_->connection().streamInfo().setResponseFlag(response_flag);
  }
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush,
                                      connection_termination_details);
}

/**
 * Set the filter handshake state and record it in the dynamic metadata.
 */
void Filter::setHandshakeState(HandshakeState state) {
  handshake_state_ = state;

  // Set dynamic metadata to keep track of the handshake state for access log debugging.
  ProtobufWkt::Value handshake_state_val;
  handshake_state_val.set_number_value(static_cast<int>(state));
  ProtobufWkt::Struct metadata;
  (*metadata.mutable_fields())[CommonConstants::HANDSHAKE_STATE_KEY] = handshake_state_val;
  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().DatabricksSqlProxy, metadata);
}

/**
 * If the error type is found with ErrorInfo defintion, this function will
 * send the error response to the downstream.
 * Otherwise, this is a No-OP.
 */
void Filter::maySendErrorResponseToDownstream(CommonErrors error_type,
                                              absl::string_view additional_detail_message) {
  if (config_->protocol() == DatabricksSqlProxyProto::POSTGRES) {
    auto it = PostgresCommonErrorInfo.find(error_type);
    // If we found error info, send the error response to the downstream.
    // Otherwise, skip it.
    if (it != PostgresCommonErrorInfo.end()) {
      ErrorInfo errorInfo = it->second;
      if (additional_detail_message.empty()) {
        sql_proxy_->sendErrorResponseToDownstream(static_cast<int16_t>(errorInfo.error_code),
                                                  errorInfo.sql_state, errorInfo.error_message,
                                                  errorInfo.detail_message);
      } else {
        // If additional detail message is provided, append it to the original detail message.
        // This is useful for providing more context about the error.
        std::string detail_message =
            fmt::format("{} {}", errorInfo.detail_message, additional_detail_message);
        sql_proxy_->sendErrorResponseToDownstream(static_cast<int16_t>(errorInfo.error_code),
                                                  errorInfo.sql_state, errorInfo.error_message,
                                                  detail_message);
      }
    }
  } else if (config_->protocol() == DatabricksSqlProxyProto::MYSQL) {
    auto it = MySqlCommonErrorInfo.find(error_type);
    // If we found error info, send the error response to the downstream.
    // Otherwise, skip it.
    if (it != MySqlCommonErrorInfo.end()) {
      ErrorInfo errorInfo = it->second;
      sql_proxy_->sendErrorResponseToDownstream(static_cast<int16_t>(errorInfo.error_code),
                                                errorInfo.sql_state, errorInfo.error_message,
                                                errorInfo.detail_message);
    }
  }
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
