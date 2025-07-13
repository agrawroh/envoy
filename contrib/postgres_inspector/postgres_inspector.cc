#include "contrib/postgres_inspector/postgres_inspector.h"

#include <cstddef>
#include <cstring>

#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/fmt.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/router/string_accessor_impl.h"
#include "source/common/stream_info/bool_accessor_impl.h"

#include "contrib/postgres_common/postgres_constants.h"
#include "contrib/postgres_inspector/postgres_inspector_metadata.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace PostgresInspector {

using Common::Postgres::PostgresConstants;

Config::Config(Stats::Scope& scope, const std::string& stat_prefix, size_t max_read_bytes)
    : stats_{ALL_POSTGRES_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, stat_prefix))},
      max_read_bytes_(max_read_bytes) {}

Filter::Filter(const ConfigSharedPtr& config) : config_(config) {}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "postgres_inspector: new connection accepted");

  const Network::ConnectionSocket& socket = cb.socket();
  const absl::string_view transport_protocol = socket.detectedTransportProtocol();

  // Skip inspection if transport protocol is already detected and not raw buffer.
  if (!transport_protocol.empty() && transport_protocol != "raw_buffer") {
    ENVOY_LOG(trace, "postgres_inspector: skipping inspection due to transport protocol: {}",
              transport_protocol);
    return Network::FilterStatus::Continue;
  }

  cb_ = &cb;
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  auto raw_slice = buffer.rawSlice();
  ENVOY_LOG(trace, "postgres_inspector: received {} bytes", raw_slice.len_);

  // If we've already detected PostgreSQL, continue.
  if (postgres_detected_) {
    return Network::FilterStatus::Continue;
  }

  const uint8_t* data = static_cast<const uint8_t*>(raw_slice.mem_);
  const size_t data_len = raw_slice.len_;

  // Need at least 8 bytes to determine message type.
  if (data_len < 8) {
    ENVOY_LOG(trace, "postgres_inspector: need more data for detection, current length: {}",
              data_len);
    config_->stats().need_more_data_.inc();
    return Network::FilterStatus::StopIteration;
  }

  // Look at the first 4 bytes to determine the length of the message.
  uint32_t message_len = 0;
  safeMemcpyUnsafeSrc(&message_len, data);
  message_len = ntohl(message_len);

  // Basic sanity check on message length.
  if (message_len < 8 || message_len > PostgresConstants::MAX_POSTGRES_MESSAGE_LENGTH) {
    ENVOY_LOG(debug, "postgres_inspector: invalid message length: {}", message_len);
    config_->stats().invalid_message_length_.inc();
    config_->stats().error_.inc();
    return Network::FilterStatus::Continue; // Not PostgreSQL, let other filters handle.
  }

  // Check if we have the full message.
  if (data_len < message_len) {
    ENVOY_LOG(trace, "postgres_inspector: need more data, have: {}, need: {}", data_len,
              message_len);
    config_->stats().need_more_data_.inc();
    return Network::FilterStatus::StopIteration;
  }

  // Look at the protocol version (next 4 bytes).
  uint32_t protocol_version = 0;
  safeMemcpyUnsafeSrc(&protocol_version, data + 4);
  protocol_version = ntohl(protocol_version);

  ENVOY_LOG(debug, "postgres_inspector: examining message, length: {}, protocol: {:#x}",
            message_len, protocol_version);

  // Check for SSL request.
  if (protocol_version == PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION &&
      message_len == PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH) {

    ENVOY_LOG(debug, "postgres_inspector: SSL request detected");
    config_->stats().ssl_request_detected_.inc();
    config_->stats().postgres_detected_.inc();

    // Extract SNI hostname from connection context.
    std::string sni_hostname = extractSniHostname();
    if (!sni_hostname.empty()) {
      ENVOY_LOG(debug, "postgres_inspector: SNI hostname extracted: {}", sni_hostname);
      setSniRoutingMetadata(sni_hostname);
    }

    setPostgresMetadata("ssl_request", true, sni_hostname);
    postgres_detected_ = true;
    return Network::FilterStatus::Continue;
  }

  // Check for regular PostgreSQL startup message.
  else if (protocol_version == PostgresConstants::PROTOCOL_VERSION) {
    ENVOY_LOG(debug, "postgres_inspector: PostgreSQL startup message detected");
    config_->stats().startup_message_detected_.inc();
    config_->stats().postgres_detected_.inc();
    setPostgresMetadata("startup_message", false);
    postgres_detected_ = true;
    return Network::FilterStatus::Continue;
  }

  // Not a recognized PostgreSQL message.
  else {
    ENVOY_LOG(debug,
              "postgres_inspector: not a PostgreSQL protocol message, protocol version: {:#x}",
              protocol_version);
    config_->stats().invalid_protocol_version_.inc();
    return Network::FilterStatus::Continue;
  }
}

void Filter::setPostgresMetadata(const std::string& protocol_type, bool supports_ssl,
                                 const std::string& sni_hostname) {
  ENVOY_LOG(debug,
            "postgres_inspector: setting metadata, protocol: postgres, type: {}, ssl: {}, sni: {}",
            protocol_type, supports_ssl, sni_hostname);

  // Set protocol metadata for downstream filters.
  cb_->socket().setDetectedTransportProtocol("postgres");

  // Set typed metadata for the network filter.
  auto metadata = NetworkFilters::PostgresProxy::PostgresInspectorMetadata::create(
      "postgres", protocol_type, supports_ssl, sni_hostname);

  auto& filter_state = cb_->filterState();
  filter_state.setData(NetworkFilters::PostgresProxy::PostgresInspectorMetadata::filterStateKey(),
                       std::move(metadata), StreamInfo::FilterState::StateType::ReadOnly,
                       StreamInfo::FilterState::LifeSpan::Connection);

  // For SSL connections, enable receive_before_connect to allow filter chain level TLS
  // processing before TCP Proxy.
  if (supports_ssl) {
    static const std::string tcp_proxy_key = "envoy.tcp_proxy.receive_before_connect";

    // Only set if not already set by other filters.
    if (!filter_state.hasDataWithName(tcp_proxy_key)) {
      filter_state.setData(tcp_proxy_key, std::make_unique<StreamInfo::BoolAccessorImpl>(true),
                           StreamInfo::FilterState::StateType::ReadOnly,
                           StreamInfo::FilterState::LifeSpan::Connection);

      ENVOY_LOG(debug, "postgres_inspector: enabled receive_before_connect for SSL connection");
    } else {
      ENVOY_LOG(trace, "postgres_inspector: receive_before_connect already set by another filter");
    }
  }
}

std::string Filter::extractSniHostname() const {
  if (!cb_) {
    return "";
  }

  // Extract SNI from SSL connection context.
  // This works with filter chain level TLS configuration.
  const auto& connection_info = cb_->socket().connectionInfoProvider();
  if (connection_info.sslConnection()) {
    const auto& ssl_info = connection_info.sslConnection();
    if (ssl_info && !ssl_info->sni().empty()) {
      const std::string& sni_hostname = ssl_info->sni();
      ENVOY_LOG(debug, "postgres_inspector: extracted SNI hostname: {}", sni_hostname);
      return sni_hostname;
    }
  }

  // Fallback: try to extract from connection socket directly.
  // This is for cases where SSL connection is not yet established.
  const auto& socket = cb_->socket();
  const auto sni_view = socket.requestedServerName();
  if (!sni_view.empty()) {
    std::string sni_hostname(sni_view);
    ENVOY_LOG(debug, "postgres_inspector: extracted SNI hostname from socket: {}", sni_hostname);
    return sni_hostname;
  }

  ENVOY_LOG(trace, "postgres_inspector: no SNI hostname available");
  return "";
}

void Filter::setSniRoutingMetadata(const std::string& sni_hostname) {
  if (sni_hostname.empty() || !cb_) {
    return;
  }

  // Set SNI-based cluster routing metadata for downstream filters.
  auto& filter_state = cb_->filterState();

  // Set the target cluster name based on SNI hostname.
  // This can be used by SNI cluster filter or similar routing filters.
  static const std::string sni_cluster_key = "envoy.filters.network.sni_cluster.cluster_name";

  if (!filter_state.hasDataWithName(sni_cluster_key)) {
    filter_state.setData(sni_cluster_key,
                         std::make_unique<Router::StringAccessorImpl>(sni_hostname),
                         StreamInfo::FilterState::StateType::ReadOnly,
                         StreamInfo::FilterState::LifeSpan::Connection);

    ENVOY_LOG(debug, "postgres_inspector: set SNI cluster routing metadata: {}", sni_hostname);
  }

  // Also set a more generic SNI metadata that can be used by other filters.
  static const std::string sni_hostname_key = "envoy.postgres_inspector.sni_hostname";

  if (!filter_state.hasDataWithName(sni_hostname_key)) {
    filter_state.setData(sni_hostname_key,
                         std::make_unique<Router::StringAccessorImpl>(sni_hostname),
                         StreamInfo::FilterState::StateType::ReadOnly,
                         StreamInfo::FilterState::LifeSpan::Connection);

    ENVOY_LOG(debug, "postgres_inspector: set SNI hostname metadata: {}", sni_hostname);
  }
}

} // namespace PostgresInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
