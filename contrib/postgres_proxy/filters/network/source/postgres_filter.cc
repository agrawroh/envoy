#include "contrib/postgres_proxy/filters/network/source/postgres_filter.h"
#include "postgres_filter.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/assert.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/postgres_inspector/postgres_inspector_metadata.h"
#include "contrib/postgres_proxy/filters/network/source/postgres_decoder.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

PostgresFilterConfig::PostgresFilterConfig(const PostgresFilterConfigOptions& config_options,
                                           Stats::Scope& scope)
    : enable_sql_parsing_(config_options.enable_sql_parsing_),
      terminate_ssl_(config_options.terminate_ssl_), upstream_ssl_(config_options.upstream_ssl_),
      downstream_ssl_(config_options.downstream_ssl_),
      ssl_response_override_(config_options.ssl_response_override_),
      force_upstream_renegotiation_(config_options.force_upstream_renegotiation_),
      ssl_handshake_timeout_ms_(config_options.ssl_handshake_timeout_ms_),
      downstream_ssl_options_(config_options.downstream_ssl_options_),
      upstream_ssl_options_(config_options.upstream_ssl_options_), scope_{scope},
      stats_{generateStats(config_options.stats_prefix_, scope)} {}

envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
PostgresFilterConfig::getEffectiveDownstreamSSLMode() const {
  // SSL mode is always determined by the base downstream_ssl field
  // downstream_ssl_options only provides additional configuration
  return downstream_ssl_;
}

envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
PostgresFilterConfig::getEffectiveUpstreamSSLMode() const {
  // SSL mode is always determined by the base upstream_ssl field
  // upstream_ssl_options only provides additional configuration
  return upstream_ssl_;
}

PostgresFilter::PostgresFilter(PostgresFilterConfigSharedPtr config) : config_{config} {
  if (!decoder_) {
    decoder_ = createDecoder(this);
  }
  if (!encoder_) {
    encoder_ = createEncoder();
  }
}

// Network::ReadFilter
Network::FilterStatus PostgresFilter::onData(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "received {} bytes", read_callbacks_->connection(), data.length());

  // Frontend Buffer
  frontend_buffer_.add(data);
  Network::FilterStatus result = doDecode(frontend_buffer_, true);
  if (result == Network::FilterStatus::StopIteration) {
    ASSERT(frontend_buffer_.length() == 0);
    data.drain(data.length());
  }
  return result;
}

Network::FilterStatus PostgresFilter::onNewConnection() { return Network::FilterStatus::Continue; }

void PostgresFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

void PostgresFilter::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
}

// Network::WriteFilter
Network::FilterStatus PostgresFilter::onWrite(Buffer::Instance& data, bool) {

  // Backend Buffer
  backend_buffer_.add(data);
  Network::FilterStatus result = doDecode(backend_buffer_, false);
  if (result == Network::FilterStatus::StopIteration) {
    ASSERT(backend_buffer_.length() == 0);
    data.drain(data.length());
  }
  return result;
}

DecoderPtr PostgresFilter::createDecoder(DecoderCallbacks* callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
}

EncoderPtr PostgresFilter::createEncoder() { return std::make_unique<Encoder>(); }

void PostgresFilter::incMessagesBackend() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_backend_.inc();
}

void PostgresFilter::incMessagesFrontend() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_frontend_.inc();
}

void PostgresFilter::incMessagesUnknown() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_unknown_.inc();
}

void PostgresFilter::incSessionsEncrypted() {
  config_->stats_.sessions_.inc();
  config_->stats_.sessions_encrypted_.inc();
}

void PostgresFilter::incSessionsUnencrypted() {
  config_->stats_.sessions_.inc();
  config_->stats_.sessions_unencrypted_.inc();
}

void PostgresFilter::incTransactions() {
  if (!decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_.inc();
  }
}

void PostgresFilter::incTransactionsCommit() {
  if (!decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_commit_.inc();
  }
}

void PostgresFilter::incTransactionsRollback() {
  if (decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_rollback_.inc();
  }
}

void PostgresFilter::incNotices(NoticeType type) {
  config_->stats_.notices_.inc();
  switch (type) {
  case DecoderCallbacks::NoticeType::Warning:
    config_->stats_.notices_warning_.inc();
    break;
  case DecoderCallbacks::NoticeType::Notice:
    config_->stats_.notices_notice_.inc();
    break;
  case DecoderCallbacks::NoticeType::Debug:
    config_->stats_.notices_debug_.inc();
    break;
  case DecoderCallbacks::NoticeType::Info:
    config_->stats_.notices_info_.inc();
    break;
  case DecoderCallbacks::NoticeType::Log:
    config_->stats_.notices_log_.inc();
    break;
  case DecoderCallbacks::NoticeType::Unknown:
    config_->stats_.notices_unknown_.inc();
    break;
  }
}

void PostgresFilter::incErrors(ErrorType type) {
  config_->stats_.errors_.inc();
  switch (type) {
  case DecoderCallbacks::ErrorType::Error:
    config_->stats_.errors_error_.inc();
    break;
  case DecoderCallbacks::ErrorType::Fatal:
    config_->stats_.errors_fatal_.inc();
    break;
  case DecoderCallbacks::ErrorType::Panic:
    config_->stats_.errors_panic_.inc();
    break;
  case DecoderCallbacks::ErrorType::Unknown:
    config_->stats_.errors_unknown_.inc();
    break;
  }
}

void PostgresFilter::incStatements(StatementType type) {
  config_->stats_.statements_.inc();

  switch (type) {
  case DecoderCallbacks::StatementType::Insert:
    config_->stats_.statements_insert_.inc();
    break;
  case DecoderCallbacks::StatementType::Delete:
    config_->stats_.statements_delete_.inc();
    break;
  case DecoderCallbacks::StatementType::Select:
    config_->stats_.statements_select_.inc();
    break;
  case DecoderCallbacks::StatementType::Update:
    config_->stats_.statements_update_.inc();
    break;
  case DecoderCallbacks::StatementType::Other:
    config_->stats_.statements_other_.inc();
    break;
  case DecoderCallbacks::StatementType::Noop:
    break;
  }
}

void PostgresFilter::processQuery(const std::string& sql) {
  if (config_->enable_sql_parsing_) {
    ProtobufWkt::Struct metadata;

    auto result = Common::SQLUtils::SQLUtils::setMetadata(sql, decoder_->getAttributes(), metadata);

    if (!result) {
      config_->stats_.statements_parse_error_.inc();
      ENVOY_CONN_LOG(trace, "postgres_proxy: cannot parse SQL: {}", read_callbacks_->connection(),
                     sql.c_str());
      return;
    }

    config_->stats_.statements_parsed_.inc();
    ENVOY_CONN_LOG(trace, "postgres_proxy: query processed {}", read_callbacks_->connection(),
                   sql.c_str());

    // Set dynamic metadata
    read_callbacks_->connection().streamInfo().setDynamicMetadata(
        NetworkFilterNames::get().PostgresProxy, metadata);
  }
}

bool PostgresFilter::checkInspectorSSLMetadata() const {
  // Check for typed metadata set by postgres_inspector.
  const auto& filter_state = read_callbacks_->connection().streamInfo().filterState();

  if (!filter_state->hasDataWithName(PostgresInspectorMetadata::filterStateKey())) {
    ENVOY_CONN_LOG(debug, "no inspector metadata found", read_callbacks_->connection());
    return false;
  }

  const auto* metadata = filter_state->getDataReadOnly<PostgresInspectorMetadata>(
      PostgresInspectorMetadata::filterStateKey());

  if (metadata == nullptr) {
    ENVOY_CONN_LOG(debug, "inspector metadata not accessible", read_callbacks_->connection());
    return false;
  }

  bool ssl_requested = metadata->sslRequested();
  ENVOY_CONN_LOG(debug, "inspector metadata indicates SSL requested: {}",
                 read_callbacks_->connection(), ssl_requested);
  return ssl_requested;
}

std::string PostgresFilter::getSSLResponse() const {
  // Check for custom SSL response in downstream config options
  if (config_->downstream_ssl_options_.has_value() &&
      !config_->downstream_ssl_options_->ssl_response_override().empty()) {
    return config_->downstream_ssl_options_->ssl_response_override();
  }

  // Check for custom SSL response in basic config
  if (!config_->ssl_response_override_.empty()) {
    return config_->ssl_response_override_;
  }

  // Default PostgreSQL SSL support response
  return "S";
}

bool PostgresFilter::handleSSLRequestWithMetadata() {
  const auto effective_downstream_ssl = config_->getEffectiveDownstreamSSLMode();

  // If SSL is disabled and we're not terminating SSL, pass through
  if (effective_downstream_ssl ==
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE &&
      !config_->terminate_ssl_) {

    // Check inspector metadata
    bool ssl_detected = checkInspectorSSLMetadata();
    ENVOY_CONN_LOG(debug, "inspector detected SSL: {}, but downstream SSL disabled",
                   read_callbacks_->connection(), ssl_detected);

    return true; // Signal to decoder to continue
  }

  // Enhanced SSL handling with inspector metadata consideration
  bool should_terminate_ssl = false;

  // Always attempt to use inspector metadata if available
  bool ssl_detected = checkInspectorSSLMetadata();

  if (ssl_detected) {
    should_terminate_ssl =
        (effective_downstream_ssl ==
             envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE ||
         effective_downstream_ssl ==
             envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::ALLOW);
    ENVOY_CONN_LOG(info, "inspector detected SSL request, terminating: {}",
                   read_callbacks_->connection(), should_terminate_ssl);
  } else {
    // If inspector metadata is not available, use original logic
    should_terminate_ssl = true;
    ENVOY_CONN_LOG(debug, "inspector metadata not available, using default SSL handling",
                   read_callbacks_->connection());
  }

  if (should_terminate_ssl) {
    // Send SSL support response
    std::string ssl_response = getSSLResponse();
    Buffer::OwnedImpl buf;
    buf.add(ssl_response);

    ENVOY_CONN_LOG(debug, "sending SSL response: '{}'", read_callbacks_->connection(),
                   ssl_response);

    // Add callback to be notified when the reply message has been transmitted
    read_callbacks_->connection().addBytesSentCallback([=, this](uint64_t bytes) -> bool {
      if (bytes >= ssl_response.length()) {
        if (!read_callbacks_->connection().startSecureTransport()) {
          ENVOY_CONN_LOG(info, "cannot enable downstream secure transport, check configuration",
                         read_callbacks_->connection());
          read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
        } else {
          config_->stats_.sessions_terminated_ssl_.inc();
          ENVOY_CONN_LOG(info, "successfully enabled SSL termination",
                         read_callbacks_->connection());
          switched_to_tls_ = true;
        }
        return false; // Unsubscribe callback
      }
      return true;
    });

    write_callbacks_->injectWriteDataToFilterChain(buf, false);
    return false; // Stop processing this message
  }

  return true; // Continue processing
}

bool PostgresFilter::onSSLRequest() { return handleSSLRequestWithMetadata(); }

bool PostgresFilter::shouldEncryptUpstream() const {
  const auto effective_upstream_ssl = config_->getEffectiveUpstreamSSLMode();
  return (effective_upstream_ssl ==
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE);
}

void PostgresFilter::sendUpstream(Buffer::Instance& data) {
  read_callbacks_->injectReadDataToFilterChain(data, false);
}

bool PostgresFilter::encryptUpstream(bool upstream_agreed, Buffer::Instance& data) {
  bool encrypted = false;
  const auto effective_upstream_ssl = config_->getEffectiveUpstreamSSLMode();

  RELEASE_ASSERT(
      effective_upstream_ssl !=
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE,
      "encryptUpstream should not be called when upstream SSL is disabled.");

  if (!upstream_agreed) {
    ENVOY_CONN_LOG(info,
                   "postgres_proxy: upstream server rejected request to establish SSL connection. "
                   "Terminating.",
                   read_callbacks_->connection());
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    config_->stats_.sessions_upstream_ssl_failed_.inc();
  } else {
    // Check if forced renegotiation is configured
    bool force_renegotiation = config_->force_upstream_renegotiation_;
    if (config_->upstream_ssl_options_.has_value()) {
      force_renegotiation = config_->upstream_ssl_options_->force_upstream_renegotiation();
    }

    ENVOY_CONN_LOG(debug,
                   "postgres_proxy: Starting upstream SSL negotiation, force_renegotiation: {}",
                   read_callbacks_->connection(), force_renegotiation);

    // Try to switch upstream connection to use a secure channel
    if (read_callbacks_->startUpstreamSecureTransport()) {
      config_->stats_.sessions_upstream_ssl_success_.inc();
      read_callbacks_->injectReadDataToFilterChain(data, false);
      encrypted = true;
      ENVOY_CONN_LOG(info, "postgres_proxy: Successfully enabled upstream SSL",
                     read_callbacks_->connection());
    } else {
      ENVOY_CONN_LOG(info,
                     "postgres_proxy: Cannot enable upstream secure transport. Check "
                     "configuration. Terminating.",
                     read_callbacks_->connection());
      read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
      config_->stats_.sessions_upstream_ssl_failed_.inc();
    }
  }

  return encrypted;
}

void PostgresFilter::verifyDownstreamSSL() {
  const auto effective_downstream_ssl = config_->getEffectiveDownstreamSSLMode();

  if (effective_downstream_ssl ==
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE &&
      (!switched_to_tls_)) {

    // Check inspector metadata
    bool ssl_detected = checkInspectorSSLMetadata();
    ENVOY_CONN_LOG(debug, "SSL required but not established, inspector detected SSL: {}",
                   read_callbacks_->connection(), ssl_detected);

    // If inspector detected SSL request but we haven't switched to TLS, this is an error
    if (ssl_detected) {
      ENVOY_LOG(warn, "SSL was requested per inspector metadata but TLS not established");
    }

    ENVOY_LOG(debug, "postgres_proxy: Closing connection because downstream SSL is required but "
                     "downstream client did not start SSL handshake.");
    closeConn();
  }
}

void PostgresFilter::closeConn() {
  Buffer::OwnedImpl rbac_error_response = encoder_->buildErrorResponse(
      "FATAL", "connection denied by Envoy proxy: downstream ssl required.",
      "28000" // return invalid_authorization_specification
  );

  // send error response to downstream client
  write_callbacks_->injectWriteDataToFilterChain(rbac_error_response, false);
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
}

Network::FilterStatus PostgresFilter::doDecode(Buffer::Instance& data, bool frontend) {
  // Keep processing data until buffer is empty or decoder says
  // that it cannot process data in the buffer.
  while (0 < data.length()) {
    switch (decoder_->onData(data, frontend)) {
    case Decoder::Result::NeedMoreData:
      return Network::FilterStatus::Continue;
    case Decoder::Result::ReadyForNext:
      continue;
    case Decoder::Result::Stopped:
      return Network::FilterStatus::StopIteration;
    }
  }
  return Network::FilterStatus::Continue;
}

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
