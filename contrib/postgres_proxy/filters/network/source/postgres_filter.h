#pragma once

#include <cstdint>
#include <memory>

#include "envoy/common/platform.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/protobuf/protobuf.h"

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"
#include "contrib/envoy/extensions/filters/network/postgres_proxy/v3alpha/postgres_proxy.pb.h"
#include "contrib/postgres_proxy/filters/network/source/postgres_decoder.h"
#include "contrib/postgres_proxy/filters/network/source/postgres_encoder.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

/**
 * All Postgres proxy stats. @see stats_macros.h
 */
#define ALL_POSTGRES_PROXY_STATS(COUNTER)                                                          \
  COUNTER(errors)                                                                                  \
  COUNTER(errors_error)                                                                            \
  COUNTER(errors_fatal)                                                                            \
  COUNTER(errors_panic)                                                                            \
  COUNTER(errors_unknown)                                                                          \
  COUNTER(messages)                                                                                \
  COUNTER(messages_backend)                                                                        \
  COUNTER(messages_frontend)                                                                       \
  COUNTER(messages_unknown)                                                                        \
  COUNTER(notices)                                                                                 \
  COUNTER(notices_debug)                                                                           \
  COUNTER(notices_info)                                                                            \
  COUNTER(notices_log)                                                                             \
  COUNTER(notices_notice)                                                                          \
  COUNTER(notices_unknown)                                                                         \
  COUNTER(notices_warning)                                                                         \
  COUNTER(sessions)                                                                                \
  COUNTER(sessions_encrypted)                                                                      \
  COUNTER(sessions_terminated_ssl)                                                                 \
  COUNTER(sessions_unencrypted)                                                                    \
  COUNTER(sessions_upstream_ssl_success)                                                           \
  COUNTER(sessions_upstream_ssl_failed)                                                            \
  COUNTER(statements)                                                                              \
  COUNTER(statements_delete)                                                                       \
  COUNTER(statements_insert)                                                                       \
  COUNTER(statements_other)                                                                        \
  COUNTER(statements_parsed)                                                                       \
  COUNTER(statements_parse_error)                                                                  \
  COUNTER(statements_select)                                                                       \
  COUNTER(statements_update)                                                                       \
  COUNTER(transactions)                                                                            \
  COUNTER(transactions_commit)                                                                     \
  COUNTER(transactions_rollback)

/**
 * Struct definition for all Postgres proxy stats. @see stats_macros.h
 */
struct PostgresProxyStats {
  ALL_POSTGRES_PROXY_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Configuration for the Postgres proxy filter.
 */
class PostgresFilterConfig {
public:
  struct PostgresFilterConfigOptions {
    std::string stats_prefix_;
    bool enable_sql_parsing_;
    bool terminate_ssl_;
    envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
        upstream_ssl_;
    envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
        downstream_ssl_;

    // SSL configuration options
    std::string ssl_response_override_;
    bool force_upstream_renegotiation_{false};
    uint32_t ssl_handshake_timeout_ms_{30000};

    // SSL configs (only valid when respective SSL mode is ALLOW or REQUIRE)
    absl::optional<envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::
                       DownstreamSSLConfig>
        downstream_ssl_options_;
    absl::optional<envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::
                       UpstreamSSLConfig>
        upstream_ssl_options_;
  };

  PostgresFilterConfig(const PostgresFilterConfigOptions& config_options, Stats::Scope& scope);

  bool enable_sql_parsing_{true};
  bool terminate_ssl_{false};
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
      upstream_ssl_{
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE};
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
      downstream_ssl_{
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE};

  // SSL configuration
  std::string ssl_response_override_;
  bool force_upstream_renegotiation_{false};
  uint32_t ssl_handshake_timeout_ms_{30000};

  // SSL configs
  absl::optional<envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::
                     DownstreamSSLConfig>
      downstream_ssl_options_;
  absl::optional<envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::
                     UpstreamSSLConfig>
      upstream_ssl_options_;

  Stats::Scope& scope_;
  PostgresProxyStats stats_;

  /**
   * Get effective downstream SSL mode, considering enhanced configuration
   */
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
  getEffectiveDownstreamSSLMode() const;

  /**
   * Get effective upstream SSL mode, considering enhanced configuration
   */
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::SSLMode
  getEffectiveUpstreamSSLMode() const;

private:
  PostgresProxyStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return PostgresProxyStats{ALL_POSTGRES_PROXY_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }
};

using PostgresFilterConfigSharedPtr = std::shared_ptr<PostgresFilterConfig>;

class PostgresFilter : public Network::Filter,
                       DecoderCallbacks,
                       Logger::Loggable<Logger::Id::filter> {
public:
  PostgresFilter(PostgresFilterConfigSharedPtr config);
  ~PostgresFilter() override = default;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override;

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

  // PostgresProxy::DecoderCallback
  void incErrors(ErrorType) override;
  void incMessagesBackend() override;
  void incMessagesFrontend() override;
  void incMessagesUnknown() override;
  void incNotices(NoticeType) override;
  void incSessionsEncrypted() override;
  void incSessionsUnencrypted() override;
  void incStatements(StatementType) override;
  void incTransactions() override;
  void incTransactionsCommit() override;
  void incTransactionsRollback() override;
  void processQuery(const std::string&) override;
  bool onSSLRequest() override;
  bool shouldEncryptUpstream() const override;
  void sendUpstream(Buffer::Instance&) override;
  bool encryptUpstream(bool, Buffer::Instance&) override;
  void verifyDownstreamSSL() override;

  void closeConn();
  bool isSwitchedToTls() { return switched_to_tls_; };

  Network::FilterStatus doDecode(Buffer::Instance& data, bool);
  DecoderPtr createDecoder(DecoderCallbacks* callbacks);
  void setDecoder(std::unique_ptr<Decoder> decoder) { decoder_ = std::move(decoder); }
  Decoder* getDecoder() const { return decoder_.get(); }

  EncoderPtr createEncoder();
  void setEncoder(std::unique_ptr<Encoder> encoder) { encoder_ = std::move(encoder); }
  Encoder* getEncoder() const { return encoder_.get(); }

  // Routines used during integration and unit tests
  uint32_t getFrontendBufLength() const { return frontend_buffer_.length(); }
  uint32_t getBackendBufLength() const { return backend_buffer_.length(); }
  const PostgresProxyStats& getStats() const { return config_->stats_; }
  Network::Connection& connection() const { return read_callbacks_->connection(); }
  const PostgresFilterConfigSharedPtr& getConfig() const { return config_; }

private:
  /**
   * Check if PostgreSQL inspector detected SSL request based on metadata
   */
  bool checkInspectorSSLMetadata() const;

  /**
   * Enhanced SSL request handling that considers inspector metadata
   */
  bool handleSSLRequestWithMetadata();

  /**
   * Get custom SSL response based on configuration
   */
  std::string getSSLResponse() const;

  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
  PostgresFilterConfigSharedPtr config_;
  Buffer::OwnedImpl frontend_buffer_;
  Buffer::OwnedImpl backend_buffer_;
  std::unique_ptr<Decoder> decoder_;
  std::unique_ptr<Encoder> encoder_;
  bool switched_to_tls_{false};
};

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
