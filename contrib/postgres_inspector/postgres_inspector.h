#pragma once

#include <string>

#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace PostgresInspector {

/**
 * All stats for the PostgreSQL inspector. @see stats_macros.h
 */
#define ALL_POSTGRES_INSPECTOR_STATS(COUNTER)                                                      \
  COUNTER(postgres_detected)                                                                       \
  COUNTER(ssl_request_detected)                                                                    \
  COUNTER(startup_message_detected)                                                                \
  COUNTER(error)                                                                                   \
  COUNTER(invalid_message_length)                                                                  \
  COUNTER(invalid_protocol_version)                                                                \
  COUNTER(need_more_data)

/**
 * Definition of all stats for the PostgreSQL inspector. @see stats_macros.h
 */
struct PostgresInspectorStats {
  ALL_POSTGRES_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Global configuration for PostgreSQL inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope, const std::string& stat_prefix = "postgres_inspector.",
         size_t max_read_bytes = DEFAULT_MAX_READ_BYTES);

  const PostgresInspectorStats& stats() const { return stats_; }
  size_t maxReadBytes() const { return max_read_bytes_; }

  // Default maximum bytes to read for protocol detection.
  static constexpr size_t DEFAULT_MAX_READ_BYTES = 16;

private:
  PostgresInspectorStats stats_;
  size_t max_read_bytes_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * PostgreSQL inspector listener filter.
 *
 * This filter detects PostgreSQL protocol by examining initial messages and sets appropriate
 * metadata for downstream filters. Supports SNI extraction for SSL connections.
 *
 * Detection:
 * - SSL Request: 8 bytes, protocol 80877103 (0x04d2162f)
 * - Startup Message: Variable length, protocol 196608 (3.0)
 * - SNI Extraction: From SSL/TLS connection context when available
 */
class Filter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr& config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;
  size_t maxReadBytes() const override { return config_->maxReadBytes(); }

private:
  /**
   * Set PostgreSQL protocol metadata for downstream filters.
   * @param protocol_type type of PostgreSQL message detected.
   * @param supports_ssl whether SSL was requested.
   * @param sni_hostname SNI hostname extracted from SSL connection (optional).
   */
  void setPostgresMetadata(const std::string& protocol_type, bool supports_ssl,
                           const std::string& sni_hostname = "");

  /**
   * Extract SNI hostname from SSL connection context.
   * @return SNI hostname if available, empty string otherwise.
   */
  std::string extractSniHostname() const;

  /**
   * Set SNI-based cluster routing metadata for downstream filters.
   * @param sni_hostname the SNI hostname to route to.
   */
  void setSniRoutingMetadata(const std::string& sni_hostname);

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{nullptr};
  bool postgres_detected_{false};
};

} // namespace PostgresInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
