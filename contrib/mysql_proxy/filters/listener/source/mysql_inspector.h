#pragma once

#include <http_parser.h>

#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"

#include "absl/container/flat_hash_set.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace MySQLInspector {

/**
 * All stats for the MySQL inspector.
 * @see stats_macros.h
 */
#define ALL_MYSQL_INSPECTOR_STATS(COUNTER)                                                         \
  COUNTER(read_error)                                                                              \
  COUNTER(http10_found)                                                                            \
  COUNTER(http11_found)                                                                            \
  COUNTER(http2_found)                                                                             \
  COUNTER(http_not_found)

/**
 * Definition of all stats for the MySQL inspector.
 * @see stats_macros.h
 */
struct MySQLInspectorStats {
  ALL_MYSQL_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT)
};

enum class ParseState {
  // Parse result is out. It could be http family or empty.
  Done,
  // Parser expects more data.
  Continue,
  // Parser reports unrecoverable error.
  Error
};

/**
 * Global configuration for MySQL inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope);

  const MySQLInspectorStats& stats() const { return stats_; }

  static constexpr uint32_t MAX_INSPECT_SIZE = 8192;

private:
  MySQLInspectorStats stats_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * MySQL inspector listener filter.
 */
class Filter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer&) override {
    return Network::FilterStatus::Continue;
  }

  size_t maxReadBytes() const override { return Config::MAX_INSPECT_SIZE; }

private:
  const absl::flat_hash_set<std::string>& httpProtocols() const;
  const absl::flat_hash_set<std::string>& http1xMethods() const;

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{nullptr};
  absl::string_view protocol_;
  http_parser parser_;
  static http_parser_settings settings_;
};

} // namespace MySQLInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
