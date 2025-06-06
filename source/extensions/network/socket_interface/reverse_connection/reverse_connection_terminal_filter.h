#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/common/platform.h"
#include "envoy/network/filter.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Configuration for the reverse connection terminal filter.
 * Simplified implementation without protobuf dependencies.
 */
class ReverseConnectionTerminalFilterConfig
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  // New constructor for factory pattern
  ReverseConnectionTerminalFilterConfig(const std::string& cluster_name, uint32_t max_connections,
                                        uint32_t timeout_seconds, bool debug_logging);

  // Legacy constructor
  ReverseConnectionTerminalFilterConfig();

  /**
   * Check if reverse connection handling is enabled.
   */
  bool isReverseConnectionEnabled() const;

  /**
   * Get the timeout for socket handoff operations.
   */
  std::chrono::milliseconds getHandoffTimeout() const;

  /**
   * Get the target cluster name.
   */
  const std::string& getClusterName() const;

  /**
   * Get maximum connections per cluster.
   */
  uint32_t getMaxConnections() const;

  /**
   * Check if debug logging is enabled.
   */
  bool isDebugLoggingEnabled() const;

private:
  bool enabled_;
  std::chrono::milliseconds handoff_timeout_;
  std::string cluster_name_;
  uint32_t max_connections_;
  bool debug_logging_;
};

/**
 * Terminal network filter for reverse connections.
 *
 * Implementation approach:
 * 1. Sits at end of filter chain for reverse connections
 * 2. Extracts cluster routing information from connection data
 * 3. Duplicates socket descriptor via dup() for connection reuse
 * 4. Hands duplicated descriptor to UpstreamReverseConnectionManager
 * 5. Terminates filter chain (StopIteration)
 */
class ReverseConnectionTerminalFilter : public Envoy::Network::ReadFilter,
                                        public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  // New constructor for factory pattern
  explicit ReverseConnectionTerminalFilter(
      std::shared_ptr<ReverseConnectionTerminalFilterConfig> config);

  // Legacy constructor
  explicit ReverseConnectionTerminalFilter(const ReverseConnectionTerminalFilterConfig& config);
  ~ReverseConnectionTerminalFilter() override;

  // Network::ReadFilter
  Envoy::Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Envoy::Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override;

private:
  /**
   * Extract target cluster name from connection data.
   * This implements a simple protocol to identify the target cluster.
   */
  std::string extractTargetCluster(Buffer::Instance& data);

  /**
   * Hand off the socket to the specified cluster.
   * Duplicates the socket descriptor and passes it to the upstream manager.
   */
  void handOffSocketToCluster(const std::string& cluster_name);

  /**
   * Get the file descriptor from the connection.
   * This is a simplified approach - production would use proper Envoy abstractions.
   */
  os_fd_t getConnectionFileDescriptor(Envoy::Network::Connection& connection);

  std::shared_ptr<ReverseConnectionTerminalFilterConfig> config_ptr_;
  const ReverseConnectionTerminalFilterConfig* config_;
  Envoy::Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  bool connection_handed_off_{false};
};

/**
 * Factory for creating reverse connection terminal filters.
 * Simplified implementation without full Envoy configuration framework.
 */
class ReverseConnectionTerminalFilterFactory
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionTerminalFilterFactory();

  /**
   * Create a filter factory callback.
   * Simplified version without protobuf configuration.
   */
  Envoy::Network::FilterFactoryCb createFilterFactory() const;
};

// Factory configuration is handled in reverse_connection_terminal_filter_config.h

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
