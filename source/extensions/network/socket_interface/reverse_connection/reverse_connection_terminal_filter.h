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
 * Configuration for reverse connection terminal filter.
 */
class ReverseConnectionTerminalFilterConfig
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionTerminalFilterConfig(const std::string& cluster_name, uint32_t max_connections,
                                        uint32_t timeout_seconds, bool debug_logging);
  ReverseConnectionTerminalFilterConfig();

  bool isReverseConnectionEnabled() const;
  std::chrono::milliseconds getHandoffTimeout() const;
  const std::string& getClusterName() const;
  uint32_t getMaxConnections() const;
  bool isDebugLoggingEnabled() const;

private:
  bool enabled_;
  std::chrono::milliseconds handoff_timeout_;
  std::string cluster_name_;
  uint32_t max_connections_;
  bool debug_logging_;
};

/**
 * Terminal filter for reverse connection hand off.
 *
 * Extracts cluster routing information from connection data and
 * hands off socket descriptors to the appropriate cluster.
 */
class ReverseConnectionTerminalFilter : public Envoy::Network::ReadFilter,
                                        public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  explicit ReverseConnectionTerminalFilter(
      std::shared_ptr<ReverseConnectionTerminalFilterConfig> config);
  explicit ReverseConnectionTerminalFilter(const ReverseConnectionTerminalFilterConfig& config);
  ~ReverseConnectionTerminalFilter() override;

  // Network::ReadFilter
  Envoy::Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Envoy::Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override;

private:
  /**
   * Extract target cluster name from connection data.
   */
  std::string extractTargetCluster(Buffer::Instance& data);

  /**
   * Hand off socket to the specified cluster.
   */
  void handOffSocketToCluster(const std::string& cluster_name);

  /**
   * Get connection file descriptor for hand off.
   */
  os_fd_t getConnectionFileDescriptor(Envoy::Network::Connection& connection);

  std::shared_ptr<ReverseConnectionTerminalFilterConfig> config_ptr_;
  const ReverseConnectionTerminalFilterConfig* config_;
  Envoy::Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  bool connection_handed_off_{false};
};

/**
 * Factory for creating reverse connection terminal filters.
 */
class ReverseConnectionTerminalFilterFactory
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionTerminalFilterFactory();
  Envoy::Network::FilterFactoryCb createFilterFactory() const;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
