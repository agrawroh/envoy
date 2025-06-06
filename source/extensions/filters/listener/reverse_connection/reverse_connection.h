#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "envoy/event/dispatcher.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/listener/reverse_connection/config.pb.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace ReverseConnection {

/**
 * Configuration for reverse connection listener filter.
 */
class Config : public Logger::Loggable<Logger::Id::filter> {
public:
  Config(
      const envoy::extensions::filters::listener::reverse_connection::v3::ReverseConnection& config,
      Server::Configuration::ListenerFactoryContext& context);

  const std::string& metadataKey() const { return metadata_key_; }
  bool enabled() const { return enabled_; }
  std::chrono::milliseconds connectTimeout() const { return connect_timeout_; }
  std::chrono::milliseconds keepaliveInterval() const { return keepalive_interval_; }
  uint32_t maxRetries() const { return max_retries_; }

  Upstream::ClusterManager& clusterManager() { return cluster_manager_; }
  Event::Dispatcher& dispatcher() { return dispatcher_; }
  Stats::Scope& scope() { return scope_; }

private:
  const std::string metadata_key_;
  const bool enabled_;
  const std::chrono::milliseconds connect_timeout_;
  const std::chrono::milliseconds keepalive_interval_;
  const uint32_t max_retries_;

  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;
  Stats::Scope& scope_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Reverse connection cluster configuration parsed from metadata.
 */
struct ReverseConnectionClusterMetadata {
  std::string cluster_name;
  uint32_t reverse_connection_count;
};

/**
 * Listener filter that detects reverse connection metadata and initiates
 * reverse connection setup workflow.
 */
class ReverseConnectionFilter : public Network::ListenerFilter,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  ReverseConnectionFilter(ConfigSharedPtr config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override {
    return Network::FilterStatus::Continue;
  }
  size_t maxReadBytes() const override { return 0; }

private:
  /**
   * Parse reverse connection metadata from listener metadata.
   */
  std::vector<ReverseConnectionClusterMetadata>
  parseReverseConnectionMetadata(const envoy::config::core::v3::Metadata& metadata);

  /**
   * Initiate reverse connections for configured clusters.
   */
  void initiateReverseConnections(const std::vector<ReverseConnectionClusterMetadata>& clusters);

  /**
   * Setup reverse connection for a specific cluster.
   */
  void setupReverseConnectionsForCluster(const ReverseConnectionClusterMetadata& cluster_config);

  ConfigSharedPtr config_;
  bool reverse_connections_initiated_;
};

} // namespace ReverseConnection
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
