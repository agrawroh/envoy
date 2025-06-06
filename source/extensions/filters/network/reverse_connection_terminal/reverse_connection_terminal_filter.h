#pragma once

#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"

#include "source/common/common/logger.h"
#include "source/extensions/network/socket_interface/reverse_connection/protocol.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ReverseConnectionTerminal {

/**
 * Terminal network filter for upstream Envoy that handles reverse connection hand off.
 *
 * Responsibilities:
 * 1. Read cluster identification from incoming reverse connection
 * 2. Duplicate socket descriptor and hand off to appropriate cluster
 * 3. Close original connection after hand off
 *
 * This filter runs on the upstream Envoy listener that receives reverse connections.
 */
class ReverseConnectionTerminalFilter : public Envoy::Network::ReadFilter,
                                        public Envoy::Logger::Loggable<Envoy::Logger::Id::filter> {
public:
  ReverseConnectionTerminalFilter();

  ~ReverseConnectionTerminalFilter() override = default;

  // Network::ReadFilter interface
  Envoy::Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Envoy::Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Envoy::Network::ReadFilterCallbacks& callbacks) override;

private:
  /**
   * Parse connection identification from reverse connection.
   */
  bool parseConnectionIdentification(Buffer::Instance& data);

  /**
   * Duplicate socket and hand off to cluster.
   */
  void handoffConnectionToCluster(const std::string& cluster_name);

  /**
   * Close the original connection after hand off.
   */
  void closeOriginalConnection();

  Envoy::Network::ReadFilterCallbacks* read_callbacks_{nullptr};
  Buffer::OwnedImpl identification_buffer_;

  bool identification_parsed_{false};
  std::string target_cluster_name_;
  std::string source_cluster_id_;
  std::string source_node_id_;
  std::string source_tenant_id_;
};

/**
 * Factory for creating ReverseConnectionTerminalFilter instances.
 */
class ReverseConnectionTerminalFilterFactory : public Envoy::Network::FilterFactoryBase {
public:
  ReverseConnectionTerminalFilterFactory();

  // Network::FilterFactoryBase interface
  std::string name() const override { return "envoy.filters.network.reverse_connection_terminal"; }

  Envoy::Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& config,
                               Envoy::Server::Configuration::FactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(ReverseConnectionTerminalFilterFactory);

} // namespace ReverseConnectionTerminal
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
