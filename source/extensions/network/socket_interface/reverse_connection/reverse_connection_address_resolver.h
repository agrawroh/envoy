#pragma once

#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/network/resolver.h"
#include "envoy/registry/registry.h"

#include "source/common/common/logger.h"
#include "source/common/network/resolver_impl.h"
#include "source/extensions/network/socket_interface/reverse_connection/downstream_reverse_socket_interface.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Custom address resolver for reverse connection metadata.
 *
 * Parses reverse connection metadata from address values.
 * Address format: "reverse://<json_metadata>@<real_address>"
 */
class ReverseConnectionAddressResolver : public Envoy::Network::Resolver,
                                         public Envoy::Logger::Loggable<Envoy::Logger::Id::config> {
public:
  ReverseConnectionAddressResolver();

  // Network::Resolver interface
  Envoy::Network::Address::InstanceConstSharedPtr
  resolve(const std::string& address, Envoy::Network::Address::IpVersion ip_version) override;

  std::string name() const override { return "envoy.network.resolver.reverse_connection"; }

private:
  /**
   * Parse reverse connection address format.
   */
  std::pair<std::string, std::string> parseReverseConnectionAddress(const std::string& address);

  /**
   * Parse JSON metadata into configuration.
   */
  ReverseConnectionSocketConfig parseMetadataJson(const std::string& json_metadata);

  /**
   * Validate parsed configuration.
   */
  bool validateConfiguration(const ReverseConnectionSocketConfig& config);
};

/**
 * Factory for creating ReverseConnectionAddressResolver instances.
 */
class ReverseConnectionAddressResolverFactory : public Envoy::Network::ResolverFactory {
public:
  // Network::ResolverFactory interface
  Envoy::Network::ResolverSharedPtr createResolver(
      const envoy::config::core::v3::Address& address,
      const envoy::config::core::v3::DnsResolverOptions& dns_resolver_options) const override;

  std::string name() const override { return "envoy.network.resolver.reverse_connection"; }
};

DECLARE_FACTORY(ReverseConnectionAddressResolverFactory);

/**
 * Bootstrap configuration for reverse connections.
 */
class ReverseConnectionBootstrapConfig {
public:
  struct ClusterConfig {
    std::string cluster_name;
    uint32_t reverse_connection_count;
  };

  std::string src_cluster_id;
  std::string src_node_id;
  std::string src_tenant_id;
  std::vector<ClusterConfig> remote_clusters;
};

/**
 * Socket interface factory for bootstrap configuration.
 */
class ReverseConnectionSocketInterfaceFactory : public Envoy::Network::SocketInterfaceFactory {
public:
  ReverseConnectionSocketInterfaceFactory(const ReverseConnectionBootstrapConfig& config);

  // Network::SocketInterfaceFactory interface
  Envoy::Network::SocketInterfacePtr
  createSocketInterface(const envoy::config::core::v3::Address& address) const override;

  std::string name() const override { return "envoy.network.socket_interface.reverse_connection"; }

private:
  const ReverseConnectionBootstrapConfig config_;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
