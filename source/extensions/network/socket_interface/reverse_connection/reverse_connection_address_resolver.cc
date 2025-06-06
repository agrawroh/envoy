#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_address_resolver.h"

#include <regex>

#include "source/common/common/logger.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

// ReverseConnectionAddressResolver implementation
ReverseConnectionAddressResolver::ReverseConnectionAddressResolver() {
  ENVOY_LOG(info,
            "Created ReverseConnectionAddressResolver for metadata-driven reverse connections");
}

Envoy::Network::Address::InstanceConstSharedPtr
ReverseConnectionAddressResolver::resolve(const std::string& address,
                                          Envoy::Network::Address::IpVersion ip_version) {

  ENVOY_LOG(debug, "Resolving address: {}", address);

  // Parse the address to check if it's a reverse connection address
  auto [metadata_json, real_address] = parseReverseConnectionAddress(address);

  if (metadata_json.empty()) {
    ENVOY_LOG(debug, "Not a reverse connection address, falling back to default resolution");
    // Fall back to default address resolution
    return Envoy::Network::Utility::parseInternetAddress(address, ip_version);
  }

  ENVOY_LOG(info, "Parsing reverse connection address with metadata: {}", metadata_json);

  // Parse the metadata JSON into configuration
  ReverseConnectionSocketConfig config = parseMetadataJson(metadata_json);

  if (!validateConfiguration(config)) {
    ENVOY_LOG(error, "Invalid reverse connection configuration in address: {}", address);
    return nullptr;
  }

  // Resolve the real address
  auto real_address_instance =
      Envoy::Network::Utility::parseInternetAddress(real_address, ip_version);
  if (!real_address_instance) {
    ENVOY_LOG(error, "Failed to resolve real address: {}", real_address);
    return nullptr;
  }

  ENVOY_LOG(info,
            "Successfully resolved reverse connection address - src_cluster: {}, clusters: {}",
            config.src_cluster_id, config.remote_clusters.size());

  // The metadata would be embedded in a custom Address::Instance for reverse connections
  // For now, return the real address and rely on other mechanisms for metadata passing
  return real_address_instance;
}

std::pair<std::string, std::string>
ReverseConnectionAddressResolver::parseReverseConnectionAddress(const std::string& address) {

  // Expected format: "reverse://<json_metadata>@<real_address>"
  std::regex reverse_pattern(R"(^reverse://([^@]+)@(.+)$)");
  std::smatch matches;

  if (std::regex_match(address, matches, reverse_pattern)) {
    std::string metadata_json = matches[1].str();
    std::string real_address = matches[2].str();

    ENVOY_LOG(debug, "Parsed reverse connection address - metadata: {}, real_address: {}",
              metadata_json, real_address);

    return {metadata_json, real_address};
  }

  ENVOY_LOG(trace, "Address {} does not match reverse connection format", address);
  return {"", ""};
}

ReverseConnectionSocketConfig
ReverseConnectionAddressResolver::parseMetadataJson(const std::string& json_metadata) {

  ReverseConnectionSocketConfig config;

  // Simplified JSON parsing - in production this would use a proper JSON library
  // For now, use a basic approach that handles the expected format

  try {
    // Expected format: {'src_cluster':'cluster1','clusters':[{'name':'cluster2','count':2}]}
    // This is a very simplified parser - production would use nlohmann::json or similar

    // Extract src_cluster
    std::regex src_cluster_pattern(R"('src_cluster'\s*:\s*'([^']+)')");
    std::smatch src_match;
    if (std::regex_search(json_metadata, src_match, src_cluster_pattern)) {
      config.src_cluster_id = src_match[1].str();
    }

    // Extract clusters array
    std::regex cluster_pattern(R"('name'\s*:\s*'([^']+)'\s*,\s*'count'\s*:\s*(\d+))");
    std::sregex_iterator iter(json_metadata.begin(), json_metadata.end(), cluster_pattern);
    std::sregex_iterator end;

    for (; iter != end; ++iter) {
      const std::smatch& match = *iter;
      ReverseConnectionSocketConfig::ClusterConfig cluster_config;
      cluster_config.cluster_name = match[1].str();
      cluster_config.reverse_connection_count = std::stoul(match[2].str());
      config.remote_clusters.push_back(cluster_config);
    }

    ENVOY_LOG(debug, "Parsed metadata - src_cluster: {}, remote_clusters: {}",
              config.src_cluster_id, config.remote_clusters.size());

  } catch (const std::exception& e) {
    ENVOY_LOG(error, "Failed to parse JSON metadata: {}, error: {}", json_metadata, e.what());
  }

  return config;
}

bool ReverseConnectionAddressResolver::validateConfiguration(
    const ReverseConnectionSocketConfig& config) {

  if (config.src_cluster_id.empty()) {
    ENVOY_LOG(error, "Missing src_cluster_id in reverse connection configuration");
    return false;
  }

  if (config.remote_clusters.empty()) {
    ENVOY_LOG(error, "No remote clusters specified in reverse connection configuration");
    return false;
  }

  for (const auto& cluster : config.remote_clusters) {
    if (cluster.cluster_name.empty()) {
      ENVOY_LOG(error, "Empty cluster name in reverse connection configuration");
      return false;
    }

    if (cluster.reverse_connection_count == 0) {
      ENVOY_LOG(error, "Zero connection count for cluster: {}", cluster.cluster_name);
      return false;
    }
  }

  ENVOY_LOG(info, "Validated reverse connection configuration - src: {}, clusters: {}",
            config.src_cluster_id, config.remote_clusters.size());

  return true;
}

// ReverseConnectionAddressResolverFactory implementation
Envoy::Network::ResolverSharedPtr ReverseConnectionAddressResolverFactory::createResolver(
    const envoy::config::core::v3::Address& address,
    const envoy::config::core::v3::DnsResolverOptions& dns_resolver_options) const {

  ENVOY_LOG(debug, "Creating ReverseConnectionAddressResolver");

  (void)address;              // Mark as used
  (void)dns_resolver_options; // Mark as used

  return std::make_shared<ReverseConnectionAddressResolver>();
}

// ReverseConnectionSocketInterfaceFactory implementation
ReverseConnectionSocketInterfaceFactory::ReverseConnectionSocketInterfaceFactory(
    const ReverseConnectionBootstrapConfig& config)
    : config_(config) {

  ENVOY_LOG(info, "Created ReverseConnectionSocketInterfaceFactory for src_cluster: {}",
            config_.src_cluster_id);
}

Envoy::Network::SocketInterfacePtr ReverseConnectionSocketInterfaceFactory::createSocketInterface(
    const envoy::config::core::v3::Address& address) const {

  ENVOY_LOG(debug, "Creating socket interface for address");

  // Convert bootstrap config to socket config
  ReverseConnectionSocketConfig socket_config;
  socket_config.src_cluster_id = config_.src_cluster_id;
  socket_config.src_node_id = config_.src_node_id;
  socket_config.src_tenant_id = config_.src_tenant_id;

  for (const auto& cluster : config_.remote_clusters) {
    ReverseConnectionSocketConfig::ClusterConfig cluster_config;
    cluster_config.cluster_name = cluster.cluster_name;
    cluster_config.reverse_connection_count = cluster.reverse_connection_count;
    socket_config.remote_clusters.push_back(cluster_config);
  }

  // Create the downstream reverse socket interface with this configuration
  return std::make_unique<DownstreamReverseSocketInterface>(socket_config);
}

// Factory registration would typically be here
// REGISTER_FACTORY(ReverseConnectionAddressResolverFactory, Envoy::Network::ResolverFactory);

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
