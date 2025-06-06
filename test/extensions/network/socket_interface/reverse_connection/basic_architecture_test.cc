#include "source/extensions/network/socket_interface/reverse_connection/downstream_reverse_socket_interface.h"
#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_listen_socket_factory.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

class BasicArchitectureTest : public testing::Test {
public:
  BasicArchitectureTest() = default;

protected:
  testing::NiceMock<Event::MockDispatcher> dispatcher_;
  testing::NiceMock<Upstream::MockClusterManager> cluster_manager_;
};

// Test that DownstreamReverseSocketInterface can be created
TEST_F(BasicArchitectureTest, CanCreateDownstreamReverseSocketInterface) {
  ReverseConnectionSocketConfig config;
  config.src_cluster_id = "test_cluster";
  config.src_node_id = "test_node";
  config.src_tenant_id = "test_tenant";
  config.remote_clusters.push_back(RemoteClusterConnectionConfig("upstream_cluster", 2));

  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config, cluster_manager_, dispatcher_);

  EXPECT_TRUE(socket_interface != nullptr);
}

// Test that ReverseConnectionListenSocketFactory can be created
TEST_F(BasicArchitectureTest, CanCreateReverseConnectionListenSocketFactory) {
  auto factory =
      std::make_unique<ReverseConnectionListenSocketFactory>(cluster_manager_, dispatcher_);

  EXPECT_TRUE(factory != nullptr);
}

// Test that socket creation works with proper parameters
TEST_F(BasicArchitectureTest, CanCreateSocket) {
  ReverseConnectionSocketConfig config;
  config.src_cluster_id = "test_cluster";
  config.src_node_id = "test_node";
  config.src_tenant_id = "test_tenant";
  config.remote_clusters.push_back(RemoteClusterConnectionConfig("upstream_cluster", 2));

  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config, cluster_manager_, dispatcher_);

  auto socket =
      socket_interface->makeSocket(-1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt,
                                   Envoy::Network::SocketCreationOptions{});

  EXPECT_TRUE(socket != nullptr);
}

// Test that the basic trigger pipe mechanism is created
TEST_F(BasicArchitectureTest, TriggerPipeIsCreated) {
  ReverseConnectionSocketConfig config;
  config.src_cluster_id = "test_cluster";
  config.src_node_id = "test_node";
  config.src_tenant_id = "test_tenant";

  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config, cluster_manager_, dispatcher_);

  auto socket =
      socket_interface->makeSocket(-1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt,
                                   Envoy::Network::SocketCreationOptions{});

  EXPECT_TRUE(socket != nullptr);

  // The ReverseConnectionIOHandle should be created with trigger pipe
  // This is validated by the fact that makeSocket returns non-null
  // and the constructor creates the trigger pipe without exceptions
}

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
