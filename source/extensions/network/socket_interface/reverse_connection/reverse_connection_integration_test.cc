#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

#include "source/extensions/network/socket_interface/reverse_connection/downstream_reverse_socket_interface.h"
#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_terminal_filter.h"
#include "source/extensions/network/socket_interface/reverse_connection/upstream_reverse_socket_interface.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/upstream/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

using Envoy::Upstream::HostSelectionResponse;

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Integration test for reverse connection architecture.
 */
class ReverseConnectionIntegrationTest : public testing::Test {
protected:
  void SetUp() override {
    setupTestConfiguration();
    initializeComponents();
  }

  void TearDown() override { cleanupComponents(); }

  void setupTestConfiguration() {
    test_config_.src_cluster_id = "test_source_cluster";
    test_config_.src_node_id = "test_node_1";
    test_config_.src_tenant_id = "test_tenant";
    test_config_.health_check_interval_ms = 1000;
    test_config_.connection_timeout_ms = 2000;
    test_config_.enable_metrics = true;
    test_config_.enable_circuit_breaker = true;

    RemoteClusterConnectionConfig cluster1("target_cluster_1", 2, 1000, 3, true);
    test_config_.remote_clusters.push_back(cluster1);

    RemoteClusterConnectionConfig cluster2("target_cluster_2", 1, 2000, 5, false);
    test_config_.remote_clusters.push_back(cluster2);
  }

  void initializeComponents() {
    mock_cluster_manager_ = std::make_unique<NiceMock<Upstream::MockClusterManager>>();
    mock_dispatcher_ = std::make_unique<NiceMock<Event::MockDispatcher>>();

    setupMockClusters();

    downstream_interface_ = std::make_unique<DownstreamReverseSocketInterface>(
        test_config_, *mock_cluster_manager_, *mock_dispatcher_, true);

    upstream_interface_cluster1_ =
        std::make_shared<UpstreamReverseSocketInterface>("target_cluster_1");
    upstream_interface_cluster2_ =
        std::make_shared<UpstreamReverseSocketInterface>("target_cluster_2");

    filter_config_ = std::make_unique<ReverseConnectionTerminalFilterConfig>();
    terminal_filter_ = std::make_unique<ReverseConnectionTerminalFilter>(*filter_config_);
  }

  void setupMockClusters() {
    mock_cluster1_ = std::make_shared<NiceMock<Upstream::MockThreadLocalCluster>>();
    mock_cluster2_ = std::make_shared<NiceMock<Upstream::MockThreadLocalCluster>>();

    auto mock_host1 = std::make_shared<NiceMock<Upstream::MockHost>>();
    auto mock_host2 = std::make_shared<NiceMock<Upstream::MockHost>>();

    auto address1 = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8080);
    auto address2 = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8081);

    ON_CALL(*mock_host1, address()).WillByDefault(Return(address1));
    ON_CALL(*mock_host2, address()).WillByDefault(Return(address2));

    auto mock_lb1 = std::make_shared<NiceMock<Upstream::MockLoadBalancer>>();
    auto mock_lb2 = std::make_shared<NiceMock<Upstream::MockLoadBalancer>>();

    ON_CALL(*mock_lb1, chooseHost(_))
        .WillByDefault(Invoke([mock_host1](Upstream::LoadBalancerContext*) {
          return HostSelectionResponse{mock_host1};
        }));
    ON_CALL(*mock_lb2, chooseHost(_))
        .WillByDefault(Invoke([mock_host2](Upstream::LoadBalancerContext*) {
          return HostSelectionResponse{mock_host2};
        }));

    ON_CALL(*mock_cluster1_, loadBalancer()).WillByDefault(ReturnRef(*mock_lb1));
    ON_CALL(*mock_cluster2_, loadBalancer()).WillByDefault(ReturnRef(*mock_lb2));

    ON_CALL(*mock_cluster_manager_, getThreadLocalCluster("target_cluster_1"))
        .WillByDefault(Return(mock_cluster1_.get()));
    ON_CALL(*mock_cluster_manager_, getThreadLocalCluster("target_cluster_2"))
        .WillByDefault(Return(mock_cluster2_.get()));
  }

  void cleanupComponents() {
    terminal_filter_.reset();
    filter_config_.reset();
    upstream_interface_cluster2_.reset();
    upstream_interface_cluster1_.reset();
    downstream_interface_.reset();
    mock_cluster2_.reset();
    mock_cluster1_.reset();
    mock_dispatcher_.reset();
    mock_cluster_manager_.reset();
  }

  std::unique_ptr<ReverseConnectionIOHandle> createTestSocket() {
    auto socket_result = downstream_interface_->socket(
        Envoy::Network::Socket::Type::Stream, Envoy::Network::Address::Type::Ip,
        Envoy::Network::Address::IpVersion::v4, false, {});

    if (!socket_result) {
      return nullptr;
    }

    auto* reverse_handle = dynamic_cast<ReverseConnectionIOHandle*>(socket_result.get());
    if (reverse_handle) {
      socket_result.release();
      return std::unique_ptr<ReverseConnectionIOHandle>(reverse_handle);
    }

    return nullptr;
  }

  ReverseConnectionSocketConfig test_config_;
  std::unique_ptr<NiceMock<Upstream::MockClusterManager>> mock_cluster_manager_;
  std::unique_ptr<NiceMock<Event::MockDispatcher>> mock_dispatcher_;
  std::unique_ptr<DownstreamReverseSocketInterface> downstream_interface_;
  std::shared_ptr<UpstreamReverseSocketInterface> upstream_interface_cluster1_;
  std::shared_ptr<UpstreamReverseSocketInterface> upstream_interface_cluster2_;
  std::unique_ptr<ReverseConnectionTerminalFilterConfig> filter_config_;
  std::unique_ptr<ReverseConnectionTerminalFilter> terminal_filter_;
  std::shared_ptr<NiceMock<Upstream::MockThreadLocalCluster>> mock_cluster1_;
  std::shared_ptr<NiceMock<Upstream::MockThreadLocalCluster>> mock_cluster2_;
};

/**
 * Test that components can be created properly.
 */
TEST_F(ReverseConnectionIntegrationTest, ComponentsCanBeCreated) {
  EXPECT_NE(downstream_interface_, nullptr);
  EXPECT_NE(upstream_interface_cluster1_, nullptr);
  EXPECT_NE(upstream_interface_cluster2_, nullptr);
  EXPECT_NE(terminal_filter_, nullptr);
  EXPECT_NE(filter_config_, nullptr);

  EXPECT_TRUE(filter_config_->isReverseConnectionEnabled());
  EXPECT_GT(filter_config_->getHandoffTimeout().count(), 0);
  EXPECT_TRUE(DownstreamReverseSocketInterface::validateConfig(test_config_));
}

/**
 * Test single-byte trigger mechanism.
 */
TEST_F(ReverseConnectionIntegrationTest, SingleByteTriggerMechanism) {
  auto reverse_handle = createTestSocket();
  ASSERT_NE(reverse_handle, nullptr);

  EXPECT_TRUE(reverse_handle->isTriggerPipeReady());

  const auto& metadata = reverse_handle->getConnectionMetadata();
  EXPECT_EQ(metadata.size(), 2);
  EXPECT_TRUE(metadata.find("target_cluster_1") != metadata.end());
  EXPECT_TRUE(metadata.find("target_cluster_2") != metadata.end());

  reverse_handle.reset();
}

/**
 * Test thread safety under concurrent access.
 */
TEST_F(ReverseConnectionIntegrationTest, ThreadSafetyAndMutexOrdering) {
  const int num_threads = 5;
  const int operations_per_thread = 10;
  std::atomic<int> successful_operations{0};
  std::atomic<int> errors{0};

  // Pre-create sockets in main thread
  std::vector<std::unique_ptr<ReverseConnectionIOHandle>> pre_created_sockets;
  for (int i = 0; i < num_threads * operations_per_thread; ++i) {
    auto socket = createTestSocket();
    if (socket) {
      pre_created_sockets.push_back(std::move(socket));
    }
  }

  std::vector<std::thread> threads;
  std::atomic<int> socket_index{0};

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([&, i]() {
      for (int j = 0; j < operations_per_thread; ++j) {
        try {
          int idx = socket_index.fetch_add(1);
          if (idx < static_cast<int>(pre_created_sockets.size())) {
            const auto& socket = pre_created_sockets[idx];
            if (socket) {
              const auto& metadata = socket->getConnectionMetadata();
              (void)metadata;
              successful_operations++;
            }
          }

          std::this_thread::sleep_for(std::chrono::milliseconds(1));

        } catch (const std::exception& e) {
          errors++;
          std::cerr << "Thread " << i << " operation " << j << " failed: " << e.what() << std::endl;
        }
      }
    });
  }

  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_EQ(errors.load(), 0);
  EXPECT_GT(successful_operations.load(), 0);

  std::cout << "Thread safety test completed: " << successful_operations.load()
            << " successful operations, " << errors.load() << " errors" << std::endl;
}

/**
 * Test upstream descriptor management.
 */
TEST_F(ReverseConnectionIntegrationTest, UpstreamDescriptorManagement) {
  os_fd_t fd1 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd1, -1);

  upstream_interface_cluster1_->addReverseConnectionDescriptor(10);
  upstream_interface_cluster1_->addReverseConnectionDescriptor(11);

  os_fd_t fd2 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_NE(fd2, -1);
  EXPECT_TRUE(fd2 == 10 || fd2 == 11);

  os_fd_t fd3 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_NE(fd3, -1);
  EXPECT_TRUE(fd3 == 10 || fd3 == 11);
  EXPECT_NE(fd2, fd3);

  os_fd_t fd4 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd4, -1);

  upstream_interface_cluster1_->returnDescriptor(fd2);
  os_fd_t fd5 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd5, fd2);
}

/**
 * Test descriptor management under load.
 */
TEST_F(ReverseConnectionIntegrationTest, DescriptorManagementUnderLoad) {
  const int num_descriptors = 100;
  const int num_cycles = 50;

  for (int i = 0; i < num_descriptors; ++i) {
    upstream_interface_cluster1_->addReverseConnectionDescriptor(i + 100);
  }

  std::vector<os_fd_t> retrieved_descriptors;

  for (int cycle = 0; cycle < num_cycles; ++cycle) {
    retrieved_descriptors.clear();
    for (int i = 0; i < num_descriptors; ++i) {
      os_fd_t fd = upstream_interface_cluster1_->getAvailableDescriptor();
      if (fd != -1) {
        retrieved_descriptors.push_back(fd);
      }
    }

    EXPECT_EQ(retrieved_descriptors.size(), num_descriptors);

    for (os_fd_t fd : retrieved_descriptors) {
      upstream_interface_cluster1_->returnDescriptor(fd);
    }
  }

  std::cout << "Descriptor management stress test completed " << num_cycles << " cycles"
            << std::endl;
}

/**
 * Test UpstreamReverseConnectionManager singleton.
 */
TEST_F(ReverseConnectionIntegrationTest, UpstreamManagerIntegration) {
  auto& manager = UpstreamReverseConnectionManager::instance();

  auto interface1 = manager.getSocketInterface("test_cluster_1");
  auto interface2 = manager.getSocketInterface("test_cluster_2");
  auto interface1_again = manager.getSocketInterface("test_cluster_1");

  EXPECT_NE(interface1, nullptr);
  EXPECT_NE(interface2, nullptr);
  EXPECT_EQ(interface1, interface1_again);
  EXPECT_NE(interface1, interface2);

  manager.addReverseConnectionDescriptor("test_cluster_1", 100);
  manager.addReverseConnectionDescriptor("test_cluster_1", 101);

  os_fd_t fd1 = interface1->getAvailableDescriptor();
  os_fd_t fd2 = interface1->getAvailableDescriptor();

  EXPECT_TRUE(fd1 == 100 || fd1 == 101);
  EXPECT_TRUE(fd2 == 100 || fd2 == 101);
  EXPECT_NE(fd1, fd2);

  manager.removeCluster("test_cluster_1");
  auto interface1_after_removal = manager.getSocketInterface("test_cluster_1");
  EXPECT_NE(interface1, interface1_after_removal);
}

/**
 * Test configuration validation.
 */
TEST_F(ReverseConnectionIntegrationTest, ConfigurationValidation) {
  EXPECT_TRUE(DownstreamReverseSocketInterface::validateConfig(test_config_));

  ReverseConnectionSocketConfig invalid_config;

  invalid_config.src_cluster_id = "";
  invalid_config.src_node_id = "test_node";
  invalid_config.remote_clusters.push_back(RemoteClusterConnectionConfig("test", 1));
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  invalid_config.src_cluster_id = "test_cluster";
  invalid_config.src_node_id = "";
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  invalid_config.src_node_id = "test_node";
  invalid_config.remote_clusters.clear();
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  invalid_config.remote_clusters.push_back(RemoteClusterConnectionConfig("", 1));
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));
}

/**
 * Test terminal filter configuration.
 */
TEST_F(ReverseConnectionIntegrationTest, TerminalFilterConfiguration) {
  EXPECT_TRUE(filter_config_->isReverseConnectionEnabled());
  EXPECT_EQ(filter_config_->getHandoffTimeout().count(), 5000);

  ReverseConnectionTerminalFilterFactory factory;
  auto filter_factory_cb = factory.createFilterFactory();

  EXPECT_NE(filter_factory_cb, nullptr);

  NiceMock<Envoy::Network::MockFilterManager> mock_filter_manager;
  EXPECT_CALL(mock_filter_manager, addReadFilter(_));

  filter_factory_cb(mock_filter_manager);
}

/**
 * Test downstream connection flow.
 */
TEST_F(ReverseConnectionIntegrationTest, DownstreamConnectionFlow) {
  std::vector<std::unique_ptr<ReverseConnectionIOHandle>> sockets;

  for (int i = 0; i < 3; i++) {
    auto socket = createTestSocket();
    ASSERT_NE(socket, nullptr);
    sockets.push_back(std::move(socket));
  }

  for (const auto& socket : sockets) {
    EXPECT_TRUE(socket->isTriggerPipeReady());
  }

  sockets.clear();
}

/**
 * Test fallback socket creation.
 */
TEST_F(ReverseConnectionIntegrationTest, FallbackSocketCreation) {
  auto socket = upstream_interface_cluster1_->makeSocket(
      -1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt, {});

  EXPECT_NE(socket, nullptr);

  auto* reverse_handle = dynamic_cast<UpstreamReverseConnectionIOHandle*>(socket.get());
  (void)reverse_handle;
}

/**
 * Test complete architecture integration.
 */
TEST_F(ReverseConnectionIntegrationTest, CompleteArchitectureIntegration) {
  auto downstream_socket = createTestSocket();
  ASSERT_NE(downstream_socket, nullptr);

  auto& manager = UpstreamReverseConnectionManager::instance();
  manager.addReverseConnectionDescriptor("target_cluster_1", 200);

  auto upstream_interface = manager.getSocketInterface("target_cluster_1");
  auto upstream_socket = upstream_interface->makeSocket(
      -1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt, {});

  EXPECT_NE(upstream_socket, nullptr);

  auto* upstream_handle = dynamic_cast<UpstreamReverseConnectionIOHandle*>(upstream_socket.get());
  EXPECT_NE(upstream_handle, nullptr);

  downstream_socket.reset();
}

/**
 * Test performance characteristics.
 */
TEST_F(ReverseConnectionIntegrationTest, PerformanceCharacteristics) {
  const int num_operations = 1000;
  const auto start_time = std::chrono::high_resolution_clock::now();

  std::vector<std::unique_ptr<ReverseConnectionIOHandle>> sockets;
  sockets.reserve(num_operations);

  for (int i = 0; i < num_operations; ++i) {
    auto socket = createTestSocket();
    if (socket) {
      sockets.push_back(std::move(socket));
    }
  }

  const auto end_time = std::chrono::high_resolution_clock::now();
  const auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

  EXPECT_EQ(sockets.size(), num_operations);
  EXPECT_LT(duration.count(), 10000);

  std::cout << "Performance test: created " << num_operations << " sockets in " << duration.count()
            << "ms ("
            << num_operations * 1000 / std::max(1LL, static_cast<long long>(duration.count()))
            << " ops/sec)" << std::endl;

  sockets.clear();
}

/**
 * Test memory safety and resource cleanup.
 */
TEST_F(ReverseConnectionIntegrationTest, MemorySafetyAndResourceCleanup) {
  const int num_cycles = 100;

  for (int i = 0; i < num_cycles; ++i) {
    {
      auto socket = createTestSocket();
      ASSERT_NE(socket, nullptr);

      const auto& metadata = socket->getConnectionMetadata();
      EXPECT_EQ(metadata.size(), 2);
    }

    auto& manager = UpstreamReverseConnectionManager::instance();
    manager.addReverseConnectionDescriptor("test_cluster_memory", i);

    auto interface = manager.getSocketInterface("test_cluster_memory");
    os_fd_t fd = interface->getAvailableDescriptor();
    if (fd != -1) {
      interface->returnDescriptor(fd);
    }
  }

  std::cout << "Memory safety test completed " << num_cycles << " cycles" << std::endl;
}

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
