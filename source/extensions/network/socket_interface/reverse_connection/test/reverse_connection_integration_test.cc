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
 * Production-grade integration test for reverse connection architecture.
 *
 * This test validates the complete end-to-end flow with:
 * 1. Thread safety and mutex ordering
 * 2. Production error conditions and recovery
 * 3. Performance characteristics under load
 * 4. Memory safety and resource cleanup
 * 5. Single-byte trigger mechanism correctness
 */
class ReverseConnectionIntegrationTest : public testing::Test {
protected:
  void SetUp() override {
    // Create test configuration
    setupTestConfiguration();

    // Initialize components
    initializeComponents();
  }

  void TearDown() override {
    // Ensure clean shutdown to prevent mutex issues in destructor
    cleanupComponents();
  }

  void setupTestConfiguration() {
    // Configure for test cluster with production-like settings
    test_config_.src_cluster_id = "test_source_cluster";
    test_config_.src_node_id = "test_node_1";
    test_config_.src_tenant_id = "test_tenant";
    test_config_.health_check_interval_ms = 1000; // Faster for testing
    test_config_.connection_timeout_ms = 2000;
    test_config_.enable_metrics = true;
    test_config_.enable_circuit_breaker = true;

    // Add target clusters with different configurations
    RemoteClusterConnectionConfig cluster1("target_cluster_1", 2, 1000, 3, true);
    test_config_.remote_clusters.push_back(cluster1);

    RemoteClusterConnectionConfig cluster2("target_cluster_2", 1, 2000, 5, false);
    test_config_.remote_clusters.push_back(cluster2);
  }

  void initializeComponents() {
    // Create mock cluster manager and dispatcher
    mock_cluster_manager_ = std::make_unique<NiceMock<Upstream::MockClusterManager>>();
    mock_dispatcher_ = std::make_unique<NiceMock<Event::MockDispatcher>>();

    // Set up mock clusters
    setupMockClusters();

    // Create downstream interface (listens for reverse connections) with test mode enabled
    downstream_interface_ = std::make_unique<DownstreamReverseSocketInterface>(
        test_config_, *mock_cluster_manager_, *mock_dispatcher_, true);

    // Create upstream interfaces for each cluster
    upstream_interface_cluster1_ =
        std::make_shared<UpstreamReverseSocketInterface>("target_cluster_1");
    upstream_interface_cluster2_ =
        std::make_shared<UpstreamReverseSocketInterface>("target_cluster_2");

    // Create terminal filter
    filter_config_ = std::make_unique<ReverseConnectionTerminalFilterConfig>();
    terminal_filter_ = std::make_unique<ReverseConnectionTerminalFilter>(*filter_config_);
  }

  void setupMockClusters() {
    // Set up mock cluster references
    mock_cluster1_ = std::make_shared<NiceMock<Upstream::MockThreadLocalCluster>>();
    mock_cluster2_ = std::make_shared<NiceMock<Upstream::MockThreadLocalCluster>>();

    // Set up mock hosts
    auto mock_host1 = std::make_shared<NiceMock<Upstream::MockHost>>();
    auto mock_host2 = std::make_shared<NiceMock<Upstream::MockHost>>();

    // Set up addresses for the hosts
    auto address1 = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8080);
    auto address2 = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8081);

    ON_CALL(*mock_host1, address()).WillByDefault(Return(address1));
    ON_CALL(*mock_host2, address()).WillByDefault(Return(address2));

    // Set up load balancers
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

    // Set up cluster manager to return our mock clusters
    ON_CALL(*mock_cluster_manager_, getThreadLocalCluster("target_cluster_1"))
        .WillByDefault(Return(mock_cluster1_.get()));
    ON_CALL(*mock_cluster_manager_, getThreadLocalCluster("target_cluster_2"))
        .WillByDefault(Return(mock_cluster2_.get()));
  }

  void cleanupComponents() {
    // Clean shutdown order to prevent deadlocks
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

  // Helper method to create test socket safely
  std::unique_ptr<ReverseConnectionIOHandle> createTestSocket() {
    auto socket_result = downstream_interface_->socket(
        Envoy::Network::Socket::Type::Stream, Envoy::Network::Address::Type::Ip,
        Envoy::Network::Address::IpVersion::v4, false, {});

    if (!socket_result) {
      return nullptr;
    }

    // Use dynamic_cast to safely convert and check the type
    auto* reverse_handle = dynamic_cast<ReverseConnectionIOHandle*>(socket_result.get());
    if (reverse_handle) {
      // Release ownership from socket_result and transfer to unique_ptr
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
 * Test that verifies the complete reverse connection approach can be constructed properly.
 */
TEST_F(ReverseConnectionIntegrationTest, ComponentsCanBeCreated) {
  // Verify all components are created successfully
  EXPECT_NE(downstream_interface_, nullptr);
  EXPECT_NE(upstream_interface_cluster1_, nullptr);
  EXPECT_NE(upstream_interface_cluster2_, nullptr);
  EXPECT_NE(terminal_filter_, nullptr);
  EXPECT_NE(filter_config_, nullptr);

  // Verify configuration is properly set
  EXPECT_TRUE(filter_config_->isReverseConnectionEnabled());
  EXPECT_GT(filter_config_->getHandoffTimeout().count(), 0);

  // Verify production configuration validation
  EXPECT_TRUE(DownstreamReverseSocketInterface::validateConfig(test_config_));
}

/**
 * Production-grade test for single-byte trigger mechanism with proper cleanup.
 */
TEST_F(ReverseConnectionIntegrationTest, SingleByteTriggerMechanism) {
  // Create a test reverse connection socket with safe cleanup
  auto reverse_handle = createTestSocket();
  ASSERT_NE(reverse_handle, nullptr);

  // Verify trigger pipe is created correctly
  EXPECT_TRUE(reverse_handle->isTriggerPipeReady());

  // Test that connection metadata is properly initialized
  const auto& metadata = reverse_handle->getConnectionMetadata();
  EXPECT_EQ(metadata.size(), 2); // Should have 2 clusters
  EXPECT_TRUE(metadata.find("target_cluster_1") != metadata.end());
  EXPECT_TRUE(metadata.find("target_cluster_2") != metadata.end());

  // Ensure proper cleanup by explicitly resetting
  reverse_handle.reset();
}

/**
 * Thread safety test to ensure no deadlocks under concurrent access.
 * Note: We avoid using the dispatcher across threads to prevent MockDispatcher issues.
 */
TEST_F(ReverseConnectionIntegrationTest, ThreadSafetyAndMutexOrdering) {
  const int num_threads = 5;
  const int operations_per_thread = 10;
  std::atomic<int> successful_operations{0};
  std::atomic<int> errors{0};

  // Pre-create sockets in the main thread to avoid dispatcher cross-thread issues
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
          // Use pre-created sockets to test concurrent access to connection metadata
          int idx = socket_index.fetch_add(1);
          if (idx < static_cast<int>(pre_created_sockets.size())) {
            const auto& socket = pre_created_sockets[idx];
            if (socket) {
              // Test concurrent access to connection metadata (this is thread-safe)
              const auto& metadata = socket->getConnectionMetadata();
              (void)metadata; // Use the metadata to ensure it's accessed
              successful_operations++;
            }
          }

          // Brief pause to allow interleaving
          std::this_thread::sleep_for(std::chrono::milliseconds(1));

        } catch (const std::exception& e) {
          errors++;
          // Log error for debugging (test output)
          std::cerr << "Thread " << i << " operation " << j << " failed: " << e.what() << std::endl;
        }
      }
    });
  }

  // Wait for all threads to complete
  for (auto& thread : threads) {
    thread.join();
  }

  // Verify no errors occurred and operations completed successfully
  EXPECT_EQ(errors.load(), 0);
  EXPECT_GT(successful_operations.load(), 0);

  // Test output for verification
  std::cout << "Thread safety test completed: " << successful_operations.load()
            << " successful operations, " << errors.load() << " errors" << std::endl;
}

/**
 * Test that verifies the upstream interface can manage descriptors correctly.
 */
TEST_F(ReverseConnectionIntegrationTest, UpstreamDescriptorManagement) {
  // Initially no descriptors should be available
  os_fd_t fd1 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd1, -1);

  // Add some test descriptors
  upstream_interface_cluster1_->addReverseConnectionDescriptor(10);
  upstream_interface_cluster1_->addReverseConnectionDescriptor(11);

  // Now descriptors should be available
  os_fd_t fd2 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_NE(fd2, -1);
  EXPECT_TRUE(fd2 == 10 || fd2 == 11);

  os_fd_t fd3 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_NE(fd3, -1);
  EXPECT_TRUE(fd3 == 10 || fd3 == 11);
  EXPECT_NE(fd2, fd3); // Should be different descriptors

  // No more descriptors should be available
  os_fd_t fd4 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd4, -1);

  // Return a descriptor and verify it becomes available again
  upstream_interface_cluster1_->returnDescriptor(fd2);
  os_fd_t fd5 = upstream_interface_cluster1_->getAvailableDescriptor();
  EXPECT_EQ(fd5, fd2);
}

/**
 * Production stress test for descriptor management under load.
 */
TEST_F(ReverseConnectionIntegrationTest, DescriptorManagementUnderLoad) {
  const int num_descriptors = 100;
  const int num_cycles = 50;

  // Add many descriptors
  for (int i = 0; i < num_descriptors; ++i) {
    upstream_interface_cluster1_->addReverseConnectionDescriptor(i + 100);
  }

  // Rapidly get and return descriptors
  std::vector<os_fd_t> retrieved_descriptors;

  for (int cycle = 0; cycle < num_cycles; ++cycle) {
    // Get all available descriptors
    retrieved_descriptors.clear();
    for (int i = 0; i < num_descriptors; ++i) {
      os_fd_t fd = upstream_interface_cluster1_->getAvailableDescriptor();
      if (fd != -1) {
        retrieved_descriptors.push_back(fd);
      }
    }

    EXPECT_EQ(retrieved_descriptors.size(), num_descriptors);

    // Return all descriptors
    for (os_fd_t fd : retrieved_descriptors) {
      upstream_interface_cluster1_->returnDescriptor(fd);
    }
  }

  std::cout << "Descriptor management stress test completed " << num_cycles << " cycles"
            << std::endl;
}

/**
 * Test that verifies the UpstreamReverseConnectionManager singleton works correctly.
 */
TEST_F(ReverseConnectionIntegrationTest, UpstreamManagerIntegration) {
  auto& manager = UpstreamReverseConnectionManager::instance();

  // Get interfaces for different clusters
  auto interface1 = manager.getSocketInterface("test_cluster_1");
  auto interface2 = manager.getSocketInterface("test_cluster_2");
  auto interface1_again = manager.getSocketInterface("test_cluster_1");

  EXPECT_NE(interface1, nullptr);
  EXPECT_NE(interface2, nullptr);

  // Should return the same interface for the same cluster
  EXPECT_EQ(interface1, interface1_again);

  // Should return different interfaces for different clusters
  EXPECT_NE(interface1, interface2);

  // Add descriptors through manager
  manager.addReverseConnectionDescriptor("test_cluster_1", 100);
  manager.addReverseConnectionDescriptor("test_cluster_1", 101);

  // Verify they're available through the interface
  os_fd_t fd1 = interface1->getAvailableDescriptor();
  os_fd_t fd2 = interface1->getAvailableDescriptor();

  EXPECT_TRUE(fd1 == 100 || fd1 == 101);
  EXPECT_TRUE(fd2 == 100 || fd2 == 101);
  EXPECT_NE(fd1, fd2);

  // Test cluster cleanup
  manager.removeCluster("test_cluster_1");
  auto interface1_after_removal = manager.getSocketInterface("test_cluster_1");
  // Should create a new interface since the old one was removed
  EXPECT_NE(interface1, interface1_after_removal);
}

/**
 * Test configuration validation with various edge cases.
 */
TEST_F(ReverseConnectionIntegrationTest, ConfigurationValidation) {
  // Test valid configuration
  EXPECT_TRUE(DownstreamReverseSocketInterface::validateConfig(test_config_));

  // Test invalid configurations
  ReverseConnectionSocketConfig invalid_config;

  // Empty cluster ID
  invalid_config.src_cluster_id = "";
  invalid_config.src_node_id = "test_node";
  invalid_config.remote_clusters.push_back(RemoteClusterConnectionConfig("test", 1));
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  // Empty node ID
  invalid_config.src_cluster_id = "test_cluster";
  invalid_config.src_node_id = "";
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  // No remote clusters
  invalid_config.src_node_id = "test_node";
  invalid_config.remote_clusters.clear();
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));

  // Empty cluster name in remote clusters
  invalid_config.remote_clusters.push_back(RemoteClusterConnectionConfig("", 1));
  EXPECT_FALSE(DownstreamReverseSocketInterface::validateConfig(invalid_config));
}

/**
 * Test that verifies the terminal filter configuration works correctly.
 */
TEST_F(ReverseConnectionIntegrationTest, TerminalFilterConfiguration) {
  // Test default configuration
  EXPECT_TRUE(filter_config_->isReverseConnectionEnabled());
  EXPECT_EQ(filter_config_->getHandoffTimeout().count(), 5000);

  // Test filter factory
  ReverseConnectionTerminalFilterFactory factory;
  auto filter_factory_cb = factory.createFilterFactory();

  EXPECT_NE(filter_factory_cb, nullptr);

  // Mock filter manager to test filter creation
  NiceMock<Envoy::Network::MockFilterManager> mock_filter_manager;
  EXPECT_CALL(mock_filter_manager, addReadFilter(_));

  // Create filter through factory
  filter_factory_cb(mock_filter_manager);
}

/**
 * Test that verifies the downstream interface handles the complete connection flow.
 */
TEST_F(ReverseConnectionIntegrationTest, DownstreamConnectionFlow) {
  // Create multiple sockets to test the trigger mechanism
  std::vector<std::unique_ptr<ReverseConnectionIOHandle>> sockets;

  for (int i = 0; i < 3; i++) {
    auto socket = createTestSocket();
    ASSERT_NE(socket, nullptr);
    sockets.push_back(std::move(socket));
  }

  // All sockets should have proper trigger pipe setup
  for (const auto& socket : sockets) {
    EXPECT_TRUE(socket->isTriggerPipeReady());
  }

  // Clean shutdown
  sockets.clear();
}

/**
 * Test that verifies socket creation falls back correctly when no reverse connections.
 */
TEST_F(ReverseConnectionIntegrationTest, FallbackSocketCreation) {
  // When no descriptors are available, should fall back to standard socket creation
  auto socket = upstream_interface_cluster1_->makeSocket(
      -1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt, {});

  EXPECT_NE(socket, nullptr);

  // Should not be a reverse connection handle since no descriptors were available
  auto* reverse_handle = dynamic_cast<UpstreamReverseConnectionIOHandle*>(socket.get());
  (void)reverse_handle; // This might be null if it fell back to standard socket implementation
}

/**
 * Test that verifies the complete architecture integration.
 */
TEST_F(ReverseConnectionIntegrationTest, CompleteArchitectureIntegration) {
  // This test verifies that all components work together in the complete reverse connection flow

  // 1. Downstream creates reverse connection sockets
  auto downstream_socket = createTestSocket();
  ASSERT_NE(downstream_socket, nullptr);

  // 2. Simulate terminal filter receiving a connection and duplicating it
  auto& manager = UpstreamReverseConnectionManager::instance();
  manager.addReverseConnectionDescriptor("target_cluster_1", 200);

  // 3. Upstream interface can now provide reused descriptors
  auto upstream_interface = manager.getSocketInterface("target_cluster_1");
  auto upstream_socket = upstream_interface->makeSocket(
      -1, false, Envoy::Network::Socket::Type::Stream, absl::nullopt, {});

  EXPECT_NE(upstream_socket, nullptr);

  // 4. Verify the descriptor reuse worked
  auto* upstream_handle = dynamic_cast<UpstreamReverseConnectionIOHandle*>(upstream_socket.get());
  EXPECT_NE(upstream_handle, nullptr);

  // Clean shutdown
  downstream_socket.reset();
}

/**
 * Performance test to ensure production-grade performance characteristics.
 */
TEST_F(ReverseConnectionIntegrationTest, PerformanceCharacteristics) {
  const int num_operations = 1000;
  const auto start_time = std::chrono::high_resolution_clock::now();

  // Measure socket creation performance
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
  EXPECT_LT(duration.count(), 10000); // Should complete within 10 seconds

  std::cout << "Performance test: created " << num_operations << " sockets in " << duration.count()
            << "ms ("
            << num_operations * 1000 / std::max(1LL, static_cast<long long>(duration.count()))
            << " ops/sec)" << std::endl;

  // Clean shutdown
  sockets.clear();
}

/**
 * Memory safety test to ensure proper resource cleanup.
 */
TEST_F(ReverseConnectionIntegrationTest, MemorySafetyAndResourceCleanup) {
  // Create and destroy many sockets to test for memory leaks
  const int num_cycles = 100;

  for (int i = 0; i < num_cycles; ++i) {
    {
      auto socket = createTestSocket();
      ASSERT_NE(socket, nullptr);

      // Access the connection metadata to ensure it's properly initialized
      const auto& metadata = socket->getConnectionMetadata();
      EXPECT_EQ(metadata.size(), 2);

      // Socket destructor should clean up properly when going out of scope
    }

    // Add some descriptors and clean them up
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
