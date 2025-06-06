#include "envoy/config/listener/v3/listener.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/address_impl.h"
#include "source/extensions/network/socket_interface/reverse_connection/downstream_reverse_socket_interface.h"
#include "source/extensions/network/socket_interface/reverse_connection/protocol.h"
#include "source/extensions/network/socket_interface/reverse_connection/reverse_connection_listen_socket_factory.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::InSequence;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {
namespace {

class ReverseConnectionTest : public testing::Test {
public:
  ReverseConnectionTest() {
    // Setup basic config
    config_.src_cluster_id = "test_cluster";
    config_.src_node_id = "test_node";
    config_.src_tenant_id = "test_tenant";

    envoy::extensions::reverse_connection::reverse_connection_listener_config::v3alpha::
        RemoteClusterConnectionConfig remote_config;
    remote_config.set_cluster_name("upstream_cluster");
    remote_config.set_reverse_connection_count(2);
    config_.remote_clusters.push_back(remote_config);
  }

protected:
  ReverseConnectionSocketConfig config_;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Event::MockTimer>* timer_;
};

class ProtocolTest : public testing::Test {
public:
  ProtocolTest() = default;
};

// Protocol Tests
TEST_F(ProtocolTest, CreateAndParseConnectionRequest) {
  Buffer::OwnedImpl buffer;
  const std::string cluster_id = "test_cluster";
  const std::string node_id = "test_node";
  const std::string tenant_id = "test_tenant";

  // Create connection request
  Protocol::ProtocolUtil::createConnectionRequest(buffer, cluster_id, node_id, tenant_id);

  EXPECT_GT(buffer.length(), Protocol::ProtocolHeader::HEADER_SIZE);

  // Parse header
  auto header_result = Protocol::ProtocolUtil::parseHeader(buffer);
  ASSERT_TRUE(header_result.ok());

  const auto& header = header_result.value();
  EXPECT_EQ(Protocol::MessageType::CONN_REQ, header.type);
  EXPECT_EQ(Protocol::ProtocolHeader::VERSION, header.version);

  // Parse connection request
  std::string parsed_cluster, parsed_node, parsed_tenant;
  auto req_result = Protocol::ProtocolUtil::parseConnectionRequest(buffer, parsed_cluster,
                                                                   parsed_node, parsed_tenant);

  ASSERT_TRUE(req_result.ok());
  EXPECT_EQ(cluster_id, parsed_cluster);
  EXPECT_EQ(node_id, parsed_node);
  EXPECT_EQ(tenant_id, parsed_tenant);
}

TEST_F(ProtocolTest, CreateAndParseConnectionAck) {
  Buffer::OwnedImpl buffer;
  const uint32_t connection_id = 12345;
  const uint32_t keepalive_interval = 30;
  const uint32_t max_data_size = 65536;

  // Create connection ACK
  Protocol::ProtocolUtil::createConnectionAck(buffer, connection_id, keepalive_interval,
                                              max_data_size);

  // Parse header
  auto header_result = Protocol::ProtocolUtil::parseHeader(buffer);
  ASSERT_TRUE(header_result.ok());
  EXPECT_EQ(Protocol::MessageType::CONN_ACK, header_result.value().type);

  // Parse connection ACK
  auto ack_result = Protocol::ProtocolUtil::parseConnectionAck(buffer);
  ASSERT_TRUE(ack_result.ok());

  const auto& ack = ack_result.value();
  EXPECT_EQ(connection_id, ack.connection_id);
  EXPECT_EQ(keepalive_interval, ack.keepalive_interval);
  EXPECT_EQ(max_data_size, ack.max_data_size);
}

TEST_F(ProtocolTest, CreateAndParseRPing) {
  Buffer::OwnedImpl buffer;
  const uint32_t connection_id = 54321;
  const uint64_t timestamp_us = 1234567890123456ULL;

  // Create RPING
  Protocol::ProtocolUtil::createRPing(buffer, connection_id, timestamp_us);

  // Parse header
  auto header_result = Protocol::ProtocolUtil::parseHeader(buffer);
  ASSERT_TRUE(header_result.ok());
  EXPECT_EQ(Protocol::MessageType::RPING, header_result.value().type);

  // Parse RPING
  auto ping_result = Protocol::ProtocolUtil::parseRPing(buffer);
  ASSERT_TRUE(ping_result.ok());

  const auto& ping = ping_result.value();
  EXPECT_EQ(connection_id, ping.connection_id);
  EXPECT_EQ(timestamp_us, ping.timestamp_us);
}

TEST_F(ProtocolTest, InvalidHeaderMagic) {
  Buffer::OwnedImpl buffer;

  // Create a header with invalid magic
  Protocol::ProtocolHeader invalid_header;
  invalid_header.magic = htobe32(0xDEADBEEF); // Wrong magic
  invalid_header.version = Protocol::ProtocolHeader::VERSION;
  invalid_header.type = Protocol::MessageType::CONN_REQ;
  invalid_header.length = htobe16(0);
  invalid_header.sequence = htobe32(1);
  invalid_header.timestamp = htobe32(0);

  buffer.add(&invalid_header, sizeof(invalid_header));

  auto result = Protocol::ProtocolUtil::parseHeader(buffer);
  EXPECT_FALSE(result.ok());
}

TEST_F(ProtocolTest, InsufficientDataForHeader) {
  Buffer::OwnedImpl buffer;
  buffer.add("short", 5); // Less than header size

  auto result = Protocol::ProtocolUtil::parseHeader(buffer);
  EXPECT_FALSE(result.ok());
}

// Socket Interface Tests
TEST_F(ReverseConnectionTest, CreateReverseSocketInterface) {
  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config_, cluster_manager_, dispatcher_);

  EXPECT_NE(nullptr, socket_interface);
}

TEST_F(ReverseConnectionTest, MakeSocketCreatesCustomIOHandle) {
  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config_, cluster_manager_, dispatcher_);

  auto io_handle = socket_interface->makeSocket(AF_INET, SOCK_STREAM, 0, false, {});
  EXPECT_NE(nullptr, io_handle);
}

TEST_F(ReverseConnectionTest, ListenInitiatesReverseTunnels) {
  timer_ = new NiceMock<Event::MockTimer>(&dispatcher_);

  // Mock cluster manager to return a cluster
  auto cluster = std::make_shared<NiceMock<Upstream::MockThreadLocalCluster>>();
  auto host = std::make_shared<NiceMock<Upstream::MockHost>>();
  auto address = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8080);

  EXPECT_CALL(cluster_manager_, getThreadLocalCluster("upstream_cluster"))
      .WillRepeatedly(Return(cluster));
  EXPECT_CALL(cluster->lb_, chooseHost(_)).WillRepeatedly(Return(host));
  EXPECT_CALL(*host, address()).WillRepeatedly(Return(address));

  // Mock dispatcher to create timer and client connection
  EXPECT_CALL(dispatcher_, createTimer(_)).WillOnce(Return(timer_));

  auto mock_connection = std::make_unique<NiceMock<Envoy::Network::MockClientConnection>>();
  EXPECT_CALL(dispatcher_, createClientConnection(_, _, _, _, _)).WillRepeatedly([&](auto&&...) {
    return std::make_unique<NiceMock<Envoy::Network::MockClientConnection>>();
  });

  auto socket_interface =
      std::make_shared<DownstreamReverseSocketInterface>(config_, cluster_manager_, dispatcher_);

  auto io_handle = socket_interface->makeSocket(AF_INET, SOCK_STREAM, 0, false, {});
  ASSERT_NE(nullptr, io_handle);

  // Call listen() which should initiate reverse tunnels
  auto result = io_handle->listen(128);
  EXPECT_EQ(0, result.return_value_);
}

// Socket Factory Tests
class ReverseConnectionSocketFactoryTest : public testing::Test {
public:
  ReverseConnectionSocketFactoryTest() : factory_(cluster_manager_, dispatcher_) {}

protected:
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  ReverseConnectionListenSocketFactory factory_;
};

TEST_F(ReverseConnectionSocketFactoryTest, DetectsReverseConnectionConfig) {
  envoy::config::listener::v3::Listener listener_config;

  // Add reverse connection metadata
  auto* metadata = listener_config.mutable_metadata();
  auto* filter_metadata =
      (*metadata->mutable_filter_metadata())["reverse_connection_listener_config"];

  EXPECT_TRUE(ReverseConnectionListenSocketFactory::hasReverseConnectionConfig(listener_config));
}

TEST_F(ReverseConnectionSocketFactoryTest, NoReverseConnectionConfig) {
  envoy::config::listener::v3::Listener listener_config;
  // No metadata added

  EXPECT_FALSE(ReverseConnectionListenSocketFactory::hasReverseConnectionConfig(listener_config));
}

TEST_F(ReverseConnectionSocketFactoryTest, CreateStandardSocketForNormalListener) {
  envoy::config::listener::v3::Listener listener_config;
  auto address = std::make_shared<Envoy::Network::Address::Ipv4Instance>("127.0.0.1", 8080);
  Envoy::Network::Socket::OptionsSharedPtr options;
  Envoy::Network::BindConfig bind_config;

  // Should return nullptr for non-reverse connection listeners
  auto socket = factory_.createListenSocket(listener_config, address, options, bind_config);
  EXPECT_EQ(nullptr, socket);
}

} // namespace
} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
