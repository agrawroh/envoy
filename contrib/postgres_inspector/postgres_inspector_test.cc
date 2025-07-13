#include <cstdint>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/network/filter.h"
#include "envoy/network/listener_filter_buffer.h"
#include "envoy/stats/scope.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/stats/isolated_store_impl.h"
#include "source/common/stream_info/filter_state_impl.h"

#include "test/mocks/network/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/utility.h"

#include "contrib/postgres_common/postgres_constants.h"
#include "contrib/postgres_inspector/postgres_inspector.h"
#include "contrib/postgres_inspector/postgres_inspector_metadata.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace PostgresInspector {
namespace {

class MockListenerFilterBuffer : public Network::ListenerFilterBuffer {
public:
  MockListenerFilterBuffer() = default;
  ~MockListenerFilterBuffer() override = default;

  MOCK_METHOD(const Buffer::ConstRawSlice, rawSlice, (), (const));
  MOCK_METHOD(bool, drain, (uint64_t length));
};

class PostgresInspectorTest : public testing::Test {
protected:
  void SetUp() override {
    config_ = std::make_shared<Config>(*scope_.rootScope());
    filter_ = std::make_unique<Filter>(config_);
  }

  void setUpFilter() {
    ON_CALL(cb_, socket()).WillByDefault(ReturnRef(socket_));
    ON_CALL(cb_, filterState()).WillByDefault(ReturnRef(filter_state_));
    ON_CALL(socket_, detectedTransportProtocol()).WillByDefault(Return(""));
  }

  Network::FilterStatus runWithData(const std::string& data) {
    MockListenerFilterBuffer filter_buffer;

    // Create a copy of the data to ensure it remains valid
    std::string data_copy = data;
    Buffer::ConstRawSlice raw_slice{data_copy.data(), data_copy.length()};

    EXPECT_CALL(filter_buffer, rawSlice()).WillRepeatedly(testing::Return(raw_slice));

    filter_->onAccept(cb_);
    return filter_->onData(filter_buffer);
  }

  // Helper method to create data with specific length
  std::string createData(size_t length, uint8_t fill_byte = 0) {
    return std::string(length, static_cast<char>(fill_byte));
  }

  Stats::IsolatedStoreImpl scope_;
  ConfigSharedPtr config_;
  std::unique_ptr<Filter> filter_;
  NiceMock<Network::MockListenerFilterCallbacks> cb_;
  NiceMock<Network::MockConnectionSocket> socket_;
  StreamInfo::FilterStateImpl filter_state_{StreamInfo::FilterState::LifeSpan::FilterChain};
};

// Test that the filter is properly configured
TEST_F(PostgresInspectorTest, ConfigTest) {
  EXPECT_EQ(Config::DEFAULT_MAX_READ_BYTES, filter_->maxReadBytes());
  EXPECT_EQ(0, config_->stats().postgres_detected_.value());
}

// Test onAccept with no transport protocol
TEST_F(PostgresInspectorTest, OnAcceptNoTransportProtocol) {
  setUpFilter();

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onAccept(cb_));
}

// Test onAccept with existing transport protocol
TEST_F(PostgresInspectorTest, OnAcceptWithTransportProtocol) {
  setUpFilter();
  ON_CALL(socket_, detectedTransportProtocol()).WillByDefault(Return("tls"));

  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onAccept(cb_));
}

// Test onAccept with raw_buffer transport protocol
TEST_F(PostgresInspectorTest, OnAcceptWithRawBuffer) {
  setUpFilter();
  ON_CALL(socket_, detectedTransportProtocol()).WillByDefault(Return("raw_buffer"));

  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onAccept(cb_));
}

// Test SSL request detection
TEST_F(PostgresInspectorTest, SSLRequestDetection) {
  setUpFilter();

  // SSL request: length=8, protocol=80877103 (0x04d2162f)
  std::string ssl_request;
  ssl_request.resize(8);
  uint32_t length = htonl(8);
  uint32_t protocol = htonl(Common::Postgres::PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION);

  safeMemcpyUnsafeDst(&ssl_request[0], &length);
  safeMemcpyUnsafeDst(&ssl_request[4], &protocol);

  EXPECT_EQ(Network::FilterStatus::Continue, runWithData(ssl_request));

  // Check stats
  EXPECT_EQ(1, config_->stats().postgres_detected_.value());
  EXPECT_EQ(1, config_->stats().ssl_request_detected_.value());

  // Check metadata was set
  const auto* metadata =
      filter_state_.getDataReadOnly<NetworkFilters::PostgresProxy::PostgresInspectorMetadata>(
          NetworkFilters::PostgresProxy::PostgresInspectorMetadata::filterStateKey());
  ASSERT_NE(nullptr, metadata);
  EXPECT_EQ("postgres", metadata->transportProtocol());
  EXPECT_EQ("ssl_request", metadata->messageType());
  EXPECT_TRUE(metadata->sslRequested());
}

// Test startup message detection
TEST_F(PostgresInspectorTest, StartupMessageDetection) {
  setUpFilter();

  // Startup message: length=variable, protocol=196608 (3.0)
  std::string startup_message;
  startup_message.resize(20); // Minimum size for startup message
  uint32_t length = htonl(20);
  uint32_t protocol = htonl(Common::Postgres::PostgresConstants::PROTOCOL_VERSION);

  safeMemcpyUnsafeDst(&startup_message[0], &length);
  safeMemcpyUnsafeDst(&startup_message[4], &protocol);

  // Fill rest with dummy data
  std::memset(&startup_message[8], 0, 12);

  EXPECT_EQ(Network::FilterStatus::Continue, runWithData(startup_message));

  // Check stats
  EXPECT_EQ(1, config_->stats().postgres_detected_.value());
  EXPECT_EQ(1, config_->stats().startup_message_detected_.value());

  // Check metadata was set
  const auto* metadata =
      filter_state_.getDataReadOnly<NetworkFilters::PostgresProxy::PostgresInspectorMetadata>(
          NetworkFilters::PostgresProxy::PostgresInspectorMetadata::filterStateKey());
  ASSERT_NE(nullptr, metadata);
  EXPECT_EQ("postgres", metadata->transportProtocol());
  EXPECT_EQ("startup_message", metadata->messageType());
  EXPECT_FALSE(metadata->sslRequested());
}

// Test insufficient data
TEST_F(PostgresInspectorTest, InsufficientData) {
  setUpFilter();

  // Only 4 bytes - not enough for protocol detection
  std::string small_data = createData(4);

  EXPECT_EQ(Network::FilterStatus::StopIteration, runWithData(small_data));
  EXPECT_EQ(1, config_->stats().need_more_data_.value());
}

// Test invalid message length
TEST_F(PostgresInspectorTest, InvalidMessageLength) {
  setUpFilter();

  // Message with invalid length (0)
  std::string invalid_message;
  invalid_message.resize(8);
  uint32_t length = htonl(0); // Invalid length
  uint32_t protocol = htonl(Common::Postgres::PostgresConstants::PROTOCOL_VERSION);

  safeMemcpyUnsafeDst(&invalid_message[0], &length);
  safeMemcpyUnsafeDst(&invalid_message[4], &protocol);

  EXPECT_EQ(Network::FilterStatus::Continue, runWithData(invalid_message));
  EXPECT_EQ(1, config_->stats().invalid_message_length_.value());
  EXPECT_EQ(1, config_->stats().error_.value());
}

// Test invalid protocol version
TEST_F(PostgresInspectorTest, InvalidProtocolVersion) {
  setUpFilter();

  // Message with invalid protocol version
  std::string invalid_message;
  invalid_message.resize(8);
  uint32_t length = htonl(8);
  uint32_t protocol = htonl(0x12345678); // Invalid protocol

  safeMemcpyUnsafeDst(&invalid_message[0], &length);
  safeMemcpyUnsafeDst(&invalid_message[4], &protocol);

  EXPECT_EQ(Network::FilterStatus::Continue, runWithData(invalid_message));
  EXPECT_EQ(1, config_->stats().invalid_protocol_version_.value());
}

// Test need more data for complete message
TEST_F(PostgresInspectorTest, NeedMoreDataForCompleteMessage) {
  setUpFilter();

  // Message header indicates 20 bytes but only provide 10
  std::string partial_message;
  partial_message.resize(10);
  uint32_t length = htonl(20); // Claims 20 bytes
  uint32_t protocol = htonl(Common::Postgres::PostgresConstants::PROTOCOL_VERSION);

  safeMemcpyUnsafeDst(&partial_message[0], &length);
  safeMemcpyUnsafeDst(&partial_message[4], &protocol);

  EXPECT_EQ(Network::FilterStatus::StopIteration, runWithData(partial_message));
  EXPECT_EQ(1, config_->stats().need_more_data_.value());
}

// Test maxReadBytes configuration
TEST_F(PostgresInspectorTest, MaxReadBytes) {
  setUpFilter();

  EXPECT_EQ(Config::DEFAULT_MAX_READ_BYTES, filter_->maxReadBytes());
}

// Test multiple calls after detection
TEST_F(PostgresInspectorTest, MultipleCallsAfterDetection) {
  setUpFilter();

  // First call with SSL request
  std::string ssl_request;
  ssl_request.resize(8);
  uint32_t length = htonl(8);
  uint32_t protocol = htonl(Common::Postgres::PostgresConstants::SSL_REQUEST_PROTOCOL_VERSION);

  safeMemcpyUnsafeDst(&ssl_request[0], &length);
  safeMemcpyUnsafeDst(&ssl_request[4], &protocol);

  EXPECT_EQ(Network::FilterStatus::Continue, runWithData(ssl_request));

  // Second call should continue immediately
  EXPECT_EQ(Network::FilterStatus::Continue, runWithData("more data"));

  // Stats should not increment again
  EXPECT_EQ(1, config_->stats().postgres_detected_.value());
  EXPECT_EQ(1, config_->stats().ssl_request_detected_.value());
}

} // namespace
} // namespace PostgresInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
