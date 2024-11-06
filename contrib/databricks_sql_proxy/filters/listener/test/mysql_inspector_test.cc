#include <cstdint>

#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/listener_filter_buffer_impl.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "test/mocks/api/mocks.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"

#include "contrib/databricks_sql_proxy/filters/helper/mysql_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/mysql_packet_utils.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/config.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/mysql_inspector.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
using testing::Throw;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {
namespace {

MATCHER_P(MapEq, rhs, "") {
  const ProtobufWkt::Struct& obj = arg;
  EXPECT_TRUE(!rhs.empty());
  for (auto const& entry : rhs) {
    EXPECT_EQ(obj.fields().at(entry.first).string_value(), entry.second);
  }
  return true;
}

class MySQLInspectorTest : public testing::Test {
public:
  void SetUp() override {
    DatabricksSqlInspectorConfigFactory factory;
    ProtobufTypes::MessagePtr proto_config = factory.createEmptyConfigProto();
    const std::string yaml = R"EOF(
        stat_prefix: "test"
        protocol: MYSQL
        mysql_config:
          server_version: "8.0.32-databricks-proxy"
          auth_plugin_name: "caching_sha2_password"
          character_set_id: 2
          server_capabilities: "0xffff"
          extended_server_capabilities: "0xffff"
          require_tls:
            value: true
    )EOF";
    TestUtility::loadFromYaml(yaml, *proto_config);

    const auto& x =
        TestUtility::downcastAndValidate<const envoy::extensions::filters::listener::
                                             databricks_sql_inspector::v3::DatabricksSqlInspector&>(
            *proto_config);
    config_ = std::make_shared<Config>(scope_, x, x.stat_prefix());
    filter_ = std::make_unique<Filter>(config_);

    EXPECT_CALL(callbacks_, dynamicMetadata()).WillRepeatedly(ReturnRef(metadata_));
    EXPECT_CALL(callbacks_, socket()).WillRepeatedly(ReturnRef(socket_));
    EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(io_handle_));
    ON_CALL(callbacks_, setDynamicMetadata(_, _))
        .WillByDefault(Invoke([this](const std::string& name, const ProtobufWkt::Struct& obj) {
          (*metadata_.mutable_filter_metadata())[name].MergeFrom(obj);
        }));
  }

  Stats::IsolatedStoreImpl store_;
  Stats::Scope& scope_{*store_.rootScope()};
  std::unique_ptr<Filter> filter_;
  ConfigSharedPtr config_;
  NiceMock<Network::MockListenerFilterCallbacks> callbacks_;
  NiceMock<Network::MockConnectionSocket> socket_;
  NiceMock<Network::MockIoHandle> io_handle_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  Event::FileReadyCb file_event_callback_;
  envoy::config::core::v3::Metadata metadata_;
};

// Test that connections are rejected when TLS is required but client doesn't support it
// When require_tls is true and client doesn't request SSL, the inspector should close the
// connection and increment ssl_mismatch_ counter.
TEST_F(MySQLInspectorTest, SSLRequiredButClientDoesNotSupport) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // First receive should prepare the buffer with message
  EXPECT_CALL(io_handle_, recv(_, _, _)).WillOnce([](void* buffer, size_t length, int flags) {
    EXPECT_EQ(length,
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
    EXPECT_EQ(flags, MSG_PEEK);

    // Create a standard client response with capabilities that don't include CLIENT_SSL
    uint8_t response[36] = {// Packet length (3 bytes)
                            0x20, 0x00, 0x00,
                            // Sequence ID (1 byte)
                            0x01,
                            // Capability flags (4 bytes) - without CLIENT_SSL
                            0x0F, 0xA2, 0x00, 0x00,
                            // Max packet size (4 bytes)
                            0x00, 0x00, 0x00, 0x01,
                            // Character set (1 byte)
                            0x21,
                            // Reserved bytes (23 bytes)
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    std::memcpy(buffer, response, length);
    return Api::IoCallUint64Result(length, Api::IoError::none());
  });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // First onAccept() sets protocol metadata
  const std::map<std::string, std::string> expected = {{"protocol", "MYSQL"}};
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), MapEq(expected)));

  // Call onAccept() to set up callbacks
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // Set up for error message and close
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _))
      .WillOnce([](const std::string&, const ProtobufWkt::Struct& obj) {
        EXPECT_TRUE(obj.fields().contains("error_message"));
        return true;
      });

  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() -> Api::IoCallUint64Result {
    return Api::IoCallUint64Result{0, Api::IoError::none()};
  }));

  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);
  // Validate counters
  EXPECT_EQ(1UL, config_->stats().handshake_received_.value()); // Received handshake
  EXPECT_EQ(1UL, config_->stats().ssl_mismatch_.value());       // SSL mismatch detected
  EXPECT_EQ(1UL, config_->stats().error_.value());              // General error
  EXPECT_EQ(0UL, config_->stats().client_using_ssl_.value());   // Client not using SSL
  EXPECT_EQ(0UL,
            config_->stats().client_not_using_ssl_.value()); // Counter not incremented due to error
  EXPECT_EQ(1UL, config_->stats().server_greeting_sent_.value()); // Server greeting was sent
}

// Test successful handshake with SSL requested.
TEST_F(MySQLInspectorTest, SuccessfulHandshakeWithSSL) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // For both peek and drain operations
  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce([](void* buffer, size_t length, int flags) {
        EXPECT_EQ(length,
                  NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
        EXPECT_EQ(flags, MSG_PEEK);

        // Create a standard client response with capabilities that include CLIENT_SSL
        uint8_t response[36] = {// Packet length (3 bytes) - 28 bytes (valid packet size)
                                0x1C, 0x00, 0x00,
                                // Sequence ID (1 byte)
                                0x01,
                                // Capability flags (4 bytes) - with CLIENT_SSL flag
                                0x0F, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        std::memcpy(buffer, response, length);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      })
      .WillOnce([](void*, size_t length, int flags) {
        // This is for the drain operation - the actual MySQL buffer contents aren't changed
        EXPECT_EQ(flags, 0); // Not MSG_PEEK for actual recv
        return Api::IoCallUint64Result(length, Api::IoError::none());
      });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Protocol and SSL metadata expectations
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _)).Times(2);

  // Initial handshake write
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

  // Validate counters
  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());   // Received handshake
  EXPECT_EQ(1UL, config_->stats().client_using_ssl_.value());     // Client using SSL
  EXPECT_EQ(0UL, config_->stats().client_not_using_ssl_.value()); // Client not using cleartext
  EXPECT_EQ(1UL, config_->stats().server_greeting_sent_.value()); // Server greeting was sent
  EXPECT_EQ(1UL, config_->stats().handshake_success_.value());    // Handshake succeeded
}

// Test that when SSL is requested, proper metadata is set
TEST_F(MySQLInspectorTest, SetShortHandshakeData) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce([](void* buffer, size_t length, int flags) {
        EXPECT_EQ(length,
                  NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
        EXPECT_EQ(flags, MSG_PEEK);

        // Create a response with valid packet size (28 bytes)
        uint8_t response[36] = {0x1C, 0x00, 0x00,       // 28 bytes
                                0x01,                   // Sequence ID
                                0x0F, 0xAA, 0x00, 0x00, // Capability flags with SSL
                                0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        std::memcpy(buffer, response, length);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      })
      .WillOnce([](void*, size_t length, int flags) {
        // Drain operation
        EXPECT_EQ(flags, 0);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Expectations for metadata
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _)).Times(2);

  // Initial handshake
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

  EXPECT_EQ(1UL, config_->stats().client_using_ssl_.value());
}

// Test that invalid handshake response (with incorrect packet size) is rejected
TEST_F(MySQLInspectorTest, InvalidPacketSizeHandshake) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // First receive should prepare the buffer with message
  EXPECT_CALL(io_handle_, recv(_, _, _)).WillOnce([](void* buffer, size_t length, int flags) {
    EXPECT_EQ(length,
              NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
    EXPECT_EQ(flags, MSG_PEEK);

    // Create a handshake response with invalid packet length
    uint8_t response[32] = {// Packet length (3 bytes) - invalid zero size
                            0x00, 0x00, 0x00,
                            // Sequence ID (1 byte)
                            0x01,
                            // Capability flags (4 bytes) - WITHOUT CLIENT_SSL
                            0x0F, 0xA2, 0x00, 0x00, // 0x0F, 0xA2 does not have CLIENT_SSL
                                                    // Rest of the packet data (filling to 32 bytes)
                            0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    std::memcpy(buffer, response, length);
    return Api::IoCallUint64Result(length, Api::IoError::none());
  });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Protocol metadata
  const std::map<std::string, std::string> expected = {{"protocol", "MYSQL"}};
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), MapEq(expected)));

  // Initial handshake setup
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // Error metadata and connection closing - with the correct error message
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _))
      .WillOnce([](const std::string&, const ProtobufWkt::Struct& obj) {
        EXPECT_TRUE(obj.fields().contains("error_message"));
        EXPECT_EQ(obj.fields().at("error_message").string_value(),
                  "Invalid MySQL handshake response");
        return true;
      });

  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() -> Api::IoCallUint64Result {
    return Api::IoCallUint64Result{0, Api::IoError::none()};
  }));

  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);
  // Expect the invalid_message_length counter to be incremented as well
  EXPECT_EQ(1UL, config_->stats().invalid_message_length_.value());
  // Expect the `ssl_mismatch` counter to not be incremented as we failed before that
  EXPECT_EQ(0UL, config_->stats().ssl_mismatch_.value());

  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());   // Received handshake
  EXPECT_EQ(1UL, config_->stats().server_greeting_sent_.value()); // Server greeting was sent
  // Ensure SSL counters haven't been incremented since we fail before that check
  EXPECT_EQ(0UL, config_->stats().client_using_ssl_.value());
  EXPECT_EQ(0UL, config_->stats().client_not_using_ssl_.value());
}

// Test handling of fragmented data - client sends partial data first, then the rest
TEST_F(MySQLInspectorTest, FragmentedDataHandling) {
  SetUp();

  // Define the complete packet we'll send in fragments
  // This is a valid handshake with CLIENT_SSL capability flag set
  uint8_t complete_packet[36] = {// Packet length (3 bytes) - 28 bytes (valid packet size)
                                 0x1C, 0x00, 0x00,
                                 // Sequence ID (1 byte)
                                 0x01,
                                 // Capability flags (4 bytes) - with CLIENT_SSL flag (0x00000800)
                                 0x0F, 0xAA, 0x00, 0x00,
                                 // Max packet size (4 bytes)
                                 0x00, 0x00, 0x00, 0x01,
                                 // Character set (1 byte)
                                 0x21,
                                 // Reserved bytes (23 bytes)
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00};

  // Part 1: Send only first 8 bytes initially
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // First recv only returns partial data (8 bytes)
  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce([&complete_packet](void* buffer, size_t /*length*/, int flags) {
        EXPECT_EQ(flags, MSG_PEEK);

        // Only copy the first 8 bytes
        std::memcpy(buffer, complete_packet, 8);
        return Api::IoCallUint64Result(8, Api::IoError::none());
      });

  // Create a buffer that matches what we'll receive (8 bytes)
  Network::ListenerFilterBufferImpl partial_buffer{
      io_handle_, dispatcher_, [](bool) {}, [](Network::ListenerFilterBuffer&) {}, false,
      8}; // Set buffer size to 8 bytes

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Protocol metadata setup
  const std::map<std::string, std::string> expected = {{"protocol", "MYSQL"}};
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), MapEq(expected)));

  // Initial handshake
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  // Process the initial partial data
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  EXPECT_EQ(filter_->onData(partial_buffer), Network::FilterStatus::StopIteration);

  // Verify need_more_data counter is incremented
  EXPECT_EQ(1UL, config_->stats().need_more_data_.value());

  // Part 2: Now simulate receiving the rest of the data
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // Second recv returns the complete data
  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce([&complete_packet](void* buffer, size_t length, int flags) {
        EXPECT_EQ(flags, MSG_PEEK);

        // Now copy the complete packet
        std::memcpy(buffer, complete_packet, length);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      })
      .WillOnce([](void*, size_t length, int flags) {
        // This is for the drain operation
        EXPECT_EQ(flags, 0); // Not MSG_PEEK for actual recv
        return Api::IoCallUint64Result(length, Api::IoError::none());
      });

  // Create a new buffer with the full size
  Network::ListenerFilterBufferImpl complete_buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Expect metadata for SSL to be set
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _));

  // With complete data, this should now succeed
  EXPECT_EQ(filter_->onData(complete_buffer), Network::FilterStatus::Continue);

  // Verify SSL upgrade was requested
  EXPECT_EQ(1UL, config_->stats().client_using_ssl_.value());
}

// Test initial handshake send failure
TEST_F(MySQLInspectorTest, InitialHandshakeSendFailure) {
  SetUp();

  // Make the write operation fail
  EXPECT_CALL(io_handle_, write(_)).WillOnce([](Buffer::Instance&) -> Api::IoCallUint64Result {
    return Api::IoCallUint64Result{0, Network::IoSocketError::getIoSocketEbadfError()};
  });

  // Error metadata will be set through Filter::setErrorMsgInDynamicMetadata()
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _));

  // Connection should be closed after error
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() -> Api::IoCallUint64Result {
    return Api::IoCallUint64Result{0, Api::IoError::none()};
  }));

  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _)).Times(1).RetiresOnSaturation();

  // Test the code path
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // Verify counter
  EXPECT_EQ(0UL, config_->stats().server_greeting_sent_.value()); // Server greeting not sent
  EXPECT_EQ(1UL, config_->stats().error_.value());                // General error
}

// Test successful handshake without SSL when SSL is not required
TEST_F(MySQLInspectorTest, SuccessfulHandshakeNoSSLWhenNotRequired) {
  DatabricksSqlInspectorConfigFactory factory;
  ProtobufTypes::MessagePtr proto_config = factory.createEmptyConfigProto();
  const std::string yaml = R"EOF(
      stat_prefix: "test"
      protocol: MYSQL
      mysql_config:
        server_version: "8.0.32-databricks-proxy"
        auth_plugin_name: "caching_sha2_password"
        character_set_id: 2
        server_capabilities: "0xffff"
        extended_server_capabilities: "0xffff"
        require_tls:
          value: false
  )EOF";
  TestUtility::loadFromYaml(yaml, *proto_config);

  const auto& x =
      TestUtility::downcastAndValidate<const envoy::extensions::filters::listener::
                                           databricks_sql_inspector::v3::DatabricksSqlInspector&>(
          *proto_config);
  config_ = std::make_shared<Config>(scope_, x, x.stat_prefix());
  filter_ = std::make_unique<Filter>(config_);

  EXPECT_CALL(callbacks_, dynamicMetadata()).WillRepeatedly(ReturnRef(metadata_));
  EXPECT_CALL(callbacks_, socket()).WillRepeatedly(ReturnRef(socket_));
  EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(io_handle_));
  ON_CALL(callbacks_, setDynamicMetadata(_, _))
      .WillByDefault(Invoke([this](const std::string& name, const ProtobufWkt::Struct& obj) {
        (*metadata_.mutable_filter_metadata())[name].MergeFrom(obj);
      }));

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // First receive should prepare the buffer with message
  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce([](void* buffer, size_t length, int flags) {
        EXPECT_EQ(length,
                  NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
        EXPECT_EQ(flags, MSG_PEEK);

        // Create a standard client response with capabilities that don't include CLIENT_SSL
        uint8_t response[36] = {// Packet length (3 bytes)
                                0x20, 0x00, 0x00,
                                // Sequence ID (1 byte)
                                0x01,
                                // Capability flags (4 bytes) - without CLIENT_SSL
                                0x0F, 0xA2, 0x00, 0x00,
                                // Max packet size (4 bytes)
                                0x00, 0x00, 0x00, 0x01,
                                // Character set (1 byte)
                                0x21,
                                // Reserved bytes (23 bytes)
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00};

        std::memcpy(buffer, response, length);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      })
      .WillOnce([](void*, size_t length, int flags) {
        // This is for the drain operation
        EXPECT_EQ(flags, 0); // Not MSG_PEEK for actual recv
        return Api::IoCallUint64Result(length, Api::IoError::none());
      });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Protocol metadata setup
  const std::map<std::string, std::string> expected = {{"protocol", "MYSQL"}};
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), MapEq(expected)));

  // Initial handshake
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result{buffer.length(), Api::IoError::none()};
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // This should hit the handshake_success_.inc() path
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

  // Validate counters
  EXPECT_EQ(1UL, config_->stats().server_greeting_sent_.value()); // Server greeting was sent
  EXPECT_EQ(0UL, config_->stats().need_more_data_.value());       // Counter not incremented
  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());   // Counter incremented
  EXPECT_EQ(1UL, config_->stats().handshake_success_.value());    // Counter incremented
  EXPECT_EQ(0UL, config_->stats().client_using_ssl_.value());     // Client not using SSL
  EXPECT_EQ(1UL, config_->stats().client_not_using_ssl_.value()); // Client using cleartext
  EXPECT_EQ(0UL, config_->stats().ssl_mismatch_.value());         // No SSL mismatch
}

// Test handling when a buffer contains bad data structure causing exception
TEST_F(MySQLInspectorTest, BadBufferData) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  // First receive should prepare the buffer with a corrupted/invalid message
  EXPECT_CALL(io_handle_, recv(_, _, _))
      .WillOnce(Invoke([](void* buffer, size_t length, int flags) {
        EXPECT_EQ(length,
                  NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH);
        EXPECT_EQ(flags, MSG_PEEK);

        // Create an invalid packet that will cause issues when parsed
        // We're intentionally creating corrupted data that will cause parsing errors
        uint8_t invalid_data[36] = {0}; // All zeros will not be a valid MySQL packet
        std::memcpy(buffer, invalid_data, length);
        return Api::IoCallUint64Result(length, Api::IoError::none());
      }));

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       NetworkFilters::DatabricksSqlProxy::MySQLConstants::SSL_HANDSHAKE_PACKET_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Protocol metadata setup
  const std::map<std::string, std::string> expected = {{"protocol", "MYSQL"}};
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), MapEq(expected)));

  // Initial handshake
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce([](Buffer::Instance& buffer) -> Api::IoCallUint64Result {
        return Api::IoCallUint64Result(buffer.length(), Api::IoError::none());
      });

  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // Error handling and connection closing
  EXPECT_CALL(callbacks_, setDynamicMetadata(Filter::name(), _));
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() -> Api::IoCallUint64Result {
    return Api::IoCallUint64Result(0, Api::IoError::none());
  }));

  // The invalid data should cause the filter to stop iteration and increment the error counter
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);
  EXPECT_EQ(1UL, config_->stats().error_.value());
  EXPECT_EQ(1UL, config_->stats().invalid_message_length_.value());

  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());   // Received handshake
  EXPECT_EQ(1UL, config_->stats().server_greeting_sent_.value()); // Server greeting was sent
  // Ensure SSL counters haven't been incremented since we fail before that check
  EXPECT_EQ(0UL, config_->stats().client_using_ssl_.value());
  EXPECT_EQ(0UL, config_->stats().client_not_using_ssl_.value());
}

} // namespace
} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
