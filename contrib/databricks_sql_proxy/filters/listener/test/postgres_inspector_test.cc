#include <cstdint>

#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/listener_filter_buffer_impl.h"

#include "test/mocks/api/mocks.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"

#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/config.h"
#include "contrib/databricks_sql_proxy/filters/listener/source/postgres_inspector.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;
using testing::ReturnRef;
using testing::SaveArg;
using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace DatabricksSqlInspector {
namespace {

MATCHER_P(MapEq, rhs, "") {
  const Protobuf::Struct& obj = arg;
  EXPECT_TRUE(!rhs.empty());
  for (auto const& entry : rhs) {
    EXPECT_EQ(obj.fields().at(entry.first).string_value(), entry.second);
  }
  return true;
}

class PostgresInspectorTest : public testing::Test {
public:
  void SetUp() override {
    DatabricksSqlInspectorConfigFactory factory;
    ProtobufTypes::MessagePtr proto_config = factory.createEmptyConfigProto();
    const std::string yaml = R"EOF(
        stat_prefix: "test"
        protocol: POSTGRES
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
        .WillByDefault(Invoke([this](const std::string& name, const Protobuf::Struct& obj) {
          (*metadata_.mutable_filter_metadata())[name].MergeFrom(obj);
        }));
  }

  // The first 4 bytes is the message size with the value of 8.
  // Follow by 4 bytes of protocol version (0x04d2162f).
  static const char* ssl_request_message;
  // The first 4 bytes is the message size with the value of 16.
  // Follow by 4 bytes of protocol version (0x04d2162e).
  // Then cancel payload (8 bytes).
  static const char* cancel_request_message;

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

const char* PostgresInspectorTest::ssl_request_message = "\x00\x00\x00\x08\x04\xd2\x16\x2f";
const char* PostgresInspectorTest::cancel_request_message =
    "\x00\x00\x00\x10\x04\xd2\x16\x2e\x00\x00\x00\x46\x5f\x68\x5f\x1d";

// Test successful SSL request message.
// Send 8 bytes of SSL request message and verify that function call returns
// Network::FilterStatus::Continue.
TEST_F(PostgresInspectorTest, SuccessfulSSLRequest) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));
  // io_handle_.recv() will be called two times. First time to setup the buffer in peek the message
  // and second time to drain the message.
  EXPECT_CALL(io_handle_, recv)
      .WillOnce([&](void* buffer, size_t length, int flags) {
        EXPECT_EQ(MSG_PEEK, flags);
        EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
        memcpy(buffer, ssl_request_message, PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);
        return Api::IoCallUint64Result(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                                       Api::IoError::none());
      })
      .WillOnce([&](void*, size_t length, int) {
        EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
        return Api::IoCallUint64Result(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                                       Api::IoError::none());
      });

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH};

  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // On success case, we will write a reply to the SSL request so we expect io_handle_.write() to be
  // called once.
  EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance&) {
    return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  const std::map<std::string, std::string> expected = {{"protocol", "POSTGRES"}};
  EXPECT_CALL(callbacks_,
              setDynamicMetadata("envoy.filters.listener.databricks_sql_proxy", MapEq(expected)));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());
  EXPECT_EQ(1UL, config_->stats().handshake_success_.value());
}

TEST_F(PostgresInspectorTest, SuccessfulCancelRequest) {
  SetUp();

  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));
  // io_handle_.recv() will be called to peek the message size.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void* buffer, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    EXPECT_EQ(PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH, length);
    memcpy(buffer, cancel_request_message, PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH);
    return Api::IoCallUint64Result(PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH,
                                   Api::IoError::none());
  });

  // buffer to store actual payload data.
  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  const std::map<std::string, std::string> expected = {{"protocol", "POSTGRES"}};
  EXPECT_CALL(callbacks_,
              setDynamicMetadata("envoy.filters.listener.databricks_sql_proxy", MapEq(expected)));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the cancel request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

  EXPECT_EQ(1UL, config_->stats().cancel_request_received_.value());
}

// Test that if the message size is smaller than expected, the function call returns
// Network::FilterStatus::StopIteration. And does not increase the error count because this is not
// error as we might not have received the full message yet. Then the test will trigger onData again
// when the buffer is filled with the full message.
TEST_F(PostgresInspectorTest, SmallerThanExpectedMessage) {
  struct TestCase {
    absl::string_view test_case_name;
    const void* incomplete_message;
    const uint64_t incomplete_message_length;
    const void* complete_message;
    const uint64_t complete_message_length;
  };

  std::vector<TestCase> test_cases = {
      {"SSL", "\x00\x00\x00\x08\x04\xd2\x16", PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH - 1,
       ssl_request_message, PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH},
      {"Cancel", "\x00\x00\x00\x10\x04\xd2\x16\x2e\x00\x00\x00\x46\x5f\x68\x5f\x1d",
       PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH - 1, cancel_request_message,
       PostgresConstants::CANCEL_REQUEST_MESSAGE_LENGTH},
  };

  SetUp();

  for (const auto& test_case : test_cases) {
    config_->stats().need_more_data_.reset();

    const size_t message_length = test_case.incomplete_message_length;

    {
      // Using InSequence because these are the order in which io_handle_.recv() should be called.
      ::testing::InSequence s;
      // io_handle_.recv() will be called one times to setup the buffer.
      EXPECT_CALL(io_handle_, recv)
          .WillOnce([&](void* buffer, size_t length, int flags) {
            EXPECT_EQ(MSG_PEEK, flags);
            EXPECT_EQ(test_case.complete_message_length, length);
            // Simulate the data send over the wire by copy the data we want to return to the
            // buffer.
            memcpy(buffer, test_case.incomplete_message, message_length);
            return Api::IoCallUint64Result(message_length, Api::IoError::none());
          })
          // This second call returns the complete message.
          .WillOnce([&](void* buffer, size_t length, int flags) {
            EXPECT_EQ(MSG_PEEK, flags);
            EXPECT_EQ(test_case.complete_message_length, length);
            // Simulate the data send over the wire by copy the data we want to return to the
            // buffer.
            memcpy(buffer, test_case.complete_message, test_case.complete_message_length);
            return Api::IoCallUint64Result(test_case.complete_message_length, Api::IoError::none());
          });

      if (test_case.test_case_name == "SSL") {
        EXPECT_CALL(io_handle_, recv)
            // Drain will call this.
            .WillOnce([&](void*, size_t length, int) {
              EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
              return Api::IoCallUint64Result(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                                             Api::IoError::none());
            });
      }
    }

    EXPECT_CALL(io_handle_,
                createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                                 Event::FileReadyType::Read | Event::FileReadyType::Closed))
        // .WillOnce(SaveArg<1>(&file_event_callback_))
        .WillOnce(SaveArg<1>(&file_event_callback_));

    Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                             [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                             false,       test_case.complete_message_length};

    // Trigger the callback to initialize the buffer.
    EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

    // Call onAccept to setup the callback.
    EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
    // Call onData to process the SSL request message.
    EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

    // Expect need more data to happen because the buffer is not filled
    // with the full message in the first recv call.
    EXPECT_EQ(1UL, config_->stats().need_more_data_.value());

    // Trigger the callback to initialize the buffer.
    EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

    if (test_case.test_case_name == "SSL") {
      // We expect to send SSL response to the client.
      EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance& data) {
        EXPECT_EQ(1, data.length());
        EXPECT_EQ('S', *(static_cast<char*>(data.linearize(1))));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));
    }

    // Call onData to process the SSL request message.
    // This time the call should succeeded because we have all the data.
    EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::Continue);

    EXPECT_EQ(1UL, config_->stats().need_more_data_.value());

    if (test_case.test_case_name == "SSL") {
      EXPECT_EQ(1UL, config_->stats().handshake_received_.value());
      EXPECT_EQ(1UL, config_->stats().handshake_success_.value());
    } else if (test_case.test_case_name == "Cancel") {
      EXPECT_EQ(1UL, config_->stats().cancel_request_received_.value());
    }
  }
}

// Test that if the SSL request message size is larger than expected, the function call returns
// Network::FilterStatus::StopIteration.
TEST_F(PostgresInspectorTest, LargerThanExpectedMessage) {
  SetUp();

  const int32_t message_length = PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH + 1;
  // io_handle_.recv() will be called two times. First time to setup the buffer in peek the message
  // and second time to drain the message.
  EXPECT_CALL(io_handle_, recv)
      .WillOnce([&](void* buffer, size_t length, int flags) {
        EXPECT_EQ(MSG_PEEK, flags);
        EXPECT_EQ(message_length, length);
        memcpy(buffer, "\x00\x00\x00\x08\x04\xd2\x16\x2f\x00", message_length);
        return Api::IoCallUint64Result(message_length, Api::IoError::none());
      })
      .WillOnce([&](void*, size_t length, int) {
        // We expect to only drain SSL_REQUEST_MESSAGE_LENGTH even though there are more message in
        // the buffer.
        EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
        return Api::IoCallUint64Result(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                                       Api::IoError::none());
      });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                           [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                           false,       message_length};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Expect that we will send SSL response to the client.
  EXPECT_CALL(io_handle_, write(_))
      .WillOnce(Invoke([](Buffer::Instance&) {
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }))
      // However, we have more data buffered in the buffer before SSL handshake
      // which is a protocol violation. We expect to call write to send the error response.
      .WillOnce(Invoke([](Buffer::Instance& data) {
        // Do some basic check on the error response. Not checking the full content.
        EXPECT_EQ(171, data.length());
        // First byte is 'E' identifies the error message.
        EXPECT_EQ('E', data.peekBEInt<uint8_t>());
        // The next 4 bytes is the message length.
        EXPECT_EQ(170, data.peekBEInt<int32_t>(1));
        EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
        return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
      }));

  // After ending error response, we will close the connection.
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() {
    return Api::IoCallUint64Result{0, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());
  EXPECT_EQ(1UL, config_->stats().protocol_violation_.value());
  EXPECT_EQ(1UL, config_->stats().error_.value());

  auto filter_meta = metadata_.mutable_filter_metadata()->at(Filter::name());
  auto fields = filter_meta.fields();
  EXPECT_TRUE(fields.contains("error_message"));
  EXPECT_EQ(fields.at("error_message").string_value(),
            "Received unencrypted data after SSL request. This could be either a client-software "
            "bug or evidence of an attempted man-in-the-middle attack.");
}

// Test that if the SSL request message length is not what is expected, the function call returns
// Network::FilterStatus::StopIteration.
TEST_F(PostgresInspectorTest, InvalidMessageLength) {
  SetUp();

  const int32_t message_length = PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH;
  // io_handle_.recv() will be called one times to setup the buffer.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void* buffer, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    EXPECT_EQ(message_length, length);
    // Set message length to 7 (The first 4 bytes). The buffer size is still 8.
    memcpy(buffer, "\x00\x00\x00\x07\x04\xd2\x16\x2f", message_length);
    return Api::IoCallUint64Result(message_length, Api::IoError::none());
  });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                           [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                           false,       message_length};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Expect onData to failed and close the connection.
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() {
    return Api::IoCallUint64Result{0, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Expect that we will send error response to the client.
  EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance& data) {
    // Do some basic check on the error response. Not checking the full content.
    EXPECT_EQ(156, data.length());
    // First byte is 'E' identifies the error message.
    EXPECT_EQ('E', data.peekBEInt<uint8_t>());
    // The next 4 bytes is the message length.
    EXPECT_EQ(155, data.peekBEInt<int32_t>(1));
    EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
    return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  EXPECT_EQ(1UL, config_->stats().invalid_message_length_.value());
  EXPECT_EQ(1UL, config_->stats().error_.value());

  auto filter_meta = metadata_.mutable_filter_metadata()->at(Filter::name());
  auto fields = filter_meta.fields();
  EXPECT_TRUE(fields.contains("error_message"));
  EXPECT_EQ(fields.at("error_message").string_value(),
            "Invalid SSL request message length. Message length: 7. Expected 8 bytes.");
}

// Test that if the SSL request message contains incorrect protocol version, the function call
// returns Network::FilterStatus::StopIteration.
TEST_F(PostgresInspectorTest, InvalidProtocolVersion) {
  SetUp();

  const int32_t message_length = PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH;
  // io_handle_.recv() will be called one times to setup the buffer.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void* buffer, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    EXPECT_EQ(message_length, length);
    // The last byte of the protocol is incorrect.
    memcpy(buffer, "\x00\x00\x00\x08\x04\xd2\x16\x00", message_length);
    return Api::IoCallUint64Result(message_length, Api::IoError::none());
  });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                           [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                           false,       message_length};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Expect onData to failed and close the connection.
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() {
    return Api::IoCallUint64Result{0, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Expect that we will send error response to the client.
  EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance& data) {
    // Do some basic check on the error response. Not checking the full content.
    EXPECT_EQ(173, data.length());
    // First byte is 'E' identifies the error message.
    EXPECT_EQ('E', data.peekBEInt<uint8_t>());
    // The next 4 bytes is the message length.
    EXPECT_EQ(172, data.peekBEInt<int32_t>(1));
    EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
    return Api::IoCallUint64Result{1, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  EXPECT_EQ(1UL, config_->stats().invalid_protocol_version_.value());
  EXPECT_EQ(1UL, config_->stats().error_.value());

  auto filter_meta = metadata_.mutable_filter_metadata()->at(Filter::name());
  auto fields = filter_meta.fields();
  EXPECT_TRUE(fields.contains("error_message"));
  EXPECT_EQ(fields.at("error_message").string_value(),
            "Invalid protocol version. Protocol version: 80877056");
}

// Test that the inspector failed to write the SSL reply to the socket, the function call returns
// Network::FilterStatus::StopIteration.
TEST_F(PostgresInspectorTest, WriteFailure) {
  SetUp();

  // io_handle_.recv() will be called one times to setup the buffer.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void* buffer, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
    memcpy(buffer, ssl_request_message, PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH);
    return Api::IoCallUint64Result(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH,
                                   Api::IoError::none());
  });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{
      io_handle_,  dispatcher_,
      [](bool) {}, [](Network::ListenerFilterBuffer&) {},
      false,       PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance&) {
    return Api::IoCallUint64Result{0, Network::IoSocketError::getIoSocketEbadfError()};
  }));
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() {
    return Api::IoCallUint64Result{0, Api::IoErrorPtr(nullptr, [](Api::IoError*) {})};
  }));

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  EXPECT_EQ(1UL, config_->stats().handshake_received_.value());
  EXPECT_EQ(1UL, config_->stats().handshake_response_failed_.value());
  EXPECT_EQ(1UL, config_->stats().error_.value());

  auto filter_meta = metadata_.mutable_filter_metadata()->at(Filter::name());
  auto fields = filter_meta.fields();
  EXPECT_TRUE(fields.contains("error_message"));
  EXPECT_EQ(fields.at("error_message").string_value(),
            "Failed to write reply to socket. code: 8 error: Bad file descriptor");
}

// Test that if we have zero length message, the function call returns
// Network::FilterStatus::StopIteration.
TEST_F(PostgresInspectorTest, ZeroLengthMessage) {
  SetUp();

  const int32_t message_length = PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH;
  // io_handle_.recv() will be called one time to setup the buffer.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void*, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    // The caller wants to read SSL_REQUEST_MESSAGE_LENGTH bytes.
    EXPECT_EQ(PostgresConstants::SSL_REQUEST_MESSAGE_LENGTH, length);
    // However, there is zero byte, return zero length message.
    return Api::IoCallUint64Result(0, Api::IoError::none());
  });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                           [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                           false,       message_length};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);
  // Call onData to process the SSL request message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  // Expect need more data to happen because the buffer is not filled
  // with the full message in the first recv call.
  EXPECT_EQ(1UL, config_->stats().need_more_data_.value());
}

// Test that if the client sends postgres startup message (can happen when client is trying to do
// unencrypted connection), the connection should be closed and error will be sent to the client. We
// expect postgres client to always use SSL because we need SNI to route the connection to the
// correct backend. The exception is cancellation request which is not encrypted.
TEST_F(PostgresInspectorTest, UnencryptedConnectionRequestError) {
  SetUp();

  const std::string connection_string_options{"user\0testuser\0database\0testdb\0", 30};
  const uint32_t message_length =
      PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH + connection_string_options.length();
  Buffer::OwnedImpl postgres_startup_message;
  postgres_startup_message.writeBEInt<int32_t>(message_length);
  postgres_startup_message.writeBEInt<uint32_t>(PostgresConstants::PROTOCOL_VERSION);
  postgres_startup_message.add(connection_string_options);

  // io_handle_.recv() will be called one time to setup the buffer.
  EXPECT_CALL(io_handle_, recv).WillOnce([&](void* buffer, size_t length, int flags) {
    EXPECT_EQ(MSG_PEEK, flags);
    EXPECT_EQ(message_length, length);
    memcpy(buffer, postgres_startup_message.linearize(message_length), message_length);
    return Api::IoCallUint64Result(message_length, Api::IoError::none());
  });
  EXPECT_CALL(io_handle_,
              createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
                               Event::FileReadyType::Read | Event::FileReadyType::Closed))
      .WillOnce(SaveArg<1>(&file_event_callback_));

  Network::ListenerFilterBufferImpl buffer{io_handle_,  dispatcher_,
                                           [](bool) {}, [](Network::ListenerFilterBuffer&) {},
                                           false,       message_length};

  // Trigger the callback to initialize the buffer.
  EXPECT_TRUE(file_event_callback_(Event::FileReadyType::Read).ok());

  // Call onAccept to setup the callback.
  EXPECT_EQ(filter_->onAccept(callbacks_), Network::FilterStatus::StopIteration);

  // Expect onData to failed and we will send error to the client
  EXPECT_CALL(io_handle_, write(_)).WillOnce(Invoke([](Buffer::Instance& data) {
    // Do some basic check on the error response. Not checking the full content.
    EXPECT_EQ(171, data.length());
    // First byte is 'E' identifies the error message.
    EXPECT_EQ('E', data.peekBEInt<uint8_t>());
    // The next 4 bytes is the message length.
    EXPECT_EQ(170, data.peekBEInt<int32_t>(1));
    EXPECT_EQ('S', data.peekBEInt<uint8_t>(5));
    EXPECT_THAT(data.toString(), testing::HasSubstr("Ensure that connection is using SSL"));
    return Api::ioCallUint64ResultNoError();
  }));
  EXPECT_CALL(io_handle_, close()).WillOnce(Invoke([]() {
    return Api::ioCallUint64ResultNoError();
  }));

  // Call onData to process the startup message.
  EXPECT_EQ(filter_->onData(buffer), Network::FilterStatus::StopIteration);

  EXPECT_EQ(1, config_->stats().invalid_protocol_version_.value());
  EXPECT_EQ(1, config_->stats().error_.value());
}

} // namespace
} // namespace DatabricksSqlInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
