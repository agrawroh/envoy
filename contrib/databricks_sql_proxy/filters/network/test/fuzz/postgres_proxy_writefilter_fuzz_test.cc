#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/address_impl.h"

#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/fuzz/fuzz_runner.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/server/factory_context.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/helper/postgres_constants.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/test/fuzz/postgres_proxy_writefilter_fuzz_test.pb.validate.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;
using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;
using PostgresConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::PostgresConstants;

using testing::Return;
using testing::ReturnRef;
using testing::WithArgs;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

DEFINE_PROTO_FUZZER(const envoy::extensions::filters::network::test::fuzz::
                        postgres_proxy_writefilter::DatabricksSqlProxyPostgresTestCase& input) {

  const std::string yaml = R"EOF(
    stat_prefix: "test"
    protocol: POSTGRES
    enable_upstream_tls: true
    destination_cluster_source: SIDECAR_SERVICE
    ext_authz_service:
      envoy_grpc:
        cluster_name: ext_authz_server
  )EOF";

  DatabricksSqlProxyProto proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  NiceMock<Server::Configuration::MockFactoryContext> context;
  const std::string stat_prefix{"fuzz_test."};
  const std::string sni_{"test.databricks.com"};
  std::shared_ptr<Ssl::MockConnectionInfo> ssl_ = std::make_shared<Ssl::MockConnectionInfo>();

  // Create a mock client and immediately pack it into a unique_ptr. This way if the ConfigSharedPtr
  // constructor fails the client will not get leaked.
  Filters::Common::ExtAuthz::MockClient* client = new Filters::Common::ExtAuthz::MockClient();
  auto client_ptr = Filters::Common::ExtAuthz::ClientPtr{client};

  ConfigSharedPtr config;
  try {
    config = std::make_shared<Config>(proto_config, context, stat_prefix);
  } catch (const EnvoyException& e) {
    ENVOY_LOG_MISC(debug, "EnvoyException during validation: {}", e.what());
    return;
  }

  auto filter = std::make_unique<Filter>(config, std::move(client_ptr));

  // Setup SNI for the filter.
  NiceMock<Network::MockReadFilterCallbacks> read_filter_callbacks;
  ON_CALL(read_filter_callbacks.connection_, ssl()).WillByDefault(Return(ssl_));
  EXPECT_CALL(*ssl_, sni()).WillRepeatedly(ReturnRef(sni_));
  const std::vector<std::string> uriSan{"someSan"};
  EXPECT_CALL(*ssl_, uriSanPeerCertificate()).WillRepeatedly(Return(uriSan));
  EXPECT_CALL(*ssl_, uriSanLocalCertificate()).WillRepeatedly(Return(uriSan));

  ON_CALL(read_filter_callbacks, startUpstreamSecureTransport()).WillByDefault(Return(true));

  filter->initializeReadFilterCallbacks(read_filter_callbacks);
  static Network::Address::InstanceConstSharedPtr addr =
      *Network::Address::PipeInstance::create("/test/test.sock");

  read_filter_callbacks.connection_.stream_info_.downstream_connection_info_provider_
      ->setRemoteAddress(addr);
  read_filter_callbacks.connection_.stream_info_.downstream_connection_info_provider_
      ->setLocalAddress(addr);

  NiceMock<Network::MockWriteFilterCallbacks> write_filter_callbacks;
  filter->initializeWriteFilterCallbacks(write_filter_callbacks);

  // ==== Setup the filter to correct state that will wait for upstream SSL response. ====
  filter->onNewConnection();

  // Setup the filter to correct state that will wait for upstream SSL response.
  Buffer::OwnedImpl postgres_startup_message;
  postgres_startup_message.writeBEInt<int32_t>(PostgresConstants::MIN_STARTUP_MESSAGE_LENGTH);
  postgres_startup_message.writeBEInt<uint32_t>(PostgresConstants::PROTOCOL_VERSION);

  filter->onData(postgres_startup_message, false);

  Filters::Common::ExtAuthz::Response ext_authz_response{};
  ext_authz_response.status = Filters::Common::ExtAuthz::CheckStatus::OK;
  ProtobufWkt::Struct dynamic_metadata;
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value("some_target_cluster");
  (*ext_authz_response.dynamic_metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] =
      target_cluster_value;

  // Simulate the ext_authz server ext_authz_response.
  filter->onComplete(std::make_unique<Filters::Common::ExtAuthz::Response>(ext_authz_response));

  // Assume that TcpProxy established the upstream connection.
  // This will enable read.
  read_filter_callbacks.connection_.read_enabled_ = true;

  // Timer object for the test is a mock object so we need to call the function directly.
  filter->pollForUpstreamConnected();

  // ==== End setup ====

  // ==== Test scenarios ====
  for (const auto& on_write : input.on_writes()) {
    Buffer::OwnedImpl buffer(on_write.data());
    filter->onWrite(buffer, on_write.end_stream());
  }
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
