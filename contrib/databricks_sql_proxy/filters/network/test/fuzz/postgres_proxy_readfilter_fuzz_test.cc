#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/address_impl.h"

#include "test/extensions/filters/common/ext_authz/mocks.h"
#include "test/fuzz/fuzz_runner.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/server/factory_context.h"

#include "contrib/databricks_sql_proxy/filters/helper/common_constants.h"
#include "contrib/databricks_sql_proxy/filters/network/source/databricks_sql_proxy.h"
#include "contrib/databricks_sql_proxy/filters/network/test/fuzz/postgres_proxy_readfilter_fuzz_test.pb.validate.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using DatabricksSqlProxyProto =
    envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy;
using CommonConstants = Envoy::Extensions::DatabricksSqlProxy::Helper::CommonConstants;

using testing::Return;
using testing::ReturnRef;
using testing::WithArgs;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DatabricksSqlProxy {

Filters::Common::ExtAuthz::ResponsePtr
makeAuthzResponse(Filters::Common::ExtAuthz::CheckStatus status) {
  Filters::Common::ExtAuthz::ResponsePtr response =
      std::make_unique<Filters::Common::ExtAuthz::Response>();
  response->status = status;

  std::string expected_target_cluster{"non_existent_cluster"};
  ProtobufWkt::Value target_cluster_value;
  target_cluster_value.set_string_value(expected_target_cluster);
  (*response->dynamic_metadata.mutable_fields())[CommonConstants::TARGET_CLUSTER_KEY] =
      target_cluster_value;

  return response;
}

Filters::Common::ExtAuthz::CheckStatus
resultCaseToCheckStatus(envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::
                            Result::ResultSelectorCase result_case) {
  Filters::Common::ExtAuthz::CheckStatus check_status;
  switch (result_case) {
  case envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::Result::
      kCheckStatusOk: {
    check_status = Filters::Common::ExtAuthz::CheckStatus::OK;
    break;
  }
  case envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::Result::
      kCheckStatusError: {
    check_status = Filters::Common::ExtAuthz::CheckStatus::Error;
    break;
  }
  case envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::Result::
      kCheckStatusDenied: {
    check_status = Filters::Common::ExtAuthz::CheckStatus::Denied;
    break;
  }
  default: {
    // Unhandled status
    PANIC("A check status handle is missing");
  }
  }
  return check_status;
}

DEFINE_PROTO_FUZZER(const envoy::extensions::filters::network::test::fuzz::
                        postgres_proxy_readfilter::DatabricksSqlProxyPostgresTestCase& input) {
  if (input.destination_cluster_source() ==
      envoy::extensions::filters::network::databricks_sql_proxy::v3::DatabricksSqlProxy::
          UNDEFINED_DESTINATION_CLUSTER_SOURCE) {
    return;
  }

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

  proto_config.set_destination_cluster_source(input.destination_cluster_source());

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

  filter->initializeReadFilterCallbacks(read_filter_callbacks);
  static Network::Address::InstanceConstSharedPtr addr =
      *Network::Address::PipeInstance::create("/test/test.sock");

  read_filter_callbacks.connection_.stream_info_.downstream_connection_info_provider_
      ->setRemoteAddress(addr);
  read_filter_callbacks.connection_.stream_info_.downstream_connection_info_provider_
      ->setLocalAddress(addr);

  NiceMock<Network::MockWriteFilterCallbacks> write_filter_callbacks;
  filter->initializeWriteFilterCallbacks(write_filter_callbacks);

  filter->onNewConnection();

  for (const auto& action : input.actions()) {
    switch (action.action_selector_case()) {
    case envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::Action::
        ActionSelectorCase::kOnData: {
      // Optional input field to set default authorization check result for the following "onData()"
      if (action.on_data().has_result()) {
        ON_CALL(*client, check(_, _, _, _))
            .WillByDefault(WithArgs<0>(
                Invoke([&](Filters::Common::ExtAuthz::RequestCallbacks& callbacks) -> void {
                  callbacks.onComplete(makeAuthzResponse(
                      resultCaseToCheckStatus(action.on_data().result().result_selector_case())));
                })));
      }
      Buffer::OwnedImpl buffer(action.on_data().data());
      filter->onData(buffer, action.on_data().end_stream());
      break;
    }
    case envoy::extensions::filters::network::test::fuzz::postgres_proxy_readfilter::Action::
        ActionSelectorCase::kOnNewConnection: {
      filter->onNewConnection();
      break;
    }
    default: {
      // Unhandled actions are ignored.
      continue;
    }
    }
  }
}

} // namespace DatabricksSqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
