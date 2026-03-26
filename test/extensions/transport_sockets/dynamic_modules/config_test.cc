#include "envoy/extensions/transport_sockets/dynamic_modules/v3/dynamic_modules.pb.h"
#include "envoy/extensions/transport_sockets/dynamic_modules/v3/dynamic_modules.pb.validate.h"

#include "source/extensions/transport_sockets/dynamic_modules/config.h"
#include "source/extensions/transport_sockets/dynamic_modules/factory.h"

#include "test/extensions/dynamic_modules/util.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {
namespace {

class DynamicModulesTransportSocketConfigTest : public testing::Test {
public:
  DynamicModulesTransportSocketConfigTest() {
    Envoy::Extensions::DynamicModules::DynamicModulesTestEnvironment::setModulesSearchPath();
  }

  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> context_;
};

// Verifies that a valid downstream config is accepted.
TEST_F(DynamicModulesTransportSocketConfigTest, DownstreamValid) {
  DownstreamDynamicModuleTransportSocketFactory factory;
  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);

  envoy::extensions::transport_sockets::dynamic_modules::v3::DynamicModuleDownstreamTransportSocket
      config;
  config.mutable_dynamic_module_config()->set_name("transport_socket_no_op");
  config.set_socket_name("test");

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

// Verifies that a valid upstream config is accepted.
TEST_F(DynamicModulesTransportSocketConfigTest, UpstreamValid) {
  UpstreamDynamicModuleTransportSocketFactory factory;
  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(proto, nullptr);

  envoy::extensions::transport_sockets::dynamic_modules::v3::DynamicModuleUpstreamTransportSocket
      config;
  config.mutable_dynamic_module_config()->set_name("transport_socket_no_op");
  config.set_socket_name("test");

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

// Verifies that config creation fails when the module returns NULL from factory_config_new.
TEST_F(DynamicModulesTransportSocketConfigTest, DownstreamConfigNewFail) {
  DownstreamDynamicModuleTransportSocketFactory factory;

  envoy::extensions::transport_sockets::dynamic_modules::v3::DynamicModuleDownstreamTransportSocket
      config;
  config.mutable_dynamic_module_config()->set_name("transport_socket_config_new_fail");
  config.set_socket_name("test");

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
  EXPECT_THAT(result.status().message(),
              testing::HasSubstr("Failed to initialize dynamic module transport socket factory"));
}

// Verifies that a missing dynamic_module_config fails proto validation.
TEST_F(DynamicModulesTransportSocketConfigTest, MissingModuleConfig) {
  DownstreamDynamicModuleTransportSocketFactory factory;

  envoy::extensions::transport_sockets::dynamic_modules::v3::DynamicModuleDownstreamTransportSocket
      config;
  config.set_socket_name("test");

  EXPECT_THROW(
      {
        auto result = factory.createTransportSocketFactory(config, context_, {});
        UNREFERENCED_PARAMETER(result);
      },
      EnvoyException);
}

// Verifies that an empty module name fails.
TEST_F(DynamicModulesTransportSocketConfigTest, EmptyModuleName) {
  DownstreamDynamicModuleTransportSocketFactory factory;

  envoy::extensions::transport_sockets::dynamic_modules::v3::DynamicModuleDownstreamTransportSocket
      config;
  config.mutable_dynamic_module_config();
  config.set_socket_name("test");

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
}

} // namespace
} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
