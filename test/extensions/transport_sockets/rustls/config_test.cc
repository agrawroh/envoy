#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.h"

#include "source/extensions/transport_sockets/rustls/config.h"

#include "test/mocks/server/transport_socket_factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {
namespace {

class RustlsConfigTest : public testing::Test {
public:
  RustlsConfigTest() = default;

protected:
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> factory_context_;
};

TEST_F(RustlsConfigTest, CreateEmptyConfigProto) {
  UpstreamRustlsSocketConfigFactory factory;
  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(nullptr, proto);
}

TEST_F(RustlsConfigTest, ConfigFactoryName) {
  UpstreamRustlsSocketConfigFactory factory;
  EXPECT_EQ("envoy.transport_sockets.rustls", factory.name());
  EXPECT_EQ("envoy.transport_sockets.upstream", factory.category());
}

TEST_F(RustlsConfigTest, DownstreamConfigFactoryName) {
  DownstreamRustlsSocketConfigFactory factory;
  EXPECT_EQ("envoy.transport_sockets.rustls", factory.name());
  EXPECT_EQ("envoy.transport_sockets.downstream", factory.category());
}

// Note: Full integration tests would require actual certificates and rustls setup.
// These are placeholder tests that verify the basic configuration infrastructure.

} // namespace
} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

