#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.h"

#include "source/common/tls/context_manager_impl.h"

#include "test/integration/integration.h"
#include "test/integration/ssl_utility.h"
#include "test/integration/utility.h"
#include "test/test_common/environment.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {
namespace {

class RustlsIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                              public BaseIntegrationTest {
public:
  RustlsIntegrationTest() : BaseIntegrationTest(GetParam(), ConfigHelper::tcpProxyConfig()) {
    skip_tag_extraction_rule_check_ = true;
  }

  void initializeWithDownstreamRustls() {
    const std::string cert_path =
        TestEnvironment::runfilesPath("test/config/integration/certs/servercert.pem");
    const std::string key_path =
        TestEnvironment::runfilesPath("test/config/integration/certs/serverkey.pem");

    config_helper_.addConfigModifier([cert_path, key_path](
                                         envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(0);
      auto* filter_chain = listener->mutable_filter_chains(0);

      envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext rustls_config;
      rustls_config.set_cert_chain(cert_path);
      rustls_config.set_private_key(key_path);

      auto* ts = filter_chain->mutable_transport_socket();
      ts->set_name("envoy.transport_sockets.rustls");
      ts->mutable_typed_config()->PackFrom(rustls_config);
    });

    BaseIntegrationTest::initialize();

    context_manager_ =
        std::make_unique<Envoy::Extensions::TransportSockets::Tls::ContextManagerImpl>(
            server_factory_context_);
    client_ssl_ctx_ = Ssl::createClientSslTransportSocketFactory({}, *context_manager_, *api_);
  }

  std::unique_ptr<Envoy::Extensions::TransportSockets::Tls::ContextManagerImpl> context_manager_;
  Network::UpstreamTransportSocketFactoryPtr client_ssl_ctx_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, RustlsIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Verifies that a downstream `rustls` TLS transport socket can accept a TLS connection, complete
// the handshake, and forward data bidirectionally through the TCP proxy to a plaintext upstream.
TEST_P(RustlsIntegrationTest, TlsDownstreamToPlaintextUpstream) {
  initializeWithDownstreamRustls();

  ConnectionStatusCallbacks connect_callbacks;
  auto payload_reader = std::make_shared<WaitForPayloadReader>(*dispatcher_);

  Network::Address::InstanceConstSharedPtr address =
      Ssl::getSslAddress(version_, lookupPort("listener_0"));
  auto ssl_client = dispatcher_->createClientConnection(
      address, Network::Address::InstanceConstSharedPtr(),
      client_ssl_ctx_->createTransportSocket(nullptr, nullptr), nullptr, nullptr);
  ssl_client->addConnectionCallbacks(connect_callbacks);
  ssl_client->addReadFilter(payload_reader);
  ssl_client->connect();

  while (!connect_callbacks.connected() && !connect_callbacks.closed()) {
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  }
  ASSERT_TRUE(connect_callbacks.connected());

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  Buffer::OwnedImpl request("hello");
  ssl_client->write(request, false);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->write("world"));
  payload_reader->setDataToWaitFor("world");
  ssl_client->dispatcher().run(Event::Dispatcher::RunType::Block);
  EXPECT_EQ(payload_reader->data(), "world");

  ssl_client->close(Network::ConnectionCloseType::NoFlush);
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

// End-to-end exercise of the rustls upstream transport socket driven through Envoy's data plane. A
// TCP-proxy listener forwards to a cluster whose upstream transport socket is `rustls`. Envoy's
// upstream rustls socket builds a real rustls `ClientConnection` and writes the ClientHello,
// observable as the upstream receiving the TLS handshake record carrying the configured SNI. A full
// handshake is not completed against the plaintext fake upstream, but the handshake being attempted
// is what this verifies. The per-connection SNI override (Route B) that this PR adds is covered at
// the factory and module layers by rustls_impl_test and the rustls_ktls unit tests; tcp_proxy does
// not set a per-connection `serverNameOverride`, so this test exercises the default-SNI path of the
// same end-to-end socket.
class RustlsUpstreamIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                      public BaseIntegrationTest {
public:
  RustlsUpstreamIntegrationTest()
      : BaseIntegrationTest(GetParam(), ConfigHelper::tcpProxyConfig()) {
    skip_tag_extraction_rule_check_ = true;
  }

  void initializeWithUpstreamRustls() {
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* cluster = bootstrap.mutable_static_resources()->mutable_clusters(0);
      envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext rustls_config;
      rustls_config.set_sni("default.example.com");
      auto* ts = cluster->mutable_transport_socket();
      ts->set_name("envoy.transport_sockets.rustls");
      ts->mutable_typed_config()->PackFrom(rustls_config);
    });
    BaseIntegrationTest::initialize();
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, RustlsUpstreamIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(RustlsUpstreamIntegrationTest, UpstreamRustlsAttemptsHandshake) {
  initializeWithUpstreamRustls();

  // A downstream client connects in plaintext; Envoy forwards to the upstream cluster over the
  // rustls transport socket. Envoy's upstream connection runs on Envoy's own dispatcher, so the
  // rustls socket reliably completes its TCP connect and writes the ClientHello.
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("listener_0"));
  // Send a byte downstream so tcp_proxy drives an upstream write, which pumps the rustls handshake.
  ASSERT_TRUE(tcp_client->write("hello", false));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // The upstream rustls socket writes the ClientHello rather than being rejected by the screen.
  // Wait until the SNI from the configured config appears in the handshake bytes, which both
  // confirms a ClientHello was sent and that it carries the expected server name. If the rustls
  // factory had screened the connection, a NotReadyRustlsSocket would have closed before writing
  // any byte.
  std::string client_hello;
  ASSERT_TRUE(fake_upstream_connection->waitForData(
      FakeRawConnection::waitForInexactMatch("default.example.com"), &client_hello));
  // A TLS handshake record starts with the content type byte 0x16.
  EXPECT_EQ(static_cast<uint8_t>(client_hello[0]), 0x16);

  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

} // namespace
} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
