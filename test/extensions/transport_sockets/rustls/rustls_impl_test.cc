#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/extensions/transport_sockets/rustls/rustls_impl.h"

#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {
namespace {

// ===========================================================================
// Factory registration and config tests, exercised against the real Rust module.
// ===========================================================================

class RustlsImplTest : public testing::Test {
public:
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> context_;
};

TEST_F(RustlsImplTest, UpstreamFactoryRegistration) {
  RustlsUpstreamTransportSocketConfigFactory factory;
  EXPECT_EQ(factory.name(), "envoy.transport_sockets.rustls");
  EXPECT_NE(factory.createEmptyConfigProto(), nullptr);
}

TEST_F(RustlsImplTest, DownstreamFactoryRegistration) {
  RustlsDownstreamTransportSocketConfigFactory factory;
  EXPECT_EQ(factory.name(), "envoy.transport_sockets.rustls");
  EXPECT_NE(factory.createEmptyConfigProto(), nullptr);
}

TEST_F(RustlsImplTest, UpstreamDefaultConfig) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  // The rustls module requires a non-empty SNI for upstream configs, so a minimal upstream config
  // is one that carries only the SNI.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamMissingSniFailsInModule) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  // The rustls module rejects an upstream config with no SNI, so the factory cannot be built.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, UpstreamWithSni) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.add_alpn_protocols("h2");
  config.add_alpn_protocols("http/1.1");

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamWithClientCert) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamWithCustomTrustedCa) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  const std::string ca_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_trusted_ca(ca_path);
  config.set_sni("example.com");

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamWithValidCerts) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamMissingCertsFailsInModule) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, DownstreamWithAlpn) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);
  config.add_alpn_protocols("h2");

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamWithTrustedCa) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");
  const std::string ca_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);
  config.set_trusted_ca(ca_path);

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamWithCrl) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem"));
  config.set_private_key(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem"));
  config.set_trusted_ca(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));
  config.set_crl(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.crl"));

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamRejectsCrlWithoutTrustedCa) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem"));
  config.set_private_key(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem"));
  // A CRL with no trusted_ca is meaningless and is rejected at config-load time.
  config.set_crl(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.crl"));

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, DownstreamRejectsCrlWithNoCrlBlocks) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem"));
  config.set_private_key(
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem"));
  config.set_trusted_ca(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));
  // The crl points at a cert file with no X509 CRL block, which is rejected fail-loud.
  config.set_crl(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, UpstreamWithTlsVersionBounds) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_tls_minimum_protocol_version(
      envoy::extensions::transport_sockets::rustls::v3::TLSv1_3);
  config.set_tls_maximum_protocol_version(
      envoy::extensions::transport_sockets::rustls::v3::TLSv1_3);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamRejectsInvertedTlsVersionRange) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_tls_minimum_protocol_version(
      envoy::extensions::transport_sockets::rustls::v3::TLSv1_3);
  config.set_tls_maximum_protocol_version(
      envoy::extensions::transport_sockets::rustls::v3::TLSv1_2);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, UpstreamWithServerCrl) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_trusted_ca(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));
  config.set_crl(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.crl"));

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamRejectsServerCrlWithNoCrlBlocks) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_trusted_ca(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));
  // The crl points at a cert file with no X509 CRL block, which is rejected fail-loud.
  config.set_crl(TestEnvironment::runfilesPath("test/common/tls/test_data/ca_cert.pem"));

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, DownstreamWithKtlsEnabled) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);
  config.set_enable_ktls(true);

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, DownstreamKtlsTxOnlyFailsInModule) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  // TX-only kTLS (`disable_ktls_rx` with `enable_ktls`) is rejected by the module, which cannot
  // route RX through userspace TLS while TX is offloaded to the kernel.
  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);
  config.set_enable_ktls(true);
  config.set_disable_ktls_rx(true);

  auto result = factory.createTransportSocketFactory(config, context_, {});
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, UpstreamWithKtlsEnabled) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_enable_ktls(true);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamKtlsTxOnlyFailsInModule) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  // TX-only kTLS is rejected by the module on the upstream path as well.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_enable_ktls(true);
  config.set_disable_ktls_rx(true);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_FALSE(result.ok());
}

TEST_F(RustlsImplTest, DisableKtlsRxWithoutEnableKtlsIsNoOp) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  // Without `enable_ktls`, `disable_ktls_rx` is a no-op and the config is accepted.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.set_disable_ktls_rx(true);

  auto result = factory.createTransportSocketFactory(config, context_);
  EXPECT_TRUE(result.ok()) << result.status().message();
}

TEST_F(RustlsImplTest, UpstreamFactoryCreatesWorkingTransportSocket) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.add_alpn_protocols("h2");

  auto result = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(result.ok()) << result.status().message();

  auto& upstream_factory = *result.value();
  EXPECT_TRUE(upstream_factory.implementsSecureTransport());

  auto socket = upstream_factory.createTransportSocket(nullptr, nullptr);
  ASSERT_NE(socket, nullptr);
  EXPECT_EQ(socket->ssl(), nullptr);
  EXPECT_FALSE(socket->startSecureTransport());
}

TEST_F(RustlsImplTest, UpstreamFactorySupportsAlpn) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.add_alpn_protocols("h2");

  auto result = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(result.ok());

  auto* upstream = dynamic_cast<RustlsUpstreamTransportSocketFactory*>(result.value().get());
  ASSERT_NE(upstream, nullptr);
  EXPECT_TRUE(upstream->supportsAlpn());
  EXPECT_EQ(upstream->defaultServerNameIndication(), "example.com");
}

TEST_F(RustlsImplTest, UpstreamFactoryNoAlpn) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  // SNI is required by the module, but no ALPN protocols are configured.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");

  auto result = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(result.ok());

  auto* upstream = dynamic_cast<RustlsUpstreamTransportSocketFactory*>(result.value().get());
  ASSERT_NE(upstream, nullptr);
  EXPECT_FALSE(upstream->supportsAlpn());
  EXPECT_EQ(upstream->defaultServerNameIndication(), "example.com");
}

TEST_F(RustlsImplTest, UpstreamFactoryHashKey) {
  RustlsUpstreamTransportSocketConfigFactory factory;

  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("example.com");
  config.add_alpn_protocols("h2");

  auto result = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(result.ok()) << result.status().message();

  std::vector<uint8_t> key;
  result.value()->hashKey(key, nullptr);
  EXPECT_FALSE(key.empty());

  // Determinism. A second factory built from the same config must hash identically, otherwise the
  // connection pool would needlessly fragment across equivalent rustls configurations.
  auto same_result = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(same_result.ok()) << same_result.status().message();
  std::vector<uint8_t> same_key;
  same_result.value()->hashKey(same_key, nullptr);
  EXPECT_EQ(key, same_key);

  // Distinctness. A different config (different SNI, which feeds both the serialized config bytes
  // and the default SNI mixed into the key) must hash differently so the pool does not collide two
  // distinct rustls configurations onto one upstream connection.
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext other_config;
  other_config.set_sni("other.example.com");
  other_config.add_alpn_protocols("h2");
  auto other_result = factory.createTransportSocketFactory(other_config, context_);
  ASSERT_TRUE(other_result.ok()) << other_result.status().message();
  std::vector<uint8_t> other_key;
  other_result.value()->hashKey(other_key, nullptr);
  EXPECT_NE(key, other_key);
}

TEST_F(RustlsImplTest, DownstreamFactoryCreatesWorkingTransportSocket) {
  RustlsDownstreamTransportSocketConfigFactory factory;

  const std::string cert_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_cert.pem");
  const std::string key_path =
      TestEnvironment::runfilesPath("test/common/tls/test_data/selfsigned_key.pem");

  envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext config;
  config.set_cert_chain(cert_path);
  config.set_private_key(key_path);

  auto result = factory.createTransportSocketFactory(config, context_, {});
  ASSERT_TRUE(result.ok()) << result.status().message();
  EXPECT_TRUE(result.value()->implementsSecureTransport());

  auto socket = result.value()->createDownstreamTransportSocket();
  ASSERT_NE(socket, nullptr);
  EXPECT_EQ(socket->ssl(), nullptr);
}

// ===========================================================================
// NotReadyRustlsSocket and the per-connection-option fail-loud guard.
// ===========================================================================

TEST(NotReadyRustlsSocketTest, DoReadAndDoWriteReturnClose) {
  NotReadyRustlsSocket socket("rustls: test reason");
  Buffer::OwnedImpl buffer;
  auto read_result = socket.doRead(buffer);
  EXPECT_EQ(read_result.action_, Network::PostIoAction::Close);
  EXPECT_EQ(read_result.bytes_processed_, 0);
  auto write_result = socket.doWrite(buffer, false);
  EXPECT_EQ(write_result.action_, Network::PostIoAction::Close);
  EXPECT_EQ(write_result.bytes_processed_, 0);
  EXPECT_EQ(socket.failureReason(), "rustls: test reason");
  EXPECT_TRUE(socket.canFlushClose());
}

TEST_F(RustlsImplTest, UpstreamCreateTransportSocketReturnsNotReadyOnSniOverride) {
  RustlsUpstreamTransportSocketConfigFactory factory;
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("static.example.com");
  auto factory_or = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(factory_or.ok()) << factory_or.status().message();

  // Build TransportSocketOptions that set a per-connection SNI override. The upstream factory
  // rejects it until per-connection options are plumbed through the dynamic-modules SDK.
  auto options = std::make_shared<Network::TransportSocketOptionsImpl>(
      /*override_server_name=*/"override.example.com",
      /*override_verify_san_list=*/std::vector<std::string>{},
      /*override_alpn=*/std::vector<std::string>{},
      /*fallback_alpn=*/std::vector<std::string>{});

  auto socket = factory_or.value()->createTransportSocket(options, nullptr);
  // createTransportSocket must NEVER return nullptr. It returns a NotReady stub instead because
  // ConnectionImpl dereferences the returned pointer without a null-check.
  ASSERT_NE(socket, nullptr);
  // The socket reports a clear failure reason and closes on any I/O.
  EXPECT_THAT(std::string(socket->failureReason()), testing::HasSubstr("not supported"));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(socket->doRead(buf).action_, Network::PostIoAction::Close);
  EXPECT_EQ(socket->doWrite(buf, false).action_, Network::PostIoAction::Close);
}

TEST_F(RustlsImplTest, UpstreamCreateTransportSocketReturnsNotReadyOnAlpnOverride) {
  RustlsUpstreamTransportSocketConfigFactory factory;
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("static.example.com");
  config.add_alpn_protocols("h2");
  auto factory_or = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(factory_or.ok()) << factory_or.status().message();

  // A per-connection ALPN override is likewise rejected with a NotReady stub.
  auto options = std::make_shared<Network::TransportSocketOptionsImpl>(
      /*override_server_name=*/"",
      /*override_verify_san_list=*/std::vector<std::string>{},
      /*override_alpn=*/std::vector<std::string>{"http/1.1"},
      /*fallback_alpn=*/std::vector<std::string>{});

  auto socket = factory_or.value()->createTransportSocket(options, nullptr);
  ASSERT_NE(socket, nullptr);
  EXPECT_THAT(std::string(socket->failureReason()), testing::HasSubstr("not supported"));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(socket->doRead(buf).action_, Network::PostIoAction::Close);
}

TEST_F(RustlsImplTest, UpstreamCreateTransportSocketReturnsNotReadyOnSanOverride) {
  RustlsUpstreamTransportSocketConfigFactory factory;
  envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext config;
  config.set_sni("static.example.com");
  auto factory_or = factory.createTransportSocketFactory(config, context_);
  ASSERT_TRUE(factory_or.ok()) << factory_or.status().message();

  // A per-connection SAN match-list override is rejected with a NotReady stub. The rustls module
  // cannot honor match_typed_subject_alt_names per connection yet, so it must fail loud rather than
  // silently skip the SAN check.
  auto options = std::make_shared<Network::TransportSocketOptionsImpl>(
      /*override_server_name=*/"",
      /*override_verify_san_list=*/std::vector<std::string>{"spiffe://example/sa"},
      /*override_alpn=*/std::vector<std::string>{},
      /*fallback_alpn=*/std::vector<std::string>{});

  auto socket = factory_or.value()->createTransportSocket(options, nullptr);
  ASSERT_NE(socket, nullptr);
  EXPECT_THAT(std::string(socket->failureReason()), testing::HasSubstr("not supported"));
  Buffer::OwnedImpl buf;
  EXPECT_EQ(socket->doRead(buf).action_, Network::PostIoAction::Close);
}

} // namespace
} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
