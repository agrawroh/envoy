#include "test/common/tls/integration/ssl_integration_test_base.h"
#include "test/integration/ssl_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace SniWithDefault {
namespace {

// Integration tests for the sni_with_default certificate selector.
//
// Test certificates used:
//   RSA cert (server_rsa_cert_=true): SAN "lyft.com"
//   ECDSA cert "server_ecdsa" (default): SAN "lyft.com" (SAME as RSA and cannot be differentiated
//   by SAN) ECDSA cert "server2_ecdsa": SAN "lyft2.com" (DIFFERENT from RSA and can be
//   differentiated)
//
// The tests verify:
// 1. SNI-based certificate selection works correctly.
// 2. When no SNI is provided, the configured default certificate is used.
// 3. When SNI doesn't match, the configured default certificate is used.
// 4. The correct certificate type (RSA vs ECDSA) is returned based on configuration.
//
// Note: To test ECDSA as a DIFFERENT default from RSA, we use server2_ecdsa which has SAN
// "lyft2.com" so we can explicitly select it over the RSA cert with SAN "lyft.com".
class SniWithDefaultCertSelectorIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public Ssl::SslIntegrationTestBase {
public:
  SniWithDefaultCertSelectorIntegrationTest() : SslIntegrationTestBase(GetParam()) {}

  void TearDown() override { SslIntegrationTestBase::TearDown(); }

  // Client that only supports RSA cipher suites.
  Ssl::ClientSslTransportOptions rsaOnlyClientOptions() {
    return Ssl::ClientSslTransportOptions().setCipherSuites({"ECDHE-RSA-AES128-GCM-SHA256"});
  }

  // Client that only supports ECDSA cipher suites.
  Ssl::ClientSslTransportOptions ecdsaOnlyClientOptions() {
    return Ssl::ClientSslTransportOptions().setCipherSuites({"ECDHE-ECDSA-AES128-GCM-SHA256"});
  }

  // Client that supports both RSA and ECDSA.
  Ssl::ClientSslTransportOptions rsaAndEcdsaClientOptions() {
    return Ssl::ClientSslTransportOptions().setCipherSuites(
        {"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"});
  }

  // Helper to generate selector config with default_san.
  std::string selectorConfigWithSan(const std::string& san) {
    return fmt::format(R"EOF(
      name: envoy.tls.certificate_selectors.sni_with_default
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.cert_selectors.sni_with_default.v3.Config
        default_san: "{}"
    )EOF",
                       san);
  }

  // Helper to generate selector config with use_first_certificate.
  std::string selectorConfigWithFirstCert() {
    return R"EOF(
      name: envoy.tls.certificate_selectors.sni_with_default
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.cert_selectors.sni_with_default.v3.Config
        use_first_certificate: true
    )EOF";
  }

  // Helper to verify connection failure and cleanup.
  void expectConnectionFailure(IntegrationCodecClientPtr& codec_client) {
    EXPECT_FALSE(codec_client->connected());
    // Must explicitly close the connection before the codec_client is destroyed.
    codec_client->connection()->close(Network::ConnectionCloseType::NoFlush);
    const std::string counter_name = listenerStatPrefix("ssl.connection_error");
    test_server_->waitForCounterGe(counter_name, 1);
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, SniWithDefaultCertSelectorIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// RSA only server, SNI matches the certificate.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_RsaOnly_SniMatches) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = false;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto options = rsaOnlyClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// RSA only server, no SNI uses configured default.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_RsaOnly_NoSniUsesDefault) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = false;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// RSA only server, SNI mismatch uses configured default.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_RsaOnly_SniMismatchUsesDefault) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = false;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto options = rsaOnlyClientOptions().setSni("unknown.example.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// ECDSA only server, SNI matches the certificate.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_EcdsaOnly_SniMatches) {
  server_rsa_cert_ = false;
  server_ecdsa_cert_ = true;
  // Default ECDSA cert has SAN "lyft.com".
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto options = ecdsaOnlyClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// ECDSA only server, no SNI uses configured default.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_EcdsaOnly_NoSniUsesDefault) {
  server_rsa_cert_ = false;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(ecdsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// ECDSA only server, RSA-only client should fail to connect.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_EcdsaOnly_RsaClientFails) {
  server_rsa_cert_ = false;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  // RSA-only client cannot use ECDSA certificate.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  expectConnectionFailure(codec_client);
}

// Mixed server with RSA default, no SNI with RSA-only client succeeds.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedRsaDefault_NoSniRsaClientSucceeds) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  // Both certs have "lyft.com", RSA is added first, so RSA becomes default.
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  // RSA-only client with no SNI. RSA default is picked.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with RSA default, no SNI with ECDSA-capable client still gets RSA.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedRsaDefault_NoSniEcdsaCapableClientGetsRsa) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  // ECDSA-capable client with no SNI. Our selector picks RSA as configured.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaAndEcdsaClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with RSA default, SNI matches the common SAN.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_MixedRsaDefault_SniMatchesCommonSan) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  // SNI matches both certs' SAN. With ECDSA-capable client, ECDSA should be preferred
  // because SNI-based selection still applies ECDSA preference.
  auto options = rsaAndEcdsaClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with RSA default, SNI mismatch uses RSA default.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedRsaDefault_SniMismatchUsesRsaDefault) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft.com");

  initialize();

  auto options = rsaOnlyClientOptions().setSni("unknown.example.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with ECDSA default (different SAN), no SNI with ECDSA-only client succeeds.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedEcdsaDefault_NoSniEcdsaClientSucceeds) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  // Use server2_ecdsa which has SAN "lyft2.com" to differentiate from RSA's "lyft.com".
  server_ecdsa_cert_name_ = "server2_ecdsa";
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft2.com");

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(ecdsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with ECDSA default (different SAN), no SNI with RSA-only client fails.
// This verifies that ECDSA default is correctly selected and RSA-only client can't use it.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedEcdsaDefault_NoSniRsaClientFails) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  server_ecdsa_cert_name_ = "server2_ecdsa";
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft2.com");

  initialize();

  // RSA-only client with no SNI. ECDSA default is selected but client can't use it.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  expectConnectionFailure(codec_client);
}

// Mixed server with ECDSA default, SNI matches RSA cert - RSA client connects.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, DefaultSan_MixedEcdsaDefault_SniMatchesRsaCert) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  server_ecdsa_cert_name_ = "server2_ecdsa";
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft2.com");

  initialize();

  // SNI matches RSA cert, RSA client should connect using RSA cert.
  auto options = rsaOnlyClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with ECDSA default, SNI mismatch with RSA-only client fails.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       DefaultSan_MixedEcdsaDefault_SniMismatchRsaClientFails) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  server_ecdsa_cert_name_ = "server2_ecdsa";
  tls_cert_selector_yaml_ = selectorConfigWithSan("lyft2.com");

  initialize();

  // SNI doesn't match, falls back to ECDSA default, RSA-only client fails.
  auto options = rsaOnlyClientOptions().setSni("unknown.example.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  expectConnectionFailure(codec_client);
}

// RSA only server with use_first_certificate, no SNI.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_RsaOnly_NoSni) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = false;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// RSA only server with use_first_certificate, SNI matches.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_RsaOnly_SniMatches) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = false;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  auto options = rsaOnlyClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// ECDSA only server with use_first_certificate, no SNI.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_EcdsaOnly_NoSni) {
  server_rsa_cert_ = false;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(ecdsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// ECDSA only server with use_first_certificate, RSA-only client fails.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_EcdsaOnly_RsaClientFails) {
  server_rsa_cert_ = false;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  expectConnectionFailure(codec_client);
}

// Mixed server with use_first_certificate, no SNI. RSA is first.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_Mixed_NoSniUsesFirst) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  // RSA is first, so RSA-only client should succeed.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaOnlyClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with use_first_certificate, ECDSA-capable client with no SNI.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_Mixed_NoSniEcdsaCapableClient) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  // First cert is RSA, so RSA is used even for ECDSA-capable client.
  auto codec_client =
      makeRawHttpConnection(makeSslClientConnection(rsaAndEcdsaClientOptions()), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with use_first_certificate, SNI matches ECDSA cert (using server2_ecdsa).
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_Mixed_SniMatchesEcdsa) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  // Use server2_ecdsa with distinct SAN "lyft2.com".
  server_ecdsa_cert_name_ = "server2_ecdsa";
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  // SNI matches ECDSA cert's SAN, so ECDSA is returned.
  auto options = ecdsaOnlyClientOptions().setSni("lyft2.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with use_first_certificate, SNI matches RSA cert.
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_Mixed_SniMatchesRsa) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  auto options = rsaOnlyClientOptions().setSni("lyft.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with use_first_certificate, SNI mismatch falls back to first (RSA).
TEST_P(SniWithDefaultCertSelectorIntegrationTest, UseFirstCert_Mixed_SniMismatchUsesFirst) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  // SNI doesn't match, falls back to first (RSA).
  auto options = rsaOnlyClientOptions().setSni("unknown.example.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  ASSERT_TRUE(codec_client->connected());
  codec_client->close();
}

// Mixed server with use_first_certificate, SNI mismatch with ECDSA-only client.
// Falls back to first (RSA), ECDSA-only client fails.
TEST_P(SniWithDefaultCertSelectorIntegrationTest,
       UseFirstCert_Mixed_SniMismatchEcdsaOnlyClientFails) {
  server_rsa_cert_ = true;
  server_ecdsa_cert_ = true;
  tls_cert_selector_yaml_ = selectorConfigWithFirstCert();

  initialize();

  // SNI doesn't match, falls back to RSA. ECDSA-only client can't use RSA cert.
  auto options = ecdsaOnlyClientOptions().setSni("unknown.example.com");
  auto codec_client = makeRawHttpConnection(makeSslClientConnection(options), absl::nullopt);
  expectConnectionFailure(codec_client);
}

} // namespace
} // namespace SniWithDefault
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
