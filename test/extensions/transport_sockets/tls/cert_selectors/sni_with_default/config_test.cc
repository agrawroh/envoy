#include "envoy/extensions/transport_sockets/tls/cert_selectors/sni_with_default/v3/config.pb.h"

#include "source/common/config/utility.h"
#include "source/extensions/transport_sockets/tls/cert_selectors/sni_with_default/config.h"

#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/ssl/mocks.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace SniWithDefault {
namespace {

using ::testing::NiceMock;

class MockTlsCertificateSelectorContext : public Ssl::TlsCertificateSelectorContext {
public:
  ~MockTlsCertificateSelectorContext() override = default;
  MOCK_METHOD(const std::vector<Ssl::TlsContext>&, getTlsContexts, (), (const));
};

class SniWithDefaultTest : public ::testing::Test {
protected:
  using ConfigProto =
      envoy::extensions::transport_sockets::tls::cert_selectors::sni_with_default::v3::Config;

  absl::StatusOr<Ssl::TlsCertificateSelectorFactoryPtr> create(const std::string& config_yaml,
                                                               bool for_quic = false) {
    ConfigProto config;
    TestUtility::loadFromYaml(config_yaml, config);
    return createFromProto(config, for_quic);
  }

  absl::StatusOr<Ssl::TlsCertificateSelectorFactoryPtr> createFromProto(const ConfigProto& config,
                                                                        bool for_quic = false) {
    Ssl::TlsCertificateSelectorConfigFactory& provider_factory =
        Config::Utility::getAndCheckFactoryByName<Ssl::TlsCertificateSelectorConfigFactory>(
            "envoy.tls.certificate_selectors.sni_with_default");
    return provider_factory.createTlsCertificateSelectorFactory(config, factory_context_,
                                                                server_context_, for_quic);
  }

  NiceMock<Server::Configuration::MockGenericFactoryContext> factory_context_;
  NiceMock<Ssl::MockServerContextConfig> server_context_;
  NiceMock<MockTlsCertificateSelectorContext> selector_context_;
};

// =============================================================================
// Factory creation tests for default_san configuration
// =============================================================================

TEST_F(SniWithDefaultTest, FactoryCreationWithDefaultSan) {
  const std::string config_yaml = R"EOF(
    default_san: "example.com"
  )EOF";
  EXPECT_OK(create(config_yaml));
}

TEST_F(SniWithDefaultTest, FactoryCreationWithWildcardDefaultSan) {
  const std::string config_yaml = R"EOF(
    default_san: "*.example.com"
  )EOF";
  EXPECT_OK(create(config_yaml));
}

TEST_F(SniWithDefaultTest, FactoryCreationWithSubdomainDefaultSan) {
  const std::string config_yaml = R"EOF(
    default_san: "api.prod.example.com"
  )EOF";
  EXPECT_OK(create(config_yaml));
}

// =============================================================================
// Factory creation tests for use_first_certificate configuration
// =============================================================================

TEST_F(SniWithDefaultTest, FactoryCreationWithUseFirstCertificate) {
  const std::string config_yaml = R"EOF(
    use_first_certificate: true
  )EOF";
  EXPECT_OK(create(config_yaml));
}

// =============================================================================
// QUIC support tests
// =============================================================================

TEST_F(SniWithDefaultTest, QuicSupportsDefaultSan) {
  const std::string config_yaml = R"EOF(
    default_san: "example.com"
  )EOF";
  EXPECT_OK(create(config_yaml, true));
}

TEST_F(SniWithDefaultTest, QuicSupportsUseFirstCertificate) {
  const std::string config_yaml = R"EOF(
    use_first_certificate: true
  )EOF";
  EXPECT_OK(create(config_yaml, true));
}

TEST_F(SniWithDefaultTest, QuicSupportsWildcardDefaultSan) {
  const std::string config_yaml = R"EOF(
    default_san: "*.example.com"
  )EOF";
  EXPECT_OK(create(config_yaml, true));
}

// =============================================================================
// Validation failure tests
// =============================================================================

TEST_F(SniWithDefaultTest, EmptyDefaultSanFails) {
  // Empty default_san should fail validation due to min_len: 1 constraint.
  const std::string config_yaml = R"EOF(
    default_san: ""
  )EOF";
  EXPECT_THROW_WITH_REGEX(auto result = create(config_yaml), EnvoyException,
                          "value length must be at least");
}

TEST_F(SniWithDefaultTest, UseFirstCertificateFalseNotAllowed) {
  // use_first_certificate must be true if specified.
  const std::string config_yaml = R"EOF(
    use_first_certificate: false
  )EOF";
  EXPECT_THROW_WITH_REGEX(auto result = create(config_yaml), EnvoyException, "value must equal");
}

TEST_F(SniWithDefaultTest, MissingOneofFails) {
  // Neither default_san nor use_first_certificate is set.
  ConfigProto config;
  EXPECT_THROW_WITH_REGEX(auto result = createFromProto(config), EnvoyException, "is required");
}

// =============================================================================
// Factory name and type URL tests
// =============================================================================

TEST_F(SniWithDefaultTest, CorrectFactoryName) {
  Ssl::TlsCertificateSelectorConfigFactory& factory =
      Config::Utility::getAndCheckFactoryByName<Ssl::TlsCertificateSelectorConfigFactory>(
          "envoy.tls.certificate_selectors.sni_with_default");
  EXPECT_EQ("envoy.tls.certificate_selectors.sni_with_default", factory.name());
}

TEST_F(SniWithDefaultTest, CreateEmptyConfigProto) {
  Ssl::TlsCertificateSelectorConfigFactory& factory =
      Config::Utility::getAndCheckFactoryByName<Ssl::TlsCertificateSelectorConfigFactory>(
          "envoy.tls.certificate_selectors.sni_with_default");
  auto proto = factory.createEmptyConfigProto();
  EXPECT_NE(nullptr, proto);
}

} // namespace
} // namespace SniWithDefault
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
