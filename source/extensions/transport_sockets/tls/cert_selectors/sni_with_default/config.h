#pragma once

#include "envoy/extensions/transport_sockets/tls/cert_selectors/sni_with_default/v3/config.pb.h"
#include "envoy/extensions/transport_sockets/tls/cert_selectors/sni_with_default/v3/config.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/handshaker.h"

#include "source/common/tls/server_context_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace SniWithDefault {

using ConfigProto =
    envoy::extensions::transport_sockets::tls::cert_selectors::sni_with_default::v3::Config;

/**
 * A certificate selector that extends the default SNI-based selection with a configurable
 * default certificate for when no SNI is provided by the client.
 */
class SniWithDefaultSelector : public Ssl::TlsCertificateSelector,
                               protected Logger::Loggable<Logger::Id::connection> {
public:
  SniWithDefaultSelector(const Ssl::ServerContextConfig& config,
                         Ssl::TlsCertificateSelectorContext& selector_ctx,
                         absl::optional<std::string> default_san);

  Ssl::SelectionResult selectTlsContext(const SSL_CLIENT_HELLO& ssl_client_hello,
                                        Ssl::CertificateSelectionCallbackPtr cb) override;

  std::pair<const Ssl::TlsContext&, Ssl::OcspStapleAction>
  findTlsContext(absl::string_view sni, const Ssl::CurveNIDVector& client_ecdsa_capabilities,
                 bool client_ocsp_capable, bool* cert_matched_sni) override;

private:
  // Maps pkey type to TlsContext for a given server name pattern.
  using PkeyTypesMap = absl::flat_hash_map<int, std::reference_wrapper<const Ssl::TlsContext>>;
  // Maps server names (including wildcard patterns) to their certificate contexts.
  using ServerNamesMap = absl::flat_hash_map<std::string, PkeyTypesMap>;

  void populateServerNamesMap(const Ssl::TlsContext& ctx, int pkey_id);

  // Finds the best certificate for a given server name considering client capabilities.
  const Ssl::TlsContext*
  findContextForServerName(absl::string_view server_name,
                           const Ssl::CurveNIDVector& client_ecdsa_capabilities,
                           bool client_ocsp_capable, Ssl::OcspStapleAction& ocsp_staple_action);

  ServerContextImpl& server_ctx_;
  const std::vector<Ssl::TlsContext>& tls_contexts_;
  ServerNamesMap server_names_map_;
  bool has_rsa_{false};
  const Ssl::ServerContextConfig::OcspStaplePolicy ocsp_staple_policy_;
  bool full_scan_certs_on_sni_mismatch_;

  // The SAN or CN of the default certificate to use when no SNI is provided.
  // If not set, the first certificate in the list is used.
  const absl::optional<std::string> default_san_;
  // Cached pointer to the default certificate context (resolved at construction time).
  const Ssl::TlsContext* default_ctx_{nullptr};
};

class SniWithDefaultSelectorFactory : public Ssl::TlsCertificateSelectorFactory {
public:
  SniWithDefaultSelectorFactory(const Ssl::ServerContextConfig& config,
                                absl::optional<std::string> default_san)
      : config_(config), default_san_(std::move(default_san)) {}

  Ssl::TlsCertificateSelectorPtr create(Ssl::TlsCertificateSelectorContext& selector_ctx) override {
    return std::make_unique<SniWithDefaultSelector>(config_, selector_ctx, default_san_);
  }

  absl::Status onConfigUpdate() override { return absl::OkStatus(); }

private:
  const Ssl::ServerContextConfig& config_;
  const absl::optional<std::string> default_san_;
};

class SniWithDefaultSelectorConfigFactory : public Ssl::TlsCertificateSelectorConfigFactory {
public:
  std::string name() const override { return "envoy.tls.certificate_selectors.sni_with_default"; }

  absl::StatusOr<Ssl::TlsCertificateSelectorFactoryPtr>
  createTlsCertificateSelectorFactory(const Protobuf::Message& config,
                                      Server::Configuration::GenericFactoryContext& factory_context,
                                      const Ssl::ServerContextConfig& tls_config,
                                      bool for_quic) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<ConfigProto>();
  }
};

DECLARE_FACTORY(SniWithDefaultSelectorConfigFactory);

} // namespace SniWithDefault
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
