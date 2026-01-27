#include "source/extensions/transport_sockets/tls/cert_selectors/sni_with_default/config.h"

#include "source/common/tls/default_tls_certificate_selector.h"
#include "source/common/tls/utility.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace CertificateSelectors {
namespace SniWithDefault {

namespace {

// Returns the SANs and CN from a certificate for matching purposes.
std::vector<std::string> getCertificateIdentifiers(const Ssl::TlsContext& ctx) {
  std::vector<std::string> identifiers;
  if (ctx.cert_chain_ == nullptr) {
    return identifiers;
  }

  // First try DNS SANs.
  auto dns_sans = Utility::getSubjectAltNames(*ctx.cert_chain_, GEN_DNS);
  for (const auto& san : dns_sans) {
    identifiers.push_back(san);
  }

  // If no SANs, try Common Name.
  if (identifiers.empty()) {
    X509_NAME* cert_subject = X509_get_subject_name(ctx.cert_chain_.get());
    const int cn_index = X509_NAME_get_index_by_NID(cert_subject, NID_commonName, -1);
    if (cn_index >= 0) {
      X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(cert_subject, cn_index);
      if (cn_entry) {
        ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
        if (ASN1_STRING_length(cn_asn1) > 0) {
          std::string subject_cn(reinterpret_cast<const char*>(ASN1_STRING_data(cn_asn1)),
                                 ASN1_STRING_length(cn_asn1));
          identifiers.push_back(subject_cn);
        }
      }
    }
  }

  return identifiers;
}

// Checks if a given SAN pattern matches any of the certificate identifiers.
// Supports wildcard matching for patterns like *.example.com.
bool matchesSan(const std::string& pattern, const std::vector<std::string>& identifiers) {
  for (const auto& id : identifiers) {
    // Exact match.
    if (pattern == id) {
      return true;
    }
    // Wildcard match: pattern is *.example.com, id is foo.example.com.
    if (absl::StartsWith(id, "*.")) {
      if (Utility::dnsNameMatch(pattern, id)) {
        return true;
      }
    }
    // Pattern is wildcard, id is exact.
    if (absl::StartsWith(pattern, "*.")) {
      if (Utility::dnsNameMatch(id, pattern)) {
        return true;
      }
    }
  }
  return false;
}

} // namespace

SniWithDefaultSelector::SniWithDefaultSelector(const Ssl::ServerContextConfig& config,
                                               Ssl::TlsCertificateSelectorContext& selector_ctx,
                                               absl::optional<std::string> default_san)
    : server_ctx_(dynamic_cast<ServerContextImpl&>(selector_ctx)),
      tls_contexts_(selector_ctx.getTlsContexts()), ocsp_staple_policy_(config.ocspStaplePolicy()),
      full_scan_certs_on_sni_mismatch_(config.fullScanCertsOnSNIMismatch()),
      default_san_(std::move(default_san)) {

  // Build the server names map.
  for (const auto& ctx : tls_contexts_) {
    if (ctx.cert_chain_ == nullptr) {
      continue;
    }
    bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(ctx.cert_chain_.get()));
    const int pkey_id = EVP_PKEY_id(public_key.get());
    has_rsa_ |= (pkey_id == EVP_PKEY_RSA);
    populateServerNamesMap(ctx, pkey_id);
  }

  // Resolve the default certificate based on configuration.
  if (default_san_.has_value()) {
    // Find certificate matching the configured SAN.
    for (const auto& ctx : tls_contexts_) {
      if (ctx.cert_chain_ == nullptr) {
        continue;
      }
      auto identifiers = getCertificateIdentifiers(ctx);
      if (matchesSan(default_san_.value(), identifiers)) {
        default_ctx_ = &ctx;
        ENVOY_LOG(debug, "Found default certificate matching SAN '{}'.", default_san_.value());
        break;
      }
    }
    // If no matching certificate found, log a warning and use first certificate as fallback.
    if (default_ctx_ == nullptr && !tls_contexts_.empty()) {
      ENVOY_LOG(warn,
                "No certificate found matching default_san '{}'. Will use first certificate as "
                "fallback when no SNI is provided.",
                default_san_.value());
      default_ctx_ = &tls_contexts_[0];
    }
  } else {
    // Use first certificate mode.
    if (!tls_contexts_.empty()) {
      default_ctx_ = &tls_contexts_[0];
      ENVOY_LOG(debug, "Using first certificate as default (use_first_certificate mode).");
    }
  }
}

void SniWithDefaultSelector::populateServerNamesMap(const Ssl::TlsContext& ctx, int pkey_id) {
  if (ctx.cert_chain_ == nullptr) {
    return;
  }

  auto populate = [&](const std::string& sn) {
    std::string sn_pattern = sn;
    if (absl::StartsWith(sn, "*.")) {
      sn_pattern = sn.substr(1);
    }
    PkeyTypesMap pkey_types_map;
    auto sn_match = server_names_map_.try_emplace(sn_pattern, pkey_types_map).first;
    auto pt_match = sn_match->second.find(pkey_id);
    if (pt_match != sn_match->second.end()) {
      // Prefer earlier certificates when there are duplicates.
      return;
    }
    sn_match->second.emplace(
        std::pair<int, std::reference_wrapper<const Ssl::TlsContext>>(pkey_id, ctx));
  };

  bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(ctx.cert_chain_.get(), NID_subject_alt_name, nullptr, nullptr)));
  if (san_names != nullptr) {
    auto dns_sans = Utility::getSubjectAltNames(*ctx.cert_chain_, GEN_DNS);
    for (const auto& san : dns_sans) {
      populate(san);
    }
  } else {
    X509_NAME* cert_subject = X509_get_subject_name(ctx.cert_chain_.get());
    const int cn_index = X509_NAME_get_index_by_NID(cert_subject, NID_commonName, -1);
    if (cn_index >= 0) {
      X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(cert_subject, cn_index);
      if (cn_entry) {
        ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
        if (ASN1_STRING_length(cn_asn1) > 0) {
          std::string subject_cn(reinterpret_cast<const char*>(ASN1_STRING_data(cn_asn1)),
                                 ASN1_STRING_length(cn_asn1));
          populate(subject_cn);
        }
      }
    }
  }
}

const Ssl::TlsContext* SniWithDefaultSelector::findContextForServerName(
    absl::string_view server_name, const Ssl::CurveNIDVector& client_ecdsa_capabilities,
    bool client_ocsp_capable, Ssl::OcspStapleAction& ocsp_staple_action) {
  auto it = server_names_map_.find(server_name);
  if (it == server_names_map_.end()) {
    return nullptr;
  }

  const bool client_ecdsa_capable = !client_ecdsa_capabilities.empty();
  const Ssl::TlsContext* selected_ctx = nullptr;
  const Ssl::TlsContext* candidate_ctx = nullptr;

  for (const auto& entry : it->second) {
    const Ssl::TlsContext& ctx = entry.second.get();
    auto action = ocspStapleAction(ctx, client_ocsp_capable, ocsp_staple_policy_);
    if (action == Ssl::OcspStapleAction::Fail) {
      continue;
    }

    // If client is ECDSA-capable and context is ECDSA with matching curve.
    if (std::find(client_ecdsa_capabilities.begin(), client_ecdsa_capabilities.end(),
                  ctx.ec_group_curve_name_) != client_ecdsa_capabilities.end()) {
      selected_ctx = &ctx;
      ocsp_staple_action = action;
      return selected_ctx;
    }

    // If client is not ECDSA-capable and context is non-ECDSA (RSA).
    if (!client_ecdsa_capable && ctx.ec_group_curve_name_ == Ssl::EC_CURVE_INVALID_NID) {
      selected_ctx = &ctx;
      ocsp_staple_action = action;
      return selected_ctx;
    }

    // RSA cert as candidate when client is ECDSA capable.
    if (client_ecdsa_capable && ctx.ec_group_curve_name_ == Ssl::EC_CURVE_INVALID_NID &&
        candidate_ctx == nullptr) {
      candidate_ctx = &ctx;
      ocsp_staple_action = action;
    }
  }

  return candidate_ctx;
}

Ssl::SelectionResult
SniWithDefaultSelector::selectTlsContext(const SSL_CLIENT_HELLO& ssl_client_hello,
                                         Ssl::CertificateSelectionCallbackPtr) {
  absl::string_view sni =
      absl::NullSafeStringView(SSL_get_servername(ssl_client_hello.ssl, TLSEXT_NAMETYPE_host_name));
  const Ssl::CurveNIDVector client_ecdsa_capabilities =
      server_ctx_.getClientEcdsaCapabilities(ssl_client_hello);
  const bool client_ocsp_capable = isClientOcspCapable(ssl_client_hello);

  auto [selected_ctx, ocsp_staple_action] =
      findTlsContext(sni, client_ecdsa_capabilities, client_ocsp_capable, nullptr);

  auto stats = server_ctx_.stats();
  if (client_ocsp_capable) {
    stats.ocsp_staple_requests_.inc();
  }

  switch (ocsp_staple_action) {
  case Ssl::OcspStapleAction::Staple:
    stats.ocsp_staple_responses_.inc();
    break;
  case Ssl::OcspStapleAction::NoStaple:
    stats.ocsp_staple_omitted_.inc();
    break;
  case Ssl::OcspStapleAction::Fail:
    stats.ocsp_staple_failed_.inc();
    return {Ssl::SelectionResult::SelectionStatus::Failed, nullptr, false};
  case Ssl::OcspStapleAction::ClientNotCapable:
    break;
  }

  return {Ssl::SelectionResult::SelectionStatus::Success, &selected_ctx,
          ocsp_staple_action == Ssl::OcspStapleAction::Staple};
}

std::pair<const Ssl::TlsContext&, Ssl::OcspStapleAction>
SniWithDefaultSelector::findTlsContext(absl::string_view sni,
                                       const Ssl::CurveNIDVector& client_ecdsa_capabilities,
                                       bool client_ocsp_capable, bool* cert_matched_sni) {
  bool unused = false;
  if (cert_matched_sni == nullptr) {
    cert_matched_sni = &unused;
  }

  const Ssl::TlsContext* selected_ctx = nullptr;
  const Ssl::TlsContext* candidate_ctx = nullptr;
  Ssl::OcspStapleAction ocsp_staple_action = Ssl::OcspStapleAction::ClientNotCapable;
  const bool client_ecdsa_capable = !client_ecdsa_capabilities.empty();

  // Key difference from the default selector is that when no SNI is provided, we use the configured
  // default certificate directly instead of doing a full scan that would prefer ECDSA.
  if (sni.empty()) {
    if (default_san_.has_value()) {
      ENVOY_LOG(debug, "No SNI provided, using configured default certificate with SAN '{}'.",
                default_san_.value());
    } else {
      ENVOY_LOG(debug, "No SNI provided, using first certificate as default.");
    }
    selected_ctx = default_ctx_;
    ASSERT(selected_ctx != nullptr);
    ocsp_staple_action = ocspStapleAction(*selected_ctx, client_ocsp_capable, ocsp_staple_policy_);
    return {*selected_ctx, ocsp_staple_action};
  }

  // SNI is provided, try to find a matching certificate.
  // Match on exact server name.
  selected_ctx = findContextForServerName(sni, client_ecdsa_capabilities, client_ocsp_capable,
                                          ocsp_staple_action);

  // Match on wildcard domain if exact match not found.
  if (selected_ctx == nullptr) {
    size_t pos = sni.find('.', 1);
    if (pos < sni.size() - 1 && pos != std::string::npos) {
      absl::string_view wildcard = sni.substr(pos);
      selected_ctx = findContextForServerName(wildcard, client_ecdsa_capabilities,
                                              client_ocsp_capable, ocsp_staple_action);
    }
  }

  *cert_matched_sni = (selected_ctx != nullptr);

  // If a match was found, return it.
  if (selected_ctx != nullptr) {
    return {*selected_ctx, ocsp_staple_action};
  }

  // SNI was provided but no match found.
  if (!full_scan_certs_on_sni_mismatch_) {
    // Use the configured default certificate as fallback.
    ENVOY_LOG(debug, "No certificate matched SNI '{}', using configured default.", sni);
    selected_ctx = default_ctx_;
    ASSERT(selected_ctx != nullptr);
    ocsp_staple_action = ocspStapleAction(*selected_ctx, client_ocsp_capable, ocsp_staple_policy_);
    return {*selected_ctx, ocsp_staple_action};
  }

  // Full scan is enabled for SNI mismatch. Scan all certs which is same as the default selector.
  if (client_ecdsa_capable || has_rsa_) {
    for (const auto& ctx : tls_contexts_) {
      auto action = ocspStapleAction(ctx, client_ocsp_capable, ocsp_staple_policy_);
      if (action == Ssl::OcspStapleAction::Fail) {
        continue;
      }

      // ECDSA match for ECDSA-capable client.
      if (std::find(client_ecdsa_capabilities.begin(), client_ecdsa_capabilities.end(),
                    ctx.ec_group_curve_name_) != client_ecdsa_capabilities.end()) {
        selected_ctx = &ctx;
        ocsp_staple_action = action;
        break;
      }

      // RSA match for non-ECDSA client.
      if (!client_ecdsa_capable && ctx.ec_group_curve_name_ == Ssl::EC_CURVE_INVALID_NID) {
        selected_ctx = &ctx;
        ocsp_staple_action = action;
        break;
      }

      // RSA candidate when client is ECDSA capable.
      if (client_ecdsa_capable && ctx.ec_group_curve_name_ == Ssl::EC_CURVE_INVALID_NID &&
          candidate_ctx == nullptr) {
        candidate_ctx = &ctx;
        ocsp_staple_action = action;
      }
    }
  }

  // Use candidate if no perfect match found.
  if (selected_ctx == nullptr) {
    selected_ctx = candidate_ctx;
  }

  // Final fallback to the configured default.
  if (selected_ctx == nullptr) {
    selected_ctx = default_ctx_;
    ocsp_staple_action = ocspStapleAction(*selected_ctx, client_ocsp_capable, ocsp_staple_policy_);
  }

  ASSERT(selected_ctx != nullptr);
  return {*selected_ctx, ocsp_staple_action};
}

absl::StatusOr<Ssl::TlsCertificateSelectorFactoryPtr>
SniWithDefaultSelectorConfigFactory::createTlsCertificateSelectorFactory(
    const Protobuf::Message& config, Server::Configuration::GenericFactoryContext& factory_context,
    const Ssl::ServerContextConfig& tls_config, bool /*for_quic*/) {
  const ConfigProto& typed_config = MessageUtil::downcastAndValidate<const ConfigProto&>(
      config, factory_context.messageValidationVisitor());

  absl::optional<std::string> default_san;
  if (typed_config.has_default_san()) {
    default_san = typed_config.default_san();
  }
  // If use_first_certificate is set, default_san remains nullopt.

  return std::make_unique<SniWithDefaultSelectorFactory>(tls_config, std::move(default_san));
}

REGISTER_FACTORY(SniWithDefaultSelectorConfigFactory, Ssl::TlsCertificateSelectorConfigFactory);

} // namespace SniWithDefault
} // namespace CertificateSelectors
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
