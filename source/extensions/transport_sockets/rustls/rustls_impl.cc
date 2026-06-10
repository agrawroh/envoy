#include "source/extensions/transport_sockets/rustls/rustls_impl.h"

#include <string>
#include <vector>

#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.h"
#include "envoy/extensions/transport_sockets/rustls/v3/rustls.pb.validate.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"
#include "source/extensions/transport_sockets/dynamic_modules/transport_socket.h"

#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Rustls {

namespace {

// The static module name for the `rustls` `kTLS` Rust module.
constexpr absl::string_view RustlsModuleName = "rustls_ktls_static";

// Loads the statically linked rustls module and builds a shared dynamic-module transport socket
// config from the validated proto serialized to JSON, also returning the JSON so the factory can
// fold it into its connection-pool hash key. The rustls socket always terminates TLS, so it always
// implements secure transport.
absl::StatusOr<DynamicModuleTransportSocketConfigSharedPtr>
createRustlsConfig(bool is_upstream, const Protobuf::Message& validated_proto,
                   std::string& config_json_out) {
  if (auto status = Protobuf::util::MessageToJsonString(validated_proto, &config_json_out);
      !status.ok()) {
    return absl::InternalError(
        absl::StrCat("rustls: MessageToJsonString failed: ", status.message()));
  }
  // The rustls module is statically linked and registered at process init. A failure here is a
  // build/linkage error, but propagate via Status (not RELEASE_ASSERT) so a future packaging bug
  // doesn't crash the proxy on first config push.
  auto module_or = Envoy::Extensions::DynamicModules::newDynamicModuleByName(
      RustlsModuleName, /*do_not_close=*/true);
  if (!module_or.ok()) {
    return absl::InternalError(
        absl::StrCat("rustls: failed to load static module: ", module_or.status().message()));
  }
  return DynamicModules::newDynamicModuleTransportSocketConfig(
      std::string(RustlsModuleName), config_json_out, is_upstream,
      /*implements_secure_transport=*/true, std::move(*module_or));
}

} // namespace

// -- RustlsUpstreamTransportSocketFactory -------------------------------------

RustlsUpstreamTransportSocketFactory::RustlsUpstreamTransportSocketFactory(
    DynamicModuleTransportSocketConfigSharedPtr config, std::string default_sni,
    std::vector<std::string> alpn_protocols, std::string socket_config_bytes)
    : config_(std::move(config)), default_sni_(std::move(default_sni)),
      alpn_protocols_(std::move(alpn_protocols)),
      socket_config_bytes_(std::move(socket_config_bytes)) {}

Network::TransportSocketPtr RustlsUpstreamTransportSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    Upstream::HostDescriptionConstSharedPtr) const {
  // The rustls socket builds one rustls `ClientConfig` per factory and clones it into every
  // connection. Per-connection TransportSocketOptions overrides for SNI, ALPN, and SAN match list
  // cannot be honored yet. Return a `NotReadyRustlsSocket` stub when any override is set; the
  // connection layer surfaces this as `upstream_cx_connect_fail` with the failure reason in
  // `failureReason()`. (Returning a real nullptr is NOT safe here. `ConnectionImpl` dereferences
  // `transport_socket_` without a null-check at construction time.)
  if (options != nullptr) {
    const bool has_sni_override =
        options->serverNameOverride().has_value() && !options->serverNameOverride()->empty();
    const bool has_alpn_override = !options->applicationProtocolListOverride().empty();
    const bool has_san_override = !options->verifySubjectAltNameListOverride().empty();
    // `applicationProtocolFallback` is set by the HTTP/2 connection pool (e.g. `{"h2",
    // "http/1.1"}`) when the static ALPN list is empty. Without honoring it, a cluster that
    // expects ALPN-driven protocol selection would silently negotiate an ALPN-empty handshake and
    // downgrade, surfaced as a stealth protocol mismatch. Refuse the connection so the operator
    // gets a clear `upstream_cx_connect_fail` instead.
    const bool has_alpn_fallback_unbacked =
        !options->applicationProtocolFallback().empty() && alpn_protocols_.empty();
    if (has_sni_override || has_alpn_override || has_san_override || has_alpn_fallback_unbacked) {
      ENVOY_LOG_PERIODIC_MISC(
          warn, std::chrono::seconds(30),
          "rustls upstream transport socket received per-connection options (sni_override={}, "
          "alpn_override={}, san_override={}, alpn_fallback_unbacked={}); these are not yet "
          "supported and the connection will fail. Use envoy.transport_sockets.tls if you need "
          "auto_sni / match_typed_subject_alt_names / ALPN override / ALPN fallback.",
          has_sni_override, has_alpn_override, has_san_override, has_alpn_fallback_unbacked);
      return std::make_unique<NotReadyRustlsSocket>(
          "rustls: per-connection SNI/ALPN/SAN overrides (and ALPN fallback without a static "
          "alpn_protocols list) are not supported by this extension");
    }
  }
  return std::make_unique<DynamicModules::DynamicModuleTransportSocket>(config_);
}

void RustlsUpstreamTransportSocketFactory::hashKey(
    std::vector<uint8_t>& key, Network::TransportSocketOptionsConstSharedPtr options) const {
  // Mix the factory-static bits: the static module name + a NUL separator + the serialized proto
  // config + a NUL separator + default SNI + the ALPN list. The NUL between name and config
  // prevents prefix-attack collisions on configs whose concatenated bytes happen to overlap. The
  // base class call below handles per-connection options (SNI/SAN/ALPN overrides, ALPN fallback,
  // shared filter-state objects); duplicating those bits here would create encoding mismatches with
  // the base class and silently re-partition the connection pool.
  const absl::string_view name = RustlsModuleName;
  key.insert(key.end(), name.begin(), name.end());
  key.push_back('\0');
  key.insert(key.end(), socket_config_bytes_.begin(), socket_config_bytes_.end());
  key.push_back('\0');
  key.insert(key.end(), default_sni_.begin(), default_sni_.end());
  for (const auto& alpn : alpn_protocols_) {
    key.push_back('\0');
    key.insert(key.end(), alpn.begin(), alpn.end());
  }
  Network::CommonUpstreamTransportSocketFactory::hashKey(key, options);
}

// -- RustlsDownstreamTransportSocketFactory -----------------------------------

Network::TransportSocketPtr
RustlsDownstreamTransportSocketFactory::createDownstreamTransportSocket() const {
  return std::make_unique<DynamicModules::DynamicModuleTransportSocket>(config_);
}

// -- Config factories ---------------------------------------------------------

ProtobufTypes::MessagePtr RustlsUpstreamTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
RustlsUpstreamTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& config,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& proto = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::rustls::v3::RustlsUpstreamTlsContext&>(
      config, context.messageValidationVisitor());

  std::string config_json;
  auto config_or = createRustlsConfig(/*is_upstream=*/true, proto, config_json);
  RETURN_IF_NOT_OK_REF(config_or.status());

  return std::make_unique<RustlsUpstreamTransportSocketFactory>(
      std::move(*config_or), proto.sni(),
      std::vector<std::string>(proto.alpn_protocols().begin(), proto.alpn_protocols().end()),
      std::move(config_json));
}

ProtobufTypes::MessagePtr RustlsDownstreamTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext>();
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
RustlsDownstreamTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& config, Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& /*server_names*/) {
  const auto& proto = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::rustls::v3::RustlsDownstreamTlsContext&>(
      config, context.messageValidationVisitor());

  std::string config_json;
  auto config_or = createRustlsConfig(/*is_upstream=*/false, proto, config_json);
  RETURN_IF_NOT_OK_REF(config_or.status());

  return std::make_unique<RustlsDownstreamTransportSocketFactory>(std::move(*config_or));
}

REGISTER_FACTORY(RustlsUpstreamTransportSocketConfigFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);

REGISTER_FACTORY(RustlsDownstreamTransportSocketConfigFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);

} // namespace Rustls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
