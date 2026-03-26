#include "source/extensions/transport_sockets/dynamic_modules/factory.h"

#include "envoy/common/exception.h"
#include "envoy/extensions/transport_sockets/dynamic_modules/v3/dynamic_modules.pb.h"
#include "envoy/extensions/transport_sockets/dynamic_modules/v3/dynamic_modules.pb.validate.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"
#include "source/extensions/transport_sockets/dynamic_modules/config.h"
#include "source/extensions/transport_sockets/dynamic_modules/transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {

namespace {

absl::StatusOr<::Envoy::Extensions::DynamicModules::DynamicModulePtr> loadDynamicModule(
    const envoy::extensions::dynamic_modules::v3::DynamicModuleConfig& module_config) {
  if (module_config.has_module()) {
    if (!module_config.module().has_local() || !module_config.module().local().has_filename()) {
      return absl::InvalidArgumentError(
          "Only a local module filename is supported for dynamic module transport sockets.");
    }
    return ::Envoy::Extensions::DynamicModules::newDynamicModule(
        module_config.module().local().filename(), module_config.do_not_close(),
        module_config.load_globally());
  }
  if (module_config.name().empty()) {
    return absl::InvalidArgumentError(
        "Either 'name' or 'module.local.filename' must be set in dynamic_module_config.");
  }
  return ::Envoy::Extensions::DynamicModules::newDynamicModuleByName(
      module_config.name(), module_config.do_not_close(), module_config.load_globally());
}

} // namespace

ProtobufTypes::MessagePtr UpstreamDynamicModuleTransportSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::dynamic_modules::v3::
                              DynamicModuleUpstreamTransportSocket>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
UpstreamDynamicModuleTransportSocketFactory::createTransportSocketFactory(
    const Protobuf::Message& config,
    Server::Configuration::TransportSocketFactoryContext& context) {

  const auto& proto =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::dynamic_modules::
                                           v3::DynamicModuleUpstreamTransportSocket&>(
          config, context.messageValidationVisitor());

  std::string socket_config_bytes;
  if (proto.has_socket_config()) {
    auto bytes_or = MessageUtil::anyToBytes(proto.socket_config());
    RETURN_IF_NOT_OK_REF(bytes_or.status());
    socket_config_bytes = std::move(bytes_or.value());
  }

  auto module_or_error = loadDynamicModule(proto.dynamic_module_config());
  if (!module_or_error.ok()) {
    return module_or_error.status();
  }

  auto factory_config_or_error = newDynamicModuleTransportSocketFactoryConfig(
      true, proto.socket_name(), socket_config_bytes, std::move(module_or_error.value()));
  if (!factory_config_or_error.ok()) {
    return factory_config_or_error.status();
  }

  std::vector<std::string> alpn;
  alpn.reserve(static_cast<size_t>(proto.alpn_protocols_size()));
  for (const auto& p : proto.alpn_protocols()) {
    alpn.push_back(p);
  }

  return std::make_unique<DynamicModuleUpstreamTransportSocketFactory>(
      std::move(factory_config_or_error.value()), proto.sni(), std::move(alpn),
      proto.implements_secure_transport());
}

ProtobufTypes::MessagePtr DownstreamDynamicModuleTransportSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::dynamic_modules::v3::
                              DynamicModuleDownstreamTransportSocket>();
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
DownstreamDynamicModuleTransportSocketFactory::createTransportSocketFactory(
    const Protobuf::Message& config, Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {

  (void)server_names;

  const auto& proto =
      MessageUtil::downcastAndValidate<const envoy::extensions::transport_sockets::dynamic_modules::
                                           v3::DynamicModuleDownstreamTransportSocket&>(
          config, context.messageValidationVisitor());

  std::string socket_config_bytes;
  if (proto.has_socket_config()) {
    auto bytes_or = MessageUtil::anyToBytes(proto.socket_config());
    RETURN_IF_NOT_OK_REF(bytes_or.status());
    socket_config_bytes = std::move(bytes_or.value());
  }

  auto module_or_error = loadDynamicModule(proto.dynamic_module_config());
  if (!module_or_error.ok()) {
    return module_or_error.status();
  }

  auto factory_config_or_error = newDynamicModuleTransportSocketFactoryConfig(
      false, proto.socket_name(), socket_config_bytes, std::move(module_or_error.value()));
  if (!factory_config_or_error.ok()) {
    return factory_config_or_error.status();
  }

  return std::make_unique<DynamicModuleDownstreamTransportSocketFactory>(
      std::move(factory_config_or_error.value()), proto.implements_secure_transport());
}

LEGACY_REGISTER_FACTORY(UpstreamDynamicModuleTransportSocketFactory,
                        Server::Configuration::UpstreamTransportSocketConfigFactory,
                        "dynamic_modules");

LEGACY_REGISTER_FACTORY(DownstreamDynamicModuleTransportSocketFactory,
                        Server::Configuration::DownstreamTransportSocketConfigFactory,
                        "dynamic_modules");

} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
