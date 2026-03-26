#include "source/extensions/transport_sockets/dynamic_modules/config.h"

#include "envoy/common/exception.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {

DynamicModuleTransportSocketFactoryConfig::DynamicModuleTransportSocketFactoryConfig(
    const bool is_upstream, std::string socket_name, std::string socket_config_bytes,
    ::Envoy::Extensions::DynamicModules::DynamicModulePtr dynamic_module)
    : is_upstream_(is_upstream), socket_name_(std::move(socket_name)),
      socket_config_bytes_(std::move(socket_config_bytes)),
      dynamic_module_(std::move(dynamic_module)) {}

DynamicModuleTransportSocketFactoryConfig::~DynamicModuleTransportSocketFactoryConfig() {
  if (in_module_factory_config_ != nullptr && on_factory_config_destroy_ != nullptr) {
    on_factory_config_destroy_(in_module_factory_config_);
    in_module_factory_config_ = nullptr;
  }
}

absl::StatusOr<DynamicModuleTransportSocketFactoryConfigSharedPtr>
newDynamicModuleTransportSocketFactoryConfig(
    const bool is_upstream, const absl::string_view socket_name,
    const absl::string_view socket_config_bytes,
    ::Envoy::Extensions::DynamicModules::DynamicModulePtr dynamic_module) {

  auto on_factory_new = dynamic_module->getFunctionPointer<OnTransportSocketFactoryConfigNewType>(
      "envoy_dynamic_module_on_transport_socket_factory_config_new");
  RETURN_IF_NOT_OK_REF(on_factory_new.status());

  auto on_factory_destroy =
      dynamic_module->getFunctionPointer<OnTransportSocketFactoryConfigDestroyType>(
          "envoy_dynamic_module_on_transport_socket_factory_config_destroy");
  RETURN_IF_NOT_OK_REF(on_factory_destroy.status());

  auto on_new = dynamic_module->getFunctionPointer<OnTransportSocketNewType>(
      "envoy_dynamic_module_on_transport_socket_new");
  RETURN_IF_NOT_OK_REF(on_new.status());

  auto on_destroy = dynamic_module->getFunctionPointer<OnTransportSocketDestroyType>(
      "envoy_dynamic_module_on_transport_socket_destroy");
  RETURN_IF_NOT_OK_REF(on_destroy.status());

  auto on_set_callbacks = dynamic_module->getFunctionPointer<OnTransportSocketSetCallbacksType>(
      "envoy_dynamic_module_on_transport_socket_set_callbacks");
  RETURN_IF_NOT_OK_REF(on_set_callbacks.status());

  auto on_connected = dynamic_module->getFunctionPointer<OnTransportSocketOnConnectedType>(
      "envoy_dynamic_module_on_transport_socket_on_connected");
  RETURN_IF_NOT_OK_REF(on_connected.status());

  auto on_read = dynamic_module->getFunctionPointer<OnTransportSocketDoReadType>(
      "envoy_dynamic_module_on_transport_socket_do_read");
  RETURN_IF_NOT_OK_REF(on_read.status());

  auto on_write = dynamic_module->getFunctionPointer<OnTransportSocketDoWriteType>(
      "envoy_dynamic_module_on_transport_socket_do_write");
  RETURN_IF_NOT_OK_REF(on_write.status());

  auto on_close = dynamic_module->getFunctionPointer<OnTransportSocketCloseType>(
      "envoy_dynamic_module_on_transport_socket_close");
  RETURN_IF_NOT_OK_REF(on_close.status());

  auto on_protocol = dynamic_module->getFunctionPointer<OnTransportSocketGetProtocolType>(
      "envoy_dynamic_module_on_transport_socket_get_protocol");
  RETURN_IF_NOT_OK_REF(on_protocol.status());

  auto on_failure = dynamic_module->getFunctionPointer<OnTransportSocketGetFailureReasonType>(
      "envoy_dynamic_module_on_transport_socket_get_failure_reason");
  RETURN_IF_NOT_OK_REF(on_failure.status());

  auto on_can_flush = dynamic_module->getFunctionPointer<OnTransportSocketCanFlushCloseType>(
      "envoy_dynamic_module_on_transport_socket_can_flush_close");
  RETURN_IF_NOT_OK_REF(on_can_flush.status());

  auto config = std::make_shared<DynamicModuleTransportSocketFactoryConfig>(
      is_upstream, std::string(socket_name), std::string(socket_config_bytes),
      std::move(dynamic_module));

  config->on_factory_config_destroy_ = on_factory_destroy.value();
  config->on_socket_new_ = on_new.value();
  config->on_socket_destroy_ = on_destroy.value();
  config->on_set_callbacks_ = on_set_callbacks.value();
  config->on_on_connected_ = on_connected.value();
  config->on_do_read_ = on_read.value();
  config->on_do_write_ = on_write.value();
  config->on_close_ = on_close.value();
  config->on_get_protocol_ = on_protocol.value();
  config->on_get_failure_reason_ = on_failure.value();
  config->on_can_flush_close_ = on_can_flush.value();

  const envoy_dynamic_module_type_envoy_buffer name_buf = {config->socketName().data(),
                                                           config->socketName().size()};
  const envoy_dynamic_module_type_envoy_buffer cfg_buf = {config->socketConfigBytes().data(),
                                                          config->socketConfigBytes().size()};
  config->in_module_factory_config_ = on_factory_new.value()(
      static_cast<envoy_dynamic_module_type_transport_socket_factory_config_envoy_ptr>(
          config.get()),
      name_buf, cfg_buf, is_upstream);

  if (config->in_module_factory_config_ == nullptr) {
    return absl::InvalidArgumentError(
        "Failed to initialize dynamic module transport socket factory configuration.");
  }

  return config;
}

} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
