#pragma once

#include <memory>
#include <string>

#include "source/common/common/statusor.h"
#include "source/extensions/dynamic_modules/abi/abi.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {

using OnTransportSocketFactoryConfigNewType =
    decltype(&envoy_dynamic_module_on_transport_socket_factory_config_new);
using OnTransportSocketFactoryConfigDestroyType =
    decltype(&envoy_dynamic_module_on_transport_socket_factory_config_destroy);
using OnTransportSocketNewType = decltype(&envoy_dynamic_module_on_transport_socket_new);
using OnTransportSocketDestroyType = decltype(&envoy_dynamic_module_on_transport_socket_destroy);
using OnTransportSocketSetCallbacksType =
    decltype(&envoy_dynamic_module_on_transport_socket_set_callbacks);
using OnTransportSocketOnConnectedType =
    decltype(&envoy_dynamic_module_on_transport_socket_on_connected);
using OnTransportSocketDoReadType = decltype(&envoy_dynamic_module_on_transport_socket_do_read);
using OnTransportSocketDoWriteType = decltype(&envoy_dynamic_module_on_transport_socket_do_write);
using OnTransportSocketCloseType = decltype(&envoy_dynamic_module_on_transport_socket_close);
using OnTransportSocketGetProtocolType =
    decltype(&envoy_dynamic_module_on_transport_socket_get_protocol);
using OnTransportSocketGetFailureReasonType =
    decltype(&envoy_dynamic_module_on_transport_socket_get_failure_reason);
using OnTransportSocketCanFlushCloseType =
    decltype(&envoy_dynamic_module_on_transport_socket_can_flush_close);

/**
 * Holds the loaded dynamic module, resolved ABI entry points, and in-module factory configuration
 * for dynamic module transport sockets.
 */
class DynamicModuleTransportSocketFactoryConfig {
public:
  DynamicModuleTransportSocketFactoryConfig(
      bool is_upstream, std::string socket_name, std::string socket_config_bytes,
      ::Envoy::Extensions::DynamicModules::DynamicModulePtr dynamic_module);

  ~DynamicModuleTransportSocketFactoryConfig();

  envoy_dynamic_module_type_transport_socket_factory_config_module_ptr in_module_factory_config_{
      nullptr};

  OnTransportSocketFactoryConfigDestroyType on_factory_config_destroy_{nullptr};
  OnTransportSocketNewType on_socket_new_{nullptr};
  OnTransportSocketDestroyType on_socket_destroy_{nullptr};
  OnTransportSocketSetCallbacksType on_set_callbacks_{nullptr};
  OnTransportSocketOnConnectedType on_on_connected_{nullptr};
  OnTransportSocketDoReadType on_do_read_{nullptr};
  OnTransportSocketDoWriteType on_do_write_{nullptr};
  OnTransportSocketCloseType on_close_{nullptr};
  OnTransportSocketGetProtocolType on_get_protocol_{nullptr};
  OnTransportSocketGetFailureReasonType on_get_failure_reason_{nullptr};
  OnTransportSocketCanFlushCloseType on_can_flush_close_{nullptr};

  bool isUpstream() const { return is_upstream_; }
  const std::string& socketName() const { return socket_name_; }
  const std::string& socketConfigBytes() const { return socket_config_bytes_; }

private:
  const bool is_upstream_;
  const std::string socket_name_;
  const std::string socket_config_bytes_;
  ::Envoy::Extensions::DynamicModules::DynamicModulePtr dynamic_module_;
};

using DynamicModuleTransportSocketFactoryConfigSharedPtr =
    std::shared_ptr<DynamicModuleTransportSocketFactoryConfig>;

/**
 * Loads the module, resolves ABI symbols, and constructs the in-module factory configuration.
 */
absl::StatusOr<DynamicModuleTransportSocketFactoryConfigSharedPtr>
newDynamicModuleTransportSocketFactoryConfig(
    bool is_upstream, absl::string_view socket_name, absl::string_view socket_config_bytes,
    ::Envoy::Extensions::DynamicModules::DynamicModulePtr dynamic_module);

} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
