#include "source/extensions/transport_sockets/dynamic_modules/transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {

namespace {

Network::PostIoAction
toPostIoAction(const envoy_dynamic_module_type_transport_socket_post_io_action a) {
  return a == envoy_dynamic_module_type_transport_socket_post_io_action_Close
             ? Network::PostIoAction::Close
             : Network::PostIoAction::KeepOpen;
}

} // namespace

DynamicModuleTransportSocket::DynamicModuleTransportSocket(
    DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config, const bool /*is_upstream*/,
    Network::TransportSocketOptionsConstSharedPtr options)
    : factory_config_(std::move(factory_config)), transport_socket_options_(std::move(options)) {
  socket_module_ =
      factory_config_->on_socket_new_(factory_config_->in_module_factory_config_, thisAsEnvoyPtr());
  if (socket_module_ == nullptr) {
    ENVOY_LOG(error, "dynamic module transport socket: on_transport_socket_new returned nullptr.");
  }
}

DynamicModuleTransportSocket::~DynamicModuleTransportSocket() {
  if (socket_module_ != nullptr) {
    factory_config_->on_socket_destroy_(socket_module_);
    socket_module_ = nullptr;
  }
}

void DynamicModuleTransportSocket::setTransportSocketCallbacks(
    Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  if (socket_module_ != nullptr) {
    factory_config_->on_set_callbacks_(thisAsEnvoyPtr(), socket_module_);
  }
}

void DynamicModuleTransportSocket::refreshProtocolString() const {
  auto* mutable_this = const_cast<DynamicModuleTransportSocket*>(this);
  mutable_this->protocol_storage_.clear();
  if (socket_module_ == nullptr) {
    return;
  }
  envoy_dynamic_module_type_module_buffer out{nullptr, 0};
  factory_config_->on_get_protocol_(mutable_this->thisAsEnvoyPtr(), socket_module_, &out);
  if (out.ptr != nullptr && out.length > 0) {
    mutable_this->protocol_storage_.assign(out.ptr, out.length);
  }
}

void DynamicModuleTransportSocket::refreshFailureReasonString() const {
  auto* mutable_this = const_cast<DynamicModuleTransportSocket*>(this);
  mutable_this->failure_reason_storage_.clear();
  if (socket_module_ == nullptr) {
    return;
  }
  envoy_dynamic_module_type_module_buffer out{nullptr, 0};
  factory_config_->on_get_failure_reason_(mutable_this->thisAsEnvoyPtr(), socket_module_, &out);
  if (out.ptr != nullptr && out.length > 0) {
    mutable_this->failure_reason_storage_.assign(out.ptr, out.length);
  }
}

std::string DynamicModuleTransportSocket::protocol() const {
  refreshProtocolString();
  return protocol_storage_;
}

absl::string_view DynamicModuleTransportSocket::failureReason() const {
  refreshFailureReasonString();
  return failure_reason_storage_;
}

bool DynamicModuleTransportSocket::canFlushClose() {
  if (socket_module_ == nullptr) {
    return true;
  }
  return factory_config_->on_can_flush_close_(thisAsEnvoyPtr(), socket_module_);
}

void DynamicModuleTransportSocket::closeSocket(const Network::ConnectionEvent event) {
  if (socket_module_ == nullptr) {
    return;
  }
  const auto abi_event = static_cast<envoy_dynamic_module_type_network_connection_event>(event);
  factory_config_->on_close_(thisAsEnvoyPtr(), socket_module_, abi_event);
}

void DynamicModuleTransportSocket::onConnected() {
  if (socket_module_ == nullptr) {
    return;
  }
  factory_config_->on_on_connected_(thisAsEnvoyPtr(), socket_module_);
}

Network::IoResult DynamicModuleTransportSocket::doRead(Buffer::Instance& buffer) {
  if (socket_module_ == nullptr) {
    return {Network::PostIoAction::Close, 0, false, absl::nullopt};
  }
  active_read_buffer_ = &buffer;
  const envoy_dynamic_module_type_transport_socket_io_result abi_result =
      factory_config_->on_do_read_(thisAsEnvoyPtr(), socket_module_);
  active_read_buffer_ = nullptr;
  return {toPostIoAction(abi_result.action), abi_result.bytes_processed, abi_result.end_stream_read,
          absl::nullopt};
}

Network::IoResult DynamicModuleTransportSocket::doWrite(Buffer::Instance& buffer,
                                                        const bool end_stream) {
  if (socket_module_ == nullptr) {
    return {Network::PostIoAction::Close, 0, false, absl::nullopt};
  }
  active_write_buffer_ = &buffer;
  const envoy_dynamic_module_type_transport_socket_io_result abi_result =
      factory_config_->on_do_write_(thisAsEnvoyPtr(), socket_module_, buffer.length(), end_stream);
  active_write_buffer_ = nullptr;
  return {toPostIoAction(abi_result.action), abi_result.bytes_processed, false, absl::nullopt};
}

DynamicModuleUpstreamTransportSocketFactory::DynamicModuleUpstreamTransportSocketFactory(
    DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config, std::string default_sni,
    std::vector<std::string> alpn_protocols, const bool implements_secure_transport)
    : factory_config_(std::move(factory_config)), default_sni_(std::move(default_sni)),
      alpn_protocols_(std::move(alpn_protocols)),
      implements_secure_transport_(implements_secure_transport) {}

Network::TransportSocketPtr DynamicModuleUpstreamTransportSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr options,
    Upstream::HostDescriptionConstSharedPtr /*host*/) const {
  return std::make_unique<DynamicModuleTransportSocket>(factory_config_, true, std::move(options));
}

void DynamicModuleUpstreamTransportSocketFactory::hashKey(
    std::vector<uint8_t>& key, Network::TransportSocketOptionsConstSharedPtr options) const {
  const absl::string_view name = factory_config_->socketName();
  key.insert(key.end(), name.begin(), name.end());
  const absl::string_view cfg = factory_config_->socketConfigBytes();
  key.insert(key.end(), cfg.begin(), cfg.end());
  key.push_back('\0');
  key.insert(key.end(), default_sni_.begin(), default_sni_.end());
  for (const auto& alpn : alpn_protocols_) {
    key.push_back('\0');
    key.insert(key.end(), alpn.begin(), alpn.end());
  }
  Network::CommonUpstreamTransportSocketFactory::hashKey(key, options);
}

DynamicModuleDownstreamTransportSocketFactory::DynamicModuleDownstreamTransportSocketFactory(
    DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config,
    const bool implements_secure_transport)
    : factory_config_(std::move(factory_config)),
      implements_secure_transport_(implements_secure_transport) {}

Network::TransportSocketPtr
DynamicModuleDownstreamTransportSocketFactory::createDownstreamTransportSocket() const {
  return std::make_unique<DynamicModuleTransportSocket>(factory_config_, false);
}

} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
