#include "source/extensions/transport_sockets/ktls/ktls_socket_interface.h"

#include "envoy/extensions/network/socket_interface/v3/ktls_socket_interface.pb.h"
#include "envoy/extensions/network/socket_interface/v3/ktls_socket_interface.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/assert.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

// Add a reference to the default socket interface implementation
namespace {
const Network::SocketInterface& defaultSocketInterface() {
  // Get the default socket interface
  static const Network::SocketInterface* interface = Network::socketInterface(
      "envoy.extensions.network.socket_interface.default_socket_interface");
  RELEASE_ASSERT(interface != nullptr, "Default socket interface not found");
  return *interface;
}
} // namespace

Network::IoHandlePtr
KtlsSocketInterface::socket(Network::Socket::Type socket_type, Network::Address::Type addr_type,
                            Network::Address::IpVersion version, bool socket_v6only,
                            const Network::SocketCreationOptions& options) const {
  // First create a normal socket using the default implementation
  Network::IoHandlePtr io_handle =
      defaultSocketInterface().socket(socket_type, addr_type, version, socket_v6only, options);

  // Use zero-copy TX if enabled
  if (enable_tx_zerocopy_) {
    // Set any required socket options for zero-copy TX here in the future
  }

  // Then wrap it with our kTLS-enabled socket handle
  return std::make_unique<KtlsSocketHandleImpl>(std::move(io_handle));
}

Network::IoHandlePtr
KtlsSocketInterface::socket(Network::Socket::Type socket_type,
                            const Network::Address::InstanceConstSharedPtr addr,
                            const Network::SocketCreationOptions& options) const {
  // First create a normal socket using the default implementation
  Network::IoHandlePtr io_handle = defaultSocketInterface().socket(socket_type, addr, options);

  // Use zero-copy TX if enabled
  if (enable_tx_zerocopy_) {
    // Set any required socket options for zero-copy TX here in the future
  }

  // Use no-padding mode for RX if enabled
  if (enable_rx_no_pad_) {
    // Set any required socket options for no-padding RX here in the future
  }

  // Then wrap it with our kTLS-enabled socket handle
  return std::make_unique<KtlsSocketHandleImpl>(std::move(io_handle));
}

bool KtlsSocketInterface::ipFamilySupported(int domain) {
  // We depend on the default socket interface for support, so delegate to it
  const auto& interface = defaultSocketInterface();
  const_cast<Network::SocketInterface&>(interface).ipFamilySupported(domain);
  return true;
}

Network::SocketInterface* KtlsSocketInterface::getOrCreateSocketInterface(bool enable_tx_zerocopy,
                                                                          bool enable_rx_no_pad) {
  static Network::SocketInterfacePtr socket_interface =
      std::make_unique<KtlsSocketInterface>(enable_tx_zerocopy, enable_rx_no_pad);
  return socket_interface.get();
}

// BootstrapExtensionFactory implementation
Server::BootstrapExtensionPtr
KtlsSocketInterface::createBootstrapExtension(const Protobuf::Message& config,
                                              Server::Configuration::ServerFactoryContext&) {
  const auto& message = MessageUtil::downcastAndValidate<
      const envoy::extensions::network::socket_interface::v3::KTlsSocketInterface&>(
      config, ProtobufMessage::getStrictValidationVisitor());

  bool enabled = true; // Default to enabled
  // In proto3, there's no has_* methods, just check the default value
  if (!message.enabled()) {
    enabled = false;
  }

  if (enabled) {
    // Create and register the socket interface
    auto* interface = KtlsSocketInterface::getOrCreateSocketInterface(message.enable_tx_zerocopy(),
                                                                      message.enable_rx_no_pad());

    // Register it with Envoy's socket interface registry
    auto extension = std::make_unique<Network::SocketInterfaceExtension>(*interface);

    ENVOY_LOG_MISC(info, "Registered kTLS socket interface with tx_zerocopy={}, rx_no_pad={}",
                   message.enable_tx_zerocopy(), message.enable_rx_no_pad());

    return extension;
  }

  // If disabled, return a null extension
  return nullptr;
}

ProtobufTypes::MessagePtr KtlsSocketInterface::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::network::socket_interface::v3::KTlsSocketInterface>();
}

// Register the factory
REGISTER_FACTORY(KtlsSocketInterface, Server::Configuration::BootstrapExtensionFactory);

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
