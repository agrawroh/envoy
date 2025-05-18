#pragma once

#include "envoy/extensions/network/socket_interface/v3/ktls_socket_interface.pb.h"
#include "envoy/network/socket_interface.h"
#include "envoy/registry/registry.h"
#include "envoy/server/bootstrap_extension_config.h"

#include "source/common/network/socket_interface.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/transport_sockets/ktls/ktls_socket_handle_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Implementation of Network::SocketInterface that creates KtlsSocketHandleImpl
 * for sockets that need kTLS.
 */
class KtlsSocketInterface : public Network::SocketInterfaceBase {
public:
  KtlsSocketInterface(bool enable_tx_zerocopy, bool enable_rx_no_pad)
      : enable_tx_zerocopy_(enable_tx_zerocopy), enable_rx_no_pad_(enable_rx_no_pad) {}

  // Default constructor required for REGISTER_FACTORY
  KtlsSocketInterface() : enable_tx_zerocopy_(false), enable_rx_no_pad_(false) {}

  // SocketInterface implementation
  Network::IoHandlePtr socket(Network::Socket::Type socket_type, Network::Address::Type addr_type,
                              Network::Address::IpVersion version, bool socket_v6only,
                              const Network::SocketCreationOptions& options) const override;

  Network::IoHandlePtr socket(Network::Socket::Type socket_type,
                              const Network::Address::InstanceConstSharedPtr addr,
                              const Network::SocketCreationOptions& options) const override;

  bool ipFamilySupported(int domain) override;

  // Register for ktls socket interface extension.
  static Network::SocketInterface* getOrCreateSocketInterface(bool enable_tx_zerocopy = false,
                                                              bool enable_rx_no_pad = false);

  // BootstrapExtensionFactory implementation
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.extensions.network.socket_interface.ktls_socket_interface";
  }

private:
  bool enable_tx_zerocopy_{false};
  bool enable_rx_no_pad_{false};
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
