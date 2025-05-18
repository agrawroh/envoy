#pragma once

#include "source/common/network/ktls/ktls_socket_handle_impl.h"
#include "source/common/network/socket_interface.h"
#include "source/common/protobuf/protobuf.h"

namespace Envoy {
namespace Network {

/**
 * Extension for the KTlsSocketInterface bootstrap extension.
 */
class KTlsSocketInterfaceExtension : public Network::SocketInterfaceExtension {
public:
  KTlsSocketInterfaceExtension(Network::SocketInterface& sock_interface)
      : Network::SocketInterfaceExtension(sock_interface) {}

  // Server::BootstrapExtension
  void onServerInitialized() override {}
  void onWorkerThreadInitialized() override {}
};

/**
 * Implementation of SocketInterface for kTLS.
 */
class KTlsSocketInterface : public SocketInterfaceBase {
public:
  // SocketInterface
  IoHandlePtr socket(Socket::Type socket_type, Address::Type addr_type, Address::IpVersion version,
                     bool socket_v6only, const SocketCreationOptions& options) const override;
  IoHandlePtr socket(Socket::Type socket_type, const Address::InstanceConstSharedPtr addr,
                     const SocketCreationOptions& options) const override;
  bool ipFamilySupported(int domain) override;

  // Server::Configuration::BootstrapExtensionFactory
  Server::BootstrapExtensionPtr
  createBootstrapExtension(const Protobuf::Message& config,
                           Server::Configuration::ServerFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override {
    return "envoy.extensions.network.socket_interface.ktls_socket_interface";
  };
};

DECLARE_FACTORY(KTlsSocketInterface);

} // namespace Network
} // namespace Envoy
