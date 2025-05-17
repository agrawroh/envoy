#include "source/extensions/transport_sockets/ktls/ktls_socket_interface.h"

#include "envoy/registry/registry.h"
#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

Network::IoHandlePtr KtlsSocketInterface::socket(Network::Socket::Type socket_type,
                                              Network::Address::Type addr_type,
                                              Network::Socket::OptionsSharedPtr options,
                                              const Network::SocketCreationOptions& creation_options) {
  // First create a normal socket using the base implementation
  Network::IoHandlePtr io_handle = Network::SocketInterfaceImpl::socket(
      socket_type, addr_type, options, creation_options);
  
  // Then wrap it with our kTLS-enabled socket handle
  return std::make_unique<KtlsSocketHandleImpl>(std::move(io_handle));
}

Network::SocketInterface* KtlsSocketInterface::getOrCreateSocketInterface() {
  static Network::SocketInterfacePtr socket_interface = std::make_unique<KtlsSocketInterface>();
  return socket_interface.get();
}

REGISTER_FACTORY(KtlsSocketInterfaceFactory, Network::SocketInterfaceFactory);

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 