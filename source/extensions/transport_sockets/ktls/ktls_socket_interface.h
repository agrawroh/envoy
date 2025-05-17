#pragma once

#include "envoy/registry/registry.h"
#include "source/common/network/socket_interface_impl.h"
#include "source/extensions/transport_sockets/ktls/ktls_socket_handle_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Implementation of Network::SocketInterface that creates KtlsSocketHandleImpl
 * for sockets that need kTLS.
 */
class KtlsSocketInterface : public Network::SocketInterfaceImpl {
public:
  Network::IoHandlePtr socket(Network::Socket::Type socket_type, 
                             Network::Address::Type addr_type,
                             Network::Socket::OptionsSharedPtr options,
                             const Network::SocketCreationOptions& creation_options) override;

  // Register for "ktls" extension.
  static Network::SocketInterface* getOrCreateSocketInterface();
  static constexpr absl::string_view name() { return "ktls"; }
};

// Factory registration for the ktls socket interface implementation.
DECLARE_FACTORY(KtlsSocketInterfaceFactory);

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 