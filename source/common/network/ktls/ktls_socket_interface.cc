#include "source/common/network/ktls/ktls_socket_interface.h"

#include "envoy/registry/registry.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/assert.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"

namespace Envoy {
namespace Network {

IoHandlePtr KTlsSocketInterface::socket(Socket::Type socket_type, Address::Type addr_type,
                                        Address::IpVersion version, bool socket_v6only,
                                        const SocketCreationOptions& options) const {
  // Create the socket
  Api::OsSysCalls& os_sys_calls = Api::OsSysCallsSingleton::get();
  const int domain = Address::ipVersionToDomain(version);
  const int type = socketTypeToSysSocketType(socket_type);

  const Api::SysCallSocketResult result = os_sys_calls.socket(domain, type, 0);
  if (SOCKET_INVALID(result.return_value_)) {
    throw EnvoyException(fmt::format("socket failed: {}", strerror(result.errno_)));
  }

  // Create the kTLS socket handle
  IoHandlePtr io_handle = std::make_unique<KTlsSocketHandleImpl>(result.return_value_, socket_v6only);
  if (socket_v6only && addr_type == Address::Type::Ip && version == Address::IpVersion::v6) {
    // Set the socket as IPv6 only.
    const int v6only = 1;
    const Api::SysCallIntResult result = io_handle->setOption(IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    if (result.return_value_ != 0) {
      throw EnvoyException(fmt::format("setting v6only option failed: {}", strerror(result.errno_)));
    }
  }

  // Set socket options
  if (options.socket_options_ != nullptr) {
    for (const auto& option : *options.socket_options_) {
      if (!option->setOption(*io_handle, envoy::config::core::v3::SocketOption::STATE_PREBIND)) {
        io_handle->close();
        throw EnvoyException(
            fmt::format("socket option failed for {} during prebind: {}", option->toString(),
                        io_handle->lastErrorDetails()));
      }
    }
  }

  return io_handle;
}

IoHandlePtr KTlsSocketInterface::socket(Socket::Type socket_type, const Address::InstanceConstSharedPtr addr,
                                        const SocketCreationOptions& options) const {
  Address::IpVersion ip_version = addr->ip() ? addr->ip()->version() : Address::IpVersion::v4;
  int v6only = 0;
  if (addr->type() == Address::Type::Ip && ip_version == Address::IpVersion::v6) {
    v6only = addr->ip()->ipv6()->v6only();
  }

  IoHandlePtr io_handle =
      KTlsSocketInterface::socket(socket_type, addr->type(), ip_version, v6only, options);
  if (io_handle && addr->type() == Address::Type::Ip && ip_version == Address::IpVersion::v6 &&
      !Address::forceV6()) {
    // Setting IPV6_V6ONLY restricts the IPv6 socket to IPv6 connections only.
    const int v6only = addr->ip()->ipv6()->v6only();
    const Api::SysCallIntResult result = io_handle->setOption(
        IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    ENVOY_BUG(!SOCKET_FAILURE(result.return_value_),
              fmt::format("Unable to set socket v6-only: got error: {}", result.return_value_));
  }
  return io_handle;
}

bool KTlsSocketInterface::ipFamilySupported(int domain) {
  Api::OsSysCalls& os_sys_calls = Api::OsSysCallsSingleton::get();
  const Api::SysCallSocketResult result = os_sys_calls.socket(domain, SOCK_STREAM, 0);
  if (SOCKET_VALID(result.return_value_)) {
    RELEASE_ASSERT(
        os_sys_calls.close(result.return_value_).return_value_ == 0,
        fmt::format("Fail to close fd: response code {}", errorDetails(result.return_value_)));
  }
  return SOCKET_VALID(result.return_value_);
}

Server::BootstrapExtensionPtr KTlsSocketInterface::createBootstrapExtension(
    const Protobuf::Message& config,
    Server::Configuration::ServerFactoryContext& context) {
  // We don't need to parse options from the proto for now
  UNREFERENCED_PARAMETER(config);
  UNREFERENCED_PARAMETER(context);
  
  return std::make_unique<KTlsSocketInterfaceExtension>(*this);
}

ProtobufTypes::MessagePtr KTlsSocketInterface::createEmptyConfigProto() {
  // Return empty config for now
  return std::make_unique<ProtobufWkt::Empty>();
}

REGISTER_FACTORY(KTlsSocketInterface, Server::Configuration::BootstrapExtensionFactory);

} // namespace Network
} // namespace Envoy 