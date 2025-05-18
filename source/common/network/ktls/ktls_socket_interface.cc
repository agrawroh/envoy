#include "source/common/network/ktls/ktls_socket_interface.h"

#include "envoy/registry/registry.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"
#include "source/common/network/socket_interface_impl.h"

// Include fcntl.h for SOCK_NONBLOCK on Linux
#ifdef __linux__
#include <fcntl.h>
#endif

namespace Envoy {
namespace Network {

// Define a simple logger
namespace {
struct KtlsSocketLogger : public Logger::Loggable<Logger::Id::connection> {};
} // namespace

IoHandlePtr KTlsSocketInterface::socket(Socket::Type socket_type, Address::Type addr_type,
                                        Address::IpVersion version, bool socket_v6only,
                                        const SocketCreationOptions& options) const {
  UNREFERENCED_PARAMETER(options);
  // Create the socket
  Api::OsSysCalls& os_sys_calls = Api::OsSysCallsSingleton::get();

  // Determine domain based on IP version
  int domain;
  if (addr_type == Address::Type::Ip) {
    if (version == Address::IpVersion::v6 || Address::forceV6()) {
      domain = AF_INET6;
    } else {
      ASSERT(version == Address::IpVersion::v4);
      domain = AF_INET;
    }
  } else if (addr_type == Address::Type::Pipe) {
    domain = AF_UNIX;
  } else {
    ASSERT(addr_type == Address::Type::EnvoyInternal);
    PANIC("not implemented");
    return nullptr;
  }

  // Determine socket type
  int flags = 0;
#ifdef __linux__
  flags = SOCK_NONBLOCK;
#endif

  if (socket_type == Socket::Type::Stream) {
    flags |= SOCK_STREAM;
  } else {
    flags |= SOCK_DGRAM;
  }

  // Create the socket
  const Api::SysCallSocketResult result = os_sys_calls.socket(domain, flags, 0);
  if (SOCKET_INVALID(result.return_value_)) {
    ENVOY_LOG_MISC(debug, "socket failed: {}", Envoy::errorDetails(result.errno_));
    return nullptr;
  }

  // Create the kTLS socket handle
  IoHandlePtr io_handle =
      std::make_unique<KTlsSocketHandleImpl>(result.return_value_, socket_v6only);
  if (socket_v6only && addr_type == Address::Type::Ip && version == Address::IpVersion::v6) {
    // Set the socket as IPv6 only.
    const int v6only = 1;
    const Api::SysCallIntResult v6only_result =
        io_handle->setOption(IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    if (v6only_result.return_value_ != 0) {
      io_handle->close();
      ENVOY_LOG_MISC(debug, "setting v6only option failed: {}",
                     Envoy::errorDetails(v6only_result.errno_));
      return nullptr;
    }
  }

  return io_handle;
}

IoHandlePtr KTlsSocketInterface::socket(Socket::Type socket_type,
                                        const Address::InstanceConstSharedPtr addr,
                                        const SocketCreationOptions& options) const {
  UNREFERENCED_PARAMETER(options);
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
    if (SOCKET_FAILURE(result.return_value_)) {
      ENVOY_LOG_MISC(warn, "Unable to set socket v6-only: got error: {}", result.errno_);
    }
  }
  return io_handle;
}

bool KTlsSocketInterface::ipFamilySupported(int domain) {
  Api::OsSysCalls& os_sys_calls = Api::OsSysCallsSingleton::get();
  const Api::SysCallSocketResult result = os_sys_calls.socket(domain, SOCK_STREAM, 0);
  if (SOCKET_VALID(result.return_value_)) {
    RELEASE_ASSERT(os_sys_calls.close(result.return_value_).return_value_ == 0,
                   fmt::format("Fail to close fd: response code {}", result.return_value_));
  }
  return SOCKET_VALID(result.return_value_);
}

Server::BootstrapExtensionPtr KTlsSocketInterface::createBootstrapExtension(
    const Protobuf::Message& config, Server::Configuration::ServerFactoryContext& context) {
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
