#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/io_handle.h"

#include "source/common/network/io_socket_error_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Stub implementation of KtlsSocketSplicing for platforms without splice() syscall.
 * This implementation simply returns EAGAIN for all operations.
 */
class KtlsSocketSplicing {
public:
  KtlsSocketSplicing(Network::IoHandle&, Network::IoHandle&) {}

  /**
   * Stub implementation that always returns EAGAIN.
   */
  Api::IoCallUint64Result writeFromBuffer(Buffer::Instance&) {
    return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
  }

  /**
   * Stub implementation that always returns EAGAIN.
   */
  Api::IoCallUint64Result readToBuffer(Buffer::Instance&, uint64_t) {
    return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
  }

  /**
   * Stub implementation that always returns EAGAIN.
   */
  Api::IoCallUint64Result splice(uint64_t) {
    return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
  }
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
