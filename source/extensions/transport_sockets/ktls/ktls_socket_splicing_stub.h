#pragma once

#include <memory>

#include "envoy/api/io_error.h"
#include "envoy/buffer/buffer.h"
#include "envoy/network/io_handle.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Stub implementation of socket splicing for platforms without splice support.
 * This provides the same interface as KtlsSocketSplicing but with no-op implementation.
 */
class KtlsSocketSplicing {
public:
  KtlsSocketSplicing(Network::IoHandle& source_handle, Network::IoHandle& dest_handle) {
    // Mark parameters as used to avoid unused parameter warnings
    UNREFERENCED_PARAMETER(source_handle);
    UNREFERENCED_PARAMETER(dest_handle);
  }
  
  ~KtlsSocketSplicing() = default;

  /**
   * Write from a buffer to the destination socket (no-op stub implementation).
   * @param buffer The buffer to write from.
   * @return Result containing an ENOSYS error to indicate unsupported operation.
   */
  Api::IoCallUint64Result writeFromBuffer(Buffer::Instance& buffer) {
    UNREFERENCED_PARAMETER(buffer);
    return Api::IoCallUint64Result(
        0, Network::IoSocketError::create(ENOSYS));
  }

  /**
   * Stub implementation that always returns EAGAIN.
   */
  Api::IoCallUint64Result readToBuffer(Buffer::Instance& buffer, uint64_t max_bytes) {
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(max_bytes);
    return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
  }

  /**
   * Stub implementation that always returns EAGAIN.
   */
  Api::IoCallUint64Result splice(uint64_t max_bytes) {
    UNREFERENCED_PARAMETER(max_bytes);
    return Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError());
  }

private:
  // We don't need to store these in the stub implementation
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
