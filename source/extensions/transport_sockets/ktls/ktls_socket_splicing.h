#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/io_handle.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Helper class for zero-copy data transfer using splice() syscall with kTLS sockets.
 */
class KtlsSocketSplicing : public Logger::Loggable<Logger::Id::connection> {
public:
  KtlsSocketSplicing(Network::IoHandle& source_io_handle, Network::IoHandle& dest_io_handle);
  ~KtlsSocketSplicing();

  /**
   * Transfers data from source to destination using splice.
   * @param max_bytes maximum number of bytes to transfer.
   * @return IoCallUint64Result with bytes transferred or an error.
   */
  Api::IoCallUint64Result splice(uint64_t max_bytes);

  /**
   * Transfers data from a buffer to the destination socket using zerocopy.
   * @param buffer source buffer to write.
   * @return IoCallUint64Result with bytes transferred or an error.
   */
  Api::IoCallUint64Result writeFromBuffer(Buffer::Instance& buffer);

  /**
   * Transfers data from the source socket to a buffer.
   * @param buffer destination buffer to read into.
   * @param max_bytes maximum number of bytes to transfer.
   * @return IoCallUint64Result with bytes transferred or an error.
   */
  Api::IoCallUint64Result readToBuffer(Buffer::Instance& buffer, uint64_t max_bytes);

private:
  Network::IoHandle& source_io_handle_;
  Network::IoHandle& dest_io_handle_;
  int pipe_fds_[2]{-1, -1};
  bool pipe_initialized_{false};
  
  /**
   * Initialize the pipe used for splicing.
   * @return true if successful, false otherwise.
   */
  bool initializePipe();
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 