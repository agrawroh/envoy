#pragma once

#include <sys/splice.h>

#include "envoy/network/io_handle.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

/**
 * Utility class for splice operations with kTLS sockets.
 * This provides zero-copy data transfer between file descriptors using the
 * Linux splice() system call.
 */
class KTlsSplicer : public Logger::Loggable<Logger::Id::connection> {
public:
  KTlsSplicer() = default;

  /**
   * Initialize the splicer with the given file descriptors.
   * @param source_fd The source file descriptor.
   * @param destination_fd The destination file descriptor.
   * @return true if initialization was successful, false otherwise.
   */
  bool initialize(os_fd_t source_fd, os_fd_t destination_fd);

  /**
   * Splice data from source to destination.
   * @param bytes The number of bytes to splice. Will splice as much as possible if set to 0.
   * @return The number of bytes spliced, or -1 on error.
   */
  ssize_t splice(size_t bytes = 0);

  /**
   * Check if the splicer is initialized.
   * @return true if initialized, false otherwise.
   */
  bool isInitialized() const { return pipe_initialized_; }

private:
  static constexpr int SPLICE_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
  static constexpr size_t DEFAULT_PIPE_SIZE = 65536; // 64KB
  
  // Pipe used for the splice operation
  int pipe_fds_[2]{-1, -1};
  bool pipe_initialized_{false};
  
  // Source and destination file descriptors
  os_fd_t source_fd_{-1};
  os_fd_t destination_fd_{-1};
  
  /**
   * Create the pipe used for splice operations.
   * @return true if the pipe was created successfully, false otherwise.
   */
  bool createPipe();
  
  /**
   * Close the pipe if it's open.
   */
  void closePipe();
};

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 