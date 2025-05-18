#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"

#include <vector>

#include "source/common/common/assert.h"
#include "source/common/network/io_socket_error_impl.h"

// Only include Linux-specific headers when compiling on Linux
#ifdef __linux__
#include <sys/uio.h>
// Check if we're on Linux but the header is missing
#if __has_include(<sys/splice.h>)
#include <sys/splice.h>
#define HAS_SPLICE_SYSCALL 1
#else
#define HAS_SPLICE_SYSCALL 0
#endif
#else
// Define empty stubs for non-Linux platforms
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 0
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 0
#endif
#define HAS_SPLICE_SYSCALL 0
// Stub for splice() function (not implemented on non-Linux)
inline ssize_t splice(int, void*, int, void*, size_t, unsigned int) { return -1; }
#endif

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

KtlsSocketSplicing::KtlsSocketSplicing(Network::IoHandle& source_io_handle,
                                       Network::IoHandle& dest_io_handle)
    : source_io_handle_(source_io_handle), dest_io_handle_(dest_io_handle) {
  // Initialize the pipe for splicing
  pipe_initialized_ = initializePipe();
}

KtlsSocketSplicing::~KtlsSocketSplicing() {
  // Close pipe if it's open
  if (pipe_initialized_) {
    if (pipe_fds_[0] >= 0) {
      ::close(pipe_fds_[0]);
    }
    if (pipe_fds_[1] >= 0) {
      ::close(pipe_fds_[1]);
    }
    pipe_initialized_ = false;
  }
}

bool KtlsSocketSplicing::initializePipe() {
  // Create a pipe for splicing
  if (::pipe(pipe_fds_) < 0) {
    ENVOY_LOG(error, "Failed to create pipe for kTLS socket splicing: {}",
              Envoy::errorDetails(errno));
    return false;
  }

  // Set pipe size for optimal performance
  // In a real implementation, you would tune this based on throughput requirements
#if defined(__linux__) && HAS_SPLICE_SYSCALL
  // F_SETPIPE_SZ is Linux-specific
  constexpr int pipe_size = 1024 * 1024; // 1MB pipe buffer
  if (::fcntl(pipe_fds_[0], F_SETPIPE_SZ, pipe_size) < 0 ||
      ::fcntl(pipe_fds_[1], F_SETPIPE_SZ, pipe_size) < 0) {
    ENVOY_LOG(warn, "Failed to set pipe size for kTLS socket splicing: {}",
              Envoy::errorDetails(errno));
    // Not fatal, continue
  }
#endif

  // Set the pipe to non-blocking mode
  for (int i = 0; i < 2; ++i) {
    int flags = ::fcntl(pipe_fds_[i], F_GETFL, 0);
    if (flags < 0) {
      ENVOY_LOG(error, "Failed to get pipe flags: {}", Envoy::errorDetails(errno));
      return false;
    }
    if (::fcntl(pipe_fds_[i], F_SETFL, flags | O_NONBLOCK) < 0) {
      ENVOY_LOG(error, "Failed to set pipe to non-blocking: {}", Envoy::errorDetails(errno));
      return false;
    }
  }

  return true;
}

Api::IoCallUint64Result KtlsSocketSplicing::splice(uint64_t max_bytes) {
  // Ensure pipe is initialized
  if (!pipe_initialized_) {
    return {0, Network::IoSocketError::getIoSocketEbadfError()};
  }

  // Get file descriptors from IO handles
  int source_fd = source_io_handle_.fdDoNotUse();
  int dest_fd = dest_io_handle_.fdDoNotUse();

  // Validate file descriptors
  if (source_fd < 0 || dest_fd < 0) {
    return {0, Network::IoSocketError::getIoSocketEbadfError()};
  }

#if defined(__linux__) && HAS_SPLICE_SYSCALL
  // Linux-specific splice() implementation

  // Check and clear O_APPEND flag on destination fd to prevent EINVAL
  // Store original flags to restore them after the operation
  int dest_flags = ::fcntl(dest_fd, F_GETFL);
  bool had_append_flag = false;

  if (dest_flags < 0) {
    ENVOY_LOG(warn, "Failed to get destination file flags: {}", Envoy::errorDetails(errno));
  } else if (dest_flags & O_APPEND) {
    // If destination has O_APPEND flag, temporarily clear it
    ENVOY_LOG(debug, "Clearing O_APPEND flag on destination fd for splice operation");
    had_append_flag = true;
    if (::fcntl(dest_fd, F_SETFL, dest_flags & ~O_APPEND) < 0) {
      ENVOY_LOG(warn, "Failed to clear O_APPEND flag: {}", Envoy::errorDetails(errno));
      // Continue anyway, worst case splice will fail with EINVAL
    }
  }

  // Splice flags
  int splice_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;

  // Perform two-stage splice
  // First, splice from source to pipe
  ssize_t bytes_in_pipe =
      ::splice(source_fd, nullptr, pipe_fds_[1], nullptr, max_bytes, splice_flags);
  if (bytes_in_pipe < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Restore append flag if we cleared it
      if (had_append_flag && ::fcntl(dest_fd, F_SETFL, dest_flags) < 0) {
        ENVOY_LOG(warn, "Failed to restore O_APPEND flag: {}", Envoy::errorDetails(errno));
      }
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }

    // If splice fails with EINVAL or ENOSYS, fall back to direct read/write
    if (errno == EINVAL || errno == ENOSYS) {
      ENVOY_LOG(debug,
                "Splice from source to pipe failed with {}, using direct read/write fallback",
                errno == EINVAL ? "EINVAL" : "ENOSYS");

      // Restore append flag if we cleared it
      if (had_append_flag && ::fcntl(dest_fd, F_SETFL, dest_flags) < 0) {
        ENVOY_LOG(warn, "Failed to restore O_APPEND flag: {}", Envoy::errorDetails(errno));
      }

      // Use direct read/write as fallback
      char buffer[16384];
      ssize_t bytes_read =
          ::read(source_fd, buffer, std::min(sizeof(buffer), static_cast<size_t>(max_bytes)));

      if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return {0, Network::IoSocketError::getIoSocketEagainError()};
        }
        return {0, Network::IoSocketError::create(errno)};
      }

      if (bytes_read == 0) {
        return {0, Api::IoError::none()};
      }

      ssize_t bytes_written = ::write(dest_fd, buffer, bytes_read);
      if (bytes_written < 0) {
        return {0, Network::IoSocketError::create(errno)};
      }

      return {static_cast<uint64_t>(bytes_written), Api::IoError::none()};
    }

    // Restore append flag if we cleared it
    if (had_append_flag && ::fcntl(dest_fd, F_SETFL, dest_flags) < 0) {
      ENVOY_LOG(warn, "Failed to restore O_APPEND flag: {}", Envoy::errorDetails(errno));
    }
    return {0, Network::IoSocketError::create(errno)};
  }

  if (bytes_in_pipe == 0) {
    // No data to splice
    // Restore append flag if we cleared it
    if (had_append_flag && ::fcntl(dest_fd, F_SETFL, dest_flags) < 0) {
      ENVOY_LOG(warn, "Failed to restore O_APPEND flag: {}", Envoy::errorDetails(errno));
    }
    return {0, Api::IoError::none()};
  }

  // Then, splice from pipe to destination
  ssize_t bytes_out =
      ::splice(pipe_fds_[0], nullptr, dest_fd, nullptr, bytes_in_pipe, splice_flags);

  // Restore append flag if we cleared it
  if (had_append_flag && ::fcntl(dest_fd, F_SETFL, dest_flags) < 0) {
    ENVOY_LOG(warn, "Failed to restore O_APPEND flag: {}", Envoy::errorDetails(errno));
  }

  if (bytes_out < 0) {
    // This is a serious error as we now have data in the pipe but couldn't send it
    ENVOY_LOG(error, "Failed to splice from pipe to destination: {}", Envoy::errorDetails(errno));
    if (errno == EINVAL) {
      ENVOY_LOG(debug, "EINVAL error in splice - this may occur if destination is in append mode");
    }

    // Although we have data in the pipe, we can't do much to recover it directly,
    // so we just return the error
    return {0, Network::IoSocketError::create(errno)};
  }

  // Return the number of bytes transferred
  return {static_cast<uint64_t>(bytes_out), Api::IoError::none()};
#else
  // On non-Linux platforms or if splice is not available, use direct read/write
  UNREFERENCED_PARAMETER(max_bytes);
  ENVOY_LOG(debug, "Splice syscall not available, using direct read/write fallback");

  // Use direct read/write as fallback
  char buffer[16384];
  ssize_t bytes_read =
      ::read(source_fd, buffer, std::min(sizeof(buffer), static_cast<size_t>(max_bytes)));

  if (bytes_read < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }

  if (bytes_read == 0) {
    return {0, Api::IoError::none()};
  }

  ssize_t bytes_written = ::write(dest_fd, buffer, bytes_read);
  if (bytes_written < 0) {
    return {0, Network::IoSocketError::create(errno)};
  }

  return {static_cast<uint64_t>(bytes_written), Api::IoError::none()};
#endif
}

Api::IoCallUint64Result KtlsSocketSplicing::writeFromBuffer(Buffer::Instance& buffer) {
#if defined(__linux__)
  // Get all the buffer fragments
  Buffer::RawSliceVector slices = buffer.getRawSlices();
  if (slices.empty()) {
    return {0, Api::IoError::none()}; // Nothing to write
  }

  // Create iovec array for writev using std::vector instead of VLA
  std::vector<struct iovec> iov(slices.size());
  uint64_t total_size = 0;

  for (size_t i = 0; i < slices.size(); i++) {
    if (slices[i].len_ == 0) {
      continue;
    }
    iov[i].iov_base = slices[i].mem_;
    iov[i].iov_len = slices[i].len_;
    total_size += slices[i].len_;
  }

  if (total_size == 0) {
    return {0, Api::IoError::none()}; // Nothing to write
  }

  // Get file descriptor from IO handle
  int fd = dest_io_handle_.fdDoNotUse();
  if (fd < 0) {
    return {0, Network::IoSocketError::getIoSocketEbadfError()};
  }

  // Write data in a single syscall using writev
  ssize_t written = ::writev(fd, iov.data(), iov.size());
  if (written < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }

  // Return the number of bytes written
  return {static_cast<uint64_t>(written), Api::IoError::none()};
#else
  // On non-Linux platforms, return not implemented
  UNREFERENCED_PARAMETER(buffer);
  return {0, Network::IoSocketError::create(ENOSYS)};
#endif
}

Api::IoCallUint64Result KtlsSocketSplicing::readToBuffer(Buffer::Instance& buffer,
                                                         uint64_t max_bytes) {
#if defined(__linux__)
  // Get file descriptor from IO handle
  int fd = source_io_handle_.fdDoNotUse();
  if (fd < 0) {
    return {0, Network::IoSocketError::getIoSocketEbadfError()};
  }

  // Use a temporary buffer for reading
  char read_buffer[16384];
  const size_t read_size = std::min(static_cast<size_t>(max_bytes), sizeof(read_buffer));

  // Read data directly
  ssize_t bytes_read = ::read(fd, read_buffer, read_size);

  if (bytes_read < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }

  // Add the data to the buffer if we read something
  if (bytes_read > 0) {
    buffer.add(read_buffer, bytes_read);
  }

  // Return the number of bytes read
  return {static_cast<uint64_t>(bytes_read), Api::IoError::none()};
#else
  // On non-Linux platforms, return not implemented
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(max_bytes);
  return {0, Network::IoSocketError::create(ENOSYS)};
#endif
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
