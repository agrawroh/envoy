#include "source/extensions/transport_sockets/ktls/ktls_socket_splicing.h"

#include "source/common/common/assert.h"
#include "source/common/network/io_socket_error_impl.h"

// Only include Linux-specific headers when compiling on Linux
#ifdef __linux__
#include <sys/splice.h>
#include <sys/uio.h>
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
    ENVOY_LOG(error, "Failed to create pipe for kTLS socket splicing: {}", ::strerror(errno));
    return false;
  }
  
  // Set pipe size for optimal performance
  // In a real implementation, you would tune this based on throughput requirements
#ifdef __linux__
  // F_SETPIPE_SZ is Linux-specific
  constexpr int pipe_size = 1024 * 1024; // 1MB pipe buffer
  if (::fcntl(pipe_fds_[0], F_SETPIPE_SZ, pipe_size) < 0 ||
      ::fcntl(pipe_fds_[1], F_SETPIPE_SZ, pipe_size) < 0) {
    ENVOY_LOG(warn, "Failed to set pipe size for kTLS socket splicing: {}", ::strerror(errno));
    // Not fatal, continue
  }
#endif
  
  // Set the pipe to non-blocking mode
  for (int i = 0; i < 2; ++i) {
    int flags = ::fcntl(pipe_fds_[i], F_GETFL, 0);
    if (flags < 0) {
      ENVOY_LOG(error, "Failed to get pipe flags: {}", ::strerror(errno));
      return false;
    }
    if (::fcntl(pipe_fds_[i], F_SETFL, flags | O_NONBLOCK) < 0) {
      ENVOY_LOG(error, "Failed to set pipe to non-blocking: {}", ::strerror(errno));
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
  
#ifdef __linux__
  // Linux-specific splice() implementation
  
  // Splice flags
  int splice_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
  
  // Perform two-stage splice
  // First, splice from source to pipe
  ssize_t bytes_in_pipe = ::splice(source_fd, nullptr, pipe_fds_[1], nullptr, 
                                  max_bytes, splice_flags);
  if (bytes_in_pipe < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }
  
  if (bytes_in_pipe == 0) {
    // No data to splice
    return {0, Api::IoError::none()};
  }
  
  // Then, splice from pipe to destination
  ssize_t bytes_out = ::splice(pipe_fds_[0], nullptr, dest_fd, nullptr, 
                              bytes_in_pipe, splice_flags);
  if (bytes_out < 0) {
    // This is a serious error as we now have data in the pipe but couldn't send it
    ENVOY_LOG(error, "Failed to splice from pipe to destination: {}", ::strerror(errno));
    return {0, Network::IoSocketError::create(errno)};
  }
  
  // Return the number of bytes transferred
  return {static_cast<uint64_t>(bytes_out), nullptr};
#else
  // On non-Linux platforms, splice is not available, so return not implemented
  UNREFERENCED_PARAMETER(max_bytes);
  return {0, Network::IoSocketError::create(ENOSYS)};
#endif
}

Api::IoCallUint64Result KtlsSocketSplicing::writeFromBuffer(Buffer::Instance& buffer) {
#ifdef __linux__
  // Get all the buffer fragments
  const uint64_t num_slices = buffer.getRawSlices(nullptr, 0);
  if (num_slices == 0) {
    return {0, Api::IoError::none()}; // Nothing to write
  }
  
  // Allocate array for slices
  Buffer::RawSlice slices[num_slices];
  buffer.getRawSlices(slices, num_slices);
  
  // Create iovec array for writev
  struct iovec iov[num_slices];
  uint64_t total_size = 0;
  
  for (uint64_t i = 0; i < num_slices; i++) {
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
  ssize_t written = ::writev(fd, iov, num_slices);
  if (written < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }
  
  // Return the number of bytes written
  return {static_cast<uint64_t>(written), nullptr};
#else
  // On non-Linux platforms, return not implemented
  UNREFERENCED_PARAMETER(buffer);
  return {0, Network::IoSocketError::create(ENOSYS)};
#endif
}

Api::IoCallUint64Result KtlsSocketSplicing::readToBuffer(Buffer::Instance& buffer, uint64_t max_bytes) {
#ifdef __linux__
  // Reserve space in the buffer
  Buffer::RawSlice slice;
  buffer.reserve(max_bytes, &slice, 1);
  
  if (slice.len_ == 0) {
    return {0, Network::IoSocketError::getIoSocketEnomemError()};
  }
  
  // Adjust slice length to max_bytes if needed
  slice.len_ = std::min(slice.len_, max_bytes);
  
  // Get file descriptor from IO handle
  int fd = source_io_handle_.fdDoNotUse();
  if (fd < 0) {
    return {0, Network::IoSocketError::getIoSocketEbadfError()};
  }
  
  // Read data directly into buffer's reserved space
  ssize_t bytes_read = ::read(fd, slice.mem_, slice.len_);
  
  if (bytes_read < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    return {0, Network::IoSocketError::create(errno)};
  }
  
  // Commit the data to the buffer only if we read something
  if (bytes_read > 0) {
    slice.len_ = bytes_read;
    buffer.commit(&slice, 1);
  }
  
  // Return the number of bytes read
  return {static_cast<uint64_t>(bytes_read), nullptr};
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