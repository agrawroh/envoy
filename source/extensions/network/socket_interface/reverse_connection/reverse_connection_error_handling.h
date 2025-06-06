#pragma once

#include <string>
#include <system_error>

#include "envoy/common/exception.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace Network {
namespace SocketInterface {
namespace ReverseConnection {

/**
 * Exception types for reverse connection errors.
 */
class ReverseConnectionException : public EnvoyException {
public:
  ReverseConnectionException(const std::string& message) : EnvoyException(message) {}
};

class ClusterNotFoundException : public ReverseConnectionException {
public:
  ClusterNotFoundException(const std::string& cluster_name)
      : ReverseConnectionException(fmt::format("Cluster not found: {}", cluster_name)) {}
};

class DescriptorExhaustedException : public ReverseConnectionException {
public:
  DescriptorExhaustedException() : ReverseConnectionException("File descriptor limit exceeded") {}
};

class PipeCreationException : public ReverseConnectionException {
public:
  PipeCreationException(int error_code)
      : ReverseConnectionException(
            fmt::format("Failed to create pipe: {} ({})", strerror(error_code), error_code)) {}
};

class ConnectionTimeoutException : public ReverseConnectionException {
public:
  ConnectionTimeoutException(const std::string& cluster_name)
      : ReverseConnectionException(fmt::format("Connection timeout to cluster: {}", cluster_name)) {
  }
};

/**
 * Error handling utilities for reverse connections.
 */
class ReverseConnectionErrorHandler
    : public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  /**
   * Handle system call errors with proper logging and exceptions.
   */
  static void handleSystemCallError(const std::string& operation, int error_code) {
    const std::string error_msg =
        fmt::format("{} failed: {} ({})", operation, strerror(error_code), error_code);

    ENVOY_LOG(error, "System call error: {}", error_msg);

    switch (error_code) {
    case EMFILE:
    case ENFILE:
      throw DescriptorExhaustedException();
    case EPIPE:
      throw PipeCreationException(error_code);
    case ETIMEDOUT:
      throw ConnectionTimeoutException("unknown");
    default:
      throw ReverseConnectionException(error_msg);
    }
  }

  /**
   * Validate file descriptor and throw if invalid.
   */
  static void validateFileDescriptor(os_fd_t fd, const std::string& context) {
    if (fd < 0) {
      const std::string error_msg = fmt::format("Invalid file descriptor in {}: {}", context, fd);
      ENVOY_LOG(error, error_msg);
      throw ReverseConnectionException(error_msg);
    }

    if (fd > 65536) {
      const std::string error_msg =
          fmt::format("File descriptor out of range in {}: {}", context, fd);
      ENVOY_LOG(warn, error_msg);
    }
  }

  /**
   * Log and handle connection errors gracefully.
   */
  static bool handleConnectionError(const std::string& cluster_name, const std::string& operation,
                                    const std::exception& error) {
    ENVOY_LOG(error, "Connection error for cluster {} during {}: {}", cluster_name, operation,
              error.what());

    return false;
  }

  /**
   * Check for resource limits and log warnings.
   */
  static void checkResourceLimits(uint32_t current_connections, uint32_t max_connections) {
    if (current_connections > max_connections * 0.9) {
      ENVOY_LOG(warn, "Approaching connection limit: {} / {}", current_connections,
                max_connections);
    }

    if (current_connections >= max_connections) {
      throw ReverseConnectionException(
          fmt::format("Connection limit exceeded: {} >= {}", current_connections, max_connections));
    }
  }
};

/**
 * RAII wrapper for file descriptors.
 */
class FileDescriptorGuard : public Envoy::Logger::Loggable<Envoy::Logger::Id::connection> {
public:
  explicit FileDescriptorGuard(os_fd_t fd) : fd_(fd) {
    ReverseConnectionErrorHandler::validateFileDescriptor(fd_, "FileDescriptorGuard constructor");
  }

  ~FileDescriptorGuard() {
    if (fd_ >= 0) {
      ENVOY_LOG(debug, "Closing file descriptor: {}", fd_);
      ::close(fd_);
    }
  }

  // Move-only semantics
  FileDescriptorGuard(const FileDescriptorGuard&) = delete;
  FileDescriptorGuard& operator=(const FileDescriptorGuard&) = delete;

  FileDescriptorGuard(FileDescriptorGuard&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

  FileDescriptorGuard& operator=(FileDescriptorGuard&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) {
        ::close(fd_);
      }
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }

  os_fd_t get() const { return fd_; }
  os_fd_t release() {
    os_fd_t fd = fd_;
    fd_ = -1;
    return fd;
  }

private:
  os_fd_t fd_;
};

} // namespace ReverseConnection
} // namespace SocketInterface
} // namespace Network
} // namespace Extensions
} // namespace Envoy
