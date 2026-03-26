#include <algorithm>
#include <cerrno>
#include <cstddef>

#include "envoy/buffer/buffer.h"
#include "envoy/common/platform.h"
#include "envoy/network/io_handle.h"

#include "source/extensions/dynamic_modules/abi/abi.h"
#include "source/extensions/transport_sockets/dynamic_modules/transport_socket.h"

using Envoy::Extensions::TransportSockets::DynamicModules::DynamicModuleTransportSocket;

extern "C" {

void* envoy_dynamic_module_callback_transport_socket_get_io_handle(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (socket->transportCallbacks() == nullptr) {
    return nullptr;
  }
  return static_cast<void*>(&(socket->transportCallbacks()->ioHandle()));
}

int64_t envoy_dynamic_module_callback_transport_socket_io_handle_read(void* io_handle, char* buffer,
                                                                      size_t length,
                                                                      size_t* bytes_read) {
  if (bytes_read == nullptr || io_handle == nullptr) {
    return -EINVAL;
  }
  auto* handle = static_cast<Envoy::Network::IoHandle*>(io_handle);
  Envoy::Buffer::RawSlice slice{buffer, length};
  const auto result = handle->readv(length, &slice, 1);
  if (!result.ok()) {
    *bytes_read = 0;
    return -static_cast<int64_t>(result.err_->getSystemErrorCode());
  }
  *bytes_read = static_cast<size_t>(result.return_value_);
  return 0;
}

int64_t envoy_dynamic_module_callback_transport_socket_io_handle_write(void* io_handle,
                                                                       const char* buffer,
                                                                       size_t length,
                                                                       size_t* bytes_written) {
  if (bytes_written == nullptr || io_handle == nullptr) {
    return -EINVAL;
  }
  auto* handle = static_cast<Envoy::Network::IoHandle*>(io_handle);
  Envoy::Buffer::RawSlice slice{const_cast<char*>(buffer), length};
  const auto result = handle->writev(&slice, 1);
  if (!result.ok()) {
    *bytes_written = 0;
    return -static_cast<int64_t>(result.err_->getSystemErrorCode());
  }
  *bytes_written = static_cast<size_t>(result.return_value_);
  return 0;
}

int envoy_dynamic_module_callback_transport_socket_io_handle_fd(void* io_handle) {
  if (io_handle == nullptr) {
    return -1;
  }
  auto* handle = static_cast<Envoy::Network::IoHandle*>(io_handle);
  os_fd_t fd = handle->fdDoNotUse();
  return static_cast<int>(fd);
}

void envoy_dynamic_module_callback_transport_socket_read_buffer_drain(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    size_t length) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  Envoy::Buffer::Instance* buf = socket->activeReadBuffer();
  if (buf == nullptr) {
    return;
  }
  buf->drain(length);
}

void envoy_dynamic_module_callback_transport_socket_read_buffer_add(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    const char* data, size_t length) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  Envoy::Buffer::Instance* buf = socket->activeReadBuffer();
  if (buf == nullptr || data == nullptr) {
    return;
  }
  buf->add(data, length);
}

size_t envoy_dynamic_module_callback_transport_socket_read_buffer_length(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  Envoy::Buffer::Instance* buf = socket->activeReadBuffer();
  if (buf == nullptr) {
    return 0;
  }
  return static_cast<size_t>(buf->length());
}

void envoy_dynamic_module_callback_transport_socket_write_buffer_drain(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    size_t length) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  Envoy::Buffer::Instance* buf = socket->activeWriteBuffer();
  if (buf == nullptr) {
    return;
  }
  buf->drain(length);
}

void envoy_dynamic_module_callback_transport_socket_write_buffer_get_slices(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer* slices, size_t* slices_count) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (slices_count == nullptr) {
    return;
  }
  Envoy::Buffer::Instance* buf = socket->activeWriteBuffer();
  if (buf == nullptr) {
    *slices_count = 0;
    return;
  }
  const auto raw = buf->getRawSlices(std::nullopt);
  if (slices == nullptr) {
    *slices_count = raw.size();
    return;
  }
  const size_t max_out = *slices_count;
  const size_t n = std::min(max_out, raw.size());
  for (size_t i = 0; i < n; ++i) {
    slices[i].ptr = static_cast<char*>(raw[i].mem_);
    slices[i].length = raw[i].len_;
  }
  *slices_count = n;
}

size_t envoy_dynamic_module_callback_transport_socket_write_buffer_length(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  Envoy::Buffer::Instance* buf = socket->activeWriteBuffer();
  if (buf == nullptr) {
    return 0;
  }
  return static_cast<size_t>(buf->length());
}

void envoy_dynamic_module_callback_transport_socket_raise_event(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_network_connection_event event) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (socket->transportCallbacks() == nullptr) {
    return;
  }
  socket->transportCallbacks()->raiseEvent(static_cast<Envoy::Network::ConnectionEvent>(event));
}

bool envoy_dynamic_module_callback_transport_socket_should_drain_read_buffer(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (socket->transportCallbacks() == nullptr) {
    return false;
  }
  return socket->transportCallbacks()->shouldDrainReadBuffer();
}

void envoy_dynamic_module_callback_transport_socket_set_is_readable(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (socket->transportCallbacks() == nullptr) {
    return;
  }
  socket->transportCallbacks()->setTransportSocketIsReadable();
}

void envoy_dynamic_module_callback_transport_socket_flush_write_buffer(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  auto* socket = static_cast<DynamicModuleTransportSocket*>(transport_socket_envoy_ptr);
  if (socket->transportCallbacks() == nullptr) {
    return;
  }
  socket->transportCallbacks()->flushWriteBuffer();
}

} // extern "C"
