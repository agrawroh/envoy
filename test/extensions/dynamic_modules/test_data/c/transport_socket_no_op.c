#include <errno.h>

#include "source/extensions/dynamic_modules/abi/abi.h"

// This is a minimal passthrough transport socket module (raw TCP, no TLS).

enum { kReadChunk = 16384, kMaxWriteSlices = 16 };

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

envoy_dynamic_module_type_transport_socket_factory_config_module_ptr
envoy_dynamic_module_on_transport_socket_factory_config_new(
    envoy_dynamic_module_type_transport_socket_factory_config_envoy_ptr factory_config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer socket_name,
    envoy_dynamic_module_type_envoy_buffer socket_config, bool is_upstream) {
  (void)factory_config_envoy_ptr;
  (void)socket_name;
  (void)socket_config;
  (void)is_upstream;
  static int factory_dummy = 0;
  return &factory_dummy;
}

void envoy_dynamic_module_on_transport_socket_factory_config_destroy(
    envoy_dynamic_module_type_transport_socket_factory_config_module_ptr factory_config_ptr) {
  (void)factory_config_ptr;
}

envoy_dynamic_module_type_transport_socket_module_ptr envoy_dynamic_module_on_transport_socket_new(
    envoy_dynamic_module_type_transport_socket_factory_config_module_ptr factory_config_ptr,
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr) {
  (void)factory_config_ptr;
  (void)transport_socket_envoy_ptr;
  static int socket_dummy = 0;
  return &socket_dummy;
}

void envoy_dynamic_module_on_transport_socket_destroy(
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr) {
  (void)transport_socket_module_ptr;
}

void envoy_dynamic_module_on_transport_socket_set_callbacks(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr) {
  (void)transport_socket_envoy_ptr;
  (void)transport_socket_module_ptr;
}

void envoy_dynamic_module_on_transport_socket_on_connected(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr) {
  (void)transport_socket_module_ptr;
  envoy_dynamic_module_callback_transport_socket_raise_event(
      transport_socket_envoy_ptr, envoy_dynamic_module_type_network_connection_event_Connected);
}

envoy_dynamic_module_type_transport_socket_io_result envoy_dynamic_module_on_transport_socket_do_read(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr) {
  (void)transport_socket_module_ptr;
  envoy_dynamic_module_type_transport_socket_io_result result;
  result.action = envoy_dynamic_module_type_transport_socket_post_io_action_KeepOpen;
  result.bytes_processed = 0;
  result.end_stream_read = false;

  void* io_handle =
      envoy_dynamic_module_callback_transport_socket_get_io_handle(transport_socket_envoy_ptr);
  if (io_handle == NULL) {
    return result;
  }

  char stack[kReadChunk];
  uint64_t total_read = 0;
  for (;;) {
    size_t bytes_read = 0;
    int64_t rc = envoy_dynamic_module_callback_transport_socket_io_handle_read(
        io_handle, stack, sizeof(stack), &bytes_read);
    if (rc != 0) {
      if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
        break;
      }
      result.action = envoy_dynamic_module_type_transport_socket_post_io_action_Close;
      result.bytes_processed = total_read;
      return result;
    }
    if (bytes_read == 0) {
      result.end_stream_read = true;
      break;
    }
    envoy_dynamic_module_callback_transport_socket_read_buffer_add(transport_socket_envoy_ptr, stack,
                                                                   bytes_read);
    total_read += (uint64_t)bytes_read;
  }
  result.bytes_processed = total_read;
  return result;
}

envoy_dynamic_module_type_transport_socket_io_result envoy_dynamic_module_on_transport_socket_do_write(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr,
    size_t write_buffer_length, bool end_stream) {
  (void)transport_socket_module_ptr;
  (void)write_buffer_length;
  (void)end_stream;

  envoy_dynamic_module_type_transport_socket_io_result result;
  result.action = envoy_dynamic_module_type_transport_socket_post_io_action_KeepOpen;
  result.bytes_processed = 0;
  result.end_stream_read = false;

  void* io_handle =
      envoy_dynamic_module_callback_transport_socket_get_io_handle(transport_socket_envoy_ptr);
  if (io_handle == NULL) {
    envoy_dynamic_module_callback_transport_socket_flush_write_buffer(transport_socket_envoy_ptr);
    return result;
  }

  uint64_t total_written = 0;
  for (;;) {
    envoy_dynamic_module_type_envoy_buffer slices[kMaxWriteSlices];
    size_t slice_count = kMaxWriteSlices;
    envoy_dynamic_module_callback_transport_socket_write_buffer_get_slices(transport_socket_envoy_ptr,
                                                                             slices, &slice_count);
    if (slice_count == 0) {
      break;
    }
    size_t i;
    for (i = 0; i < slice_count; ++i) {
      const char* p = slices[i].ptr;
      size_t len = slices[i].length;
      while (len > 0) {
        size_t bytes_written = 0;
        int64_t rc = envoy_dynamic_module_callback_transport_socket_io_handle_write(
            io_handle, p, len, &bytes_written);
        if (rc != 0) {
          if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
            result.bytes_processed = total_written;
            envoy_dynamic_module_callback_transport_socket_flush_write_buffer(
                transport_socket_envoy_ptr);
            return result;
          }
          result.action = envoy_dynamic_module_type_transport_socket_post_io_action_Close;
          result.bytes_processed = total_written;
          return result;
        }
        if (bytes_written == 0) {
          result.bytes_processed = total_written;
          envoy_dynamic_module_callback_transport_socket_flush_write_buffer(
              transport_socket_envoy_ptr);
          return result;
        }
        envoy_dynamic_module_callback_transport_socket_write_buffer_drain(transport_socket_envoy_ptr,
                                                                            bytes_written);
        total_written += (uint64_t)bytes_written;
        if (bytes_written < len) {
          result.bytes_processed = total_written;
          envoy_dynamic_module_callback_transport_socket_flush_write_buffer(
              transport_socket_envoy_ptr);
          return result;
        }
        p += bytes_written;
        len -= bytes_written;
      }
    }
  }
  result.bytes_processed = total_written;
  envoy_dynamic_module_callback_transport_socket_flush_write_buffer(transport_socket_envoy_ptr);
  return result;
}

void envoy_dynamic_module_on_transport_socket_close(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr,
    envoy_dynamic_module_type_network_connection_event event) {
  (void)transport_socket_envoy_ptr;
  (void)transport_socket_module_ptr;
  (void)event;
}

void envoy_dynamic_module_on_transport_socket_get_protocol(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr,
    envoy_dynamic_module_type_module_buffer* result) {
  (void)transport_socket_envoy_ptr;
  (void)transport_socket_module_ptr;
  result->ptr = NULL;
  result->length = 0;
}

void envoy_dynamic_module_on_transport_socket_get_failure_reason(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr,
    envoy_dynamic_module_type_module_buffer* result) {
  (void)transport_socket_envoy_ptr;
  (void)transport_socket_module_ptr;
  result->ptr = NULL;
  result->length = 0;
}

bool envoy_dynamic_module_on_transport_socket_can_flush_close(
    envoy_dynamic_module_type_transport_socket_envoy_ptr transport_socket_envoy_ptr,
    envoy_dynamic_module_type_transport_socket_module_ptr transport_socket_module_ptr) {
  (void)transport_socket_envoy_ptr;
  (void)transport_socket_module_ptr;
  return true;
}
