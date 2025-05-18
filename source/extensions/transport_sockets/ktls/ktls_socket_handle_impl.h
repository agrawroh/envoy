#pragma once

#include <cstddef>
#include <memory>

#include "envoy/network/io_handle.h"

#include "source/common/common/logger.h"
#include "source/common/network/default_socket_interface.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

/**
 * Implementation of IoHandle for sockets with kTLS enabled.
 */
class KtlsSocketHandleImpl : public Network::IoHandle,
                             public Logger::Loggable<Logger::Id::connection> {
public:
  /**
   * Construct a new kTLS socket handle wrapper.
   * @param io_handle the underlying original IO handle to wrap
   */
  KtlsSocketHandleImpl(Network::IoHandlePtr io_handle);

  // Network::IoHandle
  os_fd_t fdDoNotUse() const override;
  Api::IoCallUint64Result close() override;
  bool isOpen() const override;
  Api::IoCallUint64Result readv(uint64_t max_length, Buffer::RawSlice* slices,
                                uint64_t num_slice) override;
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               absl::optional<uint64_t> max_length) override;
  Api::IoCallUint64Result writev(const Buffer::RawSlice* slices, uint64_t num_slice) override;
  Api::IoCallUint64Result write(Buffer::Instance& buffer) override;
  Api::IoCallUint64Result writev(uint64_t num_slice, Buffer::RawSliceData* slice_data) override;
  Api::IoCallUint64Result send(const Buffer::RawSlice* slices, uint64_t num_slice,
                               int flags) override;
  Api::IoCallUint64Result sendmsg(const Buffer::RawSlice* slices, uint64_t num_slice, int flags,
                                  const Network::Address::Ip* self_ip,
                                  const Network::Address::Instance& peer_address) override;
  Api::IoCallUint64Result recv(Buffer::RawSlice* slices, uint64_t num_slice, int flags) override;
  Api::IoCallUint64Result recvmsg(Buffer::RawSlice* slices, uint64_t num_slice, int flags,
                                  uint32_t* self_port,
                                  Network::Address::InstancePtr* peer_address) override;
  Api::IoCallUint64Result recvmmsg(RawSliceArrays& slices, uint32_t* self_port,
                                   Network::Address::InstancePtr* peer_address) override;
  bool supportsMmsg() const override;
  bool supportsUdpGro() const override;

  // Enable kTLS for this socket.
  bool enableKtls();

private:
  Network::IoHandlePtr io_handle_;
  bool ktls_enabled_{false};
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
