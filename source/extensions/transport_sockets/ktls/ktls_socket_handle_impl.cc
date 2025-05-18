#include "source/extensions/transport_sockets/ktls/ktls_socket_handle_impl.h"

#include "source/common/network/io_socket_error_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

KtlsSocketHandleImpl::KtlsSocketHandleImpl(Network::IoHandlePtr io_handle)
    : io_handle_(std::move(io_handle)) {
  ASSERT(io_handle_ != nullptr, "IO handle cannot be null");
}

os_fd_t KtlsSocketHandleImpl::fdDoNotUse() const { return io_handle_->fdDoNotUse(); }

Api::IoCallUint64Result KtlsSocketHandleImpl::close() { return io_handle_->close(); }

bool KtlsSocketHandleImpl::isOpen() const { return io_handle_->isOpen(); }

Api::IoCallUint64Result KtlsSocketHandleImpl::readv(uint64_t max_length, Buffer::RawSlice* slices,
                                                    uint64_t num_slice) {
  return io_handle_->readv(max_length, slices, num_slice);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::read(Buffer::Instance& buffer,
                                                   absl::optional<uint64_t> max_length) {
  return io_handle_->read(buffer, max_length);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::writev(const Buffer::RawSlice* slices,
                                                     uint64_t num_slice) {
  return io_handle_->writev(slices, num_slice);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::write(Buffer::Instance& buffer) {
  return io_handle_->write(buffer);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::writev(uint64_t num_slice,
                                                     Buffer::RawSliceData* slice_data) {
  return io_handle_->writev(num_slice, slice_data);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::send(const Buffer::RawSlice* slices,
                                                   uint64_t num_slice, int flags) {
  return io_handle_->send(slices, num_slice, flags);
}

Api::IoCallUint64Result
KtlsSocketHandleImpl::sendmsg(const Buffer::RawSlice* slices, uint64_t num_slice, int flags,
                              const Network::Address::Ip* self_ip,
                              const Network::Address::Instance& peer_address) {
  return io_handle_->sendmsg(slices, num_slice, flags, self_ip, peer_address);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::recv(Buffer::RawSlice* slices, uint64_t num_slice,
                                                   int flags) {
  return io_handle_->recv(slices, num_slice, flags);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::recvmsg(Buffer::RawSlice* slices, uint64_t num_slice,
                                                      int flags, uint32_t* self_port,
                                                      Network::Address::InstancePtr* peer_address) {
  return io_handle_->recvmsg(slices, num_slice, flags, self_port, peer_address);
}

Api::IoCallUint64Result
KtlsSocketHandleImpl::recvmmsg(RawSliceArrays& slices, uint32_t* self_port,
                               Network::Address::InstancePtr* peer_address) {
  return io_handle_->recvmmsg(slices, self_port, peer_address);
}

bool KtlsSocketHandleImpl::supportsMmsg() const { return io_handle_->supportsMmsg(); }

bool KtlsSocketHandleImpl::supportsUdpGro() const { return io_handle_->supportsUdpGro(); }

bool KtlsSocketHandleImpl::enableKtls() {
  // For now, don't try to enable kTLS at this level
  // The actual enablement happens in the transport socket
  return false;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
