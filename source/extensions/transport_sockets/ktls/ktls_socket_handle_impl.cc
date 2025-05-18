#include "source/extensions/transport_sockets/ktls/ktls_socket_handle_impl.h"

#include "envoy/api/io_error.h"

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

bool KtlsSocketHandleImpl::wasConnected() const { return io_handle_->wasConnected(); }

Api::SysCallIntResult KtlsSocketHandleImpl::bind(Network::Address::InstanceConstSharedPtr address) {
  return io_handle_->bind(address);
}

Api::SysCallIntResult KtlsSocketHandleImpl::listen(int backlog) {
  return io_handle_->listen(backlog);
}

std::unique_ptr<Network::IoHandle> KtlsSocketHandleImpl::accept(struct sockaddr* addr,
                                                                socklen_t* addrlen) {
  auto accepted = io_handle_->accept(addr, addrlen);
  if (accepted == nullptr) {
    return nullptr;
  }
  return std::make_unique<KtlsSocketHandleImpl>(std::move(accepted));
}

Api::SysCallIntResult
KtlsSocketHandleImpl::connect(Network::Address::InstanceConstSharedPtr address) {
  return io_handle_->connect(address);
}

Api::SysCallIntResult KtlsSocketHandleImpl::setOption(int level, int optname, const void* optval,
                                                      socklen_t optlen) {
  return io_handle_->setOption(level, optname, optval, optlen);
}

Api::SysCallIntResult KtlsSocketHandleImpl::getOption(int level, int optname, void* optval,
                                                      socklen_t* optlen) {
  return io_handle_->getOption(level, optname, optval, optlen);
}

Api::SysCallIntResult KtlsSocketHandleImpl::ioctl(unsigned long control_code, void* in_buffer,
                                                  unsigned long in_buffer_len, void* out_buffer,
                                                  unsigned long out_buffer_len,
                                                  unsigned long* bytes_returned) {
  return io_handle_->ioctl(control_code, in_buffer, in_buffer_len, out_buffer, out_buffer_len,
                           bytes_returned);
}

Api::SysCallIntResult KtlsSocketHandleImpl::setBlocking(bool blocking) {
  return io_handle_->setBlocking(blocking);
}

absl::optional<int> KtlsSocketHandleImpl::domain() { return io_handle_->domain(); }

absl::StatusOr<Network::Address::InstanceConstSharedPtr> KtlsSocketHandleImpl::localAddress() {
  return io_handle_->localAddress();
}

absl::StatusOr<Network::Address::InstanceConstSharedPtr> KtlsSocketHandleImpl::peerAddress() {
  return io_handle_->peerAddress();
}

std::unique_ptr<Network::IoHandle> KtlsSocketHandleImpl::duplicate() {
  auto duplicated = io_handle_->duplicate();
  if (duplicated == nullptr) {
    return nullptr;
  }
  return std::make_unique<KtlsSocketHandleImpl>(std::move(duplicated));
}

void KtlsSocketHandleImpl::initializeFileEvent(Event::Dispatcher& dispatcher, Event::FileReadyCb cb,
                                               Event::FileTriggerType trigger, uint32_t events) {
  io_handle_->initializeFileEvent(dispatcher, cb, trigger, events);
}

void KtlsSocketHandleImpl::activateFileEvents(uint32_t events) {
  io_handle_->activateFileEvents(events);
}

void KtlsSocketHandleImpl::enableFileEvents(uint32_t events) {
  io_handle_->enableFileEvents(events);
}

void KtlsSocketHandleImpl::resetFileEvents() { io_handle_->resetFileEvents(); }

Api::SysCallIntResult KtlsSocketHandleImpl::shutdown(int how) { return io_handle_->shutdown(how); }

absl::optional<std::chrono::milliseconds> KtlsSocketHandleImpl::lastRoundTripTime() {
  return io_handle_->lastRoundTripTime();
}

absl::optional<uint64_t> KtlsSocketHandleImpl::congestionWindowInBytes() const {
  return io_handle_->congestionWindowInBytes();
}

absl::optional<std::string> KtlsSocketHandleImpl::interfaceName() {
  return io_handle_->interfaceName();
}

bool KtlsSocketHandleImpl::supportsTls() const {
  return true; // We specifically support TLS as that's the point of kTLS
}

Api::IoCallUint64Result
KtlsSocketHandleImpl::sendmsg(const Buffer::RawSlice* slices, uint64_t num_slice, int flags,
                              const Network::Address::Ip* self_ip,
                              const Network::Address::Instance& peer_address) {
  return io_handle_->sendmsg(slices, num_slice, flags, self_ip, peer_address);
}

Api::IoCallUint64Result
KtlsSocketHandleImpl::recvmsg(Buffer::RawSlice* slices, const uint64_t num_slice,
                              uint32_t self_port,
                              const Network::IoHandle::UdpSaveCmsgConfig& save_cmsg_config,
                              Network::IoHandle::RecvMsgOutput& output) {
  return io_handle_->recvmsg(slices, num_slice, self_port, save_cmsg_config, output);
}

Api::IoCallUint64Result
KtlsSocketHandleImpl::recvmmsg(RawSliceArrays& slices, uint32_t self_port,
                               const Network::IoHandle::UdpSaveCmsgConfig& save_cmsg_config,
                               Network::IoHandle::RecvMsgOutput& output) {
  return io_handle_->recvmmsg(slices, self_port, save_cmsg_config, output);
}

Api::IoCallUint64Result KtlsSocketHandleImpl::recv(void* buffer, size_t length, int flags) {
  return io_handle_->recv(buffer, length, flags);
}

bool KtlsSocketHandleImpl::supportsMmsg() const { return io_handle_->supportsMmsg(); }

bool KtlsSocketHandleImpl::supportsUdpGro() const { return io_handle_->supportsUdpGro(); }

bool KtlsSocketHandleImpl::enableKtls() {
  // kTLS is actually enabled at the transport socket level, not here
  // This method exists just to expose the API
  return true;
}

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
