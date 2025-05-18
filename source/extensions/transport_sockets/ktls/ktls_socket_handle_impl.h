#pragma once

#include <cstddef>
#include <memory>

#include "envoy/network/io_handle.h"

#include "source/common/common/logger.h"

#include "absl/status/statusor.h"

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

  // Socket status methods
  bool wasConnected() const override;
  Api::SysCallIntResult bind(Network::Address::InstanceConstSharedPtr address) override;
  Api::SysCallIntResult listen(int backlog) override;
  std::unique_ptr<Network::IoHandle> accept(struct sockaddr* addr, socklen_t* addrlen) override;
  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr address) override;
  Api::SysCallIntResult setOption(int level, int optname, const void* optval,
                                  socklen_t optlen) override;
  Api::SysCallIntResult getOption(int level, int optname, void* optval, socklen_t* optlen) override;
  Api::SysCallIntResult ioctl(unsigned long control_code, void* in_buffer,
                              unsigned long in_buffer_len, void* out_buffer,
                              unsigned long out_buffer_len, unsigned long* bytes_returned) override;
  Api::SysCallIntResult setBlocking(bool blocking) override;
  absl::optional<int> domain() override;
  absl::StatusOr<Network::Address::InstanceConstSharedPtr> localAddress() override;
  absl::StatusOr<Network::Address::InstanceConstSharedPtr> peerAddress() override;
  std::unique_ptr<Network::IoHandle> duplicate() override;
  void initializeFileEvent(Event::Dispatcher& dispatcher, Event::FileReadyCb cb,
                           Event::FileTriggerType trigger, uint32_t events) override;
  void activateFileEvents(uint32_t events) override;
  void enableFileEvents(uint32_t events) override;
  void resetFileEvents() override;
  Api::SysCallIntResult shutdown(int how) override;
  absl::optional<std::chrono::milliseconds> lastRoundTripTime() override;
  absl::optional<uint64_t> congestionWindowInBytes() const override;
  absl::optional<std::string> interfaceName() override;
  bool supportsTls() const override;

  // Datagram-specific UDP functionality
  Api::IoCallUint64Result sendmsg(const Buffer::RawSlice* slices, uint64_t num_slice, int flags,
                                  const Network::Address::Ip* self_ip,
                                  const Network::Address::Instance& peer_address) override;

  Api::IoCallUint64Result recvmsg(Buffer::RawSlice* slices, const uint64_t num_slice,
                                  uint32_t self_port,
                                  const Network::IoHandle::UdpSaveCmsgConfig& save_cmsg_config,
                                  Network::IoHandle::RecvMsgOutput& output) override;

  Api::IoCallUint64Result recvmmsg(RawSliceArrays& slices, uint32_t self_port,
                                   const Network::IoHandle::UdpSaveCmsgConfig& save_cmsg_config,
                                   Network::IoHandle::RecvMsgOutput& output) override;

  Api::IoCallUint64Result recv(void* buffer, size_t length, int flags) override;

  bool supportsMmsg() const override;
  bool supportsUdpGro() const override;

  // Enable kTLS for this socket.
  bool enableKtls();

private:
  Network::IoHandlePtr io_handle_;
};

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
