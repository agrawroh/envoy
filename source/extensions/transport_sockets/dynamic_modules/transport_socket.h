#pragma once

#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/network/transport_socket.h"
#include "envoy/upstream/host_description.h"

#include "source/common/common/logger.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/extensions/transport_sockets/dynamic_modules/config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace DynamicModules {

/**
 * Transport socket implementation that delegates to a dynamic module via the transport socket ABI.
 */
class DynamicModuleTransportSocket : public Network::TransportSocket,
                                     public Logger::Loggable<Logger::Id::dynamic_modules> {
public:
  DynamicModuleTransportSocket(DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config,
                               bool is_upstream,
                               Network::TransportSocketOptionsConstSharedPtr options = nullptr);

  ~DynamicModuleTransportSocket() override;

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  absl::string_view failureReason() const override;
  bool canFlushClose() override;
  void closeSocket(Network::ConnectionEvent event) override;
  void onConnected() override;
  Network::IoResult doRead(Buffer::Instance& buffer) override;
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override;
  Ssl::ConnectionInfoConstSharedPtr ssl() const override { return nullptr; }
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) override {}

  envoy_dynamic_module_type_transport_socket_envoy_ptr thisAsEnvoyPtr() {
    return static_cast<envoy_dynamic_module_type_transport_socket_envoy_ptr>(this);
  }

  Network::TransportSocketCallbacks* transportCallbacks() { return callbacks_; }

  Buffer::Instance* activeReadBuffer() { return active_read_buffer_; }
  Buffer::Instance* activeWriteBuffer() { return active_write_buffer_; }

  const Network::TransportSocketOptions* transportSocketOptions() const {
    return transport_socket_options_.get();
  }

  void setActiveReadReservation(std::unique_ptr<Buffer::Reservation> reservation) {
    active_read_reservation_ = std::move(reservation);
  }
  Buffer::Reservation* activeReadReservation() { return active_read_reservation_.get(); }

private:
  void refreshProtocolString() const;
  void refreshFailureReasonString() const;

  DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config_;

  Network::TransportSocketCallbacks* callbacks_{nullptr};
  envoy_dynamic_module_type_transport_socket_module_ptr socket_module_{nullptr};

  Buffer::Instance* active_read_buffer_{nullptr};
  Buffer::Instance* active_write_buffer_{nullptr};
  std::unique_ptr<Buffer::Reservation> active_read_reservation_;

  Network::TransportSocketOptionsConstSharedPtr transport_socket_options_;

  mutable std::string protocol_storage_;
  mutable std::string failure_reason_storage_;
};

class DynamicModuleUpstreamTransportSocketFactory
    : public Network::CommonUpstreamTransportSocketFactory {
public:
  DynamicModuleUpstreamTransportSocketFactory(
      DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config, std::string default_sni,
      std::vector<std::string> alpn_protocols, bool implements_secure_transport = false);

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        Upstream::HostDescriptionConstSharedPtr host) const override;

  bool implementsSecureTransport() const override { return implements_secure_transport_; }

  absl::string_view defaultServerNameIndication() const override { return default_sni_; }

  bool supportsAlpn() const override { return !alpn_protocols_.empty(); }

  void hashKey(std::vector<uint8_t>& key,
               Network::TransportSocketOptionsConstSharedPtr options) const override;

private:
  DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config_;
  const std::string default_sni_;
  const std::vector<std::string> alpn_protocols_;
  const bool implements_secure_transport_;
};

class DynamicModuleDownstreamTransportSocketFactory
    : public Network::DownstreamTransportSocketFactory {
public:
  explicit DynamicModuleDownstreamTransportSocketFactory(
      DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config,
      bool implements_secure_transport = false);

  Network::TransportSocketPtr createDownstreamTransportSocket() const override;

  bool implementsSecureTransport() const override { return implements_secure_transport_; }

private:
  DynamicModuleTransportSocketFactoryConfigSharedPtr factory_config_;
  const bool implements_secure_transport_;
};

} // namespace DynamicModules
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
