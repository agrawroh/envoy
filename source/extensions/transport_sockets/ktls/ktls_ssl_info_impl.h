#pragma once

#include "source/extensions/transport_sockets/ktls/ktls_ssl_info.h"
#include "source/common/tls/connection_info_impl_base.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace KTls {

/**
 * Implementation of KTlsInfo that uses the ConnectionInfoImplBase.
 */
class KTlsInfoImpl : public KTlsInfo, public Extensions::TransportSockets::Tls::ConnectionInfoImplBase {
public:
  KTlsInfoImpl(SSL* ssl) : ssl_(ssl) {}
  
  // KTlsInfo
  bool extractCryptoInfo(tls12_crypto_info_aes_gcm_128& crypto_info, bool is_tx) const override;
  SSL* ssl() const override { return ssl_; }

  // ConnectionInfoImplBase
  SSL* ssl() const override { return ssl_; }

private:
  SSL* ssl_;
};

} // namespace KTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy 