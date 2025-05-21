#pragma once

#include <array>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "envoy/ssl/connection.h"
#include "envoy/network/transport_socket.h"

#include "source/common/common/matchers.h"
#include "source/common/common/utility.h"
#include "source/extensions/transport_sockets/ktls/tls_compat.h"

namespace Envoy {
  namespace Extensions {
    namespace TransportSockets {
      namespace Ktls {

        class KtlsSslInfoImpl : public Ssl::ConnectionInfo {
        public:
          KtlsSslInfoImpl(Network::TransportSocketPtr&& ssl_socket);

          // Ssl::ConnectionInfo implementation
          const std::string& tlsVersion() const override;
          const std::string& ciphersuiteString() const override;
          const std::string& sessionId() const override;
          bool peerCertificatePresented() const override;
          bool peerCertificateValidated() const override;
          Ssl::ConnectionInfoConstSharedPtr ssl() const;

          // kTLS-specific methods
          bool getTxCryptoInfo(tls_crypto_info_t& crypto_info);
          bool getRxCryptoInfo(tls_crypto_info_t& crypto_info);
          bool extractCryptoParams();
          bool initializeSequenceNumbers(int ktls_mode);

        private:
          bool extractKeyMaterial(SSL* ssl_handle);

          Network::TransportSocketPtr ssl_socket_;
          bool is_client_;
          mutable bool params_extracted_;

          // Key material storage
          mutable std::vector<uint8_t> client_write_key_;
          mutable std::vector<uint8_t> server_write_key_;
          mutable std::vector<uint8_t> client_write_iv_;
          mutable std::vector<uint8_t> server_write_iv_;
          mutable std::vector<uint8_t> client_write_seq_;
          mutable std::vector<uint8_t> server_write_seq_;

          // String storage for returned string references
          mutable std::string tls_version_storage_;
          mutable std::string cipher_suite_storage_;
          mutable std::string session_id_storage_;
        };

      } // namespace Ktls
    } // namespace TransportSockets
  } // namespace Extensions
} // namespace Envoy
