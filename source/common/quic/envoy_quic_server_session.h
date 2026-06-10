#pragma once

#include <memory>
#include <ostream>

#include "source/common/http/session_idle_list_interface.h"
#include "source/common/quic/envoy_quic_connection_debug_visitor_factory_interface.h"
#include "source/common/quic/envoy_quic_server_connection.h"
#include "source/common/quic/envoy_quic_server_crypto_stream_factory.h"
#include "source/common/quic/envoy_quic_server_stream.h"
#include "source/common/quic/quic_filter_manager_connection_impl.h"
#include "source/common/quic/quic_stat_names.h"
#include "source/common/quic/send_buffer_monitor.h"
#include "source/common/quic/web_transport_stats.h"

#include "quiche/quic/core/http/quic_server_session_base.h"
#include "quiche/quic/core/quic_crypto_server_stream.h"
#include "quiche/quic/core/tls_server_handshaker.h"

namespace Envoy {
namespace Quic {

#define QUIC_CONNECTION_STATS(COUNTER)                                                             \
  COUNTER(num_server_migration_detected)                                                           \
  COUNTER(num_packets_rx_on_preferred_address)

struct QuicConnectionStats {
  QUIC_CONNECTION_STATS(GENERATE_COUNTER_STRUCT)
};

using FilterChainToConnectionMap =
    absl::flat_hash_map<const Network::FilterChain*,
                        std::list<std::reference_wrapper<Network::Connection>>>;
using ConnectionMapIter = std::list<std::reference_wrapper<Network::Connection>>::iterator;

// Used to track the matching filter chain and its position in the filter chain to connection map.
struct ConnectionMapPosition {
  ConnectionMapPosition(FilterChainToConnectionMap& connection_map,
                        const Network::FilterChain& filter_chain, ConnectionMapIter iterator)
      : connection_map_(connection_map), filter_chain_(filter_chain), iterator_(iterator) {}

  // Stores the map from filter chain of connections.
  FilterChainToConnectionMap& connection_map_;
  // The matching filter chain of a connection.
  const Network::FilterChain& filter_chain_;
  // The position of the connection in the map.
  ConnectionMapIter iterator_;
};

// Act as a Network::Connection to HCM and a FilterManager to FilterFactoryCb.
// TODO(danzh) Lifetime of quic connection and filter manager connection can be
// simplified by changing the inheritance to a member variable instantiated
// before quic_connection_.
class EnvoyQuicServerSession : public quic::QuicServerSessionBase,
                               public QuicFilterManagerConnectionImpl,
                               public Envoy::Http::IdleSessionInterface {
public:
  EnvoyQuicServerSession(
      const quic::QuicConfig& config, const quic::ParsedQuicVersionVector& supported_versions,
      std::unique_ptr<EnvoyQuicServerConnection> connection, quic::QuicSession::Visitor* visitor,
      quic::QuicCryptoServerStreamBase::Helper* helper,
      const quic::QuicCryptoServerConfig* crypto_config,
      quic::QuicCompressedCertsCache* compressed_certs_cache, Event::Dispatcher& dispatcher,
      uint32_t send_buffer_limit, QuicStatNames& quic_stat_names, Stats::Scope& listener_scope,
      EnvoyQuicCryptoServerStreamFactoryInterface& crypto_server_stream_factory,
      std::unique_ptr<StreamInfo::StreamInfo>&& stream_info, QuicConnectionStats& connection_stats,
      EnvoyQuicConnectionDebugVisitorFactoryInterfaceOptRef debug_visitor_factory,
      Http::SessionIdleListInterface* session_idle_list);

  ~EnvoyQuicServerSession() override;

  // Network::Connection
  absl::string_view requestedServerName() const override;
  void dumpState(std::ostream&, int) const override {
    // TODO(kbaichoo): Implement dumpState for H3.
  }

  // Called by QuicHttpServerConnectionImpl before creating data streams.
  void setHttpConnectionCallbacks(Http::ServerConnectionCallbacks& callbacks) {
    http_connection_callbacks_ = &callbacks;
  }

  void setH3GoAwayLoadShedPoints(Server::LoadShedPoint* should_send_go_away_and_close_on_dispatch,
                                 Server::LoadShedPoint* should_send_go_away_on_dispatch) {
    ENVOY_LOG_ONCE_IF(trace, should_send_go_away_and_close_on_dispatch == nullptr,
                      "LoadShedPoint "
                      "envoy.load_shed_points.http3_server_go_away_and_close_on_dispatch "
                      "is not found. Is it configured?");
    ENVOY_LOG_ONCE_IF(trace, should_send_go_away_on_dispatch == nullptr,
                      "LoadShedPoint envoy.load_shed_points.http3_server_go_away_on_dispatch "
                      "is not found. Is it configured?");
    should_send_go_away_and_close_on_dispatch_ = should_send_go_away_and_close_on_dispatch;
    should_send_go_away_on_dispatch_ = should_send_go_away_on_dispatch;
  }

  void setWebTransportAcceptLoadShedPoint(Server::LoadShedPoint* web_transport_accept) {
    web_transport_accept_load_shed_point_ = web_transport_accept;
  }

  // Whether the connection is shedding load, so a new WebTransport session should be refused.
  bool webTransportSheddingLoad() {
    return web_transport_accept_load_shed_point_ != nullptr &&
           web_transport_accept_load_shed_point_->shouldShedLoad();
  }

  // quic::QuicSession
  void OnConnectionClosed(const quic::QuicConnectionCloseFrame& frame,
                          quic::ConnectionCloseSource source) override;
  void Initialize() override;
  void OnCanWrite() override;
  void OnTlsHandshakeComplete() override;
  void OnRstStream(const quic::QuicRstStreamFrame& frame) override;
  void ProcessUdpPacket(const quic::QuicSocketAddress& self_address,
                        const quic::QuicSocketAddress& peer_address,
                        const quic::QuicReceivedPacket& packet) override;
  std::vector<absl::string_view>::const_iterator
  SelectAlpn(const std::vector<absl::string_view>& alpns) const override;

  void setHeadersWithUnderscoreAction(
      envoy::config::core::v3::HttpProtocolOptions::HeadersWithUnderscoresAction
          headers_with_underscores_action) {
    headers_with_underscores_action_ = headers_with_underscores_action;
  }

  void storeConnectionMapPosition(FilterChainToConnectionMap& connection_map,
                                  const Network::FilterChain& filter_chain,
                                  ConnectionMapIter position);

  bool setSocketOption(Envoy::Network::SocketOptionName, absl::Span<uint8_t>) override {
    return false;
  }

  void setHttp3Options(const envoy::config::core::v3::Http3ProtocolOptions& http3_options) override;

  // Overridden to remove the session from the idle list when the last stream is
  // closed.
  void OnStreamClosed(quic::QuicStreamId id) override;

  // IdleSessionInterface
  // NOLINTNEXTLINE(readability-identifier-naming)
  void TerminateIdleSession() override;

  using quic::QuicSession::PerformActionOnActiveStreams;

  // WebTransport stats for this connection, in the webtransport sub-scope.
  WebTransportStats& webTransportStats() {
    return WebTransportStats::atomicGet(web_transport_stats_, stats_scope_);
  }

  // Per-connection WebTransport session accounting. A new session is refused once the active count
  // reaches the cap.
  bool webTransportSessionLimitReached() const {
    return active_web_transport_sessions_ >= max_web_transport_sessions_;
  }
  void onWebTransportSessionOpened() { ++active_web_transport_sessions_; }
  void onWebTransportSessionClosed() { --active_web_transport_sessions_; }
  // Per-session WebTransport stream cap. Zero means no Envoy level limit.
  uint32_t maxWebTransportStreamsPerSession() const {
    return max_web_transport_streams_per_session_;
  }

protected:
  // quic::QuicServerSessionBase
  std::unique_ptr<quic::QuicCryptoServerStreamBase>
  CreateQuicCryptoServerStream(const quic::QuicCryptoServerConfig* crypto_config,
                               quic::QuicCompressedCertsCache* compressed_certs_cache) override;
  quic::QuicSSLConfig GetSSLConfig() const override;

  // quic::QuicSession
  // Overridden to create stream as encoder and associate it with an decoder.
  quic::QuicSpdyStream* CreateIncomingStream(quic::QuicStreamId id) override;
  quic::QuicSpdyStream* CreateOutgoingBidirectionalStream() override;

  quic::HttpDatagramSupport LocalHttpDatagramSupport() override { return http_datagram_support_; }

  // quic::QuicSpdySession
  // Advertises WebTransport only when it is latched on in setHttp3Options(). Flag flips apply to
  // new connections only.
  quic::WebTransportHttp3VersionSet LocallySupportedWebTransportVersions() const override {
    return web_transport_enabled_ ? quic::kDefaultSupportedWebTransportVersions
                                  : quic::WebTransportHttp3VersionSet();
  }

  // QuicFilterManagerConnectionImpl
  bool hasDataToWrite() override;
  // Used by base class to access quic connection after initialization.
  const quic::QuicConnection* quicConnection() const override;
  quic::QuicConnection* quicConnection() override;
  // NOLINTNEXTLINE(readability-identifier-naming)
  void MaybeAddSessionToIdleList();
  // NOLINTNEXTLINE(readability-identifier-naming)
  void MaybeRemoveSessionFromIdleList();

private:
  void setUpRequestDecoder(EnvoyQuicServerStream& stream);
  void ActivateStream(std::unique_ptr<quic::QuicStream> stream) override;
  // NOLINTNEXTLINE(readability-identifier-naming)
  void OnLastActiveStreamClosed();

  std::unique_ptr<EnvoyQuicServerConnection> quic_connection_;
  // These callbacks are owned by network filters and quic session should out live
  // them.
  Http::ServerConnectionCallbacks* http_connection_callbacks_{nullptr};

  envoy::config::core::v3::HttpProtocolOptions::HeadersWithUnderscoresAction
      headers_with_underscores_action_;

  EnvoyQuicCryptoServerStreamFactoryInterface& crypto_server_stream_factory_;
  absl::optional<ConnectionMapPosition> position_;
  QuicConnectionStats& connection_stats_;
  quic::HttpDatagramSupport http_datagram_support_ = quic::HttpDatagramSupport::kNone;
  // Whether to advertise WebTransport support, latched once in setHttp3Options().
  bool web_transport_enabled_ = false;
  // Maximum concurrent WebTransport sessions per connection, latched in setHttp3Options().
  uint32_t max_web_transport_sessions_ = 16;
  // Maximum concurrent WebTransport streams per session, latched in setHttp3Options(). Zero means
  // no Envoy level limit.
  uint32_t max_web_transport_streams_per_session_ = 0;
  uint32_t active_web_transport_sessions_ = 0;
  WebTransportStats::AtomicPtr web_transport_stats_;
  std::unique_ptr<quic::QuicConnectionDebugVisitor> debug_visitor_;
  // Load shed points for H3 GoAway
  Server::LoadShedPoint* should_send_go_away_and_close_on_dispatch_ = nullptr;
  Server::LoadShedPoint* should_send_go_away_on_dispatch_ = nullptr;
  Server::LoadShedPoint* web_transport_accept_load_shed_point_ = nullptr;
  Http::SessionIdleListInterface* session_idle_list_;
  bool h3_go_away_sent_ = false;
  bool on_connection_closed_called_ = false;
  bool is_in_idle_list_ = false;
};

} // namespace Quic
} // namespace Envoy
