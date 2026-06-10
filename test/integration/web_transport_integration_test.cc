#include <functional>

#include "test/integration/quic_http_integration_test.h"

#include "quiche/quic/core/http/web_transport_http3.h"

namespace Envoy {
namespace Quic {
namespace {

// A client session that advertises WebTransport support so the server negotiates it.
class WebTransportClientSession : public EnvoyQuicClientSession {
public:
  using EnvoyQuicClientSession::EnvoyQuicClientSession;

  quic::WebTransportHttp3VersionSet LocallySupportedWebTransportVersions() const override {
    return quic::kDefaultSupportedWebTransportVersions;
  }
};

// A client session visitor that records received datagrams and runs a callback on each one.
class CapturingWebTransportVisitor : public quic::WebTransportVisitor {
public:
  explicit CapturingWebTransportVisitor(std::function<void()> on_datagram)
      : on_datagram_(std::move(on_datagram)) {}

  void OnSessionReady() override {}
  void OnSessionClosed(webtransport::SessionErrorCode, const std::string&) override {}
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view datagram) override {
    received_.emplace_back(datagram);
    on_datagram_();
  }
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  const std::vector<std::string>& received() const { return received_; }

private:
  std::vector<std::string> received_;
  std::function<void()> on_datagram_;
};

class WebTransportIntegrationTest : public QuicHttpIntegrationTestBase,
                                    public testing::TestWithParam<Network::Address::IpVersion> {
public:
  WebTransportIntegrationTest()
      : QuicHttpIntegrationTestBase(GetParam(), ConfigHelper::quicHttpProxyConfig()) {}

  // Enables the runtime guard, allows extended CONNECT, registers the WebTransport upgrade and
  // prepends the terminating filter.
  void setup() {
    config_helper_.addRuntimeOverride("envoy.reloadable_features.web_transport", "true");
    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          hcm.mutable_http3_protocol_options()->set_allow_extended_connect(true);
          hcm.mutable_http3_protocol_options()->mutable_web_transport_options()->set_enabled(true);
          hcm.add_upgrade_configs()->set_upgrade_type("webtransport");
        });
    config_helper_.prependFilter(R"EOF(
name: envoy.filters.http.web_transport
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.web_transport.v3.WebTransport
)EOF");
    initialize();
  }

  Http::TestRequestHeaderMapImpl webTransportConnectHeaders() {
    return Http::TestRequestHeaderMapImpl{{":method", "CONNECT"},
                                          {":protocol", "webtransport"},
                                          {":scheme", "https"},
                                          {":path", "/"},
                                          {":authority", "host"}};
  }

  // Name of a WebTransport stat in this listener sub-scope.
  std::string webTransportStat(absl::string_view name) {
    return absl::StrCat("listener.",
                        version_ == Network::Address::IpVersion::v4 ? "127.0.0.1_0" : "[__1]_0",
                        ".webtransport.", name);
  }

  // Sends a WebTransport CONNECT, waits for the 200 and returns the client-side QUICHE session.
  quic::WebTransportHttp3* establishWebTransportSession(IntegrationStreamDecoderPtr& response) {
    auto encoder_decoder = codec_client_->startRequest(webTransportConnectHeaders());
    request_encoder_ = &encoder_decoder.first;
    response = std::move(encoder_decoder.second);
    response->waitForHeaders();
    EXPECT_EQ("200", response->headers().getStatusValue());
    return client_session_->GetWebTransportSession(
        request_encoder_->getStream().codecStreamId().value());
  }

protected:
  std::unique_ptr<EnvoyQuicClientSession>
  makeClientSession(PersistentQuicInfoImpl& persistent_info,
                    std::unique_ptr<EnvoyQuicClientConnection> connection,
                    quic::QuicForceBlockablePacketWriter* wrapper,
                    EnvoyQuicClientConnection::EnvoyQuicMigrationHelper* migration_helper,
                    const quic::QuicServerId& server_id,
                    OptRef<Http::HttpServerPropertiesCache> cache) override {
    auto session = std::make_unique<WebTransportClientSession>(
        persistent_info.quic_config_, supported_versions_, std::move(connection), wrapper,
        migration_helper, migration_config_, server_id,
        transport_socket_factory_->getCryptoConfig(), *dispatcher_,
        2 * Http2::Utility::OptionsLimits::MIN_INITIAL_STREAM_WINDOW_SIZE,
        persistent_info.crypto_stream_factory_, quic_stat_names_, cache, *stats_store_.rootScope(),
        nullptr, *transport_socket_factory_);
    client_session_ = session.get();
    return session;
  }

  WebTransportClientSession* client_session_{nullptr};
};

INSTANTIATE_TEST_SUITE_P(IpVersions, WebTransportIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// A negotiated WebTransport CONNECT is terminated by the filter with a 200 and the session stays
// open. Drives the bridge accept() against a real QUICHE session.
TEST_P(WebTransportIntegrationTest, ConnectAccepted) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  IntegrationStreamDecoderPtr response;
  quic::WebTransportHttp3* session = establishWebTransportSession(response);
  EXPECT_NE(nullptr, session);
  EXPECT_FALSE(response->complete());

  codec_client_->close();
}

// A datagram sent on the session is echoed back by the terminating filter. This drives the bridge
// send and receive paths against a real QUICHE session.
TEST_P(WebTransportIntegrationTest, DatagramEcho) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  IntegrationStreamDecoderPtr response;
  quic::WebTransportHttp3* session = establishWebTransportSession(response);
  ASSERT_NE(nullptr, session);

  auto visitor = std::make_unique<CapturingWebTransportVisitor>([this] { dispatcher_->exit(); });
  CapturingWebTransportVisitor* visitor_ptr = visitor.get();
  session->SetVisitor(std::move(visitor));
  session->SendOrQueueDatagram("ping");

  // Run the client until the echoed datagram arrives, with a timeout guard.
  bool timed_out = false;
  Event::TimerPtr timer = dispatcher_->createTimer([this, &timed_out] {
    timed_out = true;
    dispatcher_->exit();
  });
  timer->enableTimer(TestUtility::DefaultTimeout);
  while (visitor_ptr->received().empty() && !timed_out) {
    dispatcher_->run(Event::Dispatcher::RunType::Block);
  }
  ASSERT_FALSE(timed_out);
  EXPECT_EQ("ping", visitor_ptr->received()[0]);

  test_server_->waitForGauge(webTransportStat("sessions_active"), testing::Eq(1));
  test_server_->waitForCounter(webTransportStat("sessions_total"), testing::Eq(1));
  test_server_->waitForCounter(webTransportStat("datagrams_rx"), testing::Eq(1));
  test_server_->waitForCounter(webTransportStat("datagrams_tx"), testing::Eq(1));

  codec_client_->close();

  // The active gauge returns to zero on close while the cumulative session counter stays.
  test_server_->waitForGauge(webTransportStat("sessions_active"), testing::Eq(0));
  test_server_->waitForCounter(webTransportStat("sessions_total"), testing::Eq(1));
}

// An interim 1xx before the accept does not poison the WebTransport response handling.
TEST_P(WebTransportIntegrationTest, InterimResponseBeforeAccept) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  // Expect 100-continue makes the server send an interim 100 before the filter accepts.
  Http::TestRequestHeaderMapImpl headers{{":method", "CONNECT"}, {":protocol", "webtransport"},
                                         {":scheme", "https"},   {":path", "/"},
                                         {":authority", "host"}, {"expect", "100-continue"}};
  auto encoder_decoder = codec_client_->startRequest(headers);
  request_encoder_ = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  response->waitForHeaders();
  EXPECT_EQ("200", response->headers().getStatusValue());
  test_server_->waitForGauge(webTransportStat("sessions_active"), testing::Eq(1));

  codec_client_->close();
}

// Resetting the CONNECT stream mid-session tears the session down cleanly on the server.
TEST_P(WebTransportIntegrationTest, ResetMidSession) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  IntegrationStreamDecoderPtr response;
  quic::WebTransportHttp3* session = establishWebTransportSession(response);
  ASSERT_NE(nullptr, session);
  test_server_->waitForGauge(webTransportStat("sessions_active"), testing::Eq(1));

  request_encoder_->getStream().resetStream(Http::StreamResetReason::LocalReset);

  test_server_->waitForGauge(webTransportStat("sessions_active"), testing::Eq(0));

  codec_client_->close();
}

// A non-WebTransport request is not touched by the filter and is proxied upstream as usual.
TEST_P(WebTransportIntegrationTest, NonWebTransportRequestPassesThrough) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "host"}});
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(default_response_headers_, true);

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());
}

// A WebTransport CONNECT that also carries a capsule-protocol header is still accepted. QUICHE is
// already the stream datagram visitor, so capsule setup must be skipped to avoid a crash.
TEST_P(WebTransportIntegrationTest, CapsuleProtocolHeaderAccepted) {
#ifndef ENVOY_ENABLE_HTTP_DATAGRAMS
  GTEST_SKIP() << "WebTransport requires HTTP/3 datagram support.";
#endif
  setup();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  Http::TestRequestHeaderMapImpl headers{{":method", "CONNECT"}, {":protocol", "webtransport"},
                                         {":scheme", "https"},   {":path", "/"},
                                         {":authority", "host"}, {"capsule-protocol", "?1"}};
  auto encoder_decoder = codec_client_->startRequest(headers);
  auto response = std::move(encoder_decoder.second);

  response->waitForHeaders();
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_FALSE(response->complete());

  codec_client_->close();
}

} // namespace
} // namespace Quic
} // namespace Envoy
