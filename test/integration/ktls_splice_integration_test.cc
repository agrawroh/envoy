#include <string>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/network/transport_socket.h"
#include "envoy/stats/stats.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/transport_sockets/common/passthrough.h"

#include "test/integration/http_integration.h"
#include "test/test_common/registry.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"

// The L7 HTTP/1.1 kTLS body-splice fast-path relies on splice() over the loopback fds, which is
// Linux-only, so the whole fixture is gated to Linux. No kernel-TLS dependency is introduced: the
// fake upstream transport socket below wraps plaintext raw_buffer and only REPORTS kTLS installed,
// so the splice arms deterministically on any Linux kernel and relays plaintext fd to fd unchanged.
#ifdef __linux__

namespace Envoy {
namespace {

// A test-only upstream transport socket that delegates everything to an inner raw_buffer socket but
// reports kernel-TLS installed and a trusted peer. The bytes on the wire stay plaintext, so the
// splice's fd to fd relay is byte-for-byte correct without any real kTLS. This lets the L7
// body-splice arm against the upstream (cluster) leg on any Linux kernel.
class FakeKtlsSocket : public Extensions::TransportSockets::PassthroughSocket {
public:
  FakeKtlsSocket(Network::TransportSocketPtr&& inner_socket)
      : PassthroughSocket(std::move(inner_socket)) {}

  // Capture the callbacks so the reported fd can be read off the real loopback socket, then forward
  // to the inner raw_buffer socket as the passthrough contract requires.
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override {
    callbacks_ = &callbacks;
    PassthroughSocket::setTransportSocketCallbacks(callbacks);
  }

  // Report kTLS installed and trusted so SpliceCoordinator treats the upstream leg as a decrypted,
  // safe-to-relay source. The returned reference must outlive the call, so it is backed by a
  // member. The fd here is informational for the splice path (engage() reads the connection's own
  // getSocket() fd), but report the real loopback fd anyway so the info is self-consistent.
  OptRef<const Network::KtlsBytestreamInfo> ktlsBytestreamInfo() const override {
    info_.installed = true;
    info_.trusted_peer = true;
    info_.fd = callbacks_ != nullptr ? callbacks_->ioHandle().fdDoNotUse() : -1;
    return info_;
  }

private:
  Network::TransportSocketCallbacks* callbacks_{};
  // Backing store for the OptRef returned by ktlsBytestreamInfo, refreshed per call.
  mutable Network::KtlsBytestreamInfo info_{};
};

// Wraps an inner raw_buffer upstream factory and produces FakeKtlsSocket instances.
class FakeKtlsSocketFactory : public Extensions::TransportSockets::PassthroughFactory {
public:
  FakeKtlsSocketFactory(Network::UpstreamTransportSocketFactoryPtr&& inner_factory)
      : PassthroughFactory(std::move(inner_factory)) {}

  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        Upstream::HostDescriptionConstSharedPtr host) const override {
    auto inner_socket = transport_socket_factory_->createTransportSocket(options, host);
    if (inner_socket == nullptr) {
      return nullptr;
    }
    return std::make_unique<FakeKtlsSocket>(std::move(inner_socket));
  }
};

// Config factory registering the fake upstream socket as envoy.transport_sockets.fake_ktls. It
// takes no parameters (an empty google.protobuf.Struct, which Envoy's config utility permits as a
// typed_config where google.protobuf.Empty is rejected) and builds the inner raw_buffer factory
// directly.
class FakeKtlsConfigFactory : public Server::Configuration::UpstreamTransportSocketConfigFactory {
public:
  std::string name() const override { return "envoy.transport_sockets.fake_ktls"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::Struct>();
  }

  absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
  createTransportSocketFactory(const Protobuf::Message&,
                               Server::Configuration::TransportSocketFactoryContext&) override {
    return std::make_unique<FakeKtlsSocketFactory>(
        std::make_unique<Network::RawBufferSocketFactory>());
  }
};

// Builds a deterministic body so the spliced bytes can be asserted byte-for-byte at the client.
std::string makeBody(uint64_t size) {
  std::string body;
  body.reserve(size);
  for (uint64_t i = 0; i < size; i++) {
    body.push_back(static_cast<char>('A' + (i % 26)));
  }
  return body;
}

// Minimum body the splice engages on, mirrored from SpliceCoordinator::MinSpliceBodyBytes.
constexpr uint64_t MinSpliceBodyBytes = 64 * 1024;

class KtlsSpliceIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                  public HttpIntegrationTest {
public:
  KtlsSpliceIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, GetParam()) {}

  void initializeWithFakeKtlsUpstream() {
    // Arm the body-splice (a FALSE_RUNTIME_GUARD, so nothing engages unless it is on) and point
    // cluster_0 at the fake kTLS upstream socket. The downstream listener stays plaintext.
    config_helper_.addRuntimeOverride("envoy.reloadable_features.http1_ktls_body_splice", "true");
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* cluster_transport_socket =
          bootstrap.mutable_static_resources()->mutable_clusters(0)->mutable_transport_socket();
      cluster_transport_socket->set_name("envoy.transport_sockets.fake_ktls");
      Protobuf::Struct empty;
      cluster_transport_socket->mutable_typed_config()->PackFrom(empty);
    });
    initialize();
  }

  // Sends a download GET, drives the upstream to return a Content-Length-framed body of `body_size`
  // bytes, and asserts the body arrives byte-for-byte downstream. Returns the response so the
  // caller can assert on the splice counters.
  //
  // The response headers and body are encoded in separate event-loop turns: the upstream encodes
  // headers (end_stream=false), the test waits for them to reach the client, and only then encodes
  // the body. This is what the splice fast-path is designed around. The coordinator arms on the
  // headers read and schedules engage() for the next iteration. Sending the whole body in the same
  // read as the headers would let the coordinator buffer the entire body before engage() ran, at
  // which point engage() sees the body already complete and abandons (nothing left to splice), so
  // the splice never engages. Holding the body back until the headers have been delivered lets
  // engage() commit first, then splices the body that follows.
  IntegrationStreamDecoderPtr runDownload(uint64_t body_size) {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(Http::TestRequestHeaderMapImpl{
        {":method", "GET"}, {":path", "/download"}, {":scheme", "http"}, {":authority", "host"}});

    waitForNextUpstreamRequest();
    upstream_request_->encodeHeaders(
        Http::TestResponseHeaderMapImpl{{":status", "200"},
                                        {"content-length", absl::StrCat(body_size)}},
        false);
    // Wait for the headers to reach the client, which guarantees the upstream-headers read (and so
    // the scheduled engage()) has unwound on the server before the body is sent.
    response->waitForHeaders();

    const std::string body = makeBody(body_size);
    Buffer::OwnedImpl response_data(body);
    upstream_request_->encodeData(response_data, true);

    RELEASE_ASSERT(response->waitForEndStream(), "download did not complete");
    EXPECT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().getStatusValue());
    EXPECT_EQ(body_size, response->body().size());
    EXPECT_EQ(body, response->body());
    return response;
  }

  FakeKtlsConfigFactory config_factory_;
  Registry::InjectFactory<Server::Configuration::UpstreamTransportSocketConfigFactory>
      registered_config_factory_{config_factory_};
};

INSTANTIATE_TEST_SUITE_P(IpVersions, KtlsSpliceIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// A 128 KiB download (>= the 64 KiB floor) over a fake-kTLS upstream engages the splice and the
// body still arrives byte-for-byte. The engaged counter assertion is what proves the fast-path
// actually fired rather than the buffered path silently carrying the bytes.
TEST_P(KtlsSpliceIntegrationTest, DownloadAboveThresholdEngagesSplice) {
  initializeWithFakeKtlsUpstream();
  auto response = runDownload(128 * 1024);
  test_server_->waitForCounter("cluster.cluster_0.http1_ktls_splice.engaged", testing::Ge(1));
  EXPECT_EQ(1, test_server_->counter("cluster.cluster_0.http1_ktls_splice.engaged")->value());
}

// A sub-64-KiB download is below the floor, so the splice never arms. The body still arrives
// byte-for-byte through the buffered path and the engaged counter stays zero. This pins the
// negative path so the threshold gate cannot silently regress to always-splice. The counter is
// lazily created the first time a splice engages, so it does not exist at all here: a null counter
// is the strongest possible evidence the splice never armed, and a present-but-zero counter (were
// it created by some other path) is equally acceptable.
TEST_P(KtlsSpliceIntegrationTest, DownloadBelowThresholdDoesNotEngage) {
  initializeWithFakeKtlsUpstream();
  auto response = runDownload(MinSpliceBodyBytes - 1);
  const Stats::CounterSharedPtr engaged =
      test_server_->counter("cluster.cluster_0.http1_ktls_splice.engaged");
  EXPECT_EQ(0, engaged == nullptr ? 0 : engaged->value());
}

} // namespace
} // namespace Envoy

#endif // __linux__
