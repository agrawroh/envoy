// Measures what a burst of xDS updates does to a running Envoy, by driving a real server with a
// fake management server and watching its main thread.
//
// Two questions are answered, each for the stock xDS path and for the proposed pipeline in which
// Tokio workers do everything that does not have to happen on the main thread:
//
// 1. A burst of N delta FCDS updates, one per filter chain. How long until the last one is active?
// 2. One State-of-the-World CDS response carrying N clusters. For how long does the main thread
//    stall, and how long until the clusters are active?
//
// The main thread is watched by a probe: a timer on the server's dispatcher that is meant to fire
// every millisecond and records how late it actually fires. The longest delay is how long the main
// thread was unable to run anything else, which is what a stalled main thread means for health
// checks, admin, stats flushes and every other xDS update.
//
// The proposed pipeline is modelled by what it would hand the main thread: the resources already
// parsed and validated, so that only the apply remains. For the SotW case it also batches the
// apply into slices that are posted to the main thread one at a time, so that the main thread can
// run other work in between, which is the only way to keep it from stalling.
//
// This is a benchmark, not a test. It only runs on demand, prints its measurements, and asserts
// nothing beyond the burst having been applied.

#include <chrono>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.validate.h"
#include "envoy/config/listener/v3/listener.pb.h"
#include "envoy/config/listener/v3/listener_components.pb.validate.h"
#include "envoy/extensions/filters/http/router/v3/router.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/extensions/matching/common_inputs/network/v3/network_inputs.pb.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/common/thread.h"
#include "source/common/protobuf/utility.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/integration/ads_integration.h"
#include "test/integration/http_integration.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/resources.h"

#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace {

using ::envoy::config::cluster::v3::Cluster;
using ::envoy::config::listener::v3::FilterChain;
using ::envoy::config::listener::v3::Listener;
using ::envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager;
using ::envoy::service::discovery::v3::DeltaDiscoveryRequest;
using Clock = std::chrono::steady_clock;

double milliseconds(Clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

// What unpacking and validating the resources costs a single thread, which is the part of today's
// main-thread work the Tokio pipeline takes over and spreads across its workers.
template <class Resource> double decodeAndValidateMs(const std::vector<Resource>& resources) {
  std::vector<Protobuf::Any> packed(resources.size());
  for (size_t i = 0; i < resources.size(); i++) {
    std::ignore = packed[i].PackFrom(resources[i]);
  }
  size_t sink = 0;
  const Clock::time_point start = Clock::now();
  for (const auto& any : packed) {
    Resource resource;
    MessageUtil::unpackTo(any, resource).IgnoreError();
    MessageUtil::validate(resource, ProtobufMessage::getStrictValidationVisitor());
    sink += resource.name().size();
  }
  RELEASE_ASSERT(sink > 0, "");
  return milliseconds(Clock::now() - start);
}

// Watches the main thread of the server under test for stalls.
class MainThreadProbe {
public:
  explicit MainThreadProbe(Event::Dispatcher& main_dispatcher) : dispatcher_(main_dispatcher) {}

  void start() {
    dispatcher_.post([this]() {
      timer_ = dispatcher_.createTimer([this]() { onTick(); });
      expected_ = Clock::now() + kPeriod;
      timer_->enableTimer(kPeriod);
    });
  }

  // Stops the probe and returns the longest delay a tick suffered. A tick that is still overdue
  // when the probe stops counts as well, since the stop runs on the main thread and so can only
  // run once the stall that delayed the tick is over.
  double stop() {
    absl::Notification stopped;
    dispatcher_.post([this, &stopped]() {
      recordDelay(Clock::now());
      timer_.reset();
      stopped.Notify();
    });
    stopped.WaitForNotification();
    return milliseconds(worst_delay_);
  }

private:
  static constexpr std::chrono::milliseconds kPeriod{1};

  void onTick() {
    const Clock::time_point now = Clock::now();
    recordDelay(now);
    expected_ = now + kPeriod;
    timer_->enableTimer(kPeriod);
  }

  void recordDelay(Clock::time_point now) {
    if (now > expected_) {
      worst_delay_ = std::max(worst_delay_, now - expected_);
    }
  }

  Event::Dispatcher& dispatcher_;
  Event::TimerPtr timer_;
  Clock::time_point expected_;
  Clock::duration worst_delay_{0};
};

class XdsBurstBenchmark : public Grpc::DeltaSotwIntegrationParamTest, public HttpIntegrationTest {
public:
  XdsBurstBenchmark()
      : HttpIntegrationTest(Http::CodecType::HTTP2, ipVersion(),
                            ConfigHelper::clustersNoListenerBootstrap(
                                sotwOrDelta() == Grpc::SotwOrDelta::Sotw ? "GRPC" : "DELTA_GRPC")) {
    use_lds_ = false;
    sotw_or_delta_ = sotwOrDelta();
    // The legacy mux is the default, and the one the in-process benchmarks measured.
    config_helper_.addRuntimeOverride("envoy.reloadable_features.unified_mux", "false");
  }

  void TearDown() override {
    if (xds_connection_ != nullptr) {
      cleanUpXdsConnection();
    }
  }

  void initialize() override {
    setUpstreamCount(1);
    setUpstreamProtocol(Http::CodecType::HTTP2);
    HttpIntegrationTest::initialize();
    AssertionResult result =
        fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, xds_connection_);
    RELEASE_ASSERT(result, result.message());
    result = xds_connection_->waitForNewStream(*dispatcher_, xds_stream_);
    RELEASE_ASSERT(result, result.message());
    xds_stream_->startGrpcStream();
    registerTestServerPorts({});
  }

  static Cluster makeCluster(uint32_t id, uint32_t generation) {
    Cluster cluster;
    cluster.set_name(absl::StrCat("cluster_", id));
    cluster.mutable_connect_timeout()->set_seconds(1 + generation);
    cluster.set_type(Cluster::STATIC);
    auto* load_assignment = cluster.mutable_load_assignment();
    load_assignment->set_cluster_name(cluster.name());
    auto* socket_address = load_assignment->add_endpoints()
                               ->add_lb_endpoints()
                               ->mutable_endpoint()
                               ->mutable_address()
                               ->mutable_socket_address();
    socket_address->set_address("127.0.0.1");
    socket_address->set_port_value(10000 + id % 50000);
    return cluster;
  }

  static std::vector<Cluster> buildClusters(uint32_t clusters) {
    std::vector<Cluster> resources;
    resources.reserve(clusters);
    for (uint32_t i = 0; i < clusters; i++) {
      resources.push_back(makeCluster(i, 0));
    }
    return resources;
  }

  void enableDeferredStats() {
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      bootstrap.mutable_deferred_stat_options()->set_enable_deferred_creation_stats(true);
    });
  }

  // Waits for every cluster of the response, plus the xDS cluster itself, to be active.
  void waitForActiveClusters(uint32_t clusters) {
    test_server_->waitForGauge("cluster_manager.active_clusters", testing::Ge(clusters + 1),
                               std::chrono::seconds(300));
  }

  // Applies the response as Envoy applies it today: one SotW response, in one go.
  void runSotwOnMainThread(uint32_t clusters, absl::string_view label) {
    initialize();
    EXPECT_TRUE(compareDiscoveryRequest(Config::TestTypeUrl::get().Cluster, "", {}, {}, {}, true));
    const std::vector<Cluster> resources = buildClusters(clusters);
    const double decode_ms = decodeAndValidateMs(resources);

    MainThreadProbe probe(mainDispatcher());
    probe.start();
    const Clock::time_point sent = Clock::now();
    sendSotwDiscoveryResponse<Cluster>(Config::TestTypeUrl::get().Cluster, resources, "1");
    // Wait for the ACK rather than polling a gauge: walking the stats store takes the lock the
    // main thread needs to create stats, and would slow down the very thing being measured.
    waitForAck("1");
    const double applied_ms = milliseconds(Clock::now() - sent);
    const double worst_stall_ms = probe.stop();
    waitForActiveClusters(clusters);

    ENVOY_LOG_MISC(critical,
                   "RESULT sotw {} clusters={} applied_ms={:.1f} worst_main_thread_stall_ms={:.1f} "
                   "single_thread_decode_validate_ms={:.1f}",
                   label, clusters, applied_ms, worst_stall_ms, decode_ms);
  }

  // Waits for Envoy to acknowledge `version`.
  void waitForAck(const std::string& version) {
    envoy::service::discovery::v3::DiscoveryRequest ack;
    do {
      AssertionResult result =
          xds_stream_->waitForGrpcMessage(*dispatcher_, ack, std::chrono::seconds(300));
      RELEASE_ASSERT(result, result.message());
    } while (ack.version_info() != version);
  }

  // A second SotW response identical to the first, and then one in which a single cluster
  // changed. This is what the main thread pays today to find out that (almost) nothing changed,
  // which a diff against the previous snapshot on the Tokio side would take off it entirely.
  void runSotwRepush(uint32_t clusters) {
    initialize();
    EXPECT_TRUE(compareDiscoveryRequest(Config::TestTypeUrl::get().Cluster, "", {}, {}, {}, true));
    std::vector<Cluster> resources = buildClusters(clusters);
    sendSotwDiscoveryResponse<Cluster>(Config::TestTypeUrl::get().Cluster, resources, "1");
    waitForAck("1");
    waitForActiveClusters(clusters);

    // What the main thread suffers with the clusters merely existing: periodic work such as the
    // stats flush, which walks every stat the clusters created.
    {
      MainThreadProbe probe(mainDispatcher());
      probe.start();
      timeSystem().realSleepDoNotUseWithoutScrutiny(std::chrono::seconds(12));
      const double idle_stall_ms = probe.stop();
      const Stats::Store& store = test_server_->statStore();
      ENVOY_LOG_MISC(critical,
                     "RESULT sotw idle clusters={} stats={} worst_main_thread_stall_ms={:.1f}",
                     clusters, store.counters().size() + store.gauges().size(), idle_stall_ms);
    }

    for (const bool change_one : {false, true}) {
      const std::string version = change_one ? "3" : "2";
      if (change_one) {
        resources[clusters / 2] = makeCluster(clusters / 2, 1);
      }
      MainThreadProbe probe(mainDispatcher());
      probe.start();
      const Clock::time_point sent = Clock::now();
      sendSotwDiscoveryResponse<Cluster>(Config::TestTypeUrl::get().Cluster, resources, version);
      waitForAck(version);
      const double applied_ms = milliseconds(Clock::now() - sent);
      const double worst_stall_ms = probe.stop();
      ENVOY_LOG_MISC(critical,
                     "RESULT sotw repush clusters={} changed={} applied_ms={:.1f} "
                     "worst_main_thread_stall_ms={:.1f}",
                     clusters, change_one ? 1 : 0, applied_ms, worst_stall_ms);
    }
  }

  // Applies the response as the Tokio pipeline would hand it to the main thread: already decoded
  // and validated, in slices of `slice` clusters with the event loop free to run in between.
  void runSotwSliced(uint32_t clusters, uint32_t slice, absl::string_view label) {
    initialize();
    EXPECT_TRUE(compareDiscoveryRequest(Config::TestTypeUrl::get().Cluster, "", {}, {}, {}, true));
    const std::vector<Cluster> resources = buildClusters(clusters);
    Event::Dispatcher& dispatcher = mainDispatcher();
    Upstream::ClusterManager& cluster_manager = test_server_->server().clusterManager();

    Event::SchedulableCallbackPtr apply;
    size_t next = 0;
    absl::Notification done;
    MainThreadProbe probe(dispatcher);
    probe.start();
    const Clock::time_point sent = Clock::now();
    dispatcher.post([&]() {
      apply = dispatcher.createSchedulableCallback([&]() {
        const size_t end = std::min(next + slice, resources.size());
        for (; next < end; next++) {
          const absl::StatusOr<bool> added =
              cluster_manager.addOrUpdateCluster(resources[next], "1", false);
          RELEASE_ASSERT(added.ok() && *added, "");
        }
        if (next < resources.size()) {
          apply->scheduleCallbackNextIteration();
        } else {
          done.Notify();
        }
      });
      apply->scheduleCallbackNextIteration();
    });
    done.WaitForNotification();
    waitForActiveClusters(clusters);
    const double applied_ms = milliseconds(Clock::now() - sent);
    const double worst_stall_ms = probe.stop();
    absl::Notification destroyed;
    dispatcher.post([&]() {
      apply.reset();
      destroyed.Notify();
    });
    destroyed.WaitForNotification();

    ENVOY_LOG_MISC(critical,
                   "RESULT sotw {} clusters={} slice={} applied_ms={:.1f} "
                   "worst_main_thread_stall_ms={:.1f}",
                   label, clusters, slice, applied_ms, worst_stall_ms);
  }

  Event::Dispatcher& mainDispatcher() { return test_server_->server().dispatcher(); }
};

INSTANTIATE_TEST_SUITE_P(IpVersionsClientType, XdsBurstBenchmark,
                         DELTA_SOTW_GRPC_CLIENT_INTEGRATION_PARAMS,
                         Grpc::DeltaSotwIntegrationParamTest::protocolTestParamsToString);

constexpr uint32_t kSotwClusters = 25000;

TEST_P(XdsBurstBenchmark, SotwClustersOnMainThread) {
  runSotwOnMainThread(kSotwClusters, "main_thread");
}

TEST_P(XdsBurstBenchmark, SotwClustersRepush) { runSotwRepush(kSotwClusters); }

TEST_P(XdsBurstBenchmark, SotwClustersOnMainThreadDeferredStats) {
  enableDeferredStats();
  runSotwOnMainThread(kSotwClusters, "main_thread_deferred_stats");
}

TEST_P(XdsBurstBenchmark, SotwClustersSliced) { runSotwSliced(kSotwClusters, 500, "sliced"); }

// One slice holding the whole response: the same apply as the stock path, without the mux.
TEST_P(XdsBurstBenchmark, SotwClustersSlicedWhole) {
  runSotwSliced(kSotwClusters, kSotwClusters, "sliced");
}

TEST_P(XdsBurstBenchmark, SotwClustersSlicedSmall) { runSotwSliced(kSotwClusters, 100, "sliced"); }

TEST_P(XdsBurstBenchmark, SotwClustersSlicedDeferredStats) {
  enableDeferredStats();
  runSotwSliced(kSotwClusters, 500, "sliced_deferred_stats");
}

// A listener with N dynamic filter chains, one FCDS subscription each, receiving bursts of delta
// updates over ADS.
class FcdsBurstBenchmark : public AdsIntegrationTest {
public:
  FcdsBurstBenchmark() { skip_tag_extraction_rule_check_ = true; }

  static std::string chainName(uint32_t id) { return absl::StrCat("fc_", id); }

  // An HTTP filter chain whose route differs per generation, so that every generation is a real
  // update rather than one FCDS skips as identical.
  static FilterChain buildChain(uint32_t id, uint32_t generation) {
    FilterChain filter_chain;
    filter_chain.set_name(chainName(id));
    auto* filter = filter_chain.add_filters();
    filter->set_name("envoy.filters.network.http_connection_manager");
    HttpConnectionManager hcm;
    hcm.set_stat_prefix("fcds");
    auto* virtual_host = hcm.mutable_route_config()->add_virtual_hosts();
    virtual_host->set_name("vhost");
    virtual_host->add_domains("*");
    auto* route = virtual_host->add_routes();
    route->mutable_match()->set_prefix("/");
    route->mutable_direct_response()->set_status(200);
    route->mutable_direct_response()->mutable_body()->set_inline_string(
        absl::StrCat("generation ", generation));
    auto* router = hcm.add_http_filters();
    router->set_name("envoy.filters.http.router");
    std::ignore = router->mutable_typed_config()->PackFrom(
        envoy::extensions::filters::http::router::v3::Router());
    std::ignore = filter->mutable_typed_config()->PackFrom(hcm);
    return filter_chain;
  }

  // A listener whose filter chain matcher refers to `chains` dynamic filter chains by name.
  Listener buildFcdsListener(uint32_t chains) {
    Listener listener;
    listener.set_name("listener_0");
    auto* socket_address = listener.mutable_address()->mutable_socket_address();
    socket_address->set_address(Network::Test::getLoopbackAddressString(ipVersion()));
    socket_address->set_port_value(0);
    listener.mutable_fcds_config()->mutable_config_source()->mutable_ads();
    auto* tree = listener.mutable_filter_chain_matcher()->mutable_matcher_tree();
    tree->mutable_input()->set_name("port");
    std::ignore = tree->mutable_input()->mutable_typed_config()->PackFrom(
        envoy::extensions::matching::common_inputs::network::v3::DestinationPortInput());
    auto& map = *tree->mutable_exact_match_map()->mutable_map();
    for (uint32_t i = 0; i < chains; i++) {
      Protobuf::StringValue name;
      name.set_value(chainName(i));
      auto* action = map[absl::StrCat(10000 + i)].mutable_action();
      action->set_name("filter-chain-name");
      std::ignore = action->mutable_typed_config()->PackFrom(name);
    }
    return listener;
  }

  // Reads requests off the ADS stream until one for `type_url` arrives.
  DeltaDiscoveryRequest waitForRequest(const std::string& type_url) {
    DeltaDiscoveryRequest request;
    do {
      AssertionResult result =
          xds_stream_->waitForGrpcMessage(*dispatcher_, request, std::chrono::seconds(300));
      RELEASE_ASSERT(result, result.message());
    } while (request.type_url() != type_url);
    return request;
  }

  // Starts Envoy with a listener referring to `chains` dynamic filter chains, and returns once it
  // has subscribed to all of them. Returns how long the listener took to subscribe.
  double startWithChains(uint32_t chains) {
    initialize();
    EXPECT_TRUE(compareDiscoveryRequest(Config::TestTypeUrl::get().Cluster, "", {}, {}, {}, true));
    sendDeltaDiscoveryResponse<Cluster>(Config::TestTypeUrl::get().Cluster, {}, {}, "1");
    waitForRequest(Config::TestTypeUrl::get().Listener);
    const Clock::time_point sent = Clock::now();
    sendDeltaDiscoveryResponse<Listener>(Config::TestTypeUrl::get().Listener,
                                         {buildFcdsListener(chains)}, {}, "1");
    DeltaDiscoveryRequest request;
    do {
      request = waitForRequest(Config::TestTypeUrl::get().FilterChain);
    } while (request.resource_names_subscribe().empty());
    EXPECT_EQ(chains, static_cast<uint32_t>(request.resource_names_subscribe().size()));
    return milliseconds(Clock::now() - sent);
  }

  struct Burst {
    double latency_ms;
    double worst_stall_ms;
  };

  // Sends every chain of `generation` in `responses` delta responses, and waits for Envoy to
  // acknowledge the last of them, which it does only once it has applied it.
  Burst sendBurst(const std::vector<FilterChain>& resources, uint32_t generation,
                  uint32_t responses) {
    const size_t per_response = resources.size() / responses;
    MainThreadProbe probe(test_server_->server().dispatcher());
    probe.start();
    const Clock::time_point sent = Clock::now();
    for (uint32_t r = 0; r < responses; r++) {
      const std::vector<FilterChain> slice(resources.begin() + r * per_response,
                                           resources.begin() + (r + 1) * per_response);
      sendDeltaDiscoveryResponse<FilterChain>(Config::TestTypeUrl::get().FilterChain, slice, {},
                                              absl::StrCat(generation, "-", r));
    }
    for (uint32_t r = 0; r < responses; r++) {
      waitForRequest(Config::TestTypeUrl::get().FilterChain);
    }
    Burst burst;
    burst.latency_ms = milliseconds(Clock::now() - sent);
    burst.worst_stall_ms = probe.stop();
    return burst;
  }

  static std::vector<FilterChain> buildGeneration(uint32_t chains, uint32_t generation) {
    std::vector<FilterChain> resources;
    resources.reserve(chains);
    for (uint32_t i = 0; i < chains; i++) {
      resources.push_back(buildChain(i, generation));
    }
    return resources;
  }
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, FcdsBurstBenchmark,
    testing::Combine(testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                     testing::Values(Grpc::ClientType::EnvoyGrpc),
                     testing::Values(Grpc::SotwOrDelta::Delta)),
    AdsIntegrationTest::protocolTestParamsToString);

// N dynamic filter chains are first delivered to a warming listener, then updated in bursts
// delivered as N responses of one chain, 10 responses, and a single response.
TEST_P(FcdsBurstBenchmark, DeltaUpdates) {
  const uint32_t chains = 10000;
  const double subscribed_ms = startWithChains(chains);
  ENVOY_LOG_MISC(critical, "RESULT fcds chains={} listener_subscribed_ms={:.1f}", chains,
                 subscribed_ms);

  uint32_t generation = 0;
  const Burst initial = sendBurst(buildGeneration(chains, generation), generation, 1);
  test_server_->waitForCounter("listener_manager.listener_create_success", testing::Ge(1));
  ENVOY_LOG_MISC(critical,
                 "RESULT fcds chains={} initial responses=1 latency_ms={:.1f} "
                 "worst_main_thread_stall_ms={:.1f}",
                 chains, initial.latency_ms, initial.worst_stall_ms);

  for (const uint32_t responses : {chains, 10u, 1u}) {
    generation++;
    const std::vector<FilterChain> resources = buildGeneration(chains, generation);
    const double decode_ms = decodeAndValidateMs(resources);
    const Burst burst = sendBurst(resources, generation, responses);
    ENVOY_LOG_MISC(critical,
                   "RESULT fcds chains={} responses={} latency_ms={:.1f} "
                   "worst_main_thread_stall_ms={:.1f} single_thread_decode_validate_ms={:.1f}",
                   chains, responses, burst.latency_ms, burst.worst_stall_ms, decode_ms);
  }
}

} // namespace
} // namespace Envoy
