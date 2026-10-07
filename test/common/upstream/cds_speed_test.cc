// Note: this should be run with --compilation_mode=opt, and would benefit from a quiescent system
// with disabled cstate power management.
//
// This measures what a delta CDS update costs Envoy, which is the work any richer configuration
// protocol would have to beat.
//
// `cdsIngestion` applies an update against a mock cluster manager, so it covers only the update
// handling itself: walking the resources, recording what happened to each one and, when a tracker
// is configured, handing it the outcomes. `cdsApply` runs the same update against a real cluster
// manager, so it additionally covers building the clusters. Both are driven through
// CdsApiHelper::onConfigUpdate(), which is the delta CDS entry point, so the difference between
// them is the work that has to run on the main thread and therefore cannot be moved off it.

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.validate.h"
#include "envoy/config/xds_config_tracker.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/config/null_grpc_mux_impl.h"
#include "source/common/upstream/cds_api_helper.h"

#include "test/benchmark/main.h"
#include "test/common/upstream/cluster_manager_impl_test_common.h"
#include "test/mocks/config/xds_manager.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"

namespace Envoy {
namespace Upstream {
namespace {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

// Builds a delta update carrying `count` distinct static clusters, each with a single endpoint.
Protobuf::RepeatedPtrField<envoy::service::discovery::v3::Resource> makeUpdate(uint32_t count) {
  Protobuf::RepeatedPtrField<envoy::service::discovery::v3::Resource> resources;
  for (uint32_t i = 0; i < count; i++) {
    envoy::config::cluster::v3::Cluster cluster;
    cluster.set_name(absl::StrCat("cluster_", i));
    cluster.mutable_connect_timeout()->set_seconds(1);
    cluster.set_type(envoy::config::cluster::v3::Cluster::STATIC);
    auto* load_assignment = cluster.mutable_load_assignment();
    load_assignment->set_cluster_name(cluster.name());
    auto* socket_address = load_assignment->add_endpoints()
                               ->add_lb_endpoints()
                               ->mutable_endpoint()
                               ->mutable_address()
                               ->mutable_socket_address();
    socket_address->set_address("127.0.0.1");
    socket_address->set_port_value(11001 + i % 1000);

    auto* resource = resources.Add();
    std::ignore = resource->mutable_resource()->PackFrom(cluster);
    resource->set_name(cluster.name());
    resource->set_version("v1");
  }
  return resources;
}

// A tracker that does what any real one has to do: the outcome views it is handed are only valid
// for the duration of the call, so whatever it intends to report has to be copied out of them.
class CopyingXdsConfigTracker : public Config::XdsConfigTracker {
public:
  void onConfigAccepted(absl::string_view,
                        const std::vector<Config::DecodedResourcePtr>&) override {}
  void onConfigAccepted(absl::string_view,
                        absl::Span<const envoy::service::discovery::v3::Resource* const>,
                        const Protobuf::RepeatedPtrField<std::string>&) override {}
  void onResourcesApplied(absl::string_view type_url,
                          absl::Span<const Config::ResourceApplyResult> results) override {
    type_url_.assign(type_url.data(), type_url.size());
    outcomes_.clear();
    outcomes_.reserve(results.size());
    for (const auto& result : results) {
      outcomes_.push_back({std::string(result.name), std::string(result.version), result.status,
                           std::string(result.details)});
    }
    ::benchmark::DoNotOptimize(outcomes_.data());
  }
  void onConfigRejected(const envoy::service::discovery::v3::DiscoveryResponse&,
                        absl::string_view) override {}
  void onConfigRejected(const envoy::service::discovery::v3::DeltaDiscoveryResponse&,
                        absl::string_view) override {}
  void onResourceUnsubscribed(absl::string_view, absl::string_view) override {}

private:
  struct Outcome {
    std::string name;
    std::string version;
    Config::ResourceApplyStatus status;
    std::string details;
  };

  std::string type_url_;
  std::vector<Outcome> outcomes_;
};

Config::XdsConfigTrackerOptRef trackerRef(bool enabled, CopyingXdsConfigTracker& tracker) {
  return enabled ? Config::XdsConfigTrackerOptRef(tracker) : Config::XdsConfigTrackerOptRef{};
}

uint32_t clusterCount(const ::benchmark::State& state) {
  return Envoy::benchmark::skipExpensiveBenchmarks() ? 1 : state.range(0);
}

// Applies a delta CDS update against a mock cluster manager, which leaves only the update handling
// itself to measure.
void cdsIngestion(::benchmark::State& state) {
  const uint32_t num_clusters = clusterCount(state);
  const bool with_tracker = state.range(1);

  NiceMock<MockClusterManager> cm;
  NiceMock<Config::MockXdsManager> xds_manager;
  CopyingXdsConfigTracker tracker;
  ON_CALL(cm, addOrUpdateCluster(_, _, _)).WillByDefault(Return(true));
  ON_CALL(xds_manager, xdsConfigTracker()).WillByDefault(Return(trackerRef(with_tracker, tracker)));

  const auto resources = makeUpdate(num_clusters);
  const auto decoded = TestUtility::decodeResources<envoy::config::cluster::v3::Cluster>(resources);
  CdsApiHelper helper(cm, xds_manager, "cds");

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    helper.onConfigUpdate(decoded.refvec_, {}, "v1");
  }
  state.counters["clusters"] = num_clusters;
}
BENCHMARK(cdsIngestion)
    ->ArgsProduct({{1, 10, 100, 1000, 10000}, {false, true}})
    ->Unit(::benchmark::kMicrosecond);

// Applies the same delta CDS update against a real cluster manager, so that building the clusters
// is measured as well.
void cdsApply(::benchmark::State& state) {
  const uint32_t num_clusters = clusterCount(state);
  const bool with_tracker = state.range(1);

  NiceMock<Network::MockDnsResolverFactory> dns_resolver_factory;
  Registry::InjectFactory<Network::DnsResolverFactory> registered_dns_factory(dns_resolver_factory);
  NiceMock<TestClusterManagerFactory> factory;
  CopyingXdsConfigTracker tracker;
  ON_CALL(factory.server_context_.xds_manager_, adsMux())
      .WillByDefault(Return(std::make_shared<Config::NullGrpcMuxImpl>()));
  ON_CALL(factory.server_context_.xds_manager_, xdsConfigTracker())
      .WillByDefault(Return(trackerRef(with_tracker, tracker)));

  const auto resources = makeUpdate(num_clusters);
  const auto decoded = TestUtility::decodeResources<envoy::config::cluster::v3::Cluster>(resources);
  const envoy::config::bootstrap::v3::Bootstrap bootstrap;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    // A cluster that is already applied is skipped, so the cluster manager is rebuilt for every
    // iteration to keep measuring the cost of adding the clusters rather than of skipping them.
    state.PauseTiming();
    // Every cluster manager registers its config dump under the same key, which the mock admin
    // only accepts once.
    factory.server_context_.admin_.config_tracker_.config_tracker_callbacks_.clear();
    auto cluster_manager = TestClusterManagerImpl::createTestClusterManager(
        bootstrap, factory, factory.server_context_);
    ON_CALL(factory.server_context_, clusterManager()).WillByDefault(ReturnRef(*cluster_manager));
    THROW_IF_NOT_OK(cluster_manager->initialize(bootstrap));
    // Complete the initialization, so that the clusters are added the way CDS adds them at runtime.
    cluster_manager->setPrimaryClustersInitializedCb([&cluster_manager, &bootstrap]() {
      THROW_IF_NOT_OK(cluster_manager->initializeSecondaryClusters(bootstrap));
    });
    CdsApiHelper helper(*cluster_manager, factory.server_context_.xds_manager_, "cds");
    state.ResumeTiming();

    helper.onConfigUpdate(decoded.refvec_, {}, "v1");

    state.PauseTiming();
    RELEASE_ASSERT(cluster_manager->clusters().active_clusters_.size() == num_clusters,
                   "the clusters were not applied");
    cluster_manager->shutdown();
    cluster_manager.reset();
    factory.server_context_.dispatcher_.to_delete_.clear();
    state.ResumeTiming();
  }
  state.counters["clusters"] = num_clusters;
}
BENCHMARK(cdsApply)
    ->ArgsProduct({{1, 10, 100, 1000, 10000}, {false, true}})
    ->Unit(::benchmark::kMicrosecond);

} // namespace
} // namespace Upstream
} // namespace Envoy
