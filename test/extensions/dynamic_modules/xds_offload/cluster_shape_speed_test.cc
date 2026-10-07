// Note: this should be run with --compilation_mode=opt, and would benefit from a quiescent system
// with disabled cstate power management.
//
// Measures what it costs the main thread to install N backend sets, depending on how they are
// represented, by applying a single delta CDS update to a real cluster manager:
//
// * `backendsAsClusters` installs one cluster per backend set, as xDS models them today, either
//   with every cluster stat created up front or with the traffic stats deferred.
// * `backendsAsHosts` installs a single cluster holding every backend set as a host, which is what
//   a dynamic module cluster managing the backend sets itself would ask Envoy to build.

#include <memory>
#include <string>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.validate.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/config/null_grpc_mux_impl.h"
#include "source/common/upstream/cds_api_helper.h"

#include "test/benchmark/main.h"
#include "test/common/upstream/cluster_manager_impl_test_common.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"

namespace Envoy {
namespace Upstream {
namespace {

using ::envoy::config::cluster::v3::Cluster;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

uint32_t scale(int64_t count) {
  return Envoy::benchmark::skipExpensiveBenchmarks() ? 1 : static_cast<uint32_t>(count);
}

Cluster makeStaticCluster(const std::string& name) {
  Cluster cluster;
  cluster.set_name(name);
  cluster.mutable_connect_timeout()->set_seconds(1);
  cluster.set_type(Cluster::STATIC);
  cluster.mutable_load_assignment()->set_cluster_name(name);
  return cluster;
}

void addEndpoint(Cluster& cluster, uint32_t id) {
  auto* socket_address = cluster.mutable_load_assignment()
                             ->mutable_endpoints(0)
                             ->add_lb_endpoints()
                             ->mutable_endpoint()
                             ->mutable_address()
                             ->mutable_socket_address();
  socket_address->set_address(
      absl::StrCat("10.", (id >> 16) & 0xff, ".", (id >> 8) & 0xff, ".", id & 0xff));
  socket_address->set_port_value(8080);
}

Protobuf::RepeatedPtrField<envoy::service::discovery::v3::Resource>
toResources(const std::vector<Cluster>& clusters) {
  Protobuf::RepeatedPtrField<envoy::service::discovery::v3::Resource> resources;
  for (const Cluster& cluster : clusters) {
    auto* resource = resources.Add();
    std::ignore = resource->mutable_resource()->PackFrom(cluster);
    resource->set_name(cluster.name());
    resource->set_version("v1");
  }
  return resources;
}

// Applies `clusters` to a freshly initialized cluster manager in every iteration, and returns the
// cluster manager of the last iteration for the caller to verify.
void applyClusters(::benchmark::State& state, const std::vector<Cluster>& clusters,
                   bool deferred_stats,
                   const std::function<void(TestClusterManagerImpl&)>& verify) {
  NiceMock<Network::MockDnsResolverFactory> dns_resolver_factory;
  Registry::InjectFactory<Network::DnsResolverFactory> registered_dns_factory(dns_resolver_factory);
  NiceMock<TestClusterManagerFactory> factory;
  ON_CALL(factory.server_context_.xds_manager_, adsMux())
      .WillByDefault(Return(std::make_shared<Config::NullGrpcMuxImpl>()));
  ON_CALL(factory.server_context_.stats_config_, enableDeferredCreationStats())
      .WillByDefault(Return(deferred_stats));
  const auto resources = toResources(clusters);
  const auto decoded = TestUtility::decodeResources<Cluster>(resources);
  const envoy::config::bootstrap::v3::Bootstrap bootstrap;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    state.PauseTiming();
    // Every cluster manager registers its config dump under the same key, which the mock admin
    // only accepts once.
    factory.server_context_.admin_.config_tracker_.config_tracker_callbacks_.clear();
    auto cluster_manager = TestClusterManagerImpl::createTestClusterManager(
        bootstrap, factory, factory.server_context_);
    ON_CALL(factory.server_context_, clusterManager()).WillByDefault(ReturnRef(*cluster_manager));
    THROW_IF_NOT_OK(cluster_manager->initialize(bootstrap));
    cluster_manager->setPrimaryClustersInitializedCb([&cluster_manager, &bootstrap]() {
      THROW_IF_NOT_OK(cluster_manager->initializeSecondaryClusters(bootstrap));
    });
    CdsApiHelper helper(*cluster_manager, factory.server_context_.xds_manager_, "cds");
    state.ResumeTiming();

    helper.onConfigUpdate(decoded.refvec_, {}, "v1");

    state.PauseTiming();
    verify(*cluster_manager);
    cluster_manager->shutdown();
    cluster_manager.reset();
    factory.server_context_.dispatcher_.to_delete_.clear();
    state.ResumeTiming();
  }
}

void backendsAsClusters(::benchmark::State& state) {
  const uint32_t backends = scale(state.range(0));
  std::vector<Cluster> clusters;
  clusters.reserve(backends);
  for (uint32_t i = 0; i < backends; i++) {
    clusters.push_back(makeStaticCluster(absl::StrCat("backend_", i)));
    clusters.back().mutable_load_assignment()->add_endpoints();
    addEndpoint(clusters.back(), i);
  }
  applyClusters(state, clusters, state.range(1), [backends](TestClusterManagerImpl& cm) {
    RELEASE_ASSERT(cm.clusters().active_clusters_.size() == backends, "clusters not applied");
  });
}
BENCHMARK(backendsAsClusters)
    ->ArgNames({"backends", "deferred_stats"})
    ->ArgsProduct({{1000, 10000}, {0, 1}})
    ->Unit(::benchmark::kMillisecond);

void backendsAsHosts(::benchmark::State& state) {
  const uint32_t backends = scale(state.range(0));
  Cluster cluster = makeStaticCluster("backends");
  cluster.mutable_load_assignment()->add_endpoints();
  for (uint32_t i = 0; i < backends; i++) {
    addEndpoint(cluster, i);
  }
  applyClusters(state, {cluster}, false, [backends](TestClusterManagerImpl& cm) {
    const auto hosts =
        cm.activeClusters().at("backends").get().prioritySet().hostSetsPerPriority()[0]->hosts();
    RELEASE_ASSERT(hosts.size() == backends, "hosts not applied");
  });
}
BENCHMARK(backendsAsHosts)
    ->ArgNames({"backends"})
    ->Arg(1000)
    ->Arg(10000)
    ->Unit(::benchmark::kMillisecond);

} // namespace
} // namespace Upstream
} // namespace Envoy
