// Note: this should be run with --compilation_mode=opt, and would benefit from a quiescent system
// with disabled cstate power management.
//
// Compares how delta xDS and the proposed Tokio based configuration pipeline cope with a burst of
// cluster updates. Both apply the clusters with the same CDS code to a real cluster manager, so
// they only differ in the work done before that, and in which thread does it:
//
// * `deltaXds` delivers the burst through the delta gRPC mux. For every response the main thread
//   parses it, runs the subscription state machine, has the watch map decode and validate the
//   resources, applies the clusters and sends the ACK.
// * `tokioOffload` hands the burst to Tokio workers, which parse it, apply policy and have Envoy
//   decode and validate the resources in parallel. The main thread only applies the clusters, and
//   reports the outcome of each one to an xDS config tracker.
//
// The iteration time is how long the whole burst takes to apply. `main_thread_ms` is the part of
// it that the main thread is busy, unable to serve anything else, and `offload_ms` the part the
// Tokio workers spend preparing the burst.
//
// `deltaXdsDecode` and `tokioOffloadDecode` measure, on their own, the work that `tokioOffload`
// moves off the main thread.

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/cluster/v3/cluster.pb.validate.h"
#include "envoy/config/xds_config_tracker.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/common/backoff_strategy.h"
#include "source/common/config/decoded_resource_impl.h"
#include "source/common/config/null_grpc_mux_impl.h"
#include "source/common/config/opaque_resource_decoder_impl.h"
#include "source/common/config/protobuf_link_hacks.h"
#include "source/common/config/resource_name.h"
#include "source/common/config/type_to_endpoint.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/upstream/cds_api_impl.h"
#include "source/extensions/config_subscription/grpc/grpc_subscription_impl.h"
#include "source/extensions/config_subscription/grpc/new_grpc_mux_impl.h"

#include "test/benchmark/main.h"
#include "test/common/upstream/cluster_manager_impl_test_common.h"
#include "test/mocks/common.h"
#include "test/mocks/config/custom_config_validators.h"
#include "test/mocks/grpc/mocks.h"
#include "test/mocks/local_info/mocks.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"

// The Tokio half of the pipeline, implemented in offload.rs.
extern "C" {
struct XdsOffload;
struct XdsOffloadCallbacks {
  void* context;
  void (*decode)(void* context, size_t index, const uint8_t* name, size_t name_length,
                 const uint8_t* version, size_t version_length, const uint8_t* resource,
                 size_t resource_length);
  void (*reject)(void* context, size_t index, const uint8_t* reason, size_t reason_length);
};
XdsOffload* xds_offload_new(size_t workers);
void xds_offload_delete(XdsOffload* offload);
int64_t xds_offload_prepare(const XdsOffload* offload, const uint8_t* data, size_t length,
                            XdsOffloadCallbacks callbacks);
}

namespace Envoy {
namespace Upstream {
namespace {

using ::envoy::config::cluster::v3::Cluster;
using ::envoy::service::discovery::v3::DeltaDiscoveryResponse;
using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

double milliseconds(std::chrono::steady_clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

uint32_t scale(int64_t count) {
  return Envoy::benchmark::skipExpensiveBenchmarks() ? 1 : static_cast<uint32_t>(count);
}

// One update of a burst, as a management server sends it.
struct Update {
  Cluster cluster;
  std::string version;
};

// A burst of `updates` cluster updates spread round robin over `distinct` clusters. Every time a
// cluster comes round again its configuration changes, so that it is rebuilt rather than skipped.
std::vector<Update> makeBurst(uint32_t updates, uint32_t distinct) {
  std::vector<Update> burst(updates);
  for (uint32_t i = 0; i < updates; i++) {
    const uint32_t id = i % distinct;
    const uint32_t generation = i / distinct;
    Cluster& cluster = burst[i].cluster;
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
    burst[i].version = absl::StrCat("v", generation);
  }
  return burst;
}

// Serializes the burst into delta xDS responses of `per_response` updates each.
std::vector<std::string> toDeltaResponses(const std::vector<Update>& burst, uint32_t per_response) {
  std::vector<std::string> responses;
  DeltaDiscoveryResponse response;
  const auto flush = [&responses, &response]() {
    response.set_type_url(Config::getTypeUrl<Cluster>());
    response.set_nonce(absl::StrCat(responses.size()));
    responses.push_back(response.SerializeAsString());
    response.Clear();
  };
  for (const Update& update : burst) {
    auto* resource = response.add_resources();
    resource->set_name(update.cluster.name());
    resource->set_version(update.version);
    std::ignore = resource->mutable_resource()->PackFrom(update.cluster);
    if (static_cast<uint32_t>(response.resources_size()) == per_response) {
      flush();
    }
  }
  if (response.resources_size() > 0) {
    flush();
  }
  return responses;
}

// Serializes the burst into the length-prefixed framing that offload.rs reads.
std::string toOffloadBatch(const std::vector<Update>& burst) {
  std::string batch;
  const auto append = [&batch](absl::string_view field) {
    const uint32_t length = field.size();
    for (uint32_t shift = 0; shift < 32; shift += 8) {
      batch.push_back(static_cast<char>((length >> shift) & 0xff));
    }
    batch.append(field.data(), field.size());
  };
  for (const Update& update : burst) {
    append(update.cluster.name());
    append(update.version);
    append(update.cluster.SerializeAsString());
  }
  return batch;
}

// A tracker that does what any real one has to: the outcomes it is handed are only valid for the
// duration of the call, so it copies whatever it is going to report.
class CopyingXdsConfigTracker : public Config::XdsConfigTracker {
public:
  void onConfigAccepted(absl::string_view,
                        const std::vector<Config::DecodedResourcePtr>&) override {}
  void onConfigAccepted(absl::string_view,
                        absl::Span<const envoy::service::discovery::v3::Resource* const>,
                        const Protobuf::RepeatedPtrField<std::string>&) override {}
  void onResourcesApplied(absl::string_view,
                          absl::Span<const Config::ResourceApplyResult> results) override {
    outcomes_.clear();
    outcomes_.reserve(results.size());
    for (const auto& result : results) {
      outcomes_.push_back({std::string(result.name), std::string(result.version), result.status,
                           std::string(result.details)});
    }
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

  std::vector<Outcome> outcomes_;
};

// A real cluster manager, initialized as it is once Envoy is serving, and the CDS API that applies
// updates to it. The mock subscription factory hands back the CDS API callbacks, which both
// pipelines drive.
class CdsHarness {
public:
  CdsHarness() : registered_dns_factory_(dns_resolver_factory_) {
    ON_CALL(serverContext().xds_manager_, adsMux())
        .WillByDefault(Return(std::make_shared<Config::NullGrpcMuxImpl>()));
  }

  ~CdsHarness() {
    if (cluster_manager_ != nullptr) {
      destroy();
    }
  }

  void setXdsConfigTracker(Config::XdsConfigTracker& tracker) {
    ON_CALL(serverContext().xds_manager_, xdsConfigTracker())
        .WillByDefault(Return(Config::XdsConfigTrackerOptRef(tracker)));
  }

  void create() {
    // Every cluster manager registers its config dump under the same key, which the mock admin
    // only accepts once.
    serverContext().admin_.config_tracker_.config_tracker_callbacks_.clear();
    cluster_manager_ =
        TestClusterManagerImpl::createTestClusterManager(bootstrap_, factory_, serverContext());
    ON_CALL(serverContext(), clusterManager()).WillByDefault(ReturnRef(*cluster_manager_));
    THROW_IF_NOT_OK(cluster_manager_->initialize(bootstrap_));
    cluster_manager_->setPrimaryClustersInitializedCb(
        [this]() { THROW_IF_NOT_OK(cluster_manager_->initializeSecondaryClusters(bootstrap_)); });
    cds_ = THROW_OR_RETURN_VALUE(CdsApiImpl::create(cds_config_, nullptr, *cluster_manager_,
                                                    *serverContext().store_.rootScope(),
                                                    ProtobufMessage::getStrictValidationVisitor(),
                                                    serverContext(), false),
                                 CdsApiPtr);
    callbacks_ = serverContext().xds_manager_.subscription_factory_.callbacks_;
  }

  void destroy() {
    cds_.reset();
    cluster_manager_->shutdown();
    cluster_manager_.reset();
    serverContext().dispatcher_.to_delete_.clear();
  }

  Server::Configuration::MockServerFactoryContext& serverContext() {
    return factory_.server_context_;
  }
  Config::SubscriptionCallbacks& callbacks() { return *callbacks_; }
  size_t activeClusters() { return cluster_manager_->clusters().active_clusters_.size(); }

private:
  NiceMock<Network::MockDnsResolverFactory> dns_resolver_factory_;
  Registry::InjectFactory<Network::DnsResolverFactory> registered_dns_factory_;
  NiceMock<TestClusterManagerFactory> factory_;
  const envoy::config::bootstrap::v3::Bootstrap bootstrap_;
  const envoy::config::core::v3::ConfigSource cds_config_;
  std::unique_ptr<TestClusterManagerImpl> cluster_manager_;
  CdsApiPtr cds_;
  Config::SubscriptionCallbacks* callbacks_{};
};

// A delta xDS CDS subscription, which `onResponse` delivers responses to as if they had just been
// read from its gRPC stream.
class DeltaCdsClient {
public:
  explicit DeltaCdsClient(CdsHarness& harness)
      : async_client_(std::make_shared<NiceMock<Grpc::MockAsyncClient>>()),
        stats_(Config::Utility::generateStats(*harness.serverContext().store_.rootScope())) {
    ON_CALL(*async_client_, startRaw(_, _, _, _)).WillByDefault(Return(&async_stream_));
    Config::GrpcMuxContext context{
        /*async_client_=*/async_client_,
        /*failover_async_client_=*/nullptr,
        /*dispatcher_=*/harness.serverContext().dispatcher_,
        /*service_method_=*/Config::deltaGrpcMethod(Config::getTypeUrl<Cluster>()),
        /*local_info_=*/local_info_,
        /*rate_limit_settings_=*/rate_limit_settings_,
        /*scope_=*/*harness.serverContext().store_.rootScope(),
        /*config_validators_=*/std::make_unique<NiceMock<Config::MockCustomConfigValidators>>(),
        /*xds_resources_delegate_=*/{},
        /*xds_config_tracker_=*/{},
        /*backoff_strategy_=*/
        std::make_unique<JitteredExponentialBackOffStrategy>(
            Config::SubscriptionFactory::RetryInitialDelayMs,
            Config::SubscriptionFactory::RetryMaxDelayMs, random_),
        /*target_xds_authority_=*/target_xds_authority_,
        /*eds_resources_cache_=*/nullptr,
        /*skip_subsequent_node_=*/true,
        /*load_stats_reporter_factory_=*/nullptr};
    mux_ = std::make_shared<Config::NewGrpcMuxImpl>(context);
    subscription_ = std::make_unique<Config::GrpcSubscriptionImpl>(
        mux_, harness.callbacks(), decoder_, stats_, Config::getTypeUrl<Cluster>(),
        harness.serverContext().dispatcher_, std::chrono::milliseconds(0), false,
        Config::SubscriptionOptions());
    subscription_->start({});
  }

  void onResponse(const std::string& serialized) {
    auto response = std::make_unique<DeltaDiscoveryResponse>();
    RELEASE_ASSERT(response->ParseFromString(serialized), "malformed response");
    mux_->grpcStreamForTest().onReceiveMessage(std::move(response));
  }

  uint64_t rejectedUpdates() { return stats_.update_rejected_.value(); }

private:
  NiceMock<Grpc::MockAsyncStream> async_stream_;
  std::shared_ptr<NiceMock<Grpc::MockAsyncClient>> async_client_;
  NiceMock<LocalInfo::MockLocalInfo> local_info_;
  NiceMock<Random::MockRandomGenerator> random_;
  const Config::RateLimitSettings rate_limit_settings_;
  const std::string target_xds_authority_;
  const Config::OpaqueResourceDecoderSharedPtr decoder_{
      std::make_shared<Config::OpaqueResourceDecoderImpl<Cluster>>(
          ProtobufMessage::getStrictValidationVisitor(), "name")};
  Config::SubscriptionStats stats_;
  std::shared_ptr<Config::NewGrpcMuxImpl> mux_;
  std::unique_ptr<Config::GrpcSubscriptionImpl> subscription_;
};

struct OffloadDeleter {
  void operator()(XdsOffload* offload) const { xds_offload_delete(offload); }
};
using OffloadPtr = std::unique_ptr<XdsOffload, OffloadDeleter>;

// A batch as the Tokio workers prepare it. Each resource is decoded or rejected by exactly one
// worker, which is the only one to touch its entries.
class PreparedBatch {
public:
  void reset(uint32_t size) {
    resources_.clear();
    resources_.resize(size);
    rejections_.clear();
    rejections_.resize(size);
  }

  int64_t prepare(const XdsOffload& offload, const std::string& serialized) {
    return xds_offload_prepare(&offload, reinterpret_cast<const uint8_t*>(serialized.data()),
                               serialized.size(),
                               {this, &PreparedBatch::decode, &PreparedBatch::reject});
  }

  std::vector<Config::DecodedResourceRef> decodedResources() {
    std::vector<Config::DecodedResourceRef> decoded;
    decoded.reserve(resources_.size());
    for (const auto& resource : resources_) {
      if (resource != nullptr) {
        decoded.emplace_back(*resource);
      }
    }
    return decoded;
  }

private:
  // Called on a Tokio worker, so it must not let an exception escape.
  static void decode(void* context, size_t index, const uint8_t* name, size_t name_length,
                     const uint8_t* version, size_t version_length, const uint8_t* resource,
                     size_t resource_length) {
    auto& batch = *static_cast<PreparedBatch*>(context);
    const std::string resource_name(reinterpret_cast<const char*>(name), name_length);
    TRY_NEEDS_AUDIT {
      ArenaWrappedProto<Cluster> cluster;
      if (!cluster->ParseFromArray(resource, static_cast<int>(resource_length))) {
        batch.rejections_[index] = "the cluster could not be parsed";
        return;
      }
      MessageUtil::validate(*cluster, ProtobufMessage::getStrictValidationVisitor());
      if (cluster->name() != resource_name) {
        batch.rejections_[index] = "the cluster name does not match the resource name";
        return;
      }
      batch.resources_[index] = std::make_unique<Config::DecodedResourceImpl>(
          std::move(cluster), resource_name, std::vector<std::string>(),
          std::string(reinterpret_cast<const char*>(version), version_length));
    }
    END_TRY
    catch (const EnvoyException& e) {
      batch.rejections_[index] = e.what();
    }
  }

  static void reject(void* context, size_t index, const uint8_t* reason, size_t reason_length) {
    static_cast<PreparedBatch*>(context)->rejections_[index].assign(
        reinterpret_cast<const char*>(reason), reason_length);
  }

  std::vector<Config::DecodedResourcePtr> resources_;
  std::vector<std::string> rejections_;
};

void deltaXdsDecode(::benchmark::State& state) {
  const uint32_t updates = scale(state.range(0));
  const std::string serialized = toDeltaResponses(makeBurst(updates, updates), updates).front();
  Config::OpaqueResourceDecoderImpl<Cluster> decoder(ProtobufMessage::getStrictValidationVisitor(),
                                                     "name");
  std::vector<Config::DecodedResourcePtr> resources;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    DeltaDiscoveryResponse response;
    RELEASE_ASSERT(response.ParseFromString(serialized), "malformed response");
    for (const auto& resource : response.resources()) {
      resources.push_back(std::make_unique<Config::DecodedResourceImpl>(decoder, resource));
    }

    state.PauseTiming();
    resources.clear();
    state.ResumeTiming();
  }
}
BENCHMARK(deltaXdsDecode)
    ->ArgNames({"updates"})
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000)
    ->MeasureProcessCPUTime()
    ->Unit(::benchmark::kMillisecond);

void tokioOffloadDecode(::benchmark::State& state) {
  const uint32_t updates = scale(state.range(0));
  const std::string serialized = toOffloadBatch(makeBurst(updates, updates));
  const OffloadPtr offload(xds_offload_new(state.range(1)));
  PreparedBatch batch;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    state.PauseTiming();
    batch.reset(updates);
    state.ResumeTiming();

    RELEASE_ASSERT(batch.prepare(*offload, serialized) == updates, "malformed batch");
  }
}
BENCHMARK(tokioOffloadDecode)
    ->ArgNames({"updates", "workers"})
    ->ArgsProduct({{100, 1000, 10000}, {1, 4, 8, 16}})
    ->UseRealTime()
    ->MeasureProcessCPUTime()
    ->Unit(::benchmark::kMillisecond);

void deltaXds(::benchmark::State& state) {
  const uint32_t updates = scale(state.range(0));
  const uint32_t distinct = scale(state.range(1));
  const uint32_t per_response = scale(state.range(2));
  Thread::MutexBasicLockable lock;
  Logger::Context logging_state(spdlog::level::warn, Logger::Logger::DEFAULT_LOG_FORMAT, lock,
                                false);
  const std::vector<std::string> responses =
      toDeltaResponses(makeBurst(updates, distinct), per_response);
  CdsHarness harness;
  double main_thread_ms = 0;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    state.PauseTiming();
    harness.create();
    auto client = std::make_unique<DeltaCdsClient>(harness);
    state.ResumeTiming();

    const auto start = std::chrono::steady_clock::now();
    for (const std::string& response : responses) {
      client->onResponse(response);
    }
    main_thread_ms += milliseconds(std::chrono::steady_clock::now() - start);

    state.PauseTiming();
    RELEASE_ASSERT(client->rejectedUpdates() == 0 && harness.activeClusters() == distinct,
                   "the burst was not applied");
    client.reset();
    harness.destroy();
    state.ResumeTiming();
  }
  state.counters["main_thread_ms"] =
      ::benchmark::Counter(main_thread_ms, ::benchmark::Counter::kAvgIterations);
}
BENCHMARK(deltaXds)
    ->ArgNames({"updates", "distinct", "per_response"})
    ->Args({100, 100, 100})
    ->Args({100, 100, 1})
    ->Args({1000, 1000, 1000})
    ->Args({1000, 1000, 1})
    ->Args({10000, 10000, 10000})
    ->Args({10000, 10000, 1})
    ->Args({10000, 1000, 1})
    ->MeasureProcessCPUTime()
    ->Unit(::benchmark::kMillisecond);

void tokioOffload(::benchmark::State& state) {
  const uint32_t updates = scale(state.range(0));
  const uint32_t distinct = scale(state.range(1));
  Thread::MutexBasicLockable lock;
  Logger::Context logging_state(spdlog::level::warn, Logger::Logger::DEFAULT_LOG_FORMAT, lock,
                                false);
  const std::string serialized = toOffloadBatch(makeBurst(updates, distinct));
  const OffloadPtr offload(xds_offload_new(state.range(2)));
  CdsHarness harness;
  CopyingXdsConfigTracker tracker;
  harness.setXdsConfigTracker(tracker);
  PreparedBatch batch;
  double offload_ms = 0;
  double main_thread_ms = 0;

  for (auto _ : state) { // NOLINT: Silences warning about dead store
    state.PauseTiming();
    harness.create();
    batch.reset(updates);
    state.ResumeTiming();

    const auto start = std::chrono::steady_clock::now();
    const int64_t prepared = batch.prepare(*offload, serialized);
    const auto handed_over = std::chrono::steady_clock::now();
    THROW_IF_NOT_OK(harness.callbacks().onConfigUpdate(batch.decodedResources(), {}, ""));
    // The main thread releases the decoded resources, as it would after applying them.
    batch.reset(0);
    const auto applied = std::chrono::steady_clock::now();
    offload_ms += milliseconds(handed_over - start);
    main_thread_ms += milliseconds(applied - handed_over);

    state.PauseTiming();
    RELEASE_ASSERT(prepared == updates && harness.activeClusters() == distinct,
                   "the burst was not applied");
    harness.destroy();
    state.ResumeTiming();
  }
  state.counters["offload_ms"] =
      ::benchmark::Counter(offload_ms, ::benchmark::Counter::kAvgIterations);
  state.counters["main_thread_ms"] =
      ::benchmark::Counter(main_thread_ms, ::benchmark::Counter::kAvgIterations);
}
BENCHMARK(tokioOffload)
    ->ArgNames({"updates", "distinct", "workers"})
    ->Args({100, 100, 8})
    ->Args({1000, 1000, 1})
    ->Args({1000, 1000, 8})
    ->Args({10000, 10000, 1})
    ->Args({10000, 10000, 4})
    ->Args({10000, 10000, 8})
    ->Args({10000, 10000, 16})
    ->Args({10000, 1000, 8})
    ->UseRealTime()
    ->MeasureProcessCPUTime()
    ->Unit(::benchmark::kMillisecond);

} // namespace
} // namespace Upstream
} // namespace Envoy
