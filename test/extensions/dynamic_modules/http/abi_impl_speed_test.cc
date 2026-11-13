// Times the metric callbacks a module calls on an HTTP filter, against a filter config whose stats
// scope lives in a ThreadLocalStoreImpl with threading initialized. The bench runs on a main thread
// registered with a real ThreadLocal::InstanceImpl. Run it with --compilation_mode=opt on a quiet
// host.

#include <memory>
#include <string>
#include <vector>

#include "envoy/config/metrics/v3/stats.pb.h"

#include "source/common/event/libevent.h"
#include "source/common/stats/allocator.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/stats/tag_producer_impl.h"
#include "source/common/stats/thread_local_store.h"
#include "source/common/thread_local/thread_local_impl.h"
#include "source/extensions/dynamic_modules/abi/abi.h"
#include "source/extensions/filters/http/dynamic_modules/filter.h"
#include "source/extensions/filters/http/dynamic_modules/filter_config.h"

#include "test/benchmark/main.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"

namespace Envoy {
namespace Extensions {
namespace DynamicModules {
namespace HttpFilters {
namespace {

using DefineMetricFn = decltype(&envoy_dynamic_module_callback_http_filter_config_define_counter);
using RecordFilterMetricFn = decltype(&envoy_dynamic_module_callback_http_filter_increment_counter);
using ModuleBuffers = std::vector<envoy_dynamic_module_type_module_buffer>;

// A stream ends after this many records, which bounds the per-stream pool the uncached path
// interns label values into, and charges each record its share of the stream's teardown.
constexpr uint64_t RecordsPerStream = 64;

// The benchmark main does not set up libevent, which a dispatcher needs.
Event::DispatcherPtr newDispatcher(Api::Api& api) {
  if (!Event::Libevent::Global::initialized()) {
    Event::Libevent::Global::initialize();
  }
  return api.allocateDispatcher("test_thread");
}

class MetricCallbackBench {
public:
  MetricCallbackBench()
      : alloc_(symbol_table_), api_(Api::createApiForTest()), dispatcher_(newDispatcher(*api_)),
        store_(alloc_) {
    envoy::config::metrics::v3::StatsConfig stats_config;
    store_.setTagProducer(Stats::TagProducerImpl::createTagProducer(stats_config, {}).value());
    tls_.registerThread(*dispatcher_, true);
    store_.initializeThreading(*dispatcher_, tls_);
    ON_CALL(context_, threadLocal()).WillByDefault(testing::ReturnRef(tls_));
    config_ = std::make_shared<DynamicModuleHttpFilterConfig>(
        "bench", "", DefaultMetricsNamespace, nullptr, *store_.rootScope(), context_);
  }

  ~MetricCallbackBench() {
    filter_.reset();
    config_.reset();
    tls_.shutdownGlobalThreading();
    store_.shutdownThreading();
    tls_.shutdownThread();
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  }

  size_t define(DefineMetricFn define, const std::string& name,
                const std::vector<std::string>& label_names) {
    ModuleBuffers names;
    for (const std::string& label_name : label_names) {
      names.push_back({label_name.data(), label_name.size()});
    }
    size_t id = 0;
    RELEASE_ASSERT(define(config_.get(), {name.data(), name.size()}, names.data(), names.size(),
                          &id) == envoy_dynamic_module_type_metrics_result_Success,
                   "define failed");
    return id;
  }

  void newStream() {
    filter_ = std::make_shared<DynamicModuleHttpFilter>(config_, symbol_table_, 0);
  }

  // Records one value per iteration, cycling through `tuples`, whose size must be a power of two,
  // and fails the bench on any record that does not succeed.
  void run(::benchmark::State& state, RecordFilterMetricFn record, size_t id,
           std::vector<ModuleBuffers>& tuples) {
    const uint64_t mask = tuples.size() - 1;
    uint64_t i = 0;
    uint64_t failures = 0;
    for (auto _ : state) { // NOLINT: Silences warning about dead store
      if (i % RecordsPerStream == 0) {
        newStream();
      }
      ModuleBuffers& values = tuples[i & mask];
      auto result = record(filter_.get(), id, values.data(), values.size(), 1);
      ::benchmark::DoNotOptimize(result);
      if (result != envoy_dynamic_module_type_metrics_result_Success) {
        failures++;
      }
      i++;
    }
    RELEASE_ASSERT(failures == 0, "a metric record failed");
  }

  DynamicModuleHttpFilter& filter() { return *filter_; }

private:
  Stats::SymbolTableImpl symbol_table_;
  Stats::Allocator alloc_;
  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  ThreadLocal::InstanceImpl tls_;
  Stats::ThreadLocalStoreImpl store_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  DynamicModuleHttpFilterConfigSharedPtr config_;
  std::shared_ptr<DynamicModuleHttpFilter> filter_;
};

ModuleBuffers moduleBuffers(const std::vector<std::string>& values) {
  ModuleBuffers buffers;
  for (const std::string& value : values) {
    buffers.push_back({value.data(), value.size()});
  }
  return buffers;
}

// Label names and value tuples of the shapes HTTP filters record per request, four tuples per
// shape with one repeated, so consecutive records differ the way a mix of requests does.
const std::vector<std::string>& labelNames(int64_t labels) {
  static const std::vector<std::vector<std::string>> names = {
      {"result"}, {"result", "reason"}, {"route", "outcome", "reason"}};
  return names[labels - 1];
}

const std::vector<std::vector<std::string>>& labelValues(int64_t labels) {
  static const std::vector<std::vector<std::vector<std::string>>> values = {
      {{"allow"}, {"deny"}, {"allow"}, {"error"}},
      {{"allow", "residual"}, {"deny", "policy"}, {"allow", "residual"}, {"allow", "default"}},
      {{"api", "allow", "residual"},
       {"api", "deny", "policy"},
       {"web", "allow", "residual"},
       {"api", "allow", "residual"}},
  };
  return values[labels - 1];
}

std::vector<ModuleBuffers> tupleBuffers(int64_t labels) {
  std::vector<ModuleBuffers> tuples;
  for (const std::vector<std::string>& tuple : labelValues(labels)) {
    tuples.push_back(moduleBuffers(tuple));
  }
  return tuples;
}

void runLabeled(::benchmark::State& state, DefineMetricFn define, RecordFilterMetricFn record) {
  MetricCallbackBench bench;
  const size_t id = bench.define(define, "metric", labelNames(state.range(0)));
  std::vector<ModuleBuffers> tuples = tupleBuffers(state.range(0));
  bench.run(state, record, id, tuples);
}

} // namespace

// A labeled counter increment, with one, two and three labels.
// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_IncrementCounterVec(::benchmark::State& state) {
  runLabeled(state, envoy_dynamic_module_callback_http_filter_config_define_counter,
             envoy_dynamic_module_callback_http_filter_increment_counter);
}
BENCHMARK(BM_IncrementCounterVec)->Arg(1)->Arg(2)->Arg(3);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_SetGaugeVec(::benchmark::State& state) {
  runLabeled(state, envoy_dynamic_module_callback_http_filter_config_define_gauge,
             envoy_dynamic_module_callback_http_filter_set_gauge);
}
BENCHMARK(BM_SetGaugeVec)->Arg(2);

// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_RecordHistogramVec(::benchmark::State& state) {
  runLabeled(state, envoy_dynamic_module_callback_http_filter_config_define_histogram,
             envoy_dynamic_module_callback_http_filter_record_histogram_value);
}
BENCHMARK(BM_RecordHistogramVec)->Arg(2);

// An unlabeled counter increment, which takes no part in the labeled path.
// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_IncrementCounter(::benchmark::State& state) {
  MetricCallbackBench bench;
  const size_t id =
      bench.define(envoy_dynamic_module_callback_http_filter_config_define_counter, "metric", {});
  std::vector<ModuleBuffers> tuples(1);
  bench.run(state, envoy_dynamic_module_callback_http_filter_increment_counter, id, tuples);
}
BENCHMARK(BM_IncrementCounter);

// A stream that records one value on each of two labeled counters, the way a filter that counts a
// result and a decision per request does, including the creation and teardown of the filter.
// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_StreamWithTwoLabeledIncrements(::benchmark::State& state) {
  MetricCallbackBench bench;
  const size_t result_id = bench.define(
      envoy_dynamic_module_callback_http_filter_config_define_counter, "result", labelNames(2));
  const size_t decision_id =
      bench.define(envoy_dynamic_module_callback_http_filter_config_define_counter, "decision",
                   {"step", "outcome"});
  std::vector<ModuleBuffers> results = tupleBuffers(2);
  static const std::vector<std::vector<std::string>> decision_values = {
      {"cache_lookup", "hit"},
      {"host_match", "overridden"},
      {"cache_lookup", "hit"},
      {"region_check", "mismatch"}};
  std::vector<ModuleBuffers> decisions;
  for (const std::vector<std::string>& tuple : decision_values) {
    decisions.push_back(moduleBuffers(tuple));
  }
  uint64_t i = 0;
  uint64_t failures = 0;
  for (auto _ : state) { // NOLINT: Silences warning about dead store
    bench.newStream();
    ModuleBuffers& result = results[i & 3];
    ModuleBuffers& decision = decisions[i & 3];
    auto first = envoy_dynamic_module_callback_http_filter_increment_counter(
        &bench.filter(), result_id, result.data(), result.size(), 1);
    auto second = envoy_dynamic_module_callback_http_filter_increment_counter(
        &bench.filter(), decision_id, decision.data(), decision.size(), 1);
    ::benchmark::DoNotOptimize(first);
    ::benchmark::DoNotOptimize(second);
    if (first != envoy_dynamic_module_type_metrics_result_Success ||
        second != envoy_dynamic_module_type_metrics_result_Success) {
      failures++;
    }
    i++;
  }
  RELEASE_ASSERT(failures == 0, "a metric record failed");
}
BENCHMARK(BM_StreamWithTwoLabeledIncrements);

// The worst case for a cache of resolved children, a label with more values than any per-thread
// cache holds. Every value already has its counter, so each call pays the stats store's lookup,
// and almost every call also misses the cache.
// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_IncrementCounterVecUncachedTuple(::benchmark::State& state) {
  if (benchmark::skipExpensiveBenchmarks()) {
    state.SkipWithError("Skipping expensive benchmark");
    return;
  }
  constexpr size_t Values = 1 << 16;
  MetricCallbackBench bench;
  const size_t id = bench.define(envoy_dynamic_module_callback_http_filter_config_define_counter,
                                 "metric", {"peer"});
  std::vector<std::string> values;
  values.reserve(Values);
  for (size_t i = 0; i < Values; i++) {
    values.push_back(absl::StrCat("10.0.", i / 256, ".", i % 256));
  }
  std::vector<ModuleBuffers> tuples;
  tuples.reserve(Values);
  for (const std::string& value : values) {
    tuples.push_back({{value.data(), value.size()}});
  }
  for (size_t i = 0; i < Values; i++) {
    if (i % RecordsPerStream == 0) {
      bench.newStream();
    }
    RELEASE_ASSERT(envoy_dynamic_module_callback_http_filter_increment_counter(
                       &bench.filter(), id, tuples[i].data(), 1, 1) ==
                       envoy_dynamic_module_type_metrics_result_Success,
                   "a metric record failed");
  }
  bench.run(state, envoy_dynamic_module_callback_http_filter_increment_counter, id, tuples);
}
BENCHMARK(BM_IncrementCounterVecUncachedTuple);

// The worst case for every caller, a label value never recorded before, so each call creates its
// counter in the stats store. It runs a fixed number of calls, since each one keeps a new counter.
// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_IncrementCounterVecNewTuple(::benchmark::State& state) {
  if (benchmark::skipExpensiveBenchmarks()) {
    state.SkipWithError("Skipping expensive benchmark");
    return;
  }
  const size_t calls = state.max_iterations;
  MetricCallbackBench bench;
  const size_t id = bench.define(envoy_dynamic_module_callback_http_filter_config_define_counter,
                                 "metric", {"request"});
  std::vector<std::string> values;
  values.reserve(calls);
  for (size_t i = 0; i < calls; i++) {
    values.push_back(absl::StrCat("request-", i));
  }
  std::vector<ModuleBuffers> tuples;
  tuples.reserve(calls);
  for (const std::string& value : values) {
    tuples.push_back({{value.data(), value.size()}});
  }
  uint64_t i = 0;
  uint64_t failures = 0;
  for (auto _ : state) { // NOLINT: Silences warning about dead store
    if (i % RecordsPerStream == 0) {
      bench.newStream();
    }
    auto result = envoy_dynamic_module_callback_http_filter_increment_counter(
        &bench.filter(), id, tuples[i].data(), 1, 1);
    ::benchmark::DoNotOptimize(result);
    if (result != envoy_dynamic_module_type_metrics_result_Success) {
      failures++;
    }
    i++;
  }
  RELEASE_ASSERT(failures == 0, "a metric record failed");
}
BENCHMARK(BM_IncrementCounterVecNewTuple)->Iterations(100000);

} // namespace HttpFilters
} // namespace DynamicModules
} // namespace Extensions
} // namespace Envoy
