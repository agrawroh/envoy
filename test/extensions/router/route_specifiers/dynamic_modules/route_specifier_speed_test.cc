// Speed test for the virtual cluster answer of the dynamic modules route specifier. It times, per
// call, route resolution with no specifier, with the eager selection of NONE, and with the router
// answer of EVERY_ROUTE_ENTRY, and the router's lookup of the virtual cluster under each.

#include <string>
#include <vector>

#include "envoy/config/route/v3/route.pb.h"

#include "source/common/http/header_map_impl.h"
#include "source/common/router/config_impl.h"
#include "source/common/stats/custom_stat_namespaces_impl.h"
#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"

#include "test/extensions/dynamic_modules/util.h"
#include "test/mocks/router/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/test_time.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "fmt/format.h"

namespace Envoy {
namespace Extensions {
namespace RouteSpecifiers {
namespace DynamicModules {
namespace {

// A route configuration whose virtual host declares rides and trips, with one route that the
// specifier answers. The module is the one named, and the answer is the one given.
std::string speedConfigYaml(absl::string_view module_name, absl::string_view answer_fields) {
  return fmt::format(R"EOF(
name: speed_route_config
virtual_hosts:
- name: speed_vhost
  domains: ["*"]
  virtual_clusters:
  - name: rides
    headers: [{{name: ":path", string_match: {{prefix: "/rides"}}}}]
  - name: trips
    headers: [{{name: ":path", string_match: {{prefix: "/trips"}}}}]
  routes:
  - match: {{prefix: "/"}}
    route: {{cluster: matched_cluster}}
  route_specifiers:
  - name: envoy.router.route_specifiers.dynamic_modules
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
      dynamic_module_config:
        name: {}
        do_not_close: true
      specifier_name: speed_specifier
      stat_prefix: speed
      failure_policy: PASS_THROUGH
      virtual_cluster_override:
        virtual_host_name: speed_vhost
        names: [rides, trips, other]
{})EOF",
                     module_name, answer_fields);
}

// The directory of the C test modules. The benchmark main does not set the runfiles handle that
// {{ test_rundir }} resolves from, so the directory comes from the runfiles root in TEST_SRCDIR,
// which bazel test and the pairing harness export along with TEST_WORKSPACE.
std::string moduleDirectory() {
  const std::string src_dir = TestEnvironment::getOptionalEnvVar("TEST_SRCDIR").value_or("");
  const std::string workspace =
      TestEnvironment::getOptionalEnvVar("TEST_WORKSPACE").value_or("_main");
  return absl::StrCat(src_dir, "/", workspace, "/test/extensions/dynamic_modules/test_data/c");
}

class SpeedFixture {
public:
  SpeedFixture() {
    TestEnvironment::setEnvVar("ENVOY_DYNAMIC_MODULES_SEARCH_PATH", moduleDirectory(), 1);
    ON_CALL(context_.api_.random_, random()).WillByDefault(testing::Return(1));
    ON_CALL(context_.api_, customStatNamespaces())
        .WillByDefault(testing::ReturnRef(custom_stat_namespaces_));
  }

  absl::StatusOr<std::shared_ptr<Router::ConfigImpl>> load(const std::string& yaml) {
    envoy::config::route::v3::RouteConfiguration proto_config;
    TestUtility::loadFromYaml(yaml, proto_config);
    return Router::ConfigImpl::create(proto_config, context_, creation_status_visitor_,
                                      init_manager_, false);
  }

  // The request headers of a path, with the virtual cluster headers the modules read and the given
  // number of filler headers, which stand for the headers a production request carries.
  Http::TestRequestHeaderMapImpl requestHeaders(absl::string_view path, size_t filler_headers = 0) {
    // The virtual cluster headers name trips, which the modules answer or select, so that the rows
    // time the found path and not a lookup that finds nothing.
    Http::TestRequestHeaderMapImpl headers{{":authority", "host"},
                                           {":path", std::string(path)},
                                           {":method", "GET"},
                                           {":scheme", "http"},
                                           {"x-forwarded-proto", "http"},
                                           {"x-virtual-cluster", "trips"},
                                           {"x-router-virtual-cluster", "trips"}};
    for (size_t i = 0; i < filler_headers; ++i) {
      headers.addCopy(Http::LowerCaseString(absl::StrCat("x-filler-", i)), "value");
    }
    return headers;
  }

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  NiceMock<Init::MockManager> init_manager_;
  ProtobufMessage::NullValidationVisitorImpl creation_status_visitor_;
  Stats::CustomStatNamespacesImpl custom_stat_namespaces_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
};

// The route a request for the path resolves to, with the specifier of the configuration.
void resolveBenchmark(benchmark::State& state, absl::string_view module_name,
                      absl::string_view answer_fields) {
  SpeedFixture fixture;
  auto config = fixture.load(speedConfigYaml(module_name, answer_fields));
  if (!config.ok()) {
    state.SkipWithError(std::string(config.status().message()).c_str());
    return;
  }
  auto headers = fixture.requestHeaders("/trips");
  for (auto _ : state) {
    auto route = config.value()->route(headers, fixture.stream_info_, 0).route;
    benchmark::DoNotOptimize(route);
  }
}

// The router's lookup of the virtual cluster of the route, which counts the request.
void routerLookupBenchmark(benchmark::State& state, absl::string_view module_name,
                           absl::string_view answer_fields, size_t filler_headers = 0) {
  SpeedFixture fixture;
  auto config = fixture.load(speedConfigYaml(module_name, answer_fields));
  if (!config.ok()) {
    state.SkipWithError(std::string(config.status().message()).c_str());
    return;
  }
  auto headers = fixture.requestHeaders("/trips", filler_headers);
  auto route = config.value()->route(headers, fixture.stream_info_, 0).route;
  if (route == nullptr) {
    state.SkipWithError("no route");
    return;
  }
  for (auto _ : state) {
    benchmark::DoNotOptimize(route->virtualHost().virtualCluster(headers));
  }
}

void BM_ResolveNoSpecifier(benchmark::State& state) {
  SpeedFixture fixture;
  auto config = fixture.load(R"EOF(
name: speed_route_config
virtual_hosts:
- name: speed_vhost
  domains: ["*"]
  routes:
  - match: {prefix: "/"}
    route: {cluster: matched_cluster}
)EOF");
  auto headers = fixture.requestHeaders("/trips");
  if (!config.ok()) {
    state.SkipWithError(std::string(config.status().message()).c_str());
    return;
  }
  if (config.value()->route(headers, fixture.stream_info_, 0).route == nullptr) {
    state.SkipWithError("no route without specifier");
    return;
  }
  for (auto _ : state) {
    benchmark::DoNotOptimize(config.value()->route(headers, fixture.stream_info_, 0).route);
  }
}

// NONE: the module runs at resolution and records the selection, which the router reads.
void BM_ResolveNone(benchmark::State& state) {
  resolveBenchmark(state, "route_specifier_virtual_cluster", "        prefer_selection: true\n");
}

// EVERY_ROUTE_ENTRY: the module is not called at resolution, only the route entry is wrapped.
void BM_ResolveEveryRouteEntry(benchmark::State& state) {
  resolveBenchmark(
      state, "route_specifier_router_answer",
      "        prefer_selection: true\n        router_answer: ROUTER_ANSWER_EVERY_ROUTE_ENTRY\n");
}

// NONE: the selection the module recorded is read back by the router.
void BM_RouterLookupNone(benchmark::State& state) {
  routerLookupBenchmark(state, "route_specifier_virtual_cluster",
                        "        prefer_selection: true\n");
}

// EVERY_ROUTE_ENTRY: the router calls the module with its headers and times the answer.
void BM_RouterLookupEveryRouteEntry(benchmark::State& state) {
  routerLookupBenchmark(
      state, "route_specifier_router_answer",
      "        prefer_selection: true\n        router_answer: ROUTER_ANSWER_EVERY_ROUTE_ENTRY\n");
}

// EVERY_ROUTE_ENTRY without prefer_selection: the router answer is only compared with the virtual
// host, which keeps its own match, so the router also pays for that match on each request.
void BM_RouterLookupEveryRouteEntryNoPrefer(benchmark::State& state) {
  routerLookupBenchmark(state, "route_specifier_router_answer",
                        "        router_answer: ROUTER_ANSWER_EVERY_ROUTE_ENTRY\n");
}

// EVERY_ROUTE_ENTRY with fifty filler headers added to the seven the fixture sends. The router
// hands the module every header, so this row measures how the bulk header getter scales with the
// count.
void BM_RouterLookupEveryRouteEntryFiftyHeaders(benchmark::State& state) {
  routerLookupBenchmark(
      state, "route_specifier_router_answer",
      "        prefer_selection: true\n        router_answer: ROUTER_ANSWER_EVERY_ROUTE_ENTRY\n",
      50);
}

// The duration row the router answer adds to a lookup: two clock reads and one record into the
// histogram of the answer, timed on its own, so that its cost is known next to the hook. The clock
// is the real one, which the production time source is.
void BM_DurationRecord(benchmark::State& state) {
  Event::TestRealTimeSystem time_system;
  Stats::IsolatedStoreImpl store;
  Stats::Histogram& histogram =
      store.histogramFromString("virtual_cluster_duration", Stats::Histogram::Unit::Nanoseconds);
  for (auto _ : state) {
    const MonotonicTime start = time_system.monotonicTime();
    const MonotonicTime end = time_system.monotonicTime();
    histogram.recordValue(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
  }
}

} // namespace
} // namespace DynamicModules
} // namespace RouteSpecifiers
} // namespace Extensions
} // namespace Envoy

BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_ResolveNoSpecifier);
BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_ResolveNone);
BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_ResolveEveryRouteEntry);
BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_RouterLookupNone);
BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_RouterLookupEveryRouteEntry);
BENCHMARK(
    Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_RouterLookupEveryRouteEntryNoPrefer);
BENCHMARK(
    Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_RouterLookupEveryRouteEntryFiftyHeaders);
BENCHMARK(Envoy::Extensions::RouteSpecifiers::DynamicModules::BM_DurationRecord);
