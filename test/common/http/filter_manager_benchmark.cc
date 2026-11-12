#include <memory>
#include <optional>

#include "envoy/common/optref.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/matcher/matcher.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/filter/config_discovery_impl.h"
#include "source/common/http/filter_chain_helper.h"
#include "source/common/http/filter_manager.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/local_reply/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/overload_manager.h"
#include "test/test_common/test_runtime.h"

#include "benchmark/benchmark.h"

using testing::NiceMock;

namespace Envoy {
namespace Http {
namespace {

struct FilterManagerBenchmarkContext {
  NiceMock<MockFilterManagerCallbacks> filter_manager_callbacks_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  NiceMock<Network::MockConnection> connection_;
  Envoy::Http::MockFilterChainFactory filter_factory_;
  NiceMock<LocalReply::MockLocalReply> local_reply_;
  Protocol protocol_{Protocol::Http2};
  NiceMock<MockTimeSystem> time_source_;
  StreamInfo::FilterStateSharedPtr filter_state_ =
      std::make_shared<StreamInfo::FilterStateImpl>(StreamInfo::FilterState::LifeSpan::Connection);
  NiceMock<Server::MockOverloadManager> overload_manager_;
};

// Creates a chain of pass-through stream filters that ends in a decoder-only filter, as a chain
// ends in the router, through the helper the HTTP connection manager uses, so each stream builds
// its chain the way a configured listener does.
class PassThroughFilterChainFactory : public FilterChainFactory {
public:
  explicit PassThroughFilterChainFactory(size_t filter_count) {
    for (size_t i = 0; i < filter_count; ++i) {
      FilterFactoryCb factory = [](FilterChainFactoryCallbacks& callbacks) {
        callbacks.addStreamFilter(std::make_shared<PassThroughFilter>());
      };
      if (i + 1 == filter_count) {
        factory = [](FilterChainFactoryCallbacks& callbacks) {
          callbacks.addStreamDecoderFilter(std::make_shared<PassThroughDecoderFilter>());
        };
      }
      filter_factories_.push_back(
          {std::make_unique<Filter::StaticFilterConfigProviderImpl<Filter::HttpFilterFactoryCb>>(
               factory, "pass_through"),
           false});
    }
  }

  bool createFilterChain(FilterChainFactoryCallbacks& callbacks) const override {
    FilterChainUtility::createFilterChainForFactories(callbacks, filter_factories_);
    return true;
  }

  bool createUpgradeFilterChain(absl::string_view, const UpgradeMap*,
                                FilterChainFactoryCallbacks&) const override {
    return false;
  }

private:
  FilterChainUtility::FilterFactoriesList filter_factories_;
};

// Times the lifecycle of BM_FilterManagerCreateDestroy with a chain of state.range(0) filters
// created in between, so the difference between the two is the cost of the chain.
static void BM_FilterManagerCreateFilterChain(benchmark::State& state) {
  FilterManagerBenchmarkContext context;
  PassThroughFilterChainFactory filter_factory(static_cast<size_t>(state.range(0)));

  for (auto _ : state) {
    auto filter_manager = std::make_unique<DownstreamFilterManager>(
        context.filter_manager_callbacks_, context.dispatcher_, context.connection_, 0, nullptr,
        true, 10000, filter_factory, context.local_reply_, context.protocol_, context.time_source_,
        context.filter_state_, context.overload_manager_);
    filter_manager->createDownstreamFilterChain();
    filter_manager->destroyFilters();
  }
}
// A chain of one filter is a router-only listener. Larger chains add stream filters before the
// router.
BENCHMARK(BM_FilterManagerCreateFilterChain)->Arg(1)->Arg(8)->Arg(16)->Arg(24);

static void BM_FilterManagerCreateDestroy(benchmark::State& state) {
  FilterManagerBenchmarkContext context;

  for (auto _ : state) {
    auto filter_manager = std::make_unique<DownstreamFilterManager>(
        context.filter_manager_callbacks_, context.dispatcher_, context.connection_, 0, nullptr,
        true, 10000, context.filter_factory_, context.local_reply_, context.protocol_,
        context.time_source_, context.filter_state_, context.overload_manager_);
    filter_manager->destroyFilters();
  }
}
BENCHMARK(BM_FilterManagerCreateDestroy);

} // namespace
} // namespace Http
} // namespace Envoy
