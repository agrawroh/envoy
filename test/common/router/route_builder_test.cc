#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/config/route/v3/route.pb.h"
#include "envoy/router/route_specifier.h"

#include "source/common/router/config_impl.h"

#include "test/mocks/init/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/registry.h"
#include "test/test_common/utility.h"

#include "absl/container/flat_hash_map.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Router {
namespace {

using ::testing::NiceMock;

// A specifier that hands every route on unchanged.
class PassThroughSpecifier : public RouteSpecifier {
public:
  OnRouteResult onRoute(RouteConstSharedPtr route, const Http::RequestHeaderMap&,
                        const StreamInfo::StreamInfo&, uint64_t,
                        OnRouteInputStatus) const override {
    return {std::move(route)};
  }
};

// Builds the routes a test declares with the route builder of the virtual host the specifier is
// configured on, which is how a specifier builds the routes it may select.
class BuildingRouteSpecifierFactory : public RouteSpecifierFactory {
public:
  absl::StatusOr<RouteSpecifierSharedPtr>
  createRouteSpecifier(const Protobuf::Message&, RouteSpecifierFactoryContext& context) override {
    for (const auto& [name, yaml] : routes_) {
      envoy::config::route::v3::Route route;
      TestUtility::loadFromYaml(yaml, route);
      absl::StatusOr<MatchableRouteConstSharedPtr> built =
          context.routeBuilder()->build(route, false);
      RETURN_IF_NOT_OK_REF(built.status());
      built_[name] = std::move(built.value());
    }
    return std::make_shared<PassThroughSpecifier>();
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<Protobuf::StringValue>();
  }
  std::string name() const override { return "envoy.test.building_route_specifier"; }

  std::vector<std::pair<std::string, std::string>> routes_;
  absl::flat_hash_map<std::string, MatchableRouteConstSharedPtr> built_;
};

class RouteBuilderTest : public testing::Test {
protected:
  void load() {
    envoy::config::route::v3::RouteConfiguration proto_config;
    TestUtility::loadFromYaml(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {prefix: "/"}
    route: {cluster: configured_cluster}
  route_specifiers:
  - name: envoy.test.building_route_specifier
    typed_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
)EOF",
                              proto_config);
    auto config = ConfigImpl::create(proto_config, context_, validator_, init_manager_, false);
    ASSERT_TRUE(config.ok());
    config_ = std::move(config.value());
  }

  RouteConstSharedPtr match(const std::string& name, uint64_t random = 0) {
    return factory_.built_.at(name)->match(headers_, stream_info_, random);
  }

  // Declared first so it is destroyed last, after the routes built from its symbol table.
  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  ProtobufMessage::NullValidationVisitorImpl validator_;
  NiceMock<Init::MockManager> init_manager_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
  BuildingRouteSpecifierFactory factory_;
  Registry::InjectFactory<RouteSpecifierFactory> registered_{factory_};
  Http::TestRequestHeaderMapImpl headers_{{":authority", "host"},
                                          {":path", "/"},
                                          {":method", "GET"},
                                          {":scheme", "http"},
                                          {"x-forwarded-proto", "http"},
                                          {"x-cluster", "header_cluster"}};
  std::shared_ptr<ConfigImpl> config_;
};

// A route that names its cluster, or answers the request directly, returns itself from every match,
// so stableRoute() is that route.
TEST_F(RouteBuilderTest, StableRouteIsTheRouteEveryMatchReturns) {
  factory_.routes_ = {
      {"named", R"EOF(
match: {prefix: "/"}
route: {cluster: named_cluster}
)EOF"},
      {"direct", R"EOF(
match: {prefix: "/"}
direct_response: {status: 204}
)EOF"},
  };
  load();
  for (const std::string name : {"named", "direct"}) {
    SCOPED_TRACE(name);
    const RouteConstSharedPtr first = match(name);
    ASSERT_NE(nullptr, first);
    EXPECT_EQ(first.get(), factory_.built_.at(name)->stableRoute());
    EXPECT_EQ(first.get(), match(name).get());
  }
}

// A route that resolves its cluster per request, from weighted clusters or from a request header,
// returns a route built for each request, so it has no stable route.
TEST_F(RouteBuilderTest, PerRequestClusterHasNoStableRoute) {
  factory_.routes_ = {
      {"weighted", R"EOF(
match: {prefix: "/"}
route:
  weighted_clusters:
    clusters:
    - {name: cluster_a, weight: 50}
    - {name: cluster_b, weight: 50}
)EOF"},
      {"header", R"EOF(
match: {prefix: "/"}
route: {cluster_header: x-cluster}
)EOF"},
  };
  load();
  for (const std::string name : {"weighted", "header"}) {
    SCOPED_TRACE(name);
    EXPECT_EQ(nullptr, factory_.built_.at(name)->stableRoute());
    const RouteConstSharedPtr first = match(name, 10);
    ASSERT_NE(nullptr, first);
    EXPECT_NE(first.get(), match(name, 10).get());
  }
}

// A route that names its cluster reports no cluster specifier plugin.
TEST_F(RouteBuilderTest, NamedClusterHasNoClusterSpecifierPlugin) {
  load();
  const RouteConstSharedPtr route = config_->route(headers_, stream_info_, 0).route;
  ASSERT_NE(nullptr, route);
  const auto* entry = dynamic_cast<const RouteEntryImplBase*>(route.get());
  ASSERT_NE(nullptr, entry);
  EXPECT_EQ(nullptr, entry->clusterSpecifierPlugin());
}

// MatchableRoute reports no stable route unless an implementation says otherwise.
TEST(MatchableRouteTest, DefaultHasNoStableRoute) {
  class AlwaysNull : public MatchableRoute {
  public:
    RouteConstSharedPtr match(const Http::RequestHeaderMap&, const StreamInfo::StreamInfo&,
                              uint64_t) const override {
      return nullptr;
    }
  };
  EXPECT_EQ(nullptr, AlwaysNull().stableRoute());
}

} // namespace
} // namespace Router
} // namespace Envoy
