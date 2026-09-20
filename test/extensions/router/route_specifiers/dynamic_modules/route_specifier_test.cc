#include <memory>
#include <string>

#include "envoy/config/route/v3/route.pb.h"
#include "envoy/extensions/router/route_specifiers/dynamic_modules/v3/dynamic_modules.pb.h"
#include "envoy/registry/registry.h"

#include "source/common/common/fmt.h"
#include "source/common/router/config_impl.h"
#include "source/common/stats/custom_stat_namespaces_impl.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"
#include "source/extensions/router/route_specifiers/dynamic_modules/config.h"

#include "test/extensions/dynamic_modules/util.h"
#include "test/mocks/init/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace RouteSpecifiers {
namespace DynamicModules {
namespace {

using ::Envoy::StatusHelpers::HasStatusMessage;
using ::testing::HasSubstr;
using ::testing::NiceMock;

// Builds a route configuration whose only virtual host runs the given route specifier
// configuration, so that templates are built through the same path a real configuration uses.
std::string routeConfigYaml(absl::string_view specifier_yaml) {
  return fmt::format(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {{prefix: "/"}}
    route: {{cluster: matched_cluster}}
  route_specifiers:
  - name: envoy.router.route_specifiers.dynamic_modules
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
{}
)EOF",
                     specifier_yaml);
}

// Indents a specifier configuration so that it nests under `typed_config`.
std::string specifierYaml(absl::string_view module_name, absl::string_view body) {
  return fmt::format(R"EOF(      dynamic_module_config:
        name: {}
        do_not_close: true
      specifier_name: test_route_specifier
      stat_prefix: test
{})EOF",
                     module_name, body);
}

// Request headers with everything route matching needs, so that only the specifier under test can
// change the outcome.
Http::TestRequestHeaderMapImpl requestHeaders(absl::string_view path = "/") {
  return Http::TestRequestHeaderMapImpl{{":authority", "host"},
                                        {":path", std::string(path)},
                                        {":method", "GET"},
                                        {":scheme", "http"},
                                        {"x-forwarded-proto", "http"}};
}

class DynamicModuleRouteSpecifierTest : public testing::Test {
public:
  DynamicModuleRouteSpecifierTest() {
    TestEnvironment::setEnvVar("ENVOY_DYNAMIC_MODULES_SEARCH_PATH",
                               TestEnvironment::substitute(
                                   "{{ test_rundir }}/test/extensions/dynamic_modules/test_data/c"),
                               1);
    ON_CALL(context_.api_, customStatNamespaces())
        .WillByDefault(testing::ReturnRef(custom_stat_namespaces_));
  }

  absl::StatusOr<std::shared_ptr<Envoy::Router::ConfigImpl>>
  loadConfig(absl::string_view specifier_yaml) {
    envoy::config::route::v3::RouteConfiguration proto_config;
    TestUtility::loadFromYaml(routeConfigYaml(specifier_yaml), proto_config);
    return Envoy::Router::ConfigImpl::create(proto_config, context_, creation_status_visitor_,
                                             init_manager_, false);
  }

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  NiceMock<Init::MockManager> init_manager_;
  ProtobufMessage::NullValidationVisitorImpl creation_status_visitor_;
  Stats::CustomStatNamespacesImpl custom_stat_namespaces_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
  DynamicModuleRouteSpecifierFactory factory_;
};

TEST_F(DynamicModuleRouteSpecifierTest, FactoryName) {
  EXPECT_EQ("envoy.router.route_specifiers.dynamic_modules", factory_.name());
}

TEST_F(DynamicModuleRouteSpecifierTest, ModuleNotFound) {
  const auto config =
      loadConfig(specifierYaml("nonexistent_module", "      failure_policy: PASS_THROUGH\n"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("Failed to load dynamic module")));
}

TEST_F(DynamicModuleRouteSpecifierTest, MissingConfigNew) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_missing_config_new", "      failure_policy: PASS_THROUGH\n"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("envoy_dynamic_module_on_route_specifier_config_new")));
}

TEST_F(DynamicModuleRouteSpecifierTest, MissingConfigDestroy) {
  const auto config = loadConfig(specifierYaml("route_specifier_missing_config_destroy",
                                               "      failure_policy: PASS_THROUGH\n"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr(
                                   "envoy_dynamic_module_on_route_specifier_config_destroy")));
}

TEST_F(DynamicModuleRouteSpecifierTest, MissingOnRoute) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_missing_on_route", "      failure_policy: PASS_THROUGH\n"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("envoy_dynamic_module_on_route_specifier_on_route")));
}

TEST_F(DynamicModuleRouteSpecifierTest, ConfigNewFail) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_config_new_fail", "      failure_policy: PASS_THROUGH\n"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("Failed to initialize dynamic module")));
}

TEST_F(DynamicModuleRouteSpecifierTest, FailurePolicyRequired) {
  const auto config = loadConfig(specifierYaml("route_specifier_no_op", ""));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("failure_policy must be set")));
}

TEST_F(DynamicModuleRouteSpecifierTest, ShadowModeWithoutFailurePolicy) {
  const auto config = loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      shadow_mode: {}
)EOF"));
  EXPECT_TRUE(config.ok());
}

TEST_F(DynamicModuleRouteSpecifierTest, DuplicateTemplateId) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_templates:
      - template_id: canary
        route:
          match: {prefix: "/"}
          route: {cluster: canary_cluster}
      - template_id: canary
        route:
          match: {prefix: "/"}
          route: {cluster: other_cluster}
)EOF"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("duplicate route template id 'canary'")));
}

TEST_F(DynamicModuleRouteSpecifierTest, TemplateWithRouteSpecifiers) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_templates:
      - template_id: canary
        route:
          match: {prefix: "/"}
          route: {cluster: canary_cluster}
          route_specifiers:
          - name: envoy.router.route_specifiers.dynamic_modules
            typed_config:
              "@type": type.googleapis.com/google.protobuf.Struct
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("route_specifiers are not supported on a built route")));
}

TEST_F(DynamicModuleRouteSpecifierTest, InvalidTemplate) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      validate_clusters: true
      route_templates:
      - template_id: canary
        route:
          match: {prefix: "/"}
          route: {cluster: unknown_cluster}
)EOF"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("route template 'canary'")));
}

TEST_F(DynamicModuleRouteSpecifierTest, EmptyRouteActionOverride) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_action_overrides:
        canary: {}
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr(
                  "Route action override must replace at least one route action property")));
}

TEST_F(DynamicModuleRouteSpecifierTest, MetadataMatchWithoutLbEntry) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_action_overrides:
        canary:
          metadata_match:
            filter_metadata:
              envoy.other: {key: value}
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr(
                  "Route action override must replace at least one route action property")));
}

TEST_F(DynamicModuleRouteSpecifierTest, ValidConfigWithTemplatesAndOverrides) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: NO_ROUTE
      route_templates:
      - template_id: canary
        route:
          match: {prefix: "/"}
          route: {cluster: canary_cluster}
      - template_id: redirect
        route:
          match: {prefix: "/"}
          redirect: {host_redirect: "example.com"}
      route_action_overrides:
        slow:
          retry_policy: {retry_on: "5xx", num_retries: 3}
      allowed_cluster_names:
      - exact: canary_cluster
      allowed_metadata_namespaces:
      - exact: envoy.test.route
)EOF"));
  ASSERT_TRUE(config.ok());

  // The no-op module passes through, so the matched route stays in effect.
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
}

// A module built against a newer ABI could return a decision this build does not know, which is
// handled by the failure policy rather than trusted.
TEST_F(DynamicModuleRouteSpecifierTest, UnknownDecisionPassesThrough) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_unknown_decision", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1,
      context_.store_.counter("route_specifier.dynamic_modules.test.failure_module_error").value());
}

// NO_ROUTE drops the route rather than falling back to the route table.
TEST_F(DynamicModuleRouteSpecifierTest, UnknownDecisionFailsClosed) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_unknown_decision", "      failure_policy: NO_ROUTE\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  EXPECT_EQ(nullptr, route.route);
}

// Every allowlist is accepted, and an empty one accepts any name.
TEST_F(DynamicModuleRouteSpecifierTest, AcceptsAllowlists) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      allowed_cluster_names:
      - prefix: shard-
      allowed_filter_names:
      - exact: envoy.filters.http.rbac
      allowed_metadata_namespaces:
      - exact: envoy.test.route
)EOF"));
  EXPECT_TRUE(config.ok());
}

TEST_F(DynamicModuleRouteSpecifierTest, ConfigDestroyRunsOnTeardown) {
  using GetConfigDestroyCountFuncType = int (*)(void);
  auto module = Extensions::DynamicModules::newDynamicModule(
      Extensions::DynamicModules::testSharedObjectPath("route_specifier_no_op", "c"),
      /*do_not_close=*/true);
  ASSERT_TRUE(module.ok());
  const auto destroy_count =
      module.value()->getFunctionPointer<GetConfigDestroyCountFuncType>("getConfigDestroyCount");
  ASSERT_TRUE(destroy_count.ok());
  const int before = destroy_count.value()();

  {
    const auto config =
        loadConfig(specifierYaml("route_specifier_no_op", "      failure_policy: PASS_THROUGH\n"));
    ASSERT_TRUE(config.ok());
  }
  EXPECT_EQ(before + 1, destroy_count.value()());
}

} // namespace
} // namespace DynamicModules
} // namespace RouteSpecifiers
} // namespace Extensions
} // namespace Envoy
