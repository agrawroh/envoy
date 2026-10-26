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
#include "test/test_common/registry.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace RouteSpecifiers {
namespace DynamicModules {
namespace {

using ::Envoy::StatusHelpers::HasStatusMessage;
using ::testing::_;
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

// Builds a route configuration whose first route is a catch all carrying the given route level
// specifier, followed by a specific route, so a test can see matching carry on past the catch all.
std::string catchAllRouteConfigYaml(absl::string_view module_name,
                                    absl::string_view failure_policy) {
  return fmt::format(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {{prefix: "/"}}
    route: {{cluster: catch_all_cluster}}
    route_specifiers:
    - name: envoy.router.route_specifiers.dynamic_modules
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
        dynamic_module_config:
          name: {}
          do_not_close: true
        specifier_name: test_route_specifier
        stat_prefix: test
        failure_policy: {}
  - match: {{prefix: "/specific"}}
    route: {{cluster: specific_cluster}}
)EOF",
                     module_name, failure_policy);
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
    return loadRaw(routeConfigYaml(specifier_yaml));
  }

  absl::StatusOr<std::shared_ptr<Envoy::Router::ConfigImpl>> loadRaw(absl::string_view yaml) {
    envoy::config::route::v3::RouteConfiguration proto_config;
    TestUtility::loadFromYaml(std::string(yaml), proto_config);
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

TEST_F(DynamicModuleRouteSpecifierTest, DoNotCloseRequired) {
  const auto config = loadConfig(R"EOF(      dynamic_module_config:
        name: route_specifier_no_op
        do_not_close: false
      specifier_name: test_route_specifier
      stat_prefix: test
      failure_policy: PASS_THROUGH
)EOF");
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr(
                  "dynamic_module_config.do_not_close must be true for a dynamic module route "
                  "specifier")));
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

// A repeated route override list can carry the same override_id twice, which is rejected at
// configuration load just like a duplicate template id.
TEST_F(DynamicModuleRouteSpecifierTest, DuplicateRouteOverrideId) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: slow
        retry_policy: {retry_on: "5xx", num_retries: 3}
      - override_id: slow
        hedge_policy: {hedge_on_per_try_timeout: true}
)EOF"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("duplicate route override id 'slow'")));
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

TEST_F(DynamicModuleRouteSpecifierTest, EmptyRouteOverride) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: canary
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("Route override must replace at least one property")));
}

TEST_F(DynamicModuleRouteSpecifierTest, MetadataMatchWithoutLbEntry) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: canary
        metadata_match:
          filter_metadata:
            envoy.other: {key: value}
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("Route override must replace at least one property")));
}

// A route override that only replaces the hedge policy is valid, so a module can add hedging
// to the route it produces.
TEST_F(DynamicModuleRouteSpecifierTest, HedgePolicyRouteOverride) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: hedged
        hedge_policy:
          hedge_on_per_try_timeout: true
)EOF"));
  EXPECT_TRUE(config.ok());
}

// A route override that only replaces the rate limits is valid, so a module can rate limit
// the route it produces.
TEST_F(DynamicModuleRouteSpecifierTest, RateLimitPolicyRouteOverride) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: rated
        rate_limits:
        - actions: [{destination_cluster: {}}]
)EOF"));
  EXPECT_TRUE(config.ok());
}

// A route override that only replaces the CORS policy is valid, so a module can set CORS on
// the route it produces.
TEST_F(DynamicModuleRouteSpecifierTest, CorsPolicyRouteOverride) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: corsed
        cors:
          allow_origin_string_match: [{exact: "example.com"}]
          allow_methods: "GET"
)EOF"));
  EXPECT_TRUE(config.ok());
}

// A CORS policy whose origin matcher cannot be built is rejected at configuration load.
TEST_F(DynamicModuleRouteSpecifierTest, CorsPolicyInvalidOriginMatcher) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: corsed
        cors:
          allow_origin_string_match: [{safe_regex: {regex: "("}}]
)EOF"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("route override 'corsed'")));
}

// A rate limit whose descriptor value cannot be built is rejected at configuration load.
TEST_F(DynamicModuleRouteSpecifierTest, RateLimitPolicyInvalidDescriptor) {
  TestScopedRuntime scoped_runtime;
  scoped_runtime.mergeValues(
      {{"envoy.reloadable_features.enable_formatter_for_ratelimit_action_descriptor_value",
        "true"}});
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: rated
        rate_limits:
        - actions: [{generic_key: {descriptor_value: "%"}}]
)EOF"));
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr("route override 'rated'")));
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
      route_overrides:
      - override_id: slow
        retry_policy: {retry_on: "5xx", num_retries: 3}
)EOF"));
  ASSERT_TRUE(config.ok());

  // The no-op module passes through, so the matched route stays in effect.
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
}

// A module built against a newer ABI could record a decision this build does not know, which is
// handled by the failure policy rather than trusted.
TEST_F(DynamicModuleRouteSpecifierTest, UnknownDecisionPassesThrough) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_unknown_decision", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1, context_.store_.counter("dynamicmodulescustom.route_specifier.test.failure_module_error")
             .value());
}

// NO_ROUTE drops the route rather than falling back to the route table.
TEST_F(DynamicModuleRouteSpecifierTest, UnknownDecisionFailsClosed) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_unknown_decision", "      failure_policy: NO_ROUTE\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  EXPECT_EQ(nullptr, route.route);
}

// A module built against a newer ABI could also return a status this build does not know, which
// is handled by the failure policy as well.
TEST_F(DynamicModuleRouteSpecifierTest, UnknownStatusPassesThrough) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_unknown_status", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1, context_.store_.counter("dynamicmodulescustom.route_specifier.test.failure_module_error")
             .value());
  // A status Envoy does not know is not a decision the module recorded.
  EXPECT_EQ(
      1,
      context_.store_.counter("dynamicmodulescustom.route_specifier.test.unknown_status").value());
  EXPECT_EQ(
      0,
      context_.store_.counter("dynamicmodulescustom.route_specifier.test.decision_error").value());
}

// A virtual host that configures no routes at all is routed entirely by the module, which is how a
// module owns the routing of a virtual host.
TEST_F(DynamicModuleRouteSpecifierTest, RoutesVirtualHostWithoutRoutes) {
  envoy::config::route::v3::RouteConfiguration proto_config;
  TestUtility::loadFromYaml(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  route_specifiers:
  - name: envoy.router.route_specifiers.dynamic_modules
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
      dynamic_module_config:
        name: route_specifier_select_template
        do_not_close: true
      specifier_name: test_route_specifier
      stat_prefix: test
      failure_policy: NO_ROUTE
      route_templates:
      - template_id: only
        route:
          match: {prefix: "/"}
          route: {cluster: module_cluster}
)EOF",
                            proto_config);
  const auto config = Envoy::Router::ConfigImpl::create(
      proto_config, context_, creation_status_visitor_, init_manager_, false);
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  ASSERT_NE(nullptr, route.route->routeEntry());
  EXPECT_EQ("module_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ("test_vhost", route.route->virtualHost().name());
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

// A route override may carry a regex rewrite, which is compiled once when the specifier loads.
TEST_F(DynamicModuleRouteSpecifierTest, RegexRewriteOverrideLoads) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: rewrite
        regex_rewrite:
          pattern: {regex: "^/api/(.*)$"}
          substitution: '/internal/\1'
)EOF"));
  EXPECT_TRUE(config.ok());
}

// A route override may carry tracing, built once when the specifier loads.
TEST_F(DynamicModuleRouteSpecifierTest, TracingOverrideLoads) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: traced
        tracing:
          client_sampling: {numerator: 10}
          overall_sampling: {numerator: 50}
)EOF"));
  EXPECT_TRUE(config.ok());
}

// An invalid tracing operation formatter is rejected when the specifier loads rather than throwing.
TEST_F(DynamicModuleRouteSpecifierTest, InvalidTracingOperationRejected) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: traced
        tracing:
          operation: "%INVALID_COMMAND_THAT_DOES_NOT_EXIST%"
)EOF"));
  EXPECT_FALSE(config.ok());
}

// A route override may carry metadata, which is a route level property valid on any route.
TEST_F(DynamicModuleRouteSpecifierTest, MetadataOverrideLoads) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      route_overrides:
      - override_id: tagged
        metadata:
          filter_metadata:
            envoy.test.override: {group: canary}
)EOF"));
  EXPECT_TRUE(config.ok());
}

// A shadow policy of a route override that names a cluster the cluster manager does not know
// is rejected when clusters are validated, since a statically named cluster can be checked at load.
TEST_F(DynamicModuleRouteSpecifierTest, ValidateClustersRejectsUnknownShadowCluster) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_no_op", R"EOF(      failure_policy: PASS_THROUGH
      validate_clusters: true
      route_overrides:
      - override_id: mirrored
        request_mirror_policies:
        - cluster: unknown_cluster
)EOF"));
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("unknown shadow cluster 'unknown_cluster'")));
}

// Route templates need a route builder, which a specifier configured on a route configuration does
// not have, so a configuration that pairs the two is rejected.
TEST_F(DynamicModuleRouteSpecifierTest, TemplatesRequireRouteBuilder) {
  envoy::config::route::v3::RouteConfiguration proto_config;
  TestUtility::loadFromYaml(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {prefix: "/"}
    route: {cluster: matched_cluster}
route_specifiers:
- name: envoy.router.route_specifiers.dynamic_modules
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
    dynamic_module_config:
      name: route_specifier_no_op
      do_not_close: true
    specifier_name: test_route_specifier
    stat_prefix: test
    failure_policy: PASS_THROUGH
    route_templates:
    - template_id: canary
      route:
        match: {prefix: "/"}
        route: {cluster: canary_cluster}
)EOF",
                            proto_config);
  const auto config = Envoy::Router::ConfigImpl::create(
      proto_config, context_, creation_status_visitor_, init_manager_, false);
  EXPECT_THAT(config.status(), HasStatusMessage(HasSubstr(
                                   "route templates require a route specifier configured on a "
                                   "virtual host or a route")));
}

// With the runtime feature enabled a configured metrics namespace replaces the default, is
// registered as a custom stat namespace, and roots the statistics of the specifier.
TEST_F(DynamicModuleRouteSpecifierTest, RegistersCustomStatNamespace) {
  TestScopedRuntime scoped_runtime;
  scoped_runtime.mergeValues(
      {{"envoy.reloadable_features.dynamic_modules_strip_custom_stat_prefix", "true"}});
  const auto config = loadConfig(R"EOF(      dynamic_module_config:
        name: route_specifier_no_op
        do_not_close: true
        metrics_namespace: custom_metrics
      specifier_name: test_route_specifier
      stat_prefix: test
      failure_policy: PASS_THROUGH
)EOF");
  ASSERT_TRUE(config.ok());
  EXPECT_TRUE(custom_stat_namespaces_.registered("custom_metrics"));

  // The statistics of the specifier are rooted at the configured metrics namespace.
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  // The no-op module records no decision, so the default Unspecified decision is in effect.
  EXPECT_EQ(
      1,
      context_.store_.counter("custom_metrics.route_specifier.test.decision_has_override").value());
}

// A decision that records route entry overrides produces a route entry wrapper. Its rewritten path,
// header transforms and typed metadata are read directly, the way the router and its consumers read
// them rather than through the finalize hooks.
TEST_F(DynamicModuleRouteSpecifierTest, RouteEntryWrapperAccessors) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  // The recorded route name, cluster, and path replace those of the route.
  EXPECT_EQ("module_route_entry", route.route->routeName());
  EXPECT_EQ("canary", entry->clusterName());
  auto headers = requestHeaders();
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/rewritten",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));

  // The recorded scalar route entry overrides replace those of the route.
  ASSERT_TRUE(entry->idleTimeout().has_value());
  EXPECT_EQ(std::chrono::milliseconds(8000), *entry->idleTimeout());
  ASSERT_TRUE(entry->maxStreamDuration().has_value());
  EXPECT_EQ(std::chrono::milliseconds(9000), *entry->maxStreamDuration());
  EXPECT_TRUE(entry->usingNewTimeouts());
  EXPECT_EQ(4096, entry->requestBodyBufferLimit());
  EXPECT_EQ(Envoy::Upstream::ResourcePriority::High, entry->priority());

  // Each recorded header mutation lands in the transform bucket of its append action, and the
  // removal in the remove list.
  const auto request_transforms = entry->requestHeaderTransforms(stream_info_, true);
  ASSERT_EQ(1, request_transforms.headers_to_append_or_add.size());
  EXPECT_EQ("x-append", request_transforms.headers_to_append_or_add[0].first.get());
  EXPECT_EQ("value", request_transforms.headers_to_append_or_add[0].second);
  ASSERT_EQ(1, request_transforms.headers_to_add_if_absent.size());
  EXPECT_EQ("x-add-if-absent", request_transforms.headers_to_add_if_absent[0].first.get());
  ASSERT_EQ(1, request_transforms.headers_to_overwrite_or_add.size());
  EXPECT_EQ("x-overwrite", request_transforms.headers_to_overwrite_or_add[0].first.get());
  ASSERT_EQ(1, request_transforms.headers_to_remove.size());
  EXPECT_EQ("x-remove", request_transforms.headers_to_remove[0].get());
  const auto response_transforms = entry->responseHeaderTransforms(stream_info_, true);
  ASSERT_EQ(1, response_transforms.headers_to_add_if_absent.size());
  EXPECT_EQ("x-added", response_transforms.headers_to_add_if_absent[0].first.get());

  // The recorded metadata is layered onto the route.
  const auto& filter_metadata = route.route->metadata().filter_metadata();
  ASSERT_TRUE(filter_metadata.contains("envoy.test.route"));
  EXPECT_EQ("value", filter_metadata.at("envoy.test.route").fields().at("key").string_value());
  // The typed accessor reads the same layered metadata, exercised for coverage since string
  // metadata has no typed representation to assert.
  static_cast<void>(route.route->typedMetadata());
}

// A decision that selects a declared route override applies its properties, so the route entry
// wrapper reads each one from the override rather than from the route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteEntryWrapperRouteOverrideAccessors) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: select-override
      route_overrides:
      - override_id: applied
        retry_policy: {retry_on: "5xx", num_retries: 3}
        hedge_policy: {hedge_on_per_try_timeout: true}
        hash_policy:
        - header: {header_name: x-hash}
        metadata_match:
          filter_metadata:
            envoy.lb: {version: canary}
        rate_limits:
        - actions: [{generic_key: {descriptor_value: rated}}]
        cors:
          allow_origin_string_match: [{exact: "example.com"}]
        request_mirror_policies:
        - cluster: canary
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  // Each property the override sets is read from the override rather than from the route.
  ASSERT_NE(nullptr, entry->retryPolicy());
  EXPECT_EQ(3, entry->retryPolicy()->numRetries());
  EXPECT_TRUE(entry->hedgePolicy().hedgeOnPerTryTimeout());
  EXPECT_NE(nullptr, entry->hashPolicy());
  EXPECT_NE(nullptr, entry->metadataMatchCriteria());
  EXPECT_FALSE(entry->rateLimitPolicy().empty());
  EXPECT_NE(nullptr, entry->corsPolicy());
  ASSERT_FALSE(entry->shadowPolicies().empty());
  EXPECT_EQ("canary", entry->shadowPolicies()[0]->cluster());
}

// A decision that records only route metadata produces a route wrapper, whose metadata accessors
// layer the recorded metadata onto the route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteWrapperMetadataAccessors) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: route-only
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto& filter_metadata = route.route->metadata().filter_metadata();
  ASSERT_TRUE(filter_metadata.contains("envoy.test.route"));
  EXPECT_EQ("value", filter_metadata.at("envoy.test.route").fields().at("key").string_value());
  // The typed accessor reads the same layered metadata, exercised for coverage.
  static_cast<void>(route.route->typedMetadata());
}

// A decision that records only a route name produces a route wrapper whose name replaces that of
// the route, without recording any route entry override.
TEST_F(DynamicModuleRouteSpecifierTest, RouteWrapperRouteName) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: route-name
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("module_route", route.route->routeName());
}

// A route wrapper that records no metadata delegates both metadata accessors to the route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteWrapperMetadataFallback) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: filter-only
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  // The recorded filter override marks the wrapper, confirming it is a route wrapper.
  EXPECT_TRUE(route.route->filterDisabled("envoy.test.disabled").value_or(false));
  // Only a filter override was recorded, so the metadata accessors and the route name fall back to
  // the route, which carries no envoy.test.route metadata and no name.
  EXPECT_FALSE(route.route->metadata().filter_metadata().contains("envoy.test.route"));
  EXPECT_EQ("", route.route->routeName());
  static_cast<void>(route.route->typedMetadata());
}

// A route entry wrapper that records no metadata delegates both metadata accessors to the route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteEntryWrapperMetadataFallback) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: entry-no-meta
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("canary", route.route->routeEntry()->clusterName());
  // Only a cluster override was recorded, so the metadata accessors and the route name fall back to
  // the route.
  EXPECT_FALSE(route.route->metadata().filter_metadata().contains("envoy.test.route"));
  EXPECT_EQ("", route.route->routeName());
  static_cast<void>(route.route->typedMetadata());
}

// A typed metadata factory that rejects the metadata recorded under its namespace, so the build of
// the route metadata pack fails the way a real factory would on input it cannot parse.
class RejectingRouteMetadataFactory : public Envoy::Router::HttpRouteTypedMetadataFactory {
public:
  std::string name() const override { return "envoy.test.route"; }
  std::unique_ptr<const Envoy::Config::TypedMetadata::Object>
  parse(const Protobuf::Struct&) const override {
    throw EnvoyException("route metadata rejected by the test factory");
  }
  std::unique_ptr<const Envoy::Config::TypedMetadata::Object>
  parse(const Protobuf::Any&) const override {
    return nullptr;
  }
};

// When a typed metadata factory rejects the metadata a module records, the decision cannot be
// honored, and the failure policy resolves it by keeping the matched route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteMetadataRejectionFailsOpen) {
  RejectingRouteMetadataFactory factory;
  Registry::InjectFactory<Envoy::Router::HttpRouteTypedMetadataFactory> injection(factory);
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1, context_.store_.counter("dynamicmodulescustom.route_specifier.test.failure_route_metadata")
             .value());
}

// A StopIterationAndSkipRoute status drops the matched route and lets matching carry on to the
// next route.
TEST_F(DynamicModuleRouteSpecifierTest, SkipRouteStatusSkipsToTheNextRoute) {
  const auto config =
      loadRaw(catchAllRouteConfigYaml("route_specifier_continue_matching", "PASS_THROUGH"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders("/specific"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  ASSERT_NE(nullptr, route.route->routeEntry());
  EXPECT_EQ("specific_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1,
      context_.store_.counter("dynamicmodulescustom.route_specifier.test.route_skipped").value());
}

// A StopIterationAndSkipRoute status on the last route that matches yields no route, since there
// is nothing left to match.
TEST_F(DynamicModuleRouteSpecifierTest, SkipRouteStatusOnTheLastRouteYieldsNoRoute) {
  const auto config =
      loadRaw(catchAllRouteConfigYaml("route_specifier_continue_matching", "PASS_THROUGH"));
  ASSERT_TRUE(config.ok());

  // The specific route does not match this path, so the catch all is the last route to try.
  const auto route = config.value()->route(requestHeaders("/"), stream_info_, 0);
  EXPECT_EQ(nullptr, route.route);
}

// With the CONTINUE_MATCHING failure policy a module error drops the matched route and lets
// matching carry on to the next route.
TEST_F(DynamicModuleRouteSpecifierTest, ContinueMatchingFailurePolicyContinuesOnError) {
  const auto config =
      loadRaw(catchAllRouteConfigYaml("route_specifier_unknown_decision", "CONTINUE_MATCHING"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders("/specific"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  ASSERT_NE(nullptr, route.route->routeEntry());
  EXPECT_EQ("specific_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(
      1, context_.store_.counter("dynamicmodulescustom.route_specifier.test.failure_module_error")
             .value());
  // The failure path has its own counters, so the skip it produced is not counted as one the
  // module asked for.
  EXPECT_EQ(
      0,
      context_.store_.counter("dynamicmodulescustom.route_specifier.test.route_skipped").value());
}

// A selection that names a template that is not declared cannot be honored, so the failure
// policy applies rather than silently falling back to the resolved route.
TEST_F(DynamicModuleRouteSpecifierTest, TemplateNotSelectedPassesThrough) {
  const auto config = loadConfig(
      specifierYaml("route_specifier_select_template", "      failure_policy: PASS_THROUGH\n"));
  ASSERT_TRUE(config.ok());

  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("matched_cluster", route.route->routeEntry()->clusterName());
  EXPECT_EQ(1,
            context_.store_
                .counter("dynamicmodulescustom.route_specifier.test.failure_template_not_selected")
                .value());
}

// The metadata a selected override carries is layered under the metadata the module records
// itself: the module's value wins for the same key, the override contributes its other keys, and
// the typed metadata the override carries reaches the produced route.
TEST_F(DynamicModuleRouteSpecifierTest, RouteOverrideMetadataLayersUnderModuleMetadata) {
  const auto config =
      loadConfig(specifierYaml("route_specifier_override", R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: select-override
      route_overrides:
      - override_id: applied
        metadata:
          filter_metadata:
            envoy.test.override: {group: override, extra: carried}
          typed_filter_metadata:
            envoy.test.typed:
              "@type": type.googleapis.com/google.protobuf.StringValue
              value: carried
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders(), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);

  const auto& metadata = route.route->metadata();
  const auto& fields = metadata.filter_metadata().at("envoy.test.override").fields();
  // The module recorded group=module, which wins over the group=override the override carries.
  EXPECT_EQ("module", fields.at("group").string_value());
  EXPECT_EQ("carried", fields.at("extra").string_value());
  EXPECT_TRUE(metadata.typed_filter_metadata().contains("envoy.test.typed"));
}

// Builds a configuration for the rewrite rule module in the given mode, with a route override that
// carries a regex rewrite and any extra specifier fields.
std::string rewriteRuleYaml(absl::string_view mode, absl::string_view extra = "") {
  return specifierYaml("route_specifier_rewrite_rule",
                       fmt::format(R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: {}
      route_overrides:
      - override_id: rewrite
        regex_rewrite:
          pattern: {{regex: "^/api/(.*)$"}}
          substitution: '/regex/\1'
{})EOF",
                                   mode, extra));
}

// Reads whether the last rule the rewrite rule module recorded was accepted.
std::string ruleAccepted(const Envoy::Router::Route& route) {
  return route.metadata()
      .filter_metadata()
      .at("envoy.test.rule")
      .fields()
      .at("accepted")
      .string_value();
}

// A route configuration whose one route, matching every path, is a template whose action is
// `action`, under the rewrite rule module in `mode`.
std::string templateRouteYaml(absl::string_view action, absl::string_view mode,
                              absl::string_view extra = "") {
  return fmt::format(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {{prefix: "/"}}
{}
  route_specifiers:
  - name: envoy.router.route_specifiers.dynamic_modules
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
{}
)EOF",
                     action, rewriteRuleYaml(mode, extra));
}

// A template that rewrites the path itself.
constexpr absl::string_view RewritingTemplate =
    "    route: {cluster: matched_cluster, prefix_rewrite: \"/route/\"}";

// A prefix rewrite rule is applied to the path the request carries when it is finalized, so a route
// built for one request rewrites another request the way a configured route would.
TEST_F(DynamicModuleRouteSpecifierTest, PrefixRewriteRuleAppliesToTheFinalizedPath) {
  const auto config = loadConfig(rewriteRuleYaml("literal"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1?x=1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  auto headers = requestHeaders("/api/v2?y=2");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/internal/v2?y=2",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/internal/v2?y=2", headers.getPathValue());
  EXPECT_EQ("/api/v2?y=2", headers.getEnvoyOriginalPathValue());
  EXPECT_EQ(0,
            context_.store_.counter("dynamicmodulescustom.route_specifier.test.rewrite_not_applied")
                .value());

  // Without insert_envoy_original_path the original path is not recorded.
  auto plain = requestHeaders("/api/v3");
  entry->finalizeRequestHeaders(plain, formatter_context, stream_info_, false);
  EXPECT_EQ("/internal/v3", plain.getPathValue());
  EXPECT_EQ(nullptr, plain.EnvoyOriginalPath());
}

// A rule that does not apply to the path at finalization leaves the path unchanged, the way a
// configured route leaves it when its rewrite yields nothing, and is counted.
TEST_F(DynamicModuleRouteSpecifierTest, PrefixRewriteRuleThatDoesNotApplyLeavesThePath) {
  const auto config = loadConfig(rewriteRuleYaml("literal"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  auto headers = requestHeaders("/other");
  Formatter::Context formatter_context(&headers);
  // The matched route configures no rewrite, so nothing rewrites the path.
  EXPECT_EQ("", entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other", headers.getPathValue());
  EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
  EXPECT_EQ(1,
            context_.store_.counter("dynamicmodulescustom.route_specifier.test.rewrite_not_applied")
                .value());
}

// A rule over the whole path replaces the path without its query string, which is what the
// prefix_rewrite of a regex route does, and keeps the query string of the finalized request.
TEST_F(DynamicModuleRouteSpecifierTest, WholePathRuleReplacesThePathAndKeepsTheQuery) {
  const auto config = loadConfig(rewriteRuleYaml("whole-path"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  auto headers = requestHeaders("/anything/else?q=1#fragment");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/fixed?q=1#fragment",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
}

// A rule that cannot apply to the request the decision is taken for is rejected and records
// nothing, so the produced route carries only the metadata the module recorded.
class RejectedPrefixRewriteRuleTest : public DynamicModuleRouteSpecifierTest,
                                      public testing::WithParamInterface<std::string> {};

INSTANTIATE_TEST_SUITE_P(Modes, RejectedPrefixRewriteRuleTest,
                         testing::Values("not-prefix", "whole-path-with-matched",
                                         "empty-replacement", "invalid-replacement", "unknown-span",
                                         "too-long"));

TEST_P(RejectedPrefixRewriteRuleTest, RecordsNothing) {
  const auto config =
      loadConfig(rewriteRuleYaml(GetParam(), "      max_rewritten_path_bytes: 16\n"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("false", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/v1");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("", entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
}

// A path the module records takes precedence over a rule whatever the call order.
TEST_F(DynamicModuleRouteSpecifierTest, RecordedPathTakesPrecedenceOverRule) {
  const auto config = loadConfig(rewriteRuleYaml("path-wins"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/v2");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/literal",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/literal", headers.getPathValue());
}

// A rule takes precedence over the regex rewrite of the selected route override.
TEST_F(DynamicModuleRouteSpecifierTest, RuleTakesPrecedenceOverRouteOverrideRegexRewrite) {
  const auto config = loadConfig(rewriteRuleYaml("rule-over-override"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/v2");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/internal/v2",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
}

// The regex rewrite of a selected route override is applied to the path the request carries when it
// is finalized rather than to the path of the request the route was built for.
TEST_F(DynamicModuleRouteSpecifierTest, RouteOverrideRegexRewriteAppliesToTheFinalizedPath) {
  const auto config = loadConfig(rewriteRuleYaml("override-only"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/other?q=1");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/regex/other?q=1",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/regex/other?q=1", headers.getPathValue());
  EXPECT_EQ("/api/other?q=1", headers.getEnvoyOriginalPathValue());
}

// A later rule replaces the rule of an earlier call.
TEST_F(DynamicModuleRouteSpecifierTest, LaterRuleReplacesEarlierRule) {
  const auto config = loadConfig(rewriteRuleYaml("replaced"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/v1");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/second/v1",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
}

// A recorded rule owns the rewrite, so when a filter changed the path and the rule no longer
// applies, the path stays as the filter left it rather than taking the rewrite of the route.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyKeepsTheRouteRewriteOut) {
  const auto config = loadRaw(templateRouteYaml(RewritingTemplate, "literal"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  // A filter changed the path after routing, so the rule no longer applies.
  auto headers = requestHeaders("/other/x");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("", entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
  EXPECT_EQ(1,
            context_.store_.counter("dynamicmodulescustom.route_specifier.test.rewrite_not_applied")
                .value());

  // An x-envoy-original-path the request already carried is left as it was.
  auto carried = requestHeaders("/other/y");
  carried.setEnvoyOriginalPath("/carried");
  entry->finalizeRequestHeaders(carried, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/y", carried.getPathValue());
  EXPECT_EQ("/carried", carried.getEnvoyOriginalPathValue());

  // Where the rule applies, it rewrites in place of the rewrite of the route.
  auto applies = requestHeaders("/api/v2");
  EXPECT_EQ("/internal/v2",
            entry->currentUrlPathAfterRewrite(applies, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(applies, formatter_context, stream_info_, true);
  EXPECT_EQ("/internal/v2", applies.getPathValue());
  EXPECT_EQ("/api/v2", applies.getEnvoyOriginalPathValue());
}

// A rule that does not apply restores the path before the header mutations of the module run, so an
// x-envoy-original-path the module records survives, as one a configured route that does not
// rewrite leaves alone.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyKeepsAnOriginalPathTheModuleRecords) {
  const auto config = loadRaw(templateRouteYaml(RewritingTemplate, "records-original-path"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);

  auto headers = requestHeaders("/other/x");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ("/module", headers.getEnvoyOriginalPathValue());

  // Where the rule applies, the module's header follows the original path the rewrite records, as
  // the header mutations of a configured route are applied before its path rewrite.
  auto applies = requestHeaders("/api/v2");
  entry->finalizeRequestHeaders(applies, formatter_context, stream_info_, true);
  EXPECT_EQ("/internal/v2", applies.getPathValue());
  EXPECT_EQ("/api/v2", applies.getEnvoyOriginalPathValue());
}

// The route records x-envoy-original-path only when its own rewrite applies, so a rule that does
// not apply keeps a value the route's header mutations set when the route does not rewrite, as a
// configured route does. When the route rewrites, its rewrite already overwrote that value, so the
// value the request carried is restored instead.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyKeepsAnOriginalPathTheRouteHeadersSet) {
  constexpr absl::string_view headers_to_add = R"EOF(
    request_headers_to_add:
    - header: {key: x-envoy-original-path, value: /configured})EOF";
  {
    const auto config = loadRaw(templateRouteYaml(
        absl::StrCat("    route: {cluster: matched_cluster}", headers_to_add), "literal"));
    ASSERT_TRUE(config.ok());
    const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
    ASSERT_NE(nullptr, route.route);
    const auto* entry = route.route->routeEntry();
    ASSERT_NE(nullptr, entry);
    auto headers = requestHeaders("/other/x");
    Formatter::Context formatter_context(&headers);
    entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
    EXPECT_EQ("/other/x", headers.getPathValue());
    EXPECT_EQ("/configured", headers.getEnvoyOriginalPathValue());
  }
  {
    const auto config =
        loadRaw(templateRouteYaml(absl::StrCat(RewritingTemplate, headers_to_add), "literal"));
    ASSERT_TRUE(config.ok());
    const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
    ASSERT_NE(nullptr, route.route);
    const auto* entry = route.route->routeEntry();
    ASSERT_NE(nullptr, entry);
    auto headers = requestHeaders("/other/x");
    Formatter::Context formatter_context(&headers);
    entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
    EXPECT_EQ("/other/x", headers.getPathValue());
    EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
    auto carried = requestHeaders("/other/y");
    carried.setEnvoyOriginalPath("/carried");
    Formatter::Context carried_context(&carried);
    entry->finalizeRequestHeaders(carried, carried_context, stream_info_, true);
    EXPECT_EQ("/carried", carried.getEnvoyOriginalPathValue());
  }
}

// The module's header mutations follow the restore, so a module that removes x-envoy-original-path
// removes a value the request carried rather than having the restore put it back.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyLetsTheModuleRemoveTheOriginalPath) {
  const auto config = loadRaw(templateRouteYaml(RewritingTemplate, "removes-original-path"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  headers.setEnvoyOriginalPath("/carried");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
}

// When the original path is not kept, the route records no x-envoy-original-path, so a rule that
// does not apply restores only the path.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyRestoresOnlyThePathWhenNotKept) {
  const auto config = loadRaw(templateRouteYaml(RewritingTemplate, "literal"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  headers.setEnvoyOriginalPath("/carried");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, false);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ("/carried", headers.getEnvoyOriginalPathValue());
  auto plain = requestHeaders("/other/y");
  Formatter::Context plain_context(&plain);
  entry->finalizeRequestHeaders(plain, plain_context, stream_info_, false);
  EXPECT_EQ("/other/y", plain.getPathValue());
  EXPECT_EQ(nullptr, plain.EnvoyOriginalPath());

  // A value the route's header mutations set is kept too, because the route records nothing, even
  // one equal to the original path, which the route would have written had it been asked to.
  const auto configured = loadRaw(templateRouteYaml(absl::StrCat(RewritingTemplate, R"EOF(
    request_headers_to_add:
    - header: {key: x-envoy-original-path, value: "%REQ(:path)%"})EOF"),
                                                    "literal"));
  ASSERT_TRUE(configured.ok());
  const auto configured_route =
      configured.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, configured_route.route);
  const auto* configured_entry = configured_route.route->routeEntry();
  ASSERT_NE(nullptr, configured_entry);
  auto set = requestHeaders("/other/z");
  Formatter::Context set_context(&set);
  configured_entry->finalizeRequestHeaders(set, set_context, stream_info_, false);
  EXPECT_EQ("/other/z", set.getPathValue());
  EXPECT_EQ("/other/z", set.getEnvoyOriginalPathValue());
}

// A route rewrite that reads a header the route's own mutations add is computed only after they
// run, so it is not predicted before the route finalizes. The path it moved shows it rewrote, so
// the x-envoy-original-path it recorded is undone as for any other route rewrite.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyUndoesARouteRewriteItsHeadersEnable) {
  const auto config = loadRaw(templateRouteYaml(R"EOF(    route:
      cluster: matched_cluster
      path_rewrite: "%REQ(x-target)%"
    request_headers_to_add:
    - header: {key: x-target, value: /svc})EOF",
                                                "literal"));
  ASSERT_TRUE(config.ok()) << config.status();
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
  auto carried = requestHeaders("/other/y");
  carried.setEnvoyOriginalPath("/carried");
  Formatter::Context carried_context(&carried);
  entry->finalizeRequestHeaders(carried, carried_context, stream_info_, true);
  EXPECT_EQ("/other/y", carried.getPathValue());
  EXPECT_EQ("/carried", carried.getEnvoyOriginalPathValue());
}

// Without a specifier the same route rewrites the path from the header its mutations add, which is
// what the test above undoes.
TEST_F(DynamicModuleRouteSpecifierTest, ARouteRewriteItsHeadersEnableRewritesWithoutASpecifier) {
  const auto config = loadRaw(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {prefix: "/"}
    route:
      cluster: matched_cluster
      path_rewrite: "%REQ(x-target)%"
    request_headers_to_add:
    - header: {key: x-target, value: /svc}
)EOF");
  ASSERT_TRUE(config.ok()) << config.status();
  const auto route = config.value()->route(requestHeaders("/other/x"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/svc", headers.getPathValue());
  EXPECT_EQ("/other/x", headers.getEnvoyOriginalPathValue());
}

// A route rewrite that leaves the path as it was still records x-envoy-original-path, so a rule
// that does not apply undoes that record too, here a regex rewrite that does not match.
TEST_F(DynamicModuleRouteSpecifierTest, RuleThatDoesNotApplyUndoesARouteRewriteThatKeepsThePath) {
  const auto config = loadRaw(templateRouteYaml(R"EOF(    route:
      cluster: matched_cluster
      regex_rewrite:
        pattern: {regex: "^/nomatch/(.*)$"}
        substitution: "/x/\\1")EOF",
                                                "literal"));
  ASSERT_TRUE(config.ok()) << config.status();
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ(nullptr, headers.EnvoyOriginalPath());
  auto carried = requestHeaders("/other/y");
  carried.setEnvoyOriginalPath("/carried");
  Formatter::Context carried_context(&carried);
  entry->finalizeRequestHeaders(carried, carried_context, stream_info_, true);
  EXPECT_EQ("/carried", carried.getEnvoyOriginalPathValue());
}

// A route whose header mutations remove the header its rewrite reads does not rewrite, so the
// x-envoy-original-path its mutations set to the original path is kept, as on that route without a
// specifier.
TEST_F(DynamicModuleRouteSpecifierTest,
       RuleThatDoesNotApplyKeepsAnOriginalPathARouteThatDidNotRewriteSet) {
  const auto config = loadRaw(templateRouteYaml(R"EOF(    route:
      cluster: matched_cluster
      path_rewrite: "%REQ(x-target)%"
    request_headers_to_remove: [x-target]
    request_headers_to_add:
    - header: {key: x-envoy-original-path, value: "%REQ(:path)%"})EOF",
                                                "literal"));
  ASSERT_TRUE(config.ok()) << config.status();
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/other/x");
  headers.addCopy(Http::LowerCaseString("x-target"), "/svc");
  Formatter::Context formatter_context(&headers);
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/other/x", headers.getPathValue());
  EXPECT_EQ("/other/x", headers.getEnvoyOriginalPathValue());
}

// A route override regex rewrite that yields nothing, here one longer than the bound, is counted
// and leaves the rewrite of the route in effect, which currentUrlPathAfterRewrite reports the same
// way.
TEST_F(DynamicModuleRouteSpecifierTest, RouteOverrideRegexThatYieldsNothingKeepsTheRouteRewrite) {
  const auto config = loadRaw(templateRouteYaml(RewritingTemplate, "override-only",
                                                "      max_rewritten_path_bytes: 16\n"));
  ASSERT_TRUE(config.ok());
  const auto route = config.value()->route(requestHeaders("/api/v1"), stream_info_, 0);
  ASSERT_NE(nullptr, route.route);
  EXPECT_EQ("true", ruleAccepted(*route.route));
  const auto* entry = route.route->routeEntry();
  ASSERT_NE(nullptr, entry);
  auto headers = requestHeaders("/api/a-path-past-the-bound");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/route/api/a-path-past-the-bound",
            entry->currentUrlPathAfterRewrite(headers, formatter_context, stream_info_));
  entry->finalizeRequestHeaders(headers, formatter_context, stream_info_, true);
  EXPECT_EQ("/route/api/a-path-past-the-bound", headers.getPathValue());
  EXPECT_EQ("/api/a-path-past-the-bound", headers.getEnvoyOriginalPathValue());
  EXPECT_EQ(1,
            context_.store_.counter("dynamicmodulescustom.route_specifier.test.rewrite_not_applied")
                .value());
}

// The result codes set_route_cache_key returns, as the route cache module reports them.
constexpr int CacheDisabled = envoy_dynamic_module_type_route_specifier_route_cache_result_Disabled;
constexpr int CacheMiss = envoy_dynamic_module_type_route_specifier_route_cache_result_Miss;
constexpr int CacheHit = envoy_dynamic_module_type_route_specifier_route_cache_result_Hit;
constexpr int CacheHitVerify =
    envoy_dynamic_module_type_route_specifier_route_cache_result_HitVerify;

// Builds a configuration for the route cache module in the given mode. The cache block is omitted
// when it is empty.
std::string routeCacheYaml(absl::string_view mode, absl::string_view cache) {
  return specifierYaml("route_specifier_route_cache",
                       fmt::format(R"EOF(      failure_policy: PASS_THROUGH
      specifier_config:
        "@type": type.googleapis.com/google.protobuf.StringValue
        value: {}
{}      route_templates:
      - template_id: only
        route:
          match: {{prefix: "/"}}
          route: {{cluster: module_cluster}}
      - template_id: direct
        route:
          match: {{prefix: "/"}}
          direct_response: {{status: 204}}
      - template_id: weighted
        route:
          match: {{prefix: "/"}}
          route:
            weighted_clusters:
              clusters:
              - {{name: cluster_a, weight: 50}}
              - {{name: cluster_b, weight: 50}}
      - template_id: header
        route:
          match: {{prefix: "/"}}
          route: {{cluster_header: x-cluster}}
      - template_id: plugin
        route:
          match: {{prefix: "/"}}
          route:
            inline_cluster_specifier_plugin:
              extension:
                name: envoy.router.cluster_specifier_plugin.dynamic_modules
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.router.cluster_specifiers.dynamic_modules.v3.DynamicModuleClusterSpecifier
                  dynamic_module_config: {{name: cluster_specifier_no_op}}
)EOF",
                                   mode, cache));
}

class DynamicModuleRouteCacheTest : public DynamicModuleRouteSpecifierTest {
public:
  void SetUp() override {
    auto module = Extensions::DynamicModules::newDynamicModule(
        Extensions::DynamicModules::testSharedObjectPath("route_specifier_route_cache", "c"),
        /*do_not_close=*/true);
    ASSERT_TRUE(module.ok());
    module_ = std::move(module.value());
    last_cache_result_ = symbol("getLastCacheResult");
    route_destroy_count_ = symbol("getRouteDestroyCount");
    config_destroy_count_ = symbol("getConfigDestroyCount");
  }

  using CountFunction = int (*)(void);
  CountFunction symbol(const std::string& name) {
    auto function = module_->getFunctionPointer<CountFunction>(name);
    EXPECT_TRUE(function.ok());
    return function.value();
  }

  Envoy::Router::RouteConstSharedPtr resolve(Envoy::Router::ConfigImpl& config, uint64_t key,
                                             uint64_t random = 0) {
    auto headers = requestHeaders("/api/v1");
    headers.addCopy(Http::LowerCaseString("x-key"), absl::StrCat(key));
    return config.route(headers, stream_info_, random).route;
  }

  uint64_t counter(absl::string_view name) {
    return context_.store_.counter(absl::StrCat("dynamicmodulescustom.route_specifier.test.", name))
        .value();
  }

  uint64_t entries() {
    return context_.store_
        .gauge("dynamicmodulescustom.route_specifier.test.route_cache_entries",
               Stats::Gauge::ImportMode::Accumulate)
        .value();
  }

  Extensions::DynamicModules::DynamicModulePtr module_;
  CountFunction last_cache_result_{};
  CountFunction route_destroy_count_{};
  CountFunction config_destroy_count_{};
};

// A hit returns the route a previous request on the worker built for the key, so two requests share
// one route and the route is built once.
TEST_F(DynamicModuleRouteCacheTest, HitReturnsTheRouteBuiltForTheKey) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  const auto second = resolve(*config.value(), 1);
  EXPECT_EQ(CacheHit, last_cache_result_());
  ASSERT_NE(nullptr, first);
  EXPECT_EQ(first.get(), second.get());
  EXPECT_EQ("cached_cluster", second->routeEntry()->clusterName());
  EXPECT_EQ(1, counter("route_cache_miss"));
  EXPECT_EQ(1, counter("route_cache_hit"));
  EXPECT_EQ(2, counter("decision_has_template"));
  EXPECT_EQ(1, counter("route_build"));
  EXPECT_EQ(1, entries());
}

// A decision that cannot be honored after the module returned produces no route, and nothing is
// cached for it.
TEST_F(DynamicModuleRouteCacheTest, FailedDecisionIsNeverCached) {
  const auto config = loadConfig(routeCacheYaml("direct-entry", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  EXPECT_EQ(2, counter("route_cache_miss"));
  EXPECT_EQ(0, counter("route_cache_hit"));
  EXPECT_EQ(2, counter("failure_override_on_non_route_entry"));
  EXPECT_EQ(0, entries());
}

// A verified hit compares what the module records with what the cached route was built from, counts
// a difference, and still produces the cached route without building another.
TEST_F(DynamicModuleRouteCacheTest, VerifiedHitCountsADifference) {
  const auto config = loadConfig(routeCacheYaml("inconsistent", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 1
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  const auto second = resolve(*config.value(), 1);
  EXPECT_EQ(CacheHitVerify, last_cache_result_());
  EXPECT_EQ(first.get(), second.get());
  const std::string cached_cluster = first->routeEntry()->clusterName();
  EXPECT_EQ(1, counter("route_cache_verify"));
  EXPECT_EQ(1, counter("route_cache_verify_mismatch"));
  // A verified hit builds nothing, so a single route carries the lease so far.
  EXPECT_EQ(1, counter("route_build"));
  // The difference removed the entry, so the third request builds the route again.
  const auto third = resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  EXPECT_NE(first.get(), third.get());
  EXPECT_EQ(cached_cluster, first->routeEntry()->clusterName());
  EXPECT_EQ(2, counter("route_build"));
}

// A verified hit whose recording matches the cached route counts no difference.
TEST_F(DynamicModuleRouteCacheTest, VerifiedHitOfAConsistentModule) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 1
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheHitVerify, last_cache_result_());
  EXPECT_EQ(1, counter("route_cache_verify"));
  EXPECT_EQ(0, counter("route_cache_verify_mismatch"));
}

// Verification is sampled one in verify_one_in hits per worker.
TEST_F(DynamicModuleRouteCacheTest, VerificationIsSampled) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 3
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  for (int i = 0; i < 6; ++i) {
    resolve(*config.value(), 1);
  }
  EXPECT_EQ(6, counter("route_cache_hit"));
  EXPECT_EQ(2, counter("route_cache_verify"));
}

// A template with weighted clusters picks its cluster per request, so the route built from it is
// specific to the request and the cache is not in effect for it.
TEST_F(DynamicModuleRouteCacheTest, WeightedTemplateIsNeverCached) {
  const auto config = loadConfig(routeCacheYaml("weighted", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1, 10);
  EXPECT_EQ(CacheDisabled, last_cache_result_());
  const auto second = resolve(*config.value(), 1, 10);
  ASSERT_NE(nullptr, first);
  ASSERT_NE(nullptr, second);
  EXPECT_NE(first.get(), second.get());
  EXPECT_EQ("cluster_a", first->routeEntry()->clusterName());
  EXPECT_EQ("cluster_b", resolve(*config.value(), 1, 60)->routeEntry()->clusterName());
  EXPECT_EQ(0, counter("route_cache_miss"));
  EXPECT_EQ(0, entries());
}

// A full worker evicts the entry CLOCK picks to make room for a new one.
TEST_F(DynamicModuleRouteCacheTest, EvictsAtTheBound) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 2
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  resolve(*config.value(), 2);
  resolve(*config.value(), 3);
  EXPECT_EQ(1, counter("route_cache_evict"));
  EXPECT_EQ(2, entries());
  // Both reference bits were set, so CLOCK cleared them and evicted the oldest entry.
  resolve(*config.value(), 2);
  resolve(*config.value(), 3);
  EXPECT_EQ(2, counter("route_cache_hit"));
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
}

// A worker sweeps the entries idle for longer than the entry age, so an idle worker releases its
// routes too, and a use keeps an entry.
TEST_F(DynamicModuleRouteCacheTest, SweepsIdleEntries) {
  auto* timer = new NiceMock<Event::MockTimer>(&context_.thread_local_.dispatcher_);
  EXPECT_CALL(*timer, enableTimer(std::chrono::milliseconds(1000), _)).Times(testing::AtLeast(1));
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        max_entry_age: 4s
)EOF"));
  ASSERT_TRUE(config.ok());
  // The sweep is armed by the first insert, not by the configuration.
  EXPECT_FALSE(timer->enabled_);
  resolve(*config.value(), 1);
  EXPECT_TRUE(timer->enabled_);
  resolve(*config.value(), 2);
  for (int i = 0; i < 3; ++i) {
    timer->invokeCallback();
  }
  // Key 2 is used before the age passes, which keeps it.
  resolve(*config.value(), 2);
  timer->invokeCallback();
  timer->invokeCallback();
  EXPECT_EQ(1, counter("route_cache_evict"));
  EXPECT_EQ(1, entries());
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  resolve(*config.value(), 2);
  EXPECT_EQ(CacheHit, last_cache_result_());
}

// The cache belongs to the specifier, so replacing the route configuration releases every cached
// route, each built route fires the destroy hook once, and the configuration is destroyed.
TEST_F(DynamicModuleRouteCacheTest, TeardownReleasesCachedRoutesAndTheConfiguration) {
  const int routes_before = route_destroy_count_();
  const int configs_before = config_destroy_count_();
  {
    const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
    ASSERT_TRUE(config.ok());
    resolve(*config.value(), 1);
    resolve(*config.value(), 2);
    resolve(*config.value(), 1);
    EXPECT_EQ(2, counter("route_build"));
    EXPECT_EQ(0, counter("route_destroy"));
  }
  EXPECT_EQ(2, counter("route_destroy"));
  EXPECT_EQ(counter("route_build"), counter("route_destroy"));
  EXPECT_EQ(routes_before + 2, route_destroy_count_());
  EXPECT_EQ(configs_before + 1, config_destroy_count_());
  EXPECT_EQ(0, entries());
}

// A module that sets no key builds a route per request exactly as without a cache.
TEST_F(DynamicModuleRouteCacheTest, ModuleWithoutAKeyBuildsPerRequest) {
  const auto config = loadConfig(routeCacheYaml("no-key", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  const auto second = resolve(*config.value(), 1);
  EXPECT_NE(first.get(), second.get());
  EXPECT_EQ(0, counter("route_cache_hit") + counter("route_cache_miss"));
  EXPECT_EQ(2, counter("route_build"));
  EXPECT_EQ(0, entries());
}

// Without a selected template there is nothing to look up.
TEST_F(DynamicModuleRouteCacheTest, KeyWithoutTemplateIsDisabled) {
  const auto config =
      loadConfig(routeCacheYaml("key-without-template", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto route = resolve(*config.value(), 1);
  EXPECT_EQ(CacheDisabled, last_cache_result_());
  ASSERT_NE(nullptr, route);
  EXPECT_EQ("uncached", route->routeEntry()->clusterName());
}

// Without a built_route_cache the key is accepted and nothing is cached.
TEST_F(DynamicModuleRouteCacheTest, KeyWithoutRouteCacheIsDisabled) {
  const auto config = loadConfig(routeCacheYaml("cached", ""));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  EXPECT_EQ(CacheDisabled, last_cache_result_());
  const auto second = resolve(*config.value(), 1);
  EXPECT_NE(first.get(), second.get());
  EXPECT_EQ(2, counter("route_build"));
}

// Selecting the template again after the lookup discards it, so the route is built and not cached.
TEST_F(DynamicModuleRouteCacheTest, ReselectingTheTemplateDiscardsTheLookup) {
  const auto config = loadConfig(routeCacheYaml("reselect", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  EXPECT_EQ(2, counter("route_cache_miss"));
  EXPECT_EQ(0, entries());
}

// With verification disabled no hit is verified.
TEST_F(DynamicModuleRouteCacheTest, VerificationCanBeDisabled) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 0
)EOF"));
  ASSERT_TRUE(config.ok());
  for (int i = 0; i < 4; ++i) {
    resolve(*config.value(), 1);
  }
  EXPECT_EQ(3, counter("route_cache_hit"));
  EXPECT_EQ(0, counter("route_cache_verify"));
}

// A module that records nothing caches the template route itself, and a verified hit compares the
// empty recording with an empty one.
TEST_F(DynamicModuleRouteCacheTest, CachesTheTemplateRouteItself) {
  const auto config = loadConfig(routeCacheYaml("bare", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 1
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  const auto second = resolve(*config.value(), 1);
  EXPECT_EQ(CacheHitVerify, last_cache_result_());
  ASSERT_NE(nullptr, first);
  EXPECT_EQ(first.get(), second.get());
  EXPECT_EQ("module_cluster", first->routeEntry()->clusterName());
  EXPECT_EQ(1, counter("route_cache_verify"));
  EXPECT_EQ(0, counter("route_cache_verify_mismatch"));
  EXPECT_EQ(0, counter("route_build"));
}

// A thread that is not registered with thread local storage has no cache, so the key is accepted
// and nothing is cached.
TEST_F(DynamicModuleRouteCacheTest, UnregisteredThreadHasNoCache) {
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  context_.thread_local_.registered_ = false;
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheDisabled, last_cache_result_());
  context_.thread_local_.registered_ = true;
}

// A worker the cache has not reached yet resolves without it.
TEST_F(DynamicModuleRouteCacheTest, WorkerWithoutTheCacheYetResolvesWithoutIt) {
  context_.thread_local_.defer_data_ = true;
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheDisabled, last_cache_result_());
  context_.thread_local_.call();
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
}

// A verified hit that finds any field of the recording changed counts a difference and removes the
// entry, while the verified request still gets the cached route.
class VerifiedHitFieldTest : public DynamicModuleRouteCacheTest,
                             public testing::WithParamInterface<std::string> {};

INSTANTIATE_TEST_SUITE_P(Fields, VerifiedHitFieldTest,
                         testing::Values("timeout", "metadata", "header", "rule", "user-data"));

TEST_P(VerifiedHitFieldTest, DifferenceRemovesTheEntry) {
  const auto config = loadConfig(routeCacheYaml("vary", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        verify_one_in: 1
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto request = [&](absl::string_view value) {
    auto headers = requestHeaders("/api/v1");
    headers.addCopy(Http::LowerCaseString("x-vary"), GetParam());
    headers.addCopy(Http::LowerCaseString("x-value"), value);
    return config.value()->route(headers, stream_info_, 0).route;
  };
  const auto first = request("1");
  EXPECT_EQ(CacheMiss, last_cache_result_());
  const auto second = request("2");
  EXPECT_EQ(CacheHitVerify, last_cache_result_());
  EXPECT_EQ(first.get(), second.get());
  EXPECT_EQ(1, counter("route_cache_verify_mismatch"));
  EXPECT_EQ(0, entries());
  request("2");
  EXPECT_EQ(CacheMiss, last_cache_result_());
}

// A path set_prefix_rewrite computed belongs to the request it was computed for, so its route is
// never cached and the next request with the key misses again.
TEST_F(DynamicModuleRouteCacheTest, RequestSpecificPathIsNeverCached) {
  const auto config = loadConfig(routeCacheYaml("legacy-rewrite", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
  ASSERT_TRUE(config.ok());
  const auto first = resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  ASSERT_NE(nullptr, first);
  auto headers = requestHeaders("/api/v1");
  Formatter::Context formatter_context(&headers);
  EXPECT_EQ("/legacy/v1", first->routeEntry()->currentUrlPathAfterRewrite(
                              headers, formatter_context, stream_info_));
  resolve(*config.value(), 1);
  EXPECT_EQ(CacheMiss, last_cache_result_());
  EXPECT_EQ(0, entries());
}

// A specifier on a route configuration has no route builder and so no templates, and rejects a
// built route cache at configuration load.
TEST_F(DynamicModuleRouteCacheTest, BuiltRouteCacheRequiresARouteBuilder) {
  const auto config = loadRaw(R"EOF(
name: test_route_config
virtual_hosts:
- name: test_vhost
  domains: ["*"]
  routes:
  - match: {prefix: "/"}
    route: {cluster: matched_cluster}
route_specifiers:
- name: envoy.router.route_specifiers.dynamic_modules
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier
    dynamic_module_config:
      name: route_specifier_route_cache
      do_not_close: true
    specifier_name: test_route_specifier
    stat_prefix: test
    failure_policy: PASS_THROUGH
    built_route_cache:
      max_entries_per_worker: 16
)EOF");
  EXPECT_THAT(config.status(),
              HasStatusMessage(HasSubstr("built_route_cache requires a route specifier configured "
                                         "on a virtual host or a route")));
}

// The sweep timer runs only while the worker caches a route.
TEST_F(DynamicModuleRouteCacheTest, SweepTimerRunsOnlyWhileEntriesRemain) {
  auto* timer = new NiceMock<Event::MockTimer>(&context_.thread_local_.dispatcher_);
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
        max_entry_age: 4s
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  for (int i = 0; i < 5; ++i) {
    ASSERT_TRUE(timer->enabled_);
    timer->invokeCallback();
  }
  EXPECT_EQ(0, entries());
  EXPECT_FALSE(timer->enabled_);
  // The next insert arms the sweep again.
  resolve(*config.value(), 1);
  EXPECT_TRUE(timer->enabled_);
}

// When a sweep removes the entry the CLOCK hand points at last, the hand starts over.
TEST_F(DynamicModuleRouteCacheTest, ClockHandStartsOverWhenItsEntryIsSwept) {
  auto* timer = new NiceMock<Event::MockTimer>(&context_.thread_local_.dispatcher_);
  const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 2
        max_entry_age: 4s
)EOF"));
  ASSERT_TRUE(config.ok());
  resolve(*config.value(), 1);
  resolve(*config.value(), 2);
  // Key 3 evicts key 1 from the first slot and leaves the hand on key 2, the last entry.
  resolve(*config.value(), 3);
  for (int i = 0; i < 3; ++i) {
    timer->invokeCallback();
  }
  resolve(*config.value(), 3);
  timer->invokeCallback();
  timer->invokeCallback();
  // Key 2 aged out, and the hand starts over at key 3, so key 4 fills the free slot and key 5
  // evicts the entry CLOCK finds unreferenced.
  EXPECT_EQ(1, entries());
  resolve(*config.value(), 4);
  resolve(*config.value(), 5);
  EXPECT_EQ(2, entries());
  EXPECT_EQ(3, counter("route_cache_evict"));
  resolve(*config.value(), 5);
  EXPECT_EQ(CacheHit, last_cache_result_());
}

// A stream that still holds a cached route when the configuration goes keeps the route, and the
// destroy hook fires once the stream releases it.
TEST_F(DynamicModuleRouteCacheTest, StreamHoldingACachedRouteReleasesItLast) {
  const int routes_before = route_destroy_count_();
  Envoy::Router::RouteConstSharedPtr held;
  {
    const auto config = loadConfig(routeCacheYaml("cached", R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
    ASSERT_TRUE(config.ok());
    held = resolve(*config.value(), 1);
  }
  EXPECT_EQ(routes_before, route_destroy_count_());
  EXPECT_EQ(0, counter("route_destroy"));
  held.reset();
  EXPECT_EQ(routes_before + 1, route_destroy_count_());
  EXPECT_EQ(1, counter("route_destroy"));
  EXPECT_EQ(counter("route_build"), counter("route_destroy"));
}

// A decision the module records after a hit, or a status that skips the route, wins over the hit.
TEST_F(DynamicModuleRouteCacheTest, DecisionsAndSkipWinOverAHit) {
  struct Case {
    std::string mode;
    std::string counter_name;
    std::string cluster;
  };
  const std::vector<Case> cases = {
      {"hit-then-no-route", "decision_no_route", ""},
      {"hit-then-pass-through", "decision_pass_through", "matched_cluster"},
      {"hit-then-error", "decision_error", "matched_cluster"},
      {"hit-then-skip", "route_skipped", ""},
  };
  for (const Case& test_case : cases) {
    SCOPED_TRACE(test_case.mode);
    const auto config = loadConfig(routeCacheYaml(test_case.mode, R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
    ASSERT_TRUE(config.ok());
    const uint64_t before = counter(test_case.counter_name);
    const auto cached = resolve(*config.value(), 1);
    ASSERT_NE(nullptr, cached);
    EXPECT_EQ("cached_cluster", cached->routeEntry()->clusterName());
    const auto route = resolve(*config.value(), 1);
    EXPECT_EQ(CacheHit, last_cache_result_());
    EXPECT_NE(cached.get(), route.get());
    EXPECT_LT(before, counter(test_case.counter_name));
    if (test_case.cluster.empty()) {
      EXPECT_EQ(nullptr, route);
    } else {
      ASSERT_NE(nullptr, route);
      EXPECT_EQ(test_case.cluster, route->routeEntry()->clusterName());
    }
  }
}

// A template whose cluster comes from a request header, or from a cluster specifier plugin,
// resolves it per request, so the cache is not in effect for it.
TEST_F(DynamicModuleRouteCacheTest, PerRequestClusterTemplatesAreNeverCached) {
  for (const std::string mode : {"header", "plugin"}) {
    SCOPED_TRACE(mode);
    const auto config = loadConfig(routeCacheYaml(mode, R"EOF(      built_route_cache:
        max_entries_per_worker: 16
)EOF"));
    ASSERT_TRUE(config.ok());
    auto headers = requestHeaders("/api/v1");
    headers.addCopy(Http::LowerCaseString("x-cluster"), "header_cluster");
    const auto first = config.value()->route(headers, stream_info_, 0).route;
    EXPECT_EQ(CacheDisabled, last_cache_result_());
    ASSERT_NE(nullptr, first);
    const auto second = config.value()->route(headers, stream_info_, 0).route;
    EXPECT_NE(first.get(), second.get());
  }
  EXPECT_EQ(0, entries());
}

} // namespace
} // namespace DynamicModules
} // namespace RouteSpecifiers
} // namespace Extensions
} // namespace Envoy
