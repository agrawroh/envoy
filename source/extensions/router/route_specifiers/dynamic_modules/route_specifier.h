#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/common/regex.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/router/route_specifiers/dynamic_modules/v3/dynamic_modules.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/hash_policy.h"
#include "envoy/router/route_specifier.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/scope.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/common/statusor.h"
#include "source/common/config/metadata.h"
#include "source/common/router/delegating_route_impl.h"
#include "source/extensions/dynamic_modules/abi/abi.h"
#include "source/extensions/dynamic_modules/dynamic_modules.h"
#include "source/extensions/dynamic_modules/metric_registry.h"

#include "absl/container/flat_hash_map.h"

namespace Envoy {
namespace Extensions {
namespace RouteSpecifiers {
namespace DynamicModules {

using DynamicModuleRouteSpecifierProto =
    envoy::extensions::router::route_specifiers::dynamic_modules::v3::DynamicModuleRouteSpecifier;

// Type aliases for function pointers resolved from the module.
using OnRouteSpecifierConfigNewType = decltype(&envoy_dynamic_module_on_route_specifier_config_new);
using OnRouteSpecifierConfigDestroyType =
    decltype(&envoy_dynamic_module_on_route_specifier_config_destroy);
using OnRouteSpecifierOnRouteType = decltype(&envoy_dynamic_module_on_route_specifier_on_route);
using OnRouteSpecifierRouteDestroyType =
    decltype(&envoy_dynamic_module_on_route_specifier_route_destroy);

// The default custom stat namespace which prepends all user-defined metrics.
// This can be overridden via the ``metrics_namespace`` field in ``DynamicModuleConfig``.
constexpr absl::string_view DefaultMetricsNamespace = "dynamicmodulescustom";

// The statistics of a route specifier.
#define ALL_DYNAMIC_MODULE_ROUTE_SPECIFIER_STATS(COUNTER, GAUGE, HISTOGRAM)                        \
  COUNTER(decision_pass_through)                                                                   \
  COUNTER(decision_has_override)                                                                   \
  COUNTER(decision_has_template)                                                                   \
  COUNTER(decision_no_route)                                                                       \
  COUNTER(decision_error)                                                                          \
  COUNTER(decision_reuse_previous)                                                                 \
  COUNTER(route_skipped)                                                                           \
  COUNTER(unknown_status)                                                                          \
  COUNTER(runtime_skipped)                                                                         \
  COUNTER(failure_module_error)                                                                    \
  COUNTER(failure_template_not_selected)                                                           \
  COUNTER(failure_template_match_failed)                                                           \
  COUNTER(failure_override_without_route)                                                          \
  COUNTER(failure_override_on_non_route_entry)                                                     \
  COUNTER(failure_route_metadata)                                                                  \
  COUNTER(reuse_previous_rejected)                                                                 \
  COUNTER(route_destroy)                                                                           \
  COUNTER(rewrite_not_applied)                                                                     \
  COUNTER(route_build)                                                                             \
  COUNTER(route_cache_hit)                                                                         \
  COUNTER(route_cache_miss)                                                                        \
  COUNTER(route_cache_verify)                                                                      \
  COUNTER(route_cache_verify_mismatch)                                                             \
  COUNTER(route_cache_evict)                                                                       \
  GAUGE(route_cache_entries, Accumulate)                                                           \
  HISTOGRAM(on_route_duration, Microseconds)                                                       \
  HISTOGRAM(specifier_duration, Microseconds)

struct RouteSpecifierStats {
  ALL_DYNAMIC_MODULE_ROUTE_SPECIFIER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT,
                                           GENERATE_HISTOGRAM_STRUCT)
};

/**
 * Route properties built from a single route_overrides entry. These properties are
 * built from extensions and are read by the router through references that must outlive the
 * request, so they are built once at configuration time and selected by override_id on the request
 * path.
 */
struct RouteOverride {
  Envoy::Router::RetryPolicyConstSharedPtr retry_policy;
  Envoy::Router::MetadataMatchCriteriaConstPtr metadata_match_criteria;
  std::vector<Envoy::Router::ShadowPolicyPtr> shadow_policies;
  std::unique_ptr<Http::HashPolicy> hash_policy;
  std::unique_ptr<Envoy::Router::HedgePolicy> hedge_policy;
  std::unique_ptr<const Envoy::Router::RateLimitPolicy> rate_limit_policy;
  std::unique_ptr<const Envoy::Router::CorsPolicy> cors_policy;
  // Regex rewrite of the request path, compiled once at configuration load. Null when unset.
  Regex::CompiledMatcherPtr regex_rewrite;
  std::string regex_rewrite_substitution;
  // Route level properties, valid on any route rather than only a route entry.
  std::shared_ptr<const Envoy::Router::RouteTracing> tracing;
  envoy::config::core::v3::Metadata metadata;

  // Whether the override carries a property only a route entry can carry.
  bool hasRouteEntryProperties() const {
    return retry_policy != nullptr || metadata_match_criteria != nullptr ||
           !shadow_policies.empty() || hash_policy != nullptr || hedge_policy != nullptr ||
           rate_limit_policy != nullptr || cors_policy != nullptr || regex_rewrite != nullptr;
  }
};

using RouteOverrideMap = absl::flat_hash_map<std::string, RouteOverride>;

// A prefix rewrite a module recorded as a rule. It is applied to the path the request carries when
// the request headers are finalized, the same way the prefix_rewrite of a configured route is, so a
// route that carries it is not specific to the request it was built for.
struct PrefixRewriteRule {
  // The literal the rule replaces. Empty when the rule replaces the whole path without its query
  // string.
  std::string matched;
  std::string replacement;
  bool whole_path{false};

  // The path the rule produces for a request path, or nullopt when the rule does not apply to it or
  // the result would exceed max_bytes.
  std::optional<std::string> apply(absl::string_view path, size_t max_bytes) const;

  bool operator==(const PrefixRewriteRule& other) const = default;
};

// A header mutation a module recorded for a request.
struct HeaderMutation {
  Http::LowerCaseString key;
  std::string value;
  envoy_dynamic_module_type_route_specifier_header_append_action action;

  bool operator==(const HeaderMutation& other) const = default;
};

/**
 * The overrides a module records for a request. They are applied to the route the decision produces
 * by the delegating routes below, and are only read on the worker thread that owns the request.
 */
struct RouteOverrides {
  std::string cluster_name;
  std::optional<std::chrono::milliseconds> timeout;
  std::optional<std::chrono::milliseconds> idle_timeout;
  std::optional<std::chrono::milliseconds> max_stream_duration;
  std::optional<uint64_t> request_body_buffer_limit;
  std::optional<Upstream::ResourcePriority> priority;
  std::optional<Http::Code> cluster_not_found_response_code;
  // Points into the override map of the configuration, which is immutable after construction. Null
  // when the module selected none.
  const RouteOverride* route_override{nullptr};
  // Metadata the module layered onto the route, keyed by namespace. Empty when the module set none.
  envoy::config::core::v3::Metadata route_metadata;
  absl::flat_hash_map<std::string, bool> filter_disabled;
  // Name the module recorded for the route it produces. Unset when the module set none.
  std::optional<std::string> route_name;
  std::optional<std::string> path;
  // Whether set_prefix_rewrite computed the path for the current request, which makes the route
  // specific to that request, so it is never cached.
  bool path_specific_to_request{false};
  // Applied when the request headers are finalized. A recorded path takes precedence over it.
  std::optional<PrefixRewriteRule> prefix_rewrite_rule;
  std::optional<std::string> host;
  std::vector<HeaderMutation> request_headers_to_add;
  std::vector<Http::LowerCaseString> request_headers_to_remove;
  std::vector<HeaderMutation> response_headers_to_add;
  std::vector<Http::LowerCaseString> response_headers_to_remove;

  // Whether anything that only a route entry can carry was recorded.
  bool hasRouteEntryOverrides() const;
  // Whether anything that any route can carry was recorded.
  bool hasRouteOverrides() const;

  // Whether two recordings produce the same route, which the route cache verifies a cached route
  // with.
  bool operator==(const RouteOverrides& other) const;
};

// The runtime fraction the module is invoked for.
struct RuntimeFraction {
  std::string key;
  envoy::type::v3::FractionalPercent default_value;
};

/**
 * Configuration for a dynamic module route specifier. This resolves and holds the symbols used to
 * resolve routes along with the in-module configuration, the route templates and the route
 * overrides the module may select. It is shared by every route the specifier produces so that the
 * module and its configuration outlive all in-flight requests.
 *
 * Note: Symbol resolution and in-module config creation are done in the factory function
 * newDynamicModuleRouteSpecifierConfig() to provide graceful error handling. The constructor only
 * initializes basic members.
 */
class DynamicModuleRouteSpecifierConfig {
public:
  DynamicModuleRouteSpecifierConfig(const DynamicModuleRouteSpecifierProto& proto_config,
                                    absl::string_view specifier_config,
                                    Extensions::DynamicModules::DynamicModulePtr dynamic_module,
                                    Envoy::Router::RouteSpecifierFactoryContext& context,
                                    absl::string_view metrics_namespace);

  ~DynamicModuleRouteSpecifierConfig();

  // A route template, along with its identifier and the kind of route it produces, which is fixed
  // by its action.
  struct Template {
    std::string id;
    Envoy::Router::MatchableRouteConstSharedPtr route;
    envoy_dynamic_module_type_route_specifier_route_kind kind;
  };

  /**
   * @param id the identifier of the route template.
   * @return the matching template, or nullptr when there is none. The returned pointer is valid for
   * the lifetime of this configuration.
   */
  const Template* routeTemplate(absl::string_view id) const;

  /**
   * @param override_id the identifier of the entry in route_overrides.
   * @return the matching override, or nullptr when there is none. The returned pointer is valid for
   * the lifetime of this configuration.
   */
  const RouteOverride* routeOverride(absl::string_view override_id) const;

  /**
   * Registers a route template from a serialized Route, building it with the route builder of the
   * configuration. Only valid while the in-module configuration is being created.
   * @param id the identifier the module selects the template with.
   * @param serialized_route the serialized envoy.config.route.v3.Route.
   * @return false when called outside configuration creation, when there is no route builder
   * because the specifier is configured on a route configuration, when the identifier is empty or
   * already used, when the bytes do not parse, or when the route is invalid.
   */
  bool registerRouteTemplate(absl::string_view id, absl::string_view serialized_route);

  const std::deque<std::string>& templateIds() const { return template_ids_; }
  const std::optional<RuntimeFraction>& runtimeFraction() const { return runtime_fraction_; }
  const std::string& specifierInstanceId() const { return specifier_instance_id_; }
  OnRouteSpecifierRouteDestroyType onRouteDestroy() const { return on_route_destroy_; }
  uint32_t maxRewrittenPathBytes() const { return max_rewritten_path_bytes_; }
  bool failClosed() const { return fail_closed_; }
  bool continueMatchingOnFailure() const { return continue_matching_on_failure_; }
  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  Runtime::Loader& runtime() const { return runtime_; }
  TimeSource& timeSource() const { return time_source_; }
  RouteSpecifierStats& stats() const { return stats_; }

  // The corresponding in-module route specifier configuration.
  envoy_dynamic_module_type_route_specifier_config_module_ptr in_module_config_{nullptr};

  // The function pointers resolved from the module, guaranteed non-nullptr after
  // newDynamicModuleRouteSpecifierConfig() succeeds.
  OnRouteSpecifierConfigDestroyType on_config_destroy_{nullptr};
  OnRouteSpecifierOnRouteType on_route_{nullptr};
  // Optional hook, null when the module does not export it, in which case route user data is a no
  // op.
  OnRouteSpecifierRouteDestroyType on_route_destroy_{nullptr};

  // ----------------------------- Metrics Support -----------------------------
  // The shared registry holding all module-defined metrics.
  Extensions::DynamicModules::MetricRegistry& metrics() { return metrics_; }

  // Owns the scope the registry references. Must precede metrics_ so it initializes first.
  const Stats::ScopeSharedPtr metrics_scope_;
  // Shared metrics registry composed from metrics_scope_.
  Extensions::DynamicModules::MetricRegistry metrics_;
  // We only allow the module to create stats during on_route_specifier_config_new, and not later
  // from worker threads, so that we don't have to wrap the metrics registry pool in a lock.
  std::atomic<bool> stat_creation_frozen_{false};

private:
  friend absl::StatusOr<std::shared_ptr<DynamicModuleRouteSpecifierConfig>>
  newDynamicModuleRouteSpecifierConfig(const DynamicModuleRouteSpecifierProto& proto_config,
                                       Extensions::DynamicModules::DynamicModulePtr dynamic_module,
                                       Envoy::Router::RouteSpecifierFactoryContext& context);

  // Declared first so that it is destroyed last, since everything below may run module code.
  const Extensions::DynamicModules::DynamicModulePtr dynamic_module_;
  const std::string specifier_name_;
  const std::string specifier_config_;
  const std::string specifier_instance_id_;
  // Immutable after configuration load, so that the pointers routeTemplate() and
  // routeOverride() hand out stay valid. A module may add templates during config creation
  // with registerRouteTemplate(). template_ids_ is a deque so that a template id buffer handed to
  // the module keeps its address when a later registration grows the container.
  absl::flat_hash_map<std::string, Template> templates_;
  std::deque<std::string> template_ids_;
  RouteOverrideMap route_overrides_;
  // Valid only while the in-module configuration is being created, so that the module can register
  // route templates Envoy builds with the route builder of the configuration.
  Envoy::Router::RouteBuilder* config_new_route_builder_{nullptr};
  bool config_new_validate_clusters_{false};
  const std::optional<RuntimeFraction> runtime_fraction_;
  const uint32_t max_rewritten_path_bytes_;
  const bool fail_closed_;
  const bool continue_matching_on_failure_;
  Upstream::ClusterManager& cluster_manager_;
  Runtime::Loader& runtime_;
  TimeSource& time_source_;
  const Stats::ScopeSharedPtr stats_scope_;
  mutable RouteSpecifierStats stats_;
};

using DynamicModuleRouteSpecifierConfigSharedPtr =
    std::shared_ptr<DynamicModuleRouteSpecifierConfig>;

// The settings of the built route cache, read from the built_route_cache field of the
// configuration.
struct BuiltRouteCacheSettings {
  uint32_t max_entries_per_worker;
  // A sweep evicts the entries idle for longer than the entry age, and runs every quarter of it.
  std::chrono::milliseconds sweep_interval;
  // Zero disables verification.
  uint32_t verify_one_in;
};

/**
 * A per worker cache of the routes a specifier built, keyed by the module. It lives in a thread
 * local slot the specifier owns rather than in the configuration, because every route it holds
 * holds the configuration, so a cache the configuration owned would keep its own configuration
 * alive. It is only read and written on the worker that owns it, so it takes no lock.
 */
class BuiltRouteCache : public ThreadLocal::ThreadLocalObject {
public:
  // A cached route and what it was built from, which a verification compares against.
  struct Entry {
    uint64_t key;
    // The route set_route_template selected. It is held so that its address, which is part of the
    // key, cannot be reused by another route while the entry lives.
    Envoy::Router::RouteConstSharedPtr base;
    Envoy::Router::RouteConstSharedPtr route;
    // What the module recorded for the route, pointing into the route. Null when nothing was
    // recorded and the route is the base itself.
    const RouteOverrides* recorded;
    std::optional<uint64_t> user_data;
    // The sweep tick of the last use, and the reference bit of the CLOCK eviction.
    uint64_t last_used_tick;
    bool referenced;
  };

  BuiltRouteCache(Event::Dispatcher& dispatcher, DynamicModuleRouteSpecifierConfigSharedPtr config,
                  const BuiltRouteCacheSettings& settings);
  ~BuiltRouteCache() override;

  /**
   * @return the entry cached for the key and the base route, or nullptr when there is none. A hit
   * marks the entry used. The entry is valid until the next insert or sweep on this worker.
   */
  const Entry* lookup(uint64_t key, const Envoy::Router::Route* base);

  /**
   * Caches a built route, evicting the least recently used entry, approximated by CLOCK, when the
   * worker is full. Nothing changes when the key and the base are cached already.
   */
  void insert(uint64_t key, Envoy::Router::RouteConstSharedPtr base,
              Envoy::Router::RouteConstSharedPtr route, const RouteOverrides* recorded,
              std::optional<uint64_t> user_data);

  // Removes the entry cached for the key and the base route, if there is one.
  void erase(uint64_t key, const Envoy::Router::Route* base);

  // Whether the hit being served is the one in verify_one_in that is verified.
  bool sampleVerification();

  size_t size() const { return entries_.size(); }

private:
  struct Key {
    uint64_t key;
    const Envoy::Router::Route* base;

    bool operator==(const Key& other) const = default;
    template <typename H> friend H AbslHashValue(H h, const Key& key) {
      return H::combine(std::move(h), key.key, key.base);
    }
  };

  static Key keyOf(const Entry& entry) { return {entry.key, entry.base.get()}; }
  // The index of the entry CLOCK evicts next. Only valid on a non empty cache.
  size_t clockVictim();
  // Evicts the entries idle for longer than the entry age.
  void sweep();
  void removeAt(size_t index);

  const DynamicModuleRouteSpecifierConfigSharedPtr config_;
  const BuiltRouteCacheSettings settings_;
  std::vector<Entry> entries_;
  absl::flat_hash_map<Key, size_t> index_;
  size_t hand_{0};
  uint64_t tick_{0};
  uint32_t hits_since_verification_{0};
  const Event::TimerPtr sweep_timer_;
};

// What set_route_cache_key found for a request.
struct BuiltRouteCacheLookup {
  uint64_t key;
  // The cached route on a hit, null on a miss.
  Envoy::Router::RouteConstSharedPtr cached;
  // What the cached route was built from, kept alive by cached. Null when nothing was recorded.
  const RouteOverrides* recorded{nullptr};
  std::optional<uint64_t> user_data;
  // Whether the hit is verified against what the module records for the request.
  bool verify{false};
};

/**
 * Creates a new DynamicModuleRouteSpecifierConfig for the given configuration.
 * @param proto_config the route specifier configuration.
 * @param dynamic_module the dynamic module to use.
 * @param context the factory context used to build the route templates.
 * @return a shared pointer to the new config object or an error if symbol resolution, route
 * template construction, route override construction or in-module initialization failed.
 */
absl::StatusOr<DynamicModuleRouteSpecifierConfigSharedPtr>
newDynamicModuleRouteSpecifierConfig(const DynamicModuleRouteSpecifierProto& proto_config,
                                     Extensions::DynamicModules::DynamicModulePtr dynamic_module,
                                     Envoy::Router::RouteSpecifierFactoryContext& context);

/**
 * Per-decision context passed to the module as the route_specifier_context_envoy_ptr. It bundles
 * the request state the module reads and the decision it is building. Valid only for the duration
 * of a single envoy_dynamic_module_on_route_specifier_on_route call.
 */
struct RouteSpecifierContext {
  const DynamicModuleRouteSpecifierConfig& config;
  const Envoy::Router::RouteConstSharedPtr& input_route;
  const Http::RequestHeaderMap& headers;
  const StreamInfo::StreamInfo& stream_info;
  const uint64_t random_value;
  const DynamicModuleRouteSpecifierConfig::Template* selected_template{nullptr};
  // Whether a set_route_template call named an identifier that is not declared. When no template
  // ends up selected and the decision is left Unspecified, the failure policy applies rather than
  // silently falling back to the route the specifier was given. A module that wants to probe for
  // a template without committing checks the configuration getters instead.
  bool template_selection_failed{false};
  // The selected template evaluated against the request, set when set_route_template succeeds so
  // that the getters reflect the route being produced. Null keeps the getters on the route matching
  // resolved, whether no template was selected or its match did not hold.
  Envoy::Router::RouteConstSharedPtr selected_route;
  // The decision set_decision recorded, which may hold a value outside the named enumerators,
  // for example from a newer ABI. Unspecified when the module recorded none.
  envoy_dynamic_module_type_route_specifier_decision decision{
      envoy_dynamic_module_type_route_specifier_decision_Unspecified};
  RouteOverrides overrides;
  // A u64 the module recorded on the route it produces. Forces the produced route to be wrapped
  // even with no override, so the route destroy hook fires for it. Unset when the module set none.
  std::optional<uint64_t> user_data;
  // Redirect locations built for the getters, kept in a stable container so a buffer handed to the
  // module stays valid until the hook returns even after the current route changes. Built once per
  // route so repeated reads for the same route return the same buffer.
  std::deque<std::string> input_redirect_locations;
  const Envoy::Router::Route* input_redirect_route{nullptr};
  // The per worker route cache of the specifier, null when the specifier configures none.
  BuiltRouteCache* built_route_cache{nullptr};
  // What set_route_cache_key found. Unset when the module set no key, and reset when a later
  // template selection changes the route the key was looked up for.
  std::optional<BuiltRouteCacheLookup> built_route_cache_lookup;

  // The route the getters read. It is the selected template evaluated against the request when one
  // was selected, otherwise the route matching resolved.
  const Envoy::Router::RouteConstSharedPtr& currentRoute() const {
    return selected_route != nullptr ? selected_route : input_route;
  }
};

/**
 * Route that delegates to the route a decision produced and applies the overrides a module recorded
 * for the request. It holds the configuration so that the module outlives the request.
 */
class DynamicModuleRoute : public Envoy::Router::DelegatingRoute {
public:
  DynamicModuleRoute(
      Envoy::Router::RouteConstSharedPtr route, DynamicModuleRouteSpecifierConfigSharedPtr config,
      RouteOverrides&& overrides,
      Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack,
      std::optional<uint64_t> user_data);
  ~DynamicModuleRoute() override;

  // What the module recorded for this route.
  const RouteOverrides& recordedOverrides() const { return overrides_; }

  // Router::Route
  const std::string& routeName() const override;
  const envoy::config::core::v3::Metadata& metadata() const override;
  const Envoy::Config::TypedMetadata& typedMetadata() const override;
  std::optional<bool> filterDisabled(absl::string_view name) const override;
  const Envoy::Router::RouteTracing* tracingConfig() const override;

protected:
  const DynamicModuleRouteSpecifierConfigSharedPtr config_;
  const RouteOverrides overrides_;
  // Null when the module recorded no route metadata, so that both accessors fall back to the route.
  const Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack_;
  // Set when the module recorded user data, passed to the route destroy hook when this is
  // destroyed.
  const std::optional<uint64_t> user_data_;
};

/**
 * Route entry that delegates to the route a decision produced and applies the overrides a module
 * recorded for the request.
 */
class DynamicModuleRouteEntry : public Envoy::Router::DelegatingRouteEntry {
public:
  DynamicModuleRouteEntry(
      Envoy::Router::RouteConstSharedPtr route, DynamicModuleRouteSpecifierConfigSharedPtr config,
      RouteOverrides&& overrides,
      Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack,
      std::optional<uint64_t> user_data);
  ~DynamicModuleRouteEntry() override;

  // What the module recorded for this route.
  const RouteOverrides& recordedOverrides() const { return overrides_; }

  // Router::Route
  const std::string& routeName() const override;
  const envoy::config::core::v3::Metadata& metadata() const override;
  const Envoy::Config::TypedMetadata& typedMetadata() const override;
  std::optional<bool> filterDisabled(absl::string_view name) const override;
  const Envoy::Router::RouteTracing* tracingConfig() const override;

  // Router::RouteEntry
  const std::string& clusterName() const override;
  std::chrono::milliseconds timeout() const override;
  std::optional<std::chrono::milliseconds> idleTimeout() const override;
  std::optional<std::chrono::milliseconds> maxStreamDuration() const override;
  bool usingNewTimeouts() const override;
  uint64_t requestBodyBufferLimit() const override;
  Upstream::ResourcePriority priority() const override;
  Http::Code clusterNotFoundResponseCode() const override;
  const Envoy::Router::RetryPolicyConstSharedPtr& retryPolicy() const override;
  const Envoy::Router::MetadataMatchCriteria* metadataMatchCriteria() const override;
  const std::vector<Envoy::Router::ShadowPolicyPtr>& shadowPolicies() const override;
  const Http::HashPolicy* hashPolicy() const override;
  const Envoy::Router::HedgePolicy& hedgePolicy() const override;
  const Envoy::Router::RateLimitPolicy& rateLimitPolicy() const override;
  const Envoy::Router::CorsPolicy* corsPolicy() const override;
  std::string currentUrlPathAfterRewrite(const Http::RequestHeaderMap& headers,
                                         const Formatter::Context& context,
                                         const StreamInfo::StreamInfo& stream_info) const override;
  void finalizeRequestHeaders(Http::RequestHeaderMap& headers, const Formatter::Context& context,
                              const StreamInfo::StreamInfo& stream_info,
                              bool insert_envoy_original_path) const override;
  Http::HeaderTransforms requestHeaderTransforms(const StreamInfo::StreamInfo& stream_info,
                                                 bool do_formatting = true) const override;
  void finalizeResponseHeaders(Http::ResponseHeaderMap& headers, const Formatter::Context& context,
                               const StreamInfo::StreamInfo& stream_info) const override;
  Http::HeaderTransforms responseHeaderTransforms(const StreamInfo::StreamInfo& stream_info,
                                                  bool do_formatting = true) const override;

private:
  // Whether a rewrite is applied to the path the request carries when it is finalized, which is the
  // prefix rewrite rule the module recorded or the regex rewrite of the selected route override.
  bool hasFinalizationRewrite() const;
  // The path the finalization rewrite produces for a request path, or nullopt when it does not
  // apply. A recorded prefix rewrite rule owns the rewrite, so the regex rewrite of the route
  // override is not tried when a rule is recorded.
  std::optional<std::string> finalizationRewrite(absl::string_view path) const;

  const DynamicModuleRouteSpecifierConfigSharedPtr config_;
  const RouteOverrides overrides_;
  const Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack_;
  const std::optional<uint64_t> user_data_;
};

// Why Envoy could not honor the decision of a module. There is one value per failure statistic of
// the route specifier.
enum class Failure {
  // The decision was honored.
  None,
  // The module recorded the Error decision, recorded a decision this build does not know, or
  // returned a status this build does not know.
  ModuleError,
  // A template selection named an identifier that is not declared, no template ended up
  // selected, and the decision was left Unspecified.
  TemplateNotSelected,
  // The match of the selected template does not hold for the request.
  TemplateMatchFailed,
  // An override or user data was recorded, with no template to build a route from, while route
  // matching resolved no route to apply them to.
  OverrideWithoutRoute,
  // Route entry overrides were recorded for a route that answers the request directly.
  OverrideOnNonRouteEntry,
  // The recorded route metadata was rejected by a typed metadata factory.
  RouteMetadata,
  // ReusePrevious was returned but the stream has no previous route.
  ReusePreviousRejected,
};

/**
 * RouteSpecifier that delegates the route decision to a dynamic module.
 */
class DynamicModuleRouteSpecifier : public Envoy::Router::RouteSpecifier,
                                    public Logger::Loggable<Logger::Id::dynamic_modules> {
public:
  // The route cache is created when the configuration sets built_route_cache. Must be called on the
  // main thread, which allocates the thread local slot.
  DynamicModuleRouteSpecifier(DynamicModuleRouteSpecifierConfigSharedPtr config,
                              const DynamicModuleRouteSpecifierProto& proto_config,
                              ThreadLocal::SlotAllocator& tls);

  // Router::RouteSpecifier
  Envoy::Router::OnRouteResult
  onRoute(Envoy::Router::RouteConstSharedPtr route, const Http::RequestHeaderMap& headers,
          const StreamInfo::StreamInfo& stream_info, uint64_t random,
          Envoy::Router::OnRouteInputStatus input_status) const override;

private:
  // The outcome of a decision, holding the route it produced, the chain status and the reason it
  // could not be honored. A chain status of StopIterationAndSkipRoute asks route matching to
  // carry on with the next route.
  struct Decision {
    Envoy::Router::RouteConstSharedPtr route;
    Envoy::Router::OnRouteStatus status{Envoy::Router::OnRouteStatus::Continue};
    Failure failure{Failure::None};
    // What the module recorded for the route, pointing into it. Null when wrap built no wrapper.
    const RouteOverrides* recorded{nullptr};
  };

  // on_route_status is the raw value the module returned, which may be outside the known enum
  // values. The decision the module recorded is read from the context.
  Decision resolve(RouteSpecifierContext& context, uint32_t on_route_status) const;
  // The route the module asked for, without the failure policy applied.
  Decision wrap(Envoy::Router::RouteConstSharedPtr route, RouteSpecifierContext& context,
                Envoy::Router::OnRouteStatus status) const;
  // Compares what the module recorded with what the cached route of a verified hit was built from,
  // and removes the entry when they differ.
  void verifyCachedRoute(const RouteSpecifierContext& context,
                         const BuiltRouteCacheLookup& lookup) const;

  const DynamicModuleRouteSpecifierConfigSharedPtr config_;
  // Null when the configuration sets no built_route_cache. Destroying it posts the removal of every
  // worker's cache to the main thread, so each worker's routes are released on that worker.
  ThreadLocal::TypedSlotPtr<BuiltRouteCache> built_route_cache_;
};

} // namespace DynamicModules
} // namespace RouteSpecifiers
} // namespace Extensions
} // namespace Envoy
