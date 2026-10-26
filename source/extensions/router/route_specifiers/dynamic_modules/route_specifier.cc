#include "source/extensions/router/route_specifiers/dynamic_modules/route_specifier.h"

#include <string>
#include <utility>

#include "envoy/common/exception.h"

#include "source/common/common/assert.h"
#include "source/common/common/macros.h"
#include "source/common/common/regex.h"
#include "source/common/common/thread.h"
#include "source/common/config/well_known_names.h"
#include "source/common/http/hash_policy.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/path_utility.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/common/router/config_impl.h"
#include "source/common/router/metadatamatchcriteria_impl.h"
#include "source/common/router/path_rewrite_utility.h"
#include "source/common/router/retry_policy_impl.h"
#include "source/common/router/router_ratelimit.h"
#include "source/common/runtime/runtime_features.h"

namespace Envoy {
namespace Extensions {
namespace RouteSpecifiers {
namespace DynamicModules {
namespace {

using RouteKind = envoy_dynamic_module_type_route_specifier_route_kind;
using RouteOverrideProto =
    envoy::extensions::router::route_specifiers::dynamic_modules::v3::RouteOverride;

absl::StatusOr<RouteOverride>
buildRouteOverride(const RouteOverrideProto& proto_override,
                   Server::Configuration::ServerFactoryContext& context) {
  RouteOverride entry;
  if (proto_override.has_retry_policy()) {
    auto policy_or_error = Envoy::Router::RetryPolicyImpl::create(
        proto_override.retry_policy(), context.messageValidationVisitor(), context);
    RETURN_IF_NOT_OK_REF(policy_or_error.status());
    entry.retry_policy = std::move(policy_or_error.value());
  }
  if (proto_override.has_metadata_match()) {
    const auto& filter_metadata = proto_override.metadata_match().filter_metadata();
    const auto filter_it = filter_metadata.find(Envoy::Config::MetadataFilters::get().ENVOY_LB);
    if (filter_it != filter_metadata.end()) {
      entry.metadata_match_criteria =
          std::make_unique<Envoy::Router::MetadataMatchCriteriaImpl>(filter_it->second);
    }
  }
  entry.shadow_policies.reserve(proto_override.request_mirror_policies().size());
  for (const auto& mirror_policy_config : proto_override.request_mirror_policies()) {
    auto policy_or_error = Envoy::Router::ShadowPolicyImpl::create(mirror_policy_config, context);
    RETURN_IF_NOT_OK_REF(policy_or_error.status());
    entry.shadow_policies.push_back(std::move(policy_or_error.value()));
  }
  if (!proto_override.hash_policy().empty()) {
    auto policy_or_error =
        Http::HashPolicyImpl::create(proto_override.hash_policy(), context.regexEngine());
    RETURN_IF_NOT_OK_REF(policy_or_error.status());
    entry.hash_policy = std::move(policy_or_error.value());
  }
  if (proto_override.has_hedge_policy()) {
    entry.hedge_policy =
        std::make_unique<Envoy::Router::HedgePolicyImpl>(proto_override.hedge_policy());
  }
  if (proto_override.has_regex_rewrite()) {
    auto regex_or_error =
        Regex::Utility::parseRegex(proto_override.regex_rewrite().pattern(), context.regexEngine());
    RETURN_IF_NOT_OK_REF(regex_or_error.status());
    entry.regex_rewrite = std::move(regex_or_error.value());
    entry.regex_rewrite_substitution = proto_override.regex_rewrite().substitution();
  }
  if (proto_override.has_tracing()) {
    auto tracing_or_error = Envoy::Router::RouteTracingImpl::create(proto_override.tracing());
    RETURN_IF_NOT_OK_REF(tracing_or_error.status());
    entry.tracing = std::move(tracing_or_error.value());
  }
  entry.metadata = proto_override.metadata();
  if (!proto_override.rate_limits().empty() || proto_override.has_cors()) {
    // RateLimitPolicyImpl and CorsPolicyImpl build extension backed matchers that throw on a
    // rejected input, so a build failure is turned into a configuration error.
    TRY_NEEDS_AUDIT {
      if (!proto_override.rate_limits().empty()) {
        absl::Status creation_status = absl::OkStatus();
        entry.rate_limit_policy = std::make_unique<Envoy::Router::RateLimitPolicyImpl>(
            proto_override.rate_limits(), context, creation_status);
        RETURN_IF_NOT_OK(creation_status);
      }
      if (proto_override.has_cors()) {
        entry.cors_policy =
            std::make_unique<Envoy::Router::CorsPolicyImpl>(proto_override.cors(), context);
      }
    }
    END_TRY
    CATCH(const EnvoyException& e, { return absl::InvalidArgumentError(e.what()); });
  }
  // Validate what was built rather than what was configured. A metadata_match without an envoy.lb
  // entry contributes nothing, so a populated looking configuration can still build an override
  // that replaces no property, which set_route_override would then accept as a decision.
  const bool has_metadata =
      !entry.metadata.filter_metadata().empty() || !entry.metadata.typed_filter_metadata().empty();
  if (entry.retry_policy == nullptr && entry.metadata_match_criteria == nullptr &&
      entry.shadow_policies.empty() && entry.hash_policy == nullptr &&
      entry.hedge_policy == nullptr && entry.rate_limit_policy == nullptr &&
      entry.cors_policy == nullptr && entry.regex_rewrite == nullptr && entry.tracing == nullptr &&
      !has_metadata) {
    return absl::InvalidArgumentError("Route override must replace at least one property");
  }
  return entry;
}

std::optional<RuntimeFraction>
buildRuntimeFraction(const DynamicModuleRouteSpecifierProto& config) {
  if (!config.has_runtime_fraction()) {
    return std::nullopt;
  }
  return RuntimeFraction{config.runtime_fraction().runtime_key(),
                         config.runtime_fraction().default_value()};
}

// Layers the metadata a module recorded onto the metadata of the route and validates it. Returns a
// null pack when the module recorded none, so that both metadata accessors fall back to the route,
// and an error when a typed metadata factory rejects the merged metadata.
absl::StatusOr<Envoy::Router::RouteMetadataPackPtr>
buildMetadataPack(const Envoy::Router::Route& route,
                  const envoy::config::core::v3::Metadata& overrides) {
  if (overrides.filter_metadata().empty() && overrides.typed_filter_metadata().empty()) {
    return Envoy::Router::RouteMetadataPackPtr{};
  }
  // One copy of the route metadata, merged in place and then moved into the pack.
  envoy::config::core::v3::Metadata merged = route.metadata();
  // Merge per namespace so an entry replaces only its own key while the other keys of the route
  // stay in effect. A top-level merge would replace the whole namespace instead.
  for (const auto& [name, fields] : overrides.filter_metadata()) {
    (*merged.mutable_filter_metadata())[name].MergeFrom(fields);
  }
  for (const auto& [name, typed] : overrides.typed_filter_metadata()) {
    (*merged.mutable_typed_filter_metadata())[name] = typed;
  }
  // create() runs the registered typed metadata factories once and returns an error instead of
  // throwing, so the wrapper it feeds cannot throw when it is constructed.
  return Envoy::Router::RouteMetadataPack::create(std::move(merged));
}

void applyHeaderMutations(Http::HeaderMap& headers,
                          const std::vector<HeaderMutation>& headers_to_add,
                          const std::vector<Http::LowerCaseString>& headers_to_remove) {
  for (const auto& mutation : headers_to_add) {
    switch (mutation.action) {
    case envoy_dynamic_module_type_route_specifier_header_append_action_AppendIfExistsOrAdd:
      headers.appendCopy(mutation.key, mutation.value);
      break;
    case envoy_dynamic_module_type_route_specifier_header_append_action_AddIfAbsent:
      if (headers.get(mutation.key).empty()) {
        headers.setCopy(mutation.key, mutation.value);
      }
      break;
    case envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExistsOrAdd:
      headers.setCopy(mutation.key, mutation.value);
      break;
    case envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExists:
      if (!headers.get(mutation.key).empty()) {
        headers.setCopy(mutation.key, mutation.value);
      }
      break;
    }
  }
  for (const auto& key : headers_to_remove) {
    headers.remove(key);
  }
}

// Applies the metadata the selected route override carries onto the recorded overrides before the
// route is built. Deferred to resolution so that unset_route_override can revert the selection
// cleanly, and defined so that the metadata the module records itself wins whatever the call order.
// The regex rewrite of the override is not applied here but when the request headers are
// finalized, to the path the request carries then, so the route stays valid for another request.
void applySelectedRouteOverride(RouteSpecifierContext& context) {
  const RouteOverride* entry = context.overrides.route_override;
  if (entry == nullptr) {
    return;
  }
  for (const auto& [name, fields] : entry->metadata.filter_metadata()) {
    auto& slot = (*context.overrides.route_metadata.mutable_filter_metadata())[name];
    Protobuf::Struct merged = fields;
    merged.MergeFrom(slot);
    slot = std::move(merged);
  }
  for (const auto& [name, typed] : entry->metadata.typed_filter_metadata()) {
    context.overrides.route_metadata.mutable_typed_filter_metadata()->insert({name, typed});
  }
}

void appendHeaderTransforms(Http::HeaderTransforms& transforms,
                            const std::vector<HeaderMutation>& headers_to_add,
                            const std::vector<Http::LowerCaseString>& headers_to_remove) {
  for (const auto& mutation : headers_to_add) {
    switch (mutation.action) {
    case envoy_dynamic_module_type_route_specifier_header_append_action_AppendIfExistsOrAdd:
      transforms.headers_to_append_or_add.emplace_back(mutation.key, mutation.value);
      break;
    case envoy_dynamic_module_type_route_specifier_header_append_action_AddIfAbsent:
      transforms.headers_to_add_if_absent.emplace_back(mutation.key, mutation.value);
      break;
    // HeaderTransforms cannot express OverwriteIfExists, so it is reported as an overwrite, the
    // same way HeaderParser reports it.
    case envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExistsOrAdd:
    case envoy_dynamic_module_type_route_specifier_header_append_action_OverwriteIfExists:
      transforms.headers_to_overwrite_or_add.emplace_back(mutation.key, mutation.value);
      break;
    }
  }
  for (const auto& key : headers_to_remove) {
    transforms.headers_to_remove.push_back(key);
  }
}

} // namespace

std::optional<std::string> PrefixRewriteRule::apply(absl::string_view path,
                                                    size_t max_bytes) const {
  // A rule over the whole path replaces the part a regex route matches, which is the path without
  // its query string and fragment.
  const absl::string_view span =
      whole_path ? Http::PathUtil::removeQueryAndFragment(path) : absl::string_view(matched);
  return Envoy::Router::rewritePathByPrefixOrRegex(path, span, replacement, nullptr, "", max_bytes);
}

bool RouteOverrides::hasRouteEntryOverrides() const {
  return !cluster_name.empty() || timeout.has_value() || idle_timeout.has_value() ||
         max_stream_duration.has_value() || request_body_buffer_limit.has_value() ||
         priority.has_value() || cluster_not_found_response_code.has_value() ||
         (route_override != nullptr && route_override->hasRouteEntryProperties()) ||
         path.has_value() || prefix_rewrite_rule.has_value() || host.has_value() ||
         !request_headers_to_add.empty() || !request_headers_to_remove.empty() ||
         !response_headers_to_add.empty() || !response_headers_to_remove.empty();
}

bool RouteOverrides::operator==(const RouteOverrides& other) const {
  // MessageUtil compares the metadata field by field, which is what the routes built from two
  // recordings observe.
  return cluster_name == other.cluster_name && timeout == other.timeout &&
         idle_timeout == other.idle_timeout && max_stream_duration == other.max_stream_duration &&
         request_body_buffer_limit == other.request_body_buffer_limit &&
         priority == other.priority &&
         cluster_not_found_response_code == other.cluster_not_found_response_code &&
         route_override == other.route_override &&
         MessageUtil()(route_metadata, other.route_metadata) &&
         filter_disabled == other.filter_disabled && route_name == other.route_name &&
         path == other.path && path_specific_to_request == other.path_specific_to_request &&
         prefix_rewrite_rule == other.prefix_rewrite_rule && host == other.host &&
         request_headers_to_add == other.request_headers_to_add &&
         request_headers_to_remove == other.request_headers_to_remove &&
         response_headers_to_add == other.response_headers_to_add &&
         response_headers_to_remove == other.response_headers_to_remove;
}

bool RouteOverrides::hasRouteOverrides() const {
  return !route_metadata.filter_metadata().empty() ||
         !route_metadata.typed_filter_metadata().empty() || !filter_disabled.empty() ||
         (route_override != nullptr && route_override->tracing != nullptr) ||
         route_name.has_value();
}

DynamicModuleRouteSpecifierConfig::DynamicModuleRouteSpecifierConfig(
    const DynamicModuleRouteSpecifierProto& proto_config, absl::string_view specifier_config,
    Extensions::DynamicModules::DynamicModulePtr dynamic_module,
    Envoy::Router::RouteSpecifierFactoryContext& context, absl::string_view metrics_namespace)
    : metrics_scope_(context.serverFactoryContext().serverScope().createScope(
          absl::StrCat(metrics_namespace, "."))),
      metrics_(*metrics_scope_), dynamic_module_(std::move(dynamic_module)),
      specifier_name_(proto_config.specifier_name()), specifier_config_(specifier_config),
      specifier_instance_id_(proto_config.specifier_instance_id()),
      runtime_fraction_(buildRuntimeFraction(proto_config)),
      max_rewritten_path_bytes_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, max_rewritten_path_bytes, 65536)),
      fail_closed_(proto_config.failure_policy() ==
                   envoy::extensions::router::route_specifiers::dynamic_modules::v3::NO_ROUTE),
      continue_matching_on_failure_(
          proto_config.failure_policy() ==
          envoy::extensions::router::route_specifiers::dynamic_modules::v3::CONTINUE_MATCHING),
      cluster_manager_(context.serverFactoryContext().clusterManager()),
      runtime_(context.serverFactoryContext().runtime()),
      time_source_(context.serverFactoryContext().timeSource()),
      stats_scope_(context.serverFactoryContext().serverScope().createScope(
          absl::StrCat(metrics_namespace, ".route_specifier.", proto_config.stat_prefix(), "."))),
      stats_{ALL_DYNAMIC_MODULE_ROUTE_SPECIFIER_STATS(
          POOL_COUNTER(*stats_scope_), POOL_GAUGE(*stats_scope_), POOL_HISTOGRAM(*stats_scope_))} {}

DynamicModuleRouteSpecifierConfig::~DynamicModuleRouteSpecifierConfig() {
  if (in_module_config_ != nullptr) {
    // The destroy hook is resolved before the in-module configuration is created.
    ASSERT(on_config_destroy_ != nullptr);
    on_config_destroy_(in_module_config_);
  }
}

const DynamicModuleRouteSpecifierConfig::Template*
DynamicModuleRouteSpecifierConfig::routeTemplate(absl::string_view id) const {
  const auto it = templates_.find(id);
  return it != templates_.end() ? &it->second : nullptr;
}

const RouteOverride*
DynamicModuleRouteSpecifierConfig::routeOverride(absl::string_view override_id) const {
  const auto it = route_overrides_.find(override_id);
  return it != route_overrides_.end() ? &it->second : nullptr;
}

bool DynamicModuleRouteSpecifierConfig::registerRouteTemplate(absl::string_view id,
                                                              absl::string_view serialized_route) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  if (config_new_route_builder_ == nullptr || id.empty() || templates_.contains(id)) {
    return false;
  }
  envoy::config::route::v3::Route route;
  if (!route.ParseFromArray(serialized_route.data(), static_cast<int>(serialized_route.size()))) {
    return false;
  }
  absl::StatusOr<Envoy::Router::MatchableRouteConstSharedPtr> built =
      config_new_route_builder_->build(route, config_new_validate_clusters_);
  if (!built.ok()) {
    ENVOY_LOG_MISC(debug, "dynamic module route specifier could not register template '{}': {}", id,
                   built.status().message());
    return false;
  }
  const RouteKind kind = route.has_redirect() || route.has_direct_response()
                             ? envoy_dynamic_module_type_route_specifier_route_kind_DirectResponse
                             : envoy_dynamic_module_type_route_specifier_route_kind_RouteEntry;
  templates_.emplace(std::string(id), Template{std::string(id), std::move(built.value()), kind});
  template_ids_.emplace_back(id);
  return true;
}

absl::StatusOr<DynamicModuleRouteSpecifierConfigSharedPtr>
newDynamicModuleRouteSpecifierConfig(const DynamicModuleRouteSpecifierProto& proto_config,
                                     Extensions::DynamicModules::DynamicModulePtr dynamic_module,
                                     Envoy::Router::RouteSpecifierFactoryContext& context) {
  ASSERT_IS_MAIN_OR_TEST_THREAD();

  if (proto_config.failure_policy() == envoy::extensions::router::route_specifiers::
                                           dynamic_modules::v3::FAILURE_POLICY_UNSPECIFIED) {
    return absl::InvalidArgumentError("failure_policy must be set");
  }
  if (!proto_config.route_templates().empty() && !context.routeBuilder().has_value()) {
    return absl::InvalidArgumentError(
        "route templates require a route specifier configured on a virtual host or a route");
  }
  // The cache holds routes built from templates, which a specifier without a route builder cannot
  // declare.
  if (proto_config.has_built_route_cache() && !context.routeBuilder().has_value()) {
    return absl::InvalidArgumentError(
        "built_route_cache requires a route specifier configured on a virtual host or a route");
  }

  auto on_config_new = dynamic_module->getFunctionPointer<OnRouteSpecifierConfigNewType>(
      "envoy_dynamic_module_on_route_specifier_config_new");
  RETURN_IF_NOT_OK_REF(on_config_new.status());

  auto on_config_destroy = dynamic_module->getFunctionPointer<OnRouteSpecifierConfigDestroyType>(
      "envoy_dynamic_module_on_route_specifier_config_destroy");
  RETURN_IF_NOT_OK_REF(on_config_destroy.status());

  auto on_route = dynamic_module->getFunctionPointer<OnRouteSpecifierOnRouteType>(
      "envoy_dynamic_module_on_route_specifier_on_route");
  RETURN_IF_NOT_OK_REF(on_route.status());

  // The route destroy hook is optional, so a module built with an older SDK that does not export it
  // is accepted and the hook is a no op.
  auto on_route_destroy = dynamic_module->getFunctionPointer<OnRouteSpecifierRouteDestroyType>(
      "envoy_dynamic_module_on_route_specifier_route_destroy");

  // Use knownAnyToBytes() to properly handle StringValue/BytesValue/Struct types.
  std::string specifier_config;
  if (proto_config.has_specifier_config()) {
    auto config_or_error = MessageUtil::knownAnyToBytes(proto_config.specifier_config());
    RETURN_IF_NOT_OK_REF(config_or_error.status());
    specifier_config = std::move(config_or_error.value());
  }

  const std::string metrics_namespace =
      proto_config.dynamic_module_config().metrics_namespace().empty()
          ? std::string(DefaultMetricsNamespace)
          : proto_config.dynamic_module_config().metrics_namespace();
  if (Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.dynamic_modules_strip_custom_stat_prefix")) {
    context.serverFactoryContext().api().customStatNamespaces().registerStatNamespace(
        metrics_namespace);
  }

  auto config = std::make_shared<DynamicModuleRouteSpecifierConfig>(
      proto_config, specifier_config, std::move(dynamic_module), context, metrics_namespace);
  config->on_config_destroy_ = on_config_destroy.value();
  config->on_route_ = on_route.value();
  config->on_route_destroy_ = on_route_destroy.ok() ? on_route_destroy.value() : nullptr;

  const bool validate_clusters =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, validate_clusters, false);
  auto route_builder = context.routeBuilder();
  for (const auto& route_template : proto_config.route_templates()) {
    const std::string& id = route_template.template_id();
    if (config->templates_.contains(id)) {
      return absl::InvalidArgumentError(fmt::format("duplicate route template id '{}'", id));
    }
    absl::StatusOr<Envoy::Router::MatchableRouteConstSharedPtr> built =
        route_builder->build(route_template.route(), validate_clusters);
    if (!built.ok()) {
      return absl::InvalidArgumentError(
          fmt::format("route template '{}': {}", id, built.status().message()));
    }
    const RouteKind kind =
        route_template.route().has_redirect() || route_template.route().has_direct_response()
            ? envoy_dynamic_module_type_route_specifier_route_kind_DirectResponse
            : envoy_dynamic_module_type_route_specifier_route_kind_RouteEntry;
    config->templates_.emplace(
        id, DynamicModuleRouteSpecifierConfig::Template{id, std::move(built.value()), kind});
    config->template_ids_.push_back(id);
  }

  config->route_overrides_.reserve(proto_config.route_overrides().size());
  for (const auto& proto_override : proto_config.route_overrides()) {
    const std::string& override_id = proto_override.override_id();
    if (config->route_overrides_.contains(override_id)) {
      return absl::InvalidArgumentError(
          fmt::format("duplicate route override id '{}'", override_id));
    }
    auto entry_or_error = buildRouteOverride(proto_override, context.serverFactoryContext());
    if (!entry_or_error.ok()) {
      return absl::InvalidArgumentError(
          fmt::format("route override '{}': {}", override_id, entry_or_error.status().message()));
    }
    if (validate_clusters) {
      for (const auto& shadow_policy : entry_or_error.value().shadow_policies) {
        // A policy that names its cluster through a request header resolves it per request, so only
        // a statically named cluster can be checked here.
        if (!shadow_policy->cluster().empty() &&
            !context.serverFactoryContext().clusterManager().hasCluster(shadow_policy->cluster())) {
          return absl::InvalidArgumentError(
              fmt::format("route override '{}': unknown shadow cluster '{}'", override_id,
                          shadow_policy->cluster()));
        }
      }
    }
    config->route_overrides_.emplace(override_id, std::move(entry_or_error.value()));
  }

  envoy_dynamic_module_type_envoy_buffer name_buf = {.ptr = config->specifier_name_.data(),
                                                     .length = config->specifier_name_.size()};
  envoy_dynamic_module_type_envoy_buffer config_buf = {.ptr = config->specifier_config_.data(),
                                                       .length = config->specifier_config_.size()};
  // Expose the route builder to the module so it can register templates while the configuration is
  // created. It borrows the init manager of the configuration, so it is cleared once the hook
  // returns.
  config->config_new_validate_clusters_ = validate_clusters;
  config->config_new_route_builder_ = route_builder.ptr();
  config->in_module_config_ =
      (*on_config_new.value())(static_cast<void*>(config.get()), name_buf, config_buf);
  config->config_new_route_builder_ = nullptr;
  config->stat_creation_frozen_.store(true, std::memory_order_release);

  if (config->in_module_config_ == nullptr) {
    return absl::InvalidArgumentError("Failed to initialize dynamic module route specifier config");
  }
  return config;
}

namespace {

// A worker sweeps its route cache every quarter of the entry age and evicts an entry idle for more
// sweeps than this, which places the eviction between the entry age and 1.25 times it after the
// last use.
constexpr uint64_t SweepsPerEntryAge = 4;

// What a cached route that is the base itself was built from, since nothing was recorded for it.
const RouteOverrides& emptyRouteOverrides() { CONSTRUCT_ON_FIRST_USE(RouteOverrides); }

} // namespace

BuiltRouteCache::BuiltRouteCache(Event::Dispatcher& dispatcher,
                                 DynamicModuleRouteSpecifierConfigSharedPtr config,
                                 const BuiltRouteCacheSettings& settings)
    : config_(std::move(config)), settings_(settings),
      // The sweep runs only while entries remain, so an empty cache costs a worker no timer.
      sweep_timer_(dispatcher.createTimer([this]() {
        sweep();
        if (!entries_.empty()) {
          sweep_timer_->enableTimer(settings_.sweep_interval);
        }
      })) {}

BuiltRouteCache::~BuiltRouteCache() { config_->stats().route_cache_entries_.sub(entries_.size()); }

const BuiltRouteCache::Entry* BuiltRouteCache::lookup(uint64_t key,
                                                      const Envoy::Router::Route* base) {
  const auto it = index_.find(Key{key, base});
  if (it == index_.end()) {
    config_->stats().route_cache_miss_.inc();
    return nullptr;
  }
  Entry& entry = entries_[it->second];
  entry.referenced = true;
  entry.last_used_tick = tick_;
  config_->stats().route_cache_hit_.inc();
  return &entry;
}

void BuiltRouteCache::insert(uint64_t key, Envoy::Router::RouteConstSharedPtr base,
                             Envoy::Router::RouteConstSharedPtr route,
                             const RouteOverrides* recorded, std::optional<uint64_t> user_data) {
  const Key cache_key{key, base.get()};
  // Unreachable, since the lookup that missed and the insert it leads to run within one decision
  // and nothing inserts in between. The guard keeps the index and the entries consistent, which the
  // bounds of every later access depend on, should that ever change.
  if (index_.contains(cache_key)) {
    return;
  }
  // A new entry starts referenced, so CLOCK gives it a full turn of the hand before it can go.
  Entry entry{key, std::move(base), std::move(route), recorded, user_data, tick_, true};
  if (entries_.size() < settings_.max_entries_per_worker) {
    index_.emplace(cache_key, entries_.size());
    entries_.push_back(std::move(entry));
    config_->stats().route_cache_entries_.inc();
    if (!sweep_timer_->enabled()) {
      sweep_timer_->enableTimer(settings_.sweep_interval);
    }
    return;
  }
  const size_t victim = clockVictim();
  index_.erase(keyOf(entries_[victim]));
  // Replacing the entry releases the evicted route, which fires its destroy hook once no stream
  // holds it anymore.
  entries_[victim] = std::move(entry);
  index_.emplace(cache_key, victim);
  config_->stats().route_cache_evict_.inc();
}

void BuiltRouteCache::erase(uint64_t key, const Envoy::Router::Route* base) {
  const auto it = index_.find(Key{key, base});
  if (it != index_.end()) {
    removeAt(it->second);
  }
}

bool BuiltRouteCache::sampleVerification() {
  if (settings_.verify_one_in == 0) {
    return false;
  }
  if (++hits_since_verification_ < settings_.verify_one_in) {
    return false;
  }
  hits_since_verification_ = 0;
  return true;
}

size_t BuiltRouteCache::clockVictim() {
  ASSERT(!entries_.empty());
  // The first turn of the hand clears every reference bit it passes, so the second turn finds an
  // entry whose bit is clear.
  for (size_t step = 0; step < 2 * entries_.size(); ++step) {
    const size_t current = hand_;
    hand_ = (hand_ + 1) % entries_.size();
    if (!entries_[current].referenced) {
      return current;
    }
    entries_[current].referenced = false;
  }
  IS_ENVOY_BUG("route cache CLOCK found no entry to evict");
  return hand_;
}

void BuiltRouteCache::sweep() {
  ++tick_;
  // Walking down lets removeAt move the last entry into the removed slot, which was already
  // visited.
  for (size_t i = entries_.size(); i > 0; --i) {
    if (tick_ - entries_[i - 1].last_used_tick > SweepsPerEntryAge) {
      removeAt(i - 1);
      config_->stats().route_cache_evict_.inc();
    }
  }
}

void BuiltRouteCache::removeAt(size_t index) {
  index_.erase(keyOf(entries_[index]));
  const size_t last = entries_.size() - 1;
  if (index != last) {
    entries_[index] = std::move(entries_[last]);
    index_[keyOf(entries_[index])] = index;
  }
  entries_.pop_back();
  config_->stats().route_cache_entries_.dec();
  if (hand_ >= entries_.size()) {
    hand_ = 0;
  }
}

DynamicModuleRoute::DynamicModuleRoute(
    Envoy::Router::RouteConstSharedPtr route, DynamicModuleRouteSpecifierConfigSharedPtr config,
    RouteOverrides&& overrides,
    Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack,
    std::optional<uint64_t> user_data)
    : Envoy::Router::DelegatingRoute(std::move(route)), config_(std::move(config)),
      overrides_(std::move(overrides)), metadata_pack_(std::move(metadata_pack)),
      user_data_(user_data) {}

DynamicModuleRoute::~DynamicModuleRoute() {
  if (user_data_.has_value() && config_->onRouteDestroy() != nullptr) {
    config_->stats().route_destroy_.inc();
    config_->onRouteDestroy()(config_->in_module_config_, *user_data_);
  }
}

const std::string& DynamicModuleRoute::routeName() const {
  return overrides_.route_name.has_value() ? *overrides_.route_name
                                           : Envoy::Router::DelegatingRoute::routeName();
}

const envoy::config::core::v3::Metadata& DynamicModuleRoute::metadata() const {
  return metadata_pack_ != nullptr ? metadata_pack_->proto_metadata_
                                   : Envoy::Router::DelegatingRoute::metadata();
}

const Envoy::Config::TypedMetadata& DynamicModuleRoute::typedMetadata() const {
  return metadata_pack_ != nullptr ? metadata_pack_->typed_metadata_
                                   : Envoy::Router::DelegatingRoute::typedMetadata();
}

std::optional<bool> DynamicModuleRoute::filterDisabled(absl::string_view name) const {
  const auto it = overrides_.filter_disabled.find(name);
  return it != overrides_.filter_disabled.end()
             ? std::optional<bool>(it->second)
             : Envoy::Router::DelegatingRoute::filterDisabled(name);
}

const Envoy::Router::RouteTracing* DynamicModuleRoute::tracingConfig() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->tracing != nullptr
             ? entry->tracing.get()
             : Envoy::Router::DelegatingRoute::tracingConfig();
}

DynamicModuleRouteEntry::DynamicModuleRouteEntry(
    Envoy::Router::RouteConstSharedPtr route, DynamicModuleRouteSpecifierConfigSharedPtr config,
    RouteOverrides&& overrides,
    Envoy::Config::MetadataPackPtr<Envoy::Router::HttpRouteTypedMetadataFactory> metadata_pack,
    std::optional<uint64_t> user_data)
    : DelegatingRouteEntry(std::move(route)), config_(std::move(config)),
      overrides_(std::move(overrides)), metadata_pack_(std::move(metadata_pack)),
      user_data_(user_data) {}

DynamicModuleRouteEntry::~DynamicModuleRouteEntry() {
  if (user_data_.has_value() && config_->onRouteDestroy() != nullptr) {
    config_->stats().route_destroy_.inc();
    config_->onRouteDestroy()(config_->in_module_config_, *user_data_);
  }
}

const std::string& DynamicModuleRouteEntry::routeName() const {
  return overrides_.route_name.has_value() ? *overrides_.route_name
                                           : DelegatingRouteEntry::routeName();
}

const envoy::config::core::v3::Metadata& DynamicModuleRouteEntry::metadata() const {
  return metadata_pack_ != nullptr ? metadata_pack_->proto_metadata_
                                   : DelegatingRouteEntry::metadata();
}

const Envoy::Config::TypedMetadata& DynamicModuleRouteEntry::typedMetadata() const {
  return metadata_pack_ != nullptr ? metadata_pack_->typed_metadata_
                                   : DelegatingRouteEntry::typedMetadata();
}

std::optional<bool> DynamicModuleRouteEntry::filterDisabled(absl::string_view name) const {
  const auto it = overrides_.filter_disabled.find(name);
  return it != overrides_.filter_disabled.end() ? std::optional<bool>(it->second)
                                                : DelegatingRouteEntry::filterDisabled(name);
}

const Envoy::Router::RouteTracing* DynamicModuleRouteEntry::tracingConfig() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->tracing != nullptr ? entry->tracing.get()
                                                       : DelegatingRouteEntry::tracingConfig();
}

const std::string& DynamicModuleRouteEntry::clusterName() const {
  return overrides_.cluster_name.empty() ? DelegatingRouteEntry::clusterName()
                                         : overrides_.cluster_name;
}

std::chrono::milliseconds DynamicModuleRouteEntry::timeout() const {
  return overrides_.timeout.value_or(DelegatingRouteEntry::timeout());
}

std::optional<std::chrono::milliseconds> DynamicModuleRouteEntry::idleTimeout() const {
  return overrides_.idle_timeout.has_value() ? overrides_.idle_timeout
                                             : DelegatingRouteEntry::idleTimeout();
}

std::optional<std::chrono::milliseconds> DynamicModuleRouteEntry::maxStreamDuration() const {
  return overrides_.max_stream_duration.has_value() ? overrides_.max_stream_duration
                                                    : DelegatingRouteEntry::maxStreamDuration();
}

bool DynamicModuleRouteEntry::usingNewTimeouts() const {
  return overrides_.max_stream_duration.has_value() || DelegatingRouteEntry::usingNewTimeouts();
}

uint64_t DynamicModuleRouteEntry::requestBodyBufferLimit() const {
  return overrides_.request_body_buffer_limit.value_or(
      DelegatingRouteEntry::requestBodyBufferLimit());
}

Upstream::ResourcePriority DynamicModuleRouteEntry::priority() const {
  return overrides_.priority.value_or(DelegatingRouteEntry::priority());
}

Http::Code DynamicModuleRouteEntry::clusterNotFoundResponseCode() const {
  return overrides_.cluster_not_found_response_code.value_or(
      DelegatingRouteEntry::clusterNotFoundResponseCode());
}

const Envoy::Router::RetryPolicyConstSharedPtr& DynamicModuleRouteEntry::retryPolicy() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->retry_policy != nullptr ? entry->retry_policy
                                                            : DelegatingRouteEntry::retryPolicy();
}

const Envoy::Router::MetadataMatchCriteria* DynamicModuleRouteEntry::metadataMatchCriteria() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->metadata_match_criteria != nullptr
             ? entry->metadata_match_criteria.get()
             : DelegatingRouteEntry::metadataMatchCriteria();
}

const std::vector<Envoy::Router::ShadowPolicyPtr>& DynamicModuleRouteEntry::shadowPolicies() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && !entry->shadow_policies.empty()
             ? entry->shadow_policies
             : DelegatingRouteEntry::shadowPolicies();
}

const Http::HashPolicy* DynamicModuleRouteEntry::hashPolicy() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->hash_policy != nullptr ? entry->hash_policy.get()
                                                           : DelegatingRouteEntry::hashPolicy();
}

const Envoy::Router::HedgePolicy& DynamicModuleRouteEntry::hedgePolicy() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->hedge_policy != nullptr ? *entry->hedge_policy
                                                            : DelegatingRouteEntry::hedgePolicy();
}

const Envoy::Router::RateLimitPolicy& DynamicModuleRouteEntry::rateLimitPolicy() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->rate_limit_policy != nullptr
             ? *entry->rate_limit_policy
             : DelegatingRouteEntry::rateLimitPolicy();
}

const Envoy::Router::CorsPolicy* DynamicModuleRouteEntry::corsPolicy() const {
  const RouteOverride* entry = overrides_.route_override;
  return entry != nullptr && entry->cors_policy != nullptr ? entry->cors_policy.get()
                                                           : DelegatingRouteEntry::corsPolicy();
}

bool DynamicModuleRouteEntry::hasFinalizationRewrite() const {
  return overrides_.prefix_rewrite_rule.has_value() ||
         (overrides_.route_override != nullptr &&
          overrides_.route_override->regex_rewrite != nullptr);
}

std::optional<std::string>
DynamicModuleRouteEntry::finalizationRewrite(absl::string_view path) const {
  if (overrides_.prefix_rewrite_rule.has_value()) {
    return overrides_.prefix_rewrite_rule->apply(path, config_->maxRewrittenPathBytes());
  }
  const RouteOverride* entry = overrides_.route_override;
  if (entry != nullptr && entry->regex_rewrite != nullptr) {
    return Envoy::Router::rewritePathByPrefixOrRegex(path, "", "", entry->regex_rewrite.get(),
                                                     entry->regex_rewrite_substitution,
                                                     config_->maxRewrittenPathBytes());
  }
  return std::nullopt;
}

std::string DynamicModuleRouteEntry::currentUrlPathAfterRewrite(
    const Http::RequestHeaderMap& headers, const Formatter::Context& context,
    const StreamInfo::StreamInfo& stream_info) const {
  if (overrides_.path.has_value()) {
    return *overrides_.path;
  }
  // A recorded rule owns the rewrite, so a rule that does not apply leaves the path unchanged,
  // which the empty result reports the same way a configured route without a rewrite reports it.
  if (overrides_.prefix_rewrite_rule.has_value()) {
    return overrides_.prefix_rewrite_rule
        ->apply(headers.getPathValue(), config_->maxRewrittenPathBytes())
        .value_or(std::string{});
  }
  // A route override regex rewrite that yields nothing leaves the rewrite of the route in effect,
  // which is what finalizeRequestHeaders applies too.
  std::optional<std::string> rewritten = finalizationRewrite(headers.getPathValue());
  return rewritten.has_value()
             ? std::move(*rewritten)
             : DelegatingRouteEntry::currentUrlPathAfterRewrite(headers, context, stream_info);
}

void DynamicModuleRouteEntry::finalizeRequestHeaders(Http::RequestHeaderMap& headers,
                                                     const Formatter::Context& context,
                                                     const StreamInfo::StreamInfo& stream_info,
                                                     bool insert_envoy_original_path) const {
  // A finalization rewrite rewrites the path the request carries when it is finalized, the same
  // path a configured route rewrites, so it is computed before the route below finalizes the
  // headers and possibly rewrites the path itself. A recorded path takes precedence over it.
  //
  // A recorded rule owns the rewrite, so when it does not apply the path the route below rewrote is
  // restored and the path is left unchanged. The route records x-envoy-original-path only when its
  // own rewrite applies and the original path is kept, and then last and as the original path, so
  // only then is the value it overwrote restored, and a value the route's header mutations set is
  // otherwise kept, as on a configured route that does not rewrite. The restore runs before the
  // header mutations of the module, so a header the module records is kept the same way.
  const bool rule_owns_path =
      !overrides_.path.has_value() && overrides_.prefix_rewrite_rule.has_value();
  std::optional<std::string> rewritten;
  std::string original_path;
  bool route_rewrite_predicted = false;
  std::optional<std::string> original_envoy_original_path;
  if (!overrides_.path.has_value() && hasFinalizationRewrite()) {
    rewritten = finalizationRewrite(headers.getPathValue());
    if (!rewritten.has_value()) {
      // A rule that does not apply leaves the path unchanged, as a configured route whose rewrite
      // yields nothing does, and a route override regex rewrite that yields nothing leaves the
      // rewrite of the route in effect.
      config_->stats().rewrite_not_applied_.inc();
    }
    if (rewritten.has_value() ? insert_envoy_original_path : rule_owns_path) {
      original_path = std::string(headers.getPathValue());
    }
    if (!rewritten.has_value() && rule_owns_path && insert_envoy_original_path) {
      // Whether the route below rewrites, predicted before its header mutations run. A rewrite that
      // reads a header those mutations add is seen after the fact, by the path it moved. This runs
      // only when a recorded rule does not apply.
      route_rewrite_predicted =
          !DelegatingRouteEntry::currentUrlPathAfterRewrite(headers, context, stream_info).empty();
      if (headers.EnvoyOriginalPath() != nullptr) {
        original_envoy_original_path = std::string(headers.getEnvoyOriginalPathValue());
      }
    }
  }
  DelegatingRouteEntry::finalizeRequestHeaders(headers, context, stream_info,
                                               insert_envoy_original_path);
  if (rule_owns_path && !rewritten.has_value()) {
    const bool route_wrote_original_path =
        insert_envoy_original_path &&
        (route_rewrite_predicted || headers.getPathValue() != original_path) &&
        headers.getEnvoyOriginalPathValue() == original_path;
    headers.setPath(original_path);
    if (route_wrote_original_path) {
      if (original_envoy_original_path.has_value()) {
        headers.setEnvoyOriginalPath(*original_envoy_original_path);
      } else {
        headers.removeEnvoyOriginalPath();
      }
    }
  }
  applyHeaderMutations(headers, overrides_.request_headers_to_add,
                       overrides_.request_headers_to_remove);
  if (overrides_.host.has_value()) {
    Http::Utility::updateAuthority(headers, *overrides_.host, appendXfh(),
                                   insert_envoy_original_path);
  }
  if (overrides_.path.has_value()) {
    // The route records the original path when it rewrites the path itself, so only record it here
    // when it did not.
    if (insert_envoy_original_path && headers.EnvoyOriginalPath() == nullptr) {
      headers.setEnvoyOriginalPath(headers.getPathValue());
    }
    headers.setPath(*overrides_.path);
  } else if (rewritten.has_value()) {
    // The original path is recorded the way finalizePathHeader of a configured route records it.
    if (insert_envoy_original_path) {
      headers.setEnvoyOriginalPath(original_path);
    }
    headers.setPath(*rewritten);
  }
}

Http::HeaderTransforms
DynamicModuleRouteEntry::requestHeaderTransforms(const StreamInfo::StreamInfo& stream_info,
                                                 bool do_formatting) const {
  Http::HeaderTransforms transforms =
      DelegatingRouteEntry::requestHeaderTransforms(stream_info, do_formatting);
  appendHeaderTransforms(transforms, overrides_.request_headers_to_add,
                         overrides_.request_headers_to_remove);
  return transforms;
}

void DynamicModuleRouteEntry::finalizeResponseHeaders(
    Http::ResponseHeaderMap& headers, const Formatter::Context& context,
    const StreamInfo::StreamInfo& stream_info) const {
  DelegatingRouteEntry::finalizeResponseHeaders(headers, context, stream_info);
  applyHeaderMutations(headers, overrides_.response_headers_to_add,
                       overrides_.response_headers_to_remove);
}

Http::HeaderTransforms
DynamicModuleRouteEntry::responseHeaderTransforms(const StreamInfo::StreamInfo& stream_info,
                                                  bool do_formatting) const {
  Http::HeaderTransforms transforms =
      DelegatingRouteEntry::responseHeaderTransforms(stream_info, do_formatting);
  appendHeaderTransforms(transforms, overrides_.response_headers_to_add,
                         overrides_.response_headers_to_remove);
  return transforms;
}

DynamicModuleRouteSpecifier::DynamicModuleRouteSpecifier(
    DynamicModuleRouteSpecifierConfigSharedPtr config,
    const DynamicModuleRouteSpecifierProto& proto_config, ThreadLocal::SlotAllocator& tls)
    : config_(std::move(config)) {
  if (!proto_config.has_built_route_cache()) {
    return;
  }
  const auto& cache = proto_config.built_route_cache();
  const std::chrono::milliseconds entry_age(
      PROTOBUF_GET_MS_OR_DEFAULT(cache, max_entry_age, 600000));
  const BuiltRouteCacheSettings settings{
      cache.max_entries_per_worker(),
      std::max(
          std::chrono::milliseconds(1),
          std::chrono::milliseconds(entry_age.count() / static_cast<int64_t>(SweepsPerEntryAge))),
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(cache, verify_one_in, 1024)};
  built_route_cache_ = ThreadLocal::TypedSlot<BuiltRouteCache>::makeUnique(tls);
  // Each worker's cache holds the configuration, so the configuration outlives the routes it holds
  // and the stats it counts in, while nothing the configuration owns holds the cache.
  built_route_cache_->set([config = config_, settings](Event::Dispatcher& dispatcher) {
    return std::make_shared<BuiltRouteCache>(dispatcher, config, settings);
  });
}

Envoy::Router::OnRouteResult
DynamicModuleRouteSpecifier::onRoute(Envoy::Router::RouteConstSharedPtr route,
                                     const Http::RequestHeaderMap& headers,
                                     const StreamInfo::StreamInfo& stream_info, uint64_t random,
                                     Envoy::Router::OnRouteInputStatus) const {
  const MonotonicTime start = config_->timeSource().monotonicTime();
  const auto record_duration = [&](Stats::Histogram& histogram) {
    histogram.recordValue(std::chrono::duration_cast<std::chrono::microseconds>(
                              config_->timeSource().monotonicTime() - start)
                              .count());
  };

  const auto& runtime_fraction = config_->runtimeFraction();
  if (runtime_fraction.has_value() &&
      !config_->runtime().snapshot().featureEnabled(runtime_fraction->key,
                                                    runtime_fraction->default_value, random)) {
    config_->stats().runtime_skipped_.inc();
    record_duration(config_->stats().specifier_duration_);
    return {std::move(route)};
  }

  RouteSpecifierContext context{*config_, route, headers, stream_info, random};
  if (built_route_cache_ != nullptr && built_route_cache_->currentThreadRegistered()) {
    if (OptRef<BuiltRouteCache> cache = built_route_cache_->get(); cache.has_value()) {
      context.built_route_cache = &cache.ref();
    }
  }
  // The module can return a status this build does not know, for example from a newer ABI, so it
  // is read as its underlying integer. Loading an out of range enum value is undefined behavior.
  const uint32_t on_route_status = static_cast<uint32_t>(
      config_->on_route_(config_->in_module_config_, static_cast<void*>(&context)));
  // Reading the clock is the most expensive thing this method does that is not the module itself,
  // so the start of the specifier doubles as the start of the module. Only the runtime fraction
  // check and the context construction sit between the two, which is why on_route_duration is
  // measured from there rather than read again.
  const MonotonicTime module_end = config_->timeSource().monotonicTime();
  config_->stats().on_route_duration_.recordValue(
      std::chrono::duration_cast<std::chrono::microseconds>(module_end - start).count());

  Decision result = resolve(context, on_route_status);

  record_duration(config_->stats().specifier_duration_);
  return {std::move(result.route), result.status};
}

DynamicModuleRouteSpecifier::Decision
DynamicModuleRouteSpecifier::resolve(RouteSpecifierContext& context,
                                     uint32_t on_route_status) const {
  using Status = Envoy::Router::OnRouteStatus;
  const auto fail = [this, &context](Failure failure) {
    switch (failure) {
    case Failure::ModuleError:
      config_->stats().failure_module_error_.inc();
      break;
    case Failure::TemplateNotSelected:
      config_->stats().failure_template_not_selected_.inc();
      break;
    case Failure::TemplateMatchFailed:
      config_->stats().failure_template_match_failed_.inc();
      break;
    case Failure::OverrideWithoutRoute:
      config_->stats().failure_override_without_route_.inc();
      break;
    case Failure::OverrideOnNonRouteEntry:
      config_->stats().failure_override_on_non_route_entry_.inc();
      break;
    case Failure::RouteMetadata:
      config_->stats().failure_route_metadata_.inc();
      break;
    case Failure::ReusePreviousRejected:
      config_->stats().reuse_previous_rejected_.inc();
      break;
    case Failure::None:
      IS_ENVOY_BUG("route specifier failure without a reason");
      break;
    }
    ENVOY_LOG(debug, "dynamic module route specifier could not honor the decision, reason {}",
              static_cast<int>(failure));
    if (config_->continueMatchingOnFailure()) {
      return Decision{context.input_route, Status::StopIterationAndSkipRoute, failure};
    }
    if (config_->failClosed()) {
      return Decision{nullptr, Status::StopIteration, failure};
    }
    return Decision{context.input_route, Status::Continue, failure};
  };

  Status status;
  switch (on_route_status) {
  case envoy_dynamic_module_type_route_specifier_on_route_status_Continue:
    status = Status::Continue;
    break;
  case envoy_dynamic_module_type_route_specifier_on_route_status_StopIteration:
    status = Status::StopIteration;
    break;
  case envoy_dynamic_module_type_route_specifier_on_route_status_StopIterationAndSkipRoute:
    // The skip turns the route down, so nothing is built for the request: the recorded decision,
    // template and overrides are ignored.
    config_->stats().route_skipped_.inc();
    return {context.input_route, Status::StopIterationAndSkipRoute};
  default:
    // A module built against a newer ABI could return a status this build does not know. This is
    // not a decision the module recorded, so it keeps its own counter.
    config_->stats().unknown_status_.inc();
    return fail(Failure::ModuleError);
  }

  switch (context.decision) {
  case envoy_dynamic_module_type_route_specifier_decision_PassThrough:
    config_->stats().decision_pass_through_.inc();
    return {context.input_route, status};
  case envoy_dynamic_module_type_route_specifier_decision_NoRoute:
    config_->stats().decision_no_route_.inc();
    return {nullptr, status};
  case envoy_dynamic_module_type_route_specifier_decision_Error:
    config_->stats().decision_error_.inc();
    return fail(Failure::ModuleError);
  case envoy_dynamic_module_type_route_specifier_decision_Unspecified: {
    applySelectedRouteOverride(context);
    if (context.selected_template != nullptr) {
      // The two ways the default decision generates its route keep their own statistic, so
      // selecting a template stays distinguishable from refining the resolved route.
      config_->stats().decision_has_template_.inc();
      // set_route_template evaluated the template against the request, so reuse the result rather
      // than matching a second time. A null result means the match did not hold for the request.
      if (context.selected_route == nullptr) {
        return fail(Failure::TemplateMatchFailed);
      }
      if (context.built_route_cache_lookup.has_value() &&
          context.built_route_cache_lookup->cached != nullptr) {
        // A hit produces the cached route and ignores what was recorded after the lookup, apart
        // from the comparison a verified hit makes.
        if (context.built_route_cache_lookup->verify) {
          verifyCachedRoute(context, *context.built_route_cache_lookup);
        }
        return {std::move(context.built_route_cache_lookup->cached), status};
      }
      Decision wrapped = wrap(context.selected_route, context, status);
      if (wrapped.failure != Failure::None) {
        // A route the decision could not produce is never cached.
        return fail(wrapped.failure);
      }
      // A path set_prefix_rewrite computed belongs to the current request, so its route is built
      // for this request alone.
      if (context.built_route_cache_lookup.has_value() &&
          (wrapped.recorded == nullptr || !wrapped.recorded->path_specific_to_request)) {
        context.built_route_cache->insert(context.built_route_cache_lookup->key,
                                          context.selected_route, wrapped.route, wrapped.recorded,
                                          context.user_data);
      }
      return wrapped;
    }
    if (context.template_selection_failed) {
      // A selection that failed must not silently fall back to the route the specifier was
      // given: the module asked for a template the configuration does not declare. A module
      // that wants to probe without committing checks the configuration getters instead.
      return fail(Failure::TemplateNotSelected);
    }
    config_->stats().decision_has_override_.inc();
    if (context.input_route == nullptr) {
      // With nothing recorded the default decision passes the route through unchanged, which is
      // what makes it safe when the module records none: the run with no route stays a run with
      // no route. Anything recorded needs a route to be applied to.
      if (context.overrides.hasRouteEntryOverrides() || context.overrides.hasRouteOverrides() ||
          context.user_data.has_value()) {
        return fail(Failure::OverrideWithoutRoute);
      }
      return {nullptr, status};
    }
    Decision wrapped = wrap(context.input_route, context, status);
    return wrapped.failure == Failure::None ? wrapped : fail(wrapped.failure);
  }
  case envoy_dynamic_module_type_route_specifier_decision_ReusePrevious: {
    config_->stats().decision_reuse_previous_.inc();
    // Reuse the route the connection manager last installed. No new wrapper is allocated, so the
    // destroy hook does not fire again and the previous route keeps its user data until the stream
    // releases it.
    Envoy::Router::RouteConstSharedPtr previous = context.stream_info.routeSharedPtr();
    if (previous == nullptr) {
      return fail(Failure::ReusePreviousRejected);
    }
    return {std::move(previous), status};
  }
  case envoy_dynamic_module_type_route_specifier_decision_Sentinel:
    // Not a decision a module records, handled like any other value this build does not know.
    break;
  }
  // A module built against a newer ABI could record a decision this build does not know.
  config_->stats().decision_error_.inc();
  return fail(Failure::ModuleError);
}

DynamicModuleRouteSpecifier::Decision
DynamicModuleRouteSpecifier::wrap(Envoy::Router::RouteConstSharedPtr route,
                                  RouteSpecifierContext& context,
                                  Envoy::Router::OnRouteStatus status) const {
  const bool route_entry_overrides = context.overrides.hasRouteEntryOverrides();
  // User data forces a wrapper even with no override, so the route destroy hook fires for the
  // produced route.
  if (!route_entry_overrides && !context.overrides.hasRouteOverrides() &&
      !context.user_data.has_value()) {
    return {std::move(route), status};
  }
  if (route_entry_overrides && route->routeEntry() == nullptr) {
    return {nullptr, status, Failure::OverrideOnNonRouteEntry};
  }
  // Build and validate the metadata pack once, before the wrapper is constructed, so a namespace a
  // typed metadata factory rejects becomes a decision failure rather than an exception the wrapper
  // constructor throws.
  auto metadata_pack = buildMetadataPack(*route, context.overrides.route_metadata);
  if (!metadata_pack.ok()) {
    ENVOY_LOG_EVERY_POW_2(warn, "dynamic module route metadata was rejected: {}",
                          metadata_pack.status().message());
    return {nullptr, status, Failure::RouteMetadata};
  }
  Decision decision{nullptr, status};
  if (route_entry_overrides) {
    auto entry = std::make_shared<DynamicModuleRouteEntry>(
        std::move(route), config_, std::move(context.overrides), std::move(metadata_pack.value()),
        context.user_data);
    decision.recorded = &entry->recordedOverrides();
    decision.route = std::move(entry);
  } else {
    auto wrapper = std::make_shared<DynamicModuleRoute>(
        std::move(route), config_, std::move(context.overrides), std::move(metadata_pack.value()),
        context.user_data);
    decision.recorded = &wrapper->recordedOverrides();
    decision.route = std::move(wrapper);
  }
  // The wrapper fires the destroy hook when it is destroyed, so counting it here balances against
  // route_destroy once every route is released.
  if (context.user_data.has_value() && config_->onRouteDestroy() != nullptr) {
    config_->stats().route_build_.inc();
  }
  return decision;
}

void DynamicModuleRouteSpecifier::verifyCachedRoute(const RouteSpecifierContext& context,
                                                    const BuiltRouteCacheLookup& lookup) const {
  config_->stats().route_cache_verify_.inc();
  const RouteOverrides& cached =
      lookup.recorded != nullptr ? *lookup.recorded : emptyRouteOverrides();
  if (context.overrides == cached && context.user_data == lookup.user_data) {
    return;
  }
  config_->stats().route_cache_verify_mismatch_.inc();
  // The key does not identify what the module builds, so the entry goes and the next request
  // builds the route again. This request still gets the cached route, since nothing is built for
  // a verified hit.
  context.built_route_cache->erase(lookup.key, context.selected_route.get());
  ENVOY_LOG_EVERY_POW_2(warn,
                        "dynamic module route specifier cached route for key {} differs from the "
                        "route the module records for it",
                        lookup.key);
}

} // namespace DynamicModules
} // namespace RouteSpecifiers
} // namespace Extensions
} // namespace Envoy
