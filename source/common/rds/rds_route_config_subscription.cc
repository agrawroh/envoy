#include "source/common/rds/rds_route_config_subscription.h"

#include "source/common/common/logger.h"
#include "source/common/rds/util.h"

namespace Envoy {
namespace Rds {

RdsRouteConfigSubscription::RdsRouteConfigSubscription(
    RouteConfigUpdatePtr&& config_update,
    std::unique_ptr<Envoy::Config::OpaqueResourceDecoder>&& resource_decoder,
    const envoy::config::core::v3::ConfigSource& config_source,
    const std::string& route_config_name, bool dry_run, const uint64_t manager_identifier,
    Server::Configuration::ServerFactoryContext& factory_context, const std::string& stat_prefix,
    const std::string& rds_type, RouteConfigProviderManager& route_config_provider_manager)
    : route_config_name_(route_config_name), dry_run_(dry_run),
      scope_(factory_context.scope().createScope(stat_prefix + route_config_name_ + ".")),
      factory_context_(factory_context),
      parent_init_target_(
          fmt::format("RdsRouteConfigSubscription {} init {}", rds_type, route_config_name_),
          [this]() { local_init_manager_.initialize(local_init_watcher_); }),
      local_init_watcher_(fmt::format("{} local-init-watcher {}", rds_type, route_config_name_),
                          [this]() { parent_init_target_.ready(); }),
      local_init_target_(fmt::format("RdsRouteConfigSubscription {} local-init-target {}", rds_type,
                                     route_config_name_),
                         [this]() { subscription_->start({route_config_name_}); }),
      local_init_manager_(fmt::format("{} local-init-manager {}", rds_type, route_config_name_)),
      stat_prefix_(stat_prefix), rds_type_(rds_type),
      stats_({ALL_RDS_STATS(POOL_COUNTER(*scope_), POOL_GAUGE(*scope_))}),
      route_config_provider_manager_(route_config_provider_manager),
      manager_identifier_(manager_identifier), config_update_info_(std::move(config_update)),
      resource_decoder_(std::move(resource_decoder)) {
  const auto resource_type = route_config_provider_manager_.protoTraits().resourceType();
  subscription_ =
      factory_context.clusterManager().subscriptionFactory().subscriptionFromConfigSource(
          config_source, Envoy::Grpc::Common::typeUrl(resource_type), *scope_, *this,
          *resource_decoder_, {});
  local_init_manager_.add(local_init_target_);
}

RdsRouteConfigSubscription::~RdsRouteConfigSubscription() {
  // If we get destroyed during initialization, make sure we signal that we "initialized".
  local_init_target_.ready();

  // The ownership of RdsRouteConfigProviderImpl is shared among all HttpConnectionManagers that
  // hold a shared_ptr to it. The RouteConfigProviderManager holds weak_ptrs to the
  // RdsRouteConfigProviders. Therefore, the map entry for the RdsRouteConfigProvider has to get
  // cleaned by the RdsRouteConfigProvider's destructor.
  route_config_provider_manager_.eraseDynamicProvider(manager_identifier_);
}

absl::optional<RouteConfigProvider*>& RdsRouteConfigSubscription::routeConfigProvider() {
  return route_config_provider_opt_;
}

void RdsRouteConfigSubscription::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  if (!validateUpdateSize(resources.size())) {
    return;
  }
  const auto& route_config = resources[0].get().resource();
  if (route_config.GetDescriptor()->full_name() !=
      route_config_provider_manager_.protoTraits().resourceType()) {
    throw EnvoyException(fmt::format("Unexpected {} configuration type (expecting {}): {}",
                                     rds_type_,
                                     route_config_provider_manager_.protoTraits().resourceType(),
                                     route_config.GetDescriptor()->full_name()));
  }
  if (resourceName(route_config_provider_manager_.protoTraits(), route_config) !=
      route_config_name_) {
    throw EnvoyException(
        fmt::format("Unexpected {} configuration (expecting {}): {}", rds_type_, route_config_name_,
                    resourceName(route_config_provider_manager_.protoTraits(), route_config)));
  }
  // Check whether RDS needs to run in the dry-run mode or now. We only emit stats when we are
  // running in the dry-run mode.
  if (dry_run_) {
    uint64_t old_hash = config_update_info_->configHash();
    uint64_t new_hash = getHash(route_config);
    ENVOY_LOG(
        debug,
        "rds: dry-run mode - loading new configuration: config_name={} old_hash={} new_hash={}",
        route_config_name_, old_hash, new_hash);
    if (old_hash != new_hash) {
      stats_.dry_run_config_mismatch_.inc();
    } else {
      stats_.dry_run_config_match_.inc();
    }
    stats_.dry_run_config_fetch_time_ms_.set(
        DateUtil::nowToMilliseconds(factory_context_.timeSource()));
  } else {
    std::unique_ptr<Init::ManagerImpl> noop_init_manager;
    std::unique_ptr<Cleanup> resume_rds;
    if (config_update_info_->onRdsUpdate(route_config, version_info)) {
      stats_.config_reload_.inc();
      stats_.config_reload_time_ms_.set(DateUtil::nowToMilliseconds(factory_context_.timeSource()));

      beforeProviderUpdate(noop_init_manager, resume_rds);

      ENVOY_LOG(debug, "rds: loading new configuration: config_name={} hash={}", route_config_name_,
                config_update_info_->configHash());

      if (route_config_provider_opt_.has_value()) {
        route_config_provider_opt_.value()->onConfigUpdate();
      }

      afterProviderUpdate();
    }
  }

  local_init_target_.ready();
}

void RdsRouteConfigSubscription::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources, const std::string&) {
  if (!removed_resources.empty()) {
    // TODO(#2500) when on-demand resource loading is supported, an RDS removal may make sense
    // (see discussion in #6879), and so we should do something other than ignoring here.
    ENVOY_LOG(error,
              "Server sent a delta {} update attempting to remove a resource (name: {}). Ignoring.",
              rds_type_, removed_resources[0]);
  }
  if (!added_resources.empty()) {
    onConfigUpdate(added_resources, added_resources[0].get().version());
  }
}

void RdsRouteConfigSubscription::onConfigUpdateFailed(
    Envoy::Config::ConfigUpdateFailureReason reason, const EnvoyException*) {
  ASSERT(Envoy::Config::ConfigUpdateFailureReason::ConnectionFailure != reason);
  // We need to allow server startup to continue, even if we have a bad
  // config.
  local_init_target_.ready();
}

bool RdsRouteConfigSubscription::validateUpdateSize(int num_resources) {
  if (num_resources == 0) {
    ENVOY_LOG(debug, "Missing {} RouteConfiguration for {} in onConfigUpdate()", rds_type_,
              route_config_name_);
    stats_.update_empty_.inc();
    local_init_target_.ready();
    return false;
  }
  if (num_resources != 1) {
    throw EnvoyException(
        fmt::format("Unexpected {} resource length: {}", rds_type_, num_resources));
    // (would be a return false here)
  }
  return true;
}

} // namespace Rds
} // namespace Envoy
