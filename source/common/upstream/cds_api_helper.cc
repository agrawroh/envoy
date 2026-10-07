#include "source/common/upstream/cds_api_helper.h"

#include <deque>

#include "envoy/common/exception.h"
#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/endpoint/v3/endpoint.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/xds_config_tracker.h"

#include "source/common/common/fmt.h"
#include "source/common/config/resource_name.h"
#include "source/common/runtime/runtime_features.h"

#include "absl/container/flat_hash_set.h"

namespace Envoy {
namespace Upstream {

std::pair<uint32_t, std::vector<std::string>>
CdsApiHelper::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& added_resources,
                             const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                             const std::string& system_version_info) {
  // A cluster update pauses sending EDS and LEDS requests.
  const std::vector<std::string> paused_xds_types{
      Config::getTypeUrl<envoy::config::endpoint::v3::ClusterLoadAssignment>(),
      Config::getTypeUrl<envoy::config::endpoint::v3::LbEndpoint>(),
      Config::getTypeUrl<envoy::extensions::transport_sockets::tls::v3::Secret>()};
  Config::ScopedResume resume_eds_leds_sds = xds_manager_.pause(paused_xds_types);

  ENVOY_LOG(
      info,
      "{}: response indicates {} added/updated cluster(s), {} removed cluster(s); applying changes",
      name_, added_resources.size(), removed_resources.size());

  std::vector<std::string> exception_msgs;
  // Backs the failure details handed to the xDS config tracker. A deque is used because it does
  // not invalidate references to the elements it already holds when it grows, so `apply_results`
  // can hold views into it.
  std::deque<std::string> failure_details;
  std::vector<Config::ResourceApplyResult> apply_results;
  apply_results.reserve(added_resources.size() + removed_resources.size());
  absl::flat_hash_set<std::string> cluster_names(added_resources.size());
  bool any_applied = false;
  uint32_t added_or_updated = 0;
  uint32_t skipped = 0;

  // Records a cluster that could not be applied, both in the aggregate list of errors returned to
  // the caller and in the per-resource outcomes reported to the xDS config tracker.
  const auto on_error = [&](absl::string_view cluster_name, absl::string_view version,
                            std::string details) {
    ENVOY_LOG(warn, "cds: cluster '{}' config rejected: {}", cluster_name, details);
    failure_details.push_back(std::move(details));
    exception_msgs.push_back(fmt::format("{}: {}", cluster_name, failure_details.back()));
    apply_results.push_back({.name = cluster_name,
                             .version = version,
                             .status = Config::ResourceApplyStatus::Failed,
                             .details = failure_details.back()});
  };

  for (const auto& resource : added_resources) {
    // Holds a reference to the name of the currently parsed cluster resource.
    // This is needed for the CATCH clause below.
    absl::string_view cluster_name = EMPTY_STRING;
    const std::string& version = resource.get().version();
    TRY_ASSERT_MAIN_THREAD {
      const envoy::config::cluster::v3::Cluster& cluster =
          Envoy::Protobuf::DynamicCastMessage<envoy::config::cluster::v3::Cluster>(
              resource.get().resource());
      cluster_name = cluster.name();
      if (!cluster_names.insert(cluster.name()).second) {
        // NOTE: at this point, the first of these duplicates has already been successfully applied.
        on_error(cluster_name, version, fmt::format("duplicate cluster {} found", cluster_name));
        continue;
      }
      auto update_or_error = cm_.addOrUpdateCluster(cluster, version);
      if (!update_or_error.status().ok()) {
        on_error(cluster_name, version, std::string(update_or_error.status().message()));
        continue;
      }
      if (*update_or_error) {
        any_applied = true;
        ENVOY_LOG(debug, "{}: add/update cluster '{}'", name_, cluster_name);
        ++added_or_updated;
        apply_results.push_back({.name = cluster_name,
                                 .version = version,
                                 .status = Config::ResourceApplyStatus::Applied});
      } else {
        ENVOY_LOG(debug, "{}: add/update cluster '{}' skipped", name_, cluster_name);
        ++skipped;
        apply_results.push_back({.name = cluster_name,
                                 .version = version,
                                 .status = Config::ResourceApplyStatus::Skipped});
      }
    }
    END_TRY
    CATCH(const EnvoyException& e, { on_error(cluster_name, version, e.what()); });
  }

  uint32_t removed = 0;
  for (const auto& resource_name : removed_resources) {
    if (cm_.removeCluster(resource_name)) {
      any_applied = true;
      ENVOY_LOG(debug, "{}: remove cluster '{}'", name_, resource_name);
      ++removed;
      apply_results.push_back(
          {.name = resource_name, .status = Config::ResourceApplyStatus::Removed});
    }
  }

  ENVOY_LOG(
      info,
      "{}: added/updated {} cluster(s) (skipped {} unmodified cluster(s)); removed {} cluster(s)",
      name_, added_or_updated, skipped, removed);

  if (Config::XdsConfigTrackerOptRef xds_config_tracker = xds_manager_.xdsConfigTracker();
      !apply_results.empty() && xds_config_tracker.has_value()) {
    xds_config_tracker->onResourcesApplied(
        Config::getTypeUrl<envoy::config::cluster::v3::Cluster>(), apply_results);
  }

  if (any_applied) {
    system_version_info_ = system_version_info;
  }
  return std::pair{added_or_updated, exception_msgs};
}

} // namespace Upstream
} // namespace Envoy
