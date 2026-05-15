#include "source/extensions/filters/listener/dynamic_modules/factory.h"

#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"
#include "source/common/runtime/runtime_features.h"
#include "source/extensions/filters/listener/dynamic_modules/filter.h"
#include "source/extensions/filters/listener/dynamic_modules/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

namespace {

// Reconciles the listener-filter ownership contract with `enable_shared_from_this`.
//
// `Network::ListenerFilterManager::addAcceptFilter` accepts a
// `std::unique_ptr<Network::ListenerFilter>`, but `DynamicModuleListenerFilter` derives from
// `std::enable_shared_from_this` and relies on `shared_from_this()` (in `sendHttpCallout`) and
// `weak_from_this()` (in the scheduler ABIs) to safely hand the filter's lifetime out to async
// machinery (HTTP callouts, cross-thread schedulers). Constructing the filter via
// `std::make_unique` would not create a `shared_ptr` control block, so `shared_from_this()` would
// throw `std::bad_weak_ptr` across the Rust `extern "C"` boundary (UB / abort), and
// `weak_from_this()` would return an already-expired weak_ptr (scheduler callbacks silently never
// fire).
//
// This adapter owns a `shared_ptr<DynamicModuleListenerFilter>` and forwards the four
// `Network::ListenerFilter` virtuals to it. The framework still receives a `unique_ptr<>`, but the
// underlying filter is shared-pointer-owned, matching the HTTP and network filter implementations
// (which use APIs that natively accept `shared_ptr`).
// `final` on the class and each override lets the compiler de-virtualize through the adapter,
// keeping the forwarding overhead at a single virtual call into `DynamicModuleListenerFilter`
// (matching the pre-fix dispatch count).
class ListenerFilterSharedAdapter final : public Network::ListenerFilter {
public:
  explicit ListenerFilterSharedAdapter(
      Extensions::DynamicModules::ListenerFilters::DynamicModuleListenerFilterSharedPtr filter)
      : filter_(std::move(filter)) {}

  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) final {
    return filter_->onAccept(cb);
  }
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) final {
    return filter_->onData(buffer);
  }
  void onClose() final { filter_->onClose(); }
  size_t maxReadBytes() const final { return filter_->maxReadBytes(); }

private:
  const Extensions::DynamicModules::ListenerFilters::DynamicModuleListenerFilterSharedPtr filter_;
};

} // namespace

Network::ListenerFilterFactoryCb
DynamicModuleListenerFilterConfigFactory::createListenerFilterFactoryFromProto(
    const Protobuf::Message& message,
    const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
    ListenerFactoryContext& context) {

  const auto& proto_config = MessageUtil::downcastAndValidate<const ListenerFilterConfig&>(
      message, context.messageValidationVisitor());

  const auto& module_config = proto_config.dynamic_module_config();
  auto dynamic_module = Extensions::DynamicModules::newDynamicModuleByName(
      module_config.name(), module_config.do_not_close(), module_config.load_globally());
  if (!dynamic_module.ok()) {
    throw EnvoyException("Failed to load dynamic module: " +
                         std::string(dynamic_module.status().message()));
  }

  std::string filter_config_str;
  if (proto_config.has_filter_config()) {
    auto config_or_error = MessageUtil::knownAnyToBytes(proto_config.filter_config());
    if (!config_or_error.ok()) {
      throw EnvoyException("Failed to parse filter config: " +
                           std::string(config_or_error.status().message()));
    }
    filter_config_str = std::move(config_or_error.value());
  }

  // Use configured metrics namespace or fall back to the default.
  const std::string metrics_namespace =
      module_config.metrics_namespace().empty()
          ? std::string(Extensions::DynamicModules::ListenerFilters::DefaultMetricsNamespace)
          : module_config.metrics_namespace();

  auto filter_config =
      Extensions::DynamicModules::ListenerFilters::newDynamicModuleListenerFilterConfig(
          proto_config.filter_name(), filter_config_str, metrics_namespace,
          std::move(dynamic_module.value()), context.serverFactoryContext().clusterManager(),
          context.listenerScope(), context.serverFactoryContext().mainThreadDispatcher());

  if (!filter_config.ok()) {
    throw EnvoyException("Failed to create filter config: " +
                         std::string(filter_config.status().message()));
  }

  // When the runtime guard is enabled, register the metrics namespace as a custom stat namespace.
  // This causes the namespace prefix to be stripped from prometheus output and no envoy_ prefix
  // is added. This is the legacy behavior for backward compatibility.
  if (Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.dynamic_modules_strip_custom_stat_prefix")) {
    context.serverFactoryContext().api().customStatNamespaces().registerStatNamespace(
        metrics_namespace);
  }

  return [filter_cfg = filter_config.value(),
          listener_filter_matcher](Network::ListenerFilterManager& filter_manager) -> void {
    // Construct via `make_shared` so the filter has a live shared_ptr control block, then wrap in
    // a thin adapter to satisfy the framework's `unique_ptr<ListenerFilter>` API. See
    // `ListenerFilterSharedAdapter` above.
    auto filter =
        std::make_shared<Extensions::DynamicModules::ListenerFilters::DynamicModuleListenerFilter>(
            filter_cfg);
    filter_manager.addAcceptFilter(
        listener_filter_matcher,
        std::make_unique<ListenerFilterSharedAdapter>(std::move(filter)));
  };
}

/**
 * Static registration for the dynamic modules listener filter.
 */
REGISTER_FACTORY(DynamicModuleListenerFilterConfigFactory, NamedListenerFilterConfigFactory);

} // namespace Configuration
} // namespace Server
} // namespace Envoy
