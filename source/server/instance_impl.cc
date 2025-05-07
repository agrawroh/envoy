#include "source/server/instance_impl.h"

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"

#include "source/common/common/utility.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/common/stats/stats_matcher_impl.h"
#include "source/common/thread_local/thread_local_impl.h"
#include "source/extensions/filters/common/expr/cel_options_provider.h"
#include "source/server/configuration_impl.h"
#include "source/server/overload_manager_impl.h"
#include "source/server/server.h"
#include "source/server/worker_impl.h"

namespace Envoy {
namespace Server {

InstanceImpl::InstanceImpl(
    const Options& options, Network::Address::InstanceConstSharedPtr local_address,
    ComponentFactory& component_factory, Stats::StoreRoot& store, ThreadLocal::Instance& tls,
    Thread::ThreadFactory& thread_factory, Filesystem::Instance& file_system,
    Random::RandomGenerator& random_generator,
    const envoy::config::bootstrap::v3::Bootstrap& bootstrap,
    const envoy::config::core::v3::Node& node, AccessLog::AccessLogManager& log_manager,
    ServerLifecycleNotifier& lifecycle_notifier,
    ProtobufMessage::ValidationContext& validation_context, Api::Api& api,
    Http::Context& http_context, Grpc::Context& grpc_context, Router::Context& router_context,
    ProcessContextOptRef process_context, Ssl::ContextManager& ssl_context_manager)
    : options_(options), api_(api), http_context_(http_context), grpc_context_(grpc_context),
      router_context_(router_context), process_context_(process_context),
      validation_context_(validation_context),
      local_info_(node, local_address, options.serviceZone(), options.serviceClusterName(),
                  options.serviceNodeName()),
      access_log_manager_(log_manager), lifecycle_notifier_(lifecycle_notifier), thread_local_(tls),
      file_system_(file_system), random_generator_(random_generator), bootstrap_(bootstrap),
      stats_(store), ssl_context_manager_(ssl_context_manager),
      singleton_manager_(std::make_unique<Singleton::ManagerImpl>(api.threadFactory())),
      thread_factory_(thread_factory) {
  initialize(options, component_factory, bootstrap, ssl_context_manager);
}

// Static method to get the current instance
InstanceImpl* InstanceImpl::getInProgressUnsafe() {
  // This is a placeholder implementation that will need to be updated with
  // proper initialization tracking. For now, returning nullptr is safer
  // than dereferencing an uninitialized pointer.
  return nullptr;
}

void InstanceImpl::initialize(const Options& options, ComponentFactory& component_factory,
                              const envoy::config::bootstrap::v3::Bootstrap& bootstrap,
                              Ssl::ContextManager& ssl_context_manager) {
  if (bootstrap.has_cel_extension_options()) {
    auto& provider =
        singleton_manager_->getTyped<Extensions::Filters::Common::Expr::CelOptionsProvider>(
            Extensions::Filters::Common::Expr::CelOptionsProvider::name, []() {
              return std::make_shared<Extensions::Filters::Common::Expr::CelOptionsProvider>();
            });
    provider.setOptions(bootstrap.cel_extension_options());
  }
}

void InstanceImpl::maybeCreateHeapShrinker() {
  heap_shrinker_ =
      std::make_unique<Memory::HeapShrinker>(dispatcher(), overloadManager(), *stats().rootScope());
}

absl::StatusOr<std::unique_ptr<OverloadManager>> InstanceImpl::createOverloadManager() {
  return OverloadManagerImpl::create(
      dispatcher(), *stats().rootScope(), threadLocal(), bootstrap().overload_manager(),
      messageValidationContext().staticValidationVisitor(), api(), options());
}

std::unique_ptr<OverloadManager> InstanceImpl::createNullOverloadManager() {
  return std::make_unique<NullOverloadManager>(threadLocal(), false);
}

std::unique_ptr<Server::GuardDog> InstanceImpl::maybeCreateGuardDog(absl::string_view name) {
  return std::make_unique<Server::GuardDogImpl>(
      *stats().rootScope(), bootstrap().watchdog().main_thread_watchdog(), api(), name);
}

std::unique_ptr<HdsDelegateApi>
InstanceImpl::maybeCreateHdsDelegate(Configuration::ServerFactoryContext& server_context,
                                     Stats::Scope& scope, Grpc::RawAsyncClientPtr&& async_client,
                                     Envoy::Stats::Store& stats,
                                     Ssl::ContextManager& ssl_context_manager) {
  return std::make_unique<Upstream::HdsDelegate>(server_context, scope, std::move(async_client),
                                                 stats, ssl_context_manager);
}

} // namespace Server
} // namespace Envoy
