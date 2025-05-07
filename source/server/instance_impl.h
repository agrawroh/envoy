#pragma once

#include "source/common/memory/heap_shrinker.h"
#include "source/server/server.h"

namespace Envoy {
namespace Server {

// The production server instance, which creates all the required components.
class InstanceImpl : public Instance, public Logger::Loggable<Logger::Id::main> {
public:
  InstanceImpl(const Options& options, Network::Address::InstanceConstSharedPtr local_address,
               ComponentFactory& component_factory, Stats::StoreRoot& store,
               ThreadLocal::Instance& tls, Thread::ThreadFactory& thread_factory,
               Filesystem::Instance& file_system, Random::RandomGenerator& random_generator,
               const envoy::config::bootstrap::v3::Bootstrap& bootstrap,
               const envoy::config::core::v3::Node& node, AccessLog::AccessLogManager& log_manager,
               ServerLifecycleNotifier& lifecycle_notifier,
               ProtobufMessage::ValidationContext& validation_context, Api::Api& api,
               Http::Context& http_context, Grpc::Context& grpc_context,
               Router::Context& router_context, ProcessContextOptRef process_context,
               Ssl::ContextManager& ssl_context_manager);

  // Static method to get the current instance that is in progress of being initialized.
  // Used by components that need to access the bootstrap config during initialization.
  // This is primarily used by the CEL evaluator to enable string extension functions.
  // Note: this is overridden in tests.
  static InstanceImpl* getInProgressUnsafe();

  // Instance
  void run() override;
  OptRef<Admin> admin() override;
  Api::Api& api() override;
  Upstream::ClusterManager& clusterManager() override;
  const Upstream::ClusterManager& clusterManager() const override;
  Http::HttpServerPropertiesCacheManager& httpServerPropertiesCacheManager() override;
  Ssl::ContextManager& sslContextManager() override;
  Event::Dispatcher& dispatcher() override;
  Network::DnsResolverSharedPtr dnsResolver() override;
  void drainListeners(
      OptRef<const Network::ExtraShutdownListenerOptions> options = absl::nullopt) override;
  DrainManager& drainManager() override;
  AccessLog::AccessLogManager& accessLogManager() override;
  void failHealthcheck(bool fail) override;
  bool healthCheckFailed() override;
  HotRestart& hotRestart() override;
  Init::Manager& initManager() override;
  ListenerManager& listenerManager() override;
  Envoy::MutexTracer* mutexTracer() override;
  OverloadManager& overloadManager() override;
  OverloadManager& nullOverloadManager() override;
  Secret::SecretManager& secretManager() override;
  const Options& options() override;
  Runtime::Loader& runtime() override;
  ServerLifecycleNotifier& lifecycleNotifier() override;
  void shutdown() override;
  bool isShutdown() override;
  void shutdownAdmin() override;
  Singleton::Manager& singletonManager() override;
  time_t startTimeCurrentEpoch() override;
  time_t startTimeFirstEpoch() override;
  Stats::Store& stats() override;
  Grpc::Context& grpcContext() override;
  Http::Context& httpContext() override;
  Router::Context& routerContext() override;
  ProcessContextOptRef processContext() override;
  ThreadLocal::Instance& threadLocal() override;
  LocalInfo::LocalInfo& localInfo() const override;
  TimeSource& timeSource() override;
  void flushStats() override;
  ProtobufMessage::ValidationContext& messageValidationContext() override;
  ProtobufMessage::ValidationVisitor& messageValidationVisitor() override;
  Configuration::StatsConfig& statsConfig() override;
  Regex::Engine& regexEngine() override;
  envoy::config::bootstrap::v3::Bootstrap& bootstrap() override;
  Configuration::ServerFactoryContext& serverFactoryContext() override;
  Configuration::TransportSocketFactoryContext& transportSocketFactoryContext() override;
  void setDefaultTracingConfig(const envoy::config::trace::v3::Tracing& tracing_config) override;
  bool enableReusePortDefault() override;
  void setSinkPredicates(std::unique_ptr<Envoy::Stats::SinkPredicates>&& sink_predicates) override;
  Config::XdsManager& xdsManager() override;

  // Helper methods
  void maybeCreateHeapShrinker();
  absl::StatusOr<std::unique_ptr<OverloadManager>> createOverloadManager();
  std::unique_ptr<OverloadManager> createNullOverloadManager();
  std::unique_ptr<Server::GuardDog> maybeCreateGuardDog(absl::string_view name);
  void initialize(const Options& options, ComponentFactory& component_factory,
                  const envoy::config::bootstrap::v3::Bootstrap& bootstrap,
                  Ssl::ContextManager& ssl_context_manager);

private:
  std::unique_ptr<Memory::HeapShrinker> heap_shrinker_;

  // Member variables referenced in the constructor initialization list
  const Options& options_;
  Api::Api& api_;
  Http::Context& http_context_;
  Grpc::Context& grpc_context_;
  Router::Context& router_context_;
  ProcessContextOptRef process_context_;
  ProtobufMessage::ValidationContext& validation_context_;
  LocalInfo::LocalInfo local_info_;
  AccessLog::AccessLogManager& access_log_manager_;
  ServerLifecycleNotifier& lifecycle_notifier_;
  ThreadLocal::Instance& thread_local_;
  Filesystem::Instance& file_system_;
  Random::RandomGenerator& random_generator_;
  const envoy::config::bootstrap::v3::Bootstrap& bootstrap_;
  Stats::StoreRoot& stats_;
  Ssl::ContextManager& ssl_context_manager_;
  std::unique_ptr<Singleton::Manager> singleton_manager_;
  Thread::ThreadFactory& thread_factory_;
};

} // namespace Server
} // namespace Envoy
