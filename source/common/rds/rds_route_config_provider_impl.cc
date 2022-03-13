#include "source/common/rds/rds_route_config_provider_impl.h"

#include "source/common/rds/util.h"

namespace Envoy {
namespace Rds {

RdsRouteConfigProviderImpl::RdsRouteConfigProviderImpl(
    const Protobuf::Message& initial_route_config, Rds::ConfigTraits& config_traits,
    RdsRouteConfigSubscriptionSharedPtr&& subscription,
    Server::Configuration::ServerFactoryContext& factory_context,
    Rds::RouteConfigProviderManager& route_config_provider_manager)
    : subscription_(std::move(subscription)),
      config_update_info_(subscription_->routeConfigUpdate()), tls_(factory_context.threadLocal()) {

  auto route_config_proto =
      cloneProto(route_config_provider_manager.protoTraits(), initial_route_config);
  auto initial_config = config_traits.createConfig(
      *route_config_proto); // config_update_info_->parsedConfiguration();
  ASSERT(initial_config);
  tls_.set([initial_config](Event::Dispatcher&) {
    return std::make_shared<ThreadLocalConfig>(initial_config);
  });
  // It should be 1:1 mapping due to shared rds config.
  ASSERT(!subscription_->routeConfigProvider().has_value());
  subscription_->routeConfigProvider().emplace(this);
}

RdsRouteConfigProviderImpl::~RdsRouteConfigProviderImpl() {
  ASSERT(subscription_->routeConfigProvider().has_value());
  subscription_->routeConfigProvider().reset();
}

const absl::optional<RouteConfigProvider::ConfigInfo>&
RdsRouteConfigProviderImpl::configInfo() const {
  return config_update_info_->configInfo();
}

void RdsRouteConfigProviderImpl::onConfigUpdate() {
  tls_.runOnAllThreads([new_config = config_update_info_->parsedConfiguration()](
                           OptRef<ThreadLocalConfig> tls) { tls->config_ = new_config; });
}

} // namespace Rds
} // namespace Envoy
