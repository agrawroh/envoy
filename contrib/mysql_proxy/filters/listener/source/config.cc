#include "envoy/extensions/filters/listener/mysql_inspector/v3/mysql_inspector.pb.h"
#include "envoy/extensions/filters/listener/mysql_inspector/v3/mysql_inspector.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "contrib/mysql_proxy/filters/listener/source/mysql_inspector.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace MySQLInspector {

/**
 * Config registration for the MySQL inspector filter. @see NamedNetworkFilterConfigFactory.
 */
class MySqlInspectorConfigFactory : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message&,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override {
    MySQLInspector::ConfigSharedPtr config(std::make_shared<MySQLInspector::Config>(context.scope()));
    return
        [listener_filter_matcher, config](Network::ListenerFilterManager& filter_manager) -> void {
          filter_manager.addAcceptFilter(listener_filter_matcher, std::make_unique<MySQLInspector::Filter>(config));
        };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::listener::mysql_inspector::v3::MySQLInspector>();
  }

  std::string name() const override { return "envoy.filters.listener.mysql_inspector"; }
};

/**
 * Static registration for the MySQL inspector filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MySqlInspectorConfigFactory, Server::Configuration::NamedListenerFilterConfigFactory){"envoy.listener.mysql_inspector"};

} // namespace MySQLInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
