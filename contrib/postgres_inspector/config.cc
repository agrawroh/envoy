#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/common/protobuf/utility.h"

#include "contrib/envoy/extensions/filters/listener/postgres_inspector/v3alpha/postgres_inspector.pb.h"
#include "contrib/envoy/extensions/filters/listener/postgres_inspector/v3alpha/postgres_inspector.pb.validate.h"
#include "contrib/postgres_inspector/postgres_inspector.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace PostgresInspector {

/**
 * Config registration for the PostgreSQL inspector filter. @see NamedListenerFilterConfigFactory.
 */
class PostgresInspectorConfigFactory
    : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& message,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override {

    const auto& proto_config =
        MessageUtil::downcastAndValidate<const envoy::extensions::filters::listener::
                                             postgres_inspector::v3alpha::PostgresInspector&>(
            message, context.messageValidationVisitor());

    const std::string stat_prefix =
        proto_config.stat_prefix().empty() ? "postgres_inspector." : proto_config.stat_prefix();

    const size_t max_read_bytes = proto_config.max_read_bytes().value() > 0
                                      ? proto_config.max_read_bytes().value()
                                      : Config::DEFAULT_MAX_READ_BYTES;

    ConfigSharedPtr config = std::make_shared<Config>(context.scope(), stat_prefix, max_read_bytes);

    return
        [listener_filter_matcher, config](Network::ListenerFilterManager& filter_manager) -> void {
          filter_manager.addAcceptFilter(listener_filter_matcher, std::make_unique<Filter>(config));
        };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::filters::listener::postgres_inspector::v3alpha::PostgresInspector>();
  }

  std::string name() const override { return "envoy.filters.listener.postgres_inspector"; }
};

/**
 * Static registration for the PostgreSQL inspector filter. @see RegisterFactory.
 */
REGISTER_FACTORY(PostgresInspectorConfigFactory,
                 Server::Configuration::NamedListenerFilterConfigFactory);

} // namespace PostgresInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
