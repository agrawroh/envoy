#include "source/extensions/transport_sockets/ktls/config.h"

#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.h"
#include "envoy/extensions/transport_sockets/ktls/v3/ktls.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/transport_sockets/common/passthrough.h"
#include "source/extensions/transport_sockets/ktls/ktls_transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Ktls {

// Note: We use the DownstreamKtlsTransportSocketFactory defined in ktls_transport_socket.h

// Helper functions to create the inner TLS transport socket factory
// We don't need the createInnerFactory helper functions since we'll implement the logic directly
// in the factory methods

ProtobufTypes::MessagePtr KtlsTransportSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket>();
}

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
KtlsClientTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context) {
  const auto& outer_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
      message, context.messageValidationVisitor());

  auto& inner_config_factory = Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::UpstreamTransportSocketConfigFactory>(
      outer_config.tls_socket_config().name());

  // Create a ProtobufTypes::MessagePtr from the typed_config
  ProtobufTypes::MessagePtr inner_factory_config = Config::Utility::translateAnyToFactoryConfig(
      outer_config.tls_socket_config().typed_config(), context.messageValidationVisitor(),
      inner_config_factory);

  // Create the inner transport socket factory
  auto inner_factory_or =
      inner_config_factory.createTransportSocketFactory(*inner_factory_config, context);
  if (!inner_factory_or.ok()) {
    return inner_factory_or.status();
  }

  // Extract safe sequence threshold configuration with default of 1 for upstream
  uint64_t safe_seq_threshold = 1;
  if (outer_config.has_upstream_safe_seq_threshold()) {
    safe_seq_threshold = outer_config.upstream_safe_seq_threshold().value();
  }

  // Extract new parameters (added in our enhancement)
  bool retry_on_failure = true; // Default value
  if (outer_config.has_retry_on_failure()) {
    retry_on_failure = outer_config.retry_on_failure().value();
  }

  uint32_t max_retry_attempts = 5; // Default value
  if (outer_config.has_max_retry_attempts()) {
    max_retry_attempts = outer_config.max_retry_attempts().value();
  }

  bool try_loading_module = false; // Default value
  if (outer_config.has_try_loading_module()) {
    try_loading_module = outer_config.try_loading_module().value();
  }

  uint32_t error_handling_mode = 1; // Default to balanced approach
  if (outer_config.has_error_handling_mode()) {
    error_handling_mode = outer_config.error_handling_mode().value();
  }

  // Create upstream socket factory with all parameters
  auto factory = std::make_unique<KtlsTransportSocketFactory>(
      std::move(inner_factory_or).value(), outer_config.enable_tx_zerocopy(),
      outer_config.enable_rx_no_pad(), safe_seq_threshold);

  // Configure the additional parameters
  factory->setRetryOnFailure(retry_on_failure);
  factory->setMaxRetryAttempts(max_retry_attempts);
  factory->setTryLoadingModule(try_loading_module);
  factory->setErrorHandlingMode(error_handling_mode);

  return factory;
}

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
KtlsServerTransportSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message& message, Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {
  const auto& outer_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::transport_sockets::ktls::v3::KtlsTransportSocket&>(
      message, context.messageValidationVisitor());

  auto& inner_config_factory = Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::DownstreamTransportSocketConfigFactory>(
      outer_config.tls_socket_config().name());

  // Create a ProtobufTypes::MessagePtr from the typed_config
  ProtobufTypes::MessagePtr inner_factory_config = Config::Utility::translateAnyToFactoryConfig(
      outer_config.tls_socket_config().typed_config(), context.messageValidationVisitor(),
      inner_config_factory);

  // Create the inner transport socket factory with server names for SNI
  auto inner_factory_or = inner_config_factory.createTransportSocketFactory(*inner_factory_config,
                                                                            context, server_names);
  if (!inner_factory_or.ok()) {
    return inner_factory_or.status();
  }

  // Extract safe sequence threshold configuration with default of 5 for downstream
  uint64_t safe_seq_threshold = 5;
  if (outer_config.has_downstream_safe_seq_threshold()) {
    safe_seq_threshold = outer_config.downstream_safe_seq_threshold().value();
  }

  // Extract new parameters (added in our enhancement)
  bool retry_on_failure = true; // Default value
  if (outer_config.has_retry_on_failure()) {
    retry_on_failure = outer_config.retry_on_failure().value();
  }

  uint32_t max_retry_attempts = 5; // Default value
  if (outer_config.has_max_retry_attempts()) {
    max_retry_attempts = outer_config.max_retry_attempts().value();
  }

  bool try_loading_module = false; // Default value
  if (outer_config.has_try_loading_module()) {
    try_loading_module = outer_config.try_loading_module().value();
  }

  uint32_t error_handling_mode = 1; // Default to balanced approach
  if (outer_config.has_error_handling_mode()) {
    error_handling_mode = outer_config.error_handling_mode().value();
  }

  // Create downstream socket factory with all parameters
  auto factory = std::make_unique<DownstreamKtlsTransportSocketFactory>(
      std::move(inner_factory_or).value(), outer_config.enable_tx_zerocopy(),
      outer_config.enable_rx_no_pad(), safe_seq_threshold);

  // Configure the additional parameters
  factory->setRetryOnFailure(retry_on_failure);
  factory->setMaxRetryAttempts(max_retry_attempts);
  factory->setTryLoadingModule(try_loading_module);
  factory->setErrorHandlingMode(error_handling_mode);

  return factory;
}

REGISTER_FACTORY(KtlsClientTransportSocketConfigFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);
REGISTER_FACTORY(KtlsServerTransportSocketConfigFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);

} // namespace Ktls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
