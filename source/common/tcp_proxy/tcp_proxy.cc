#include "source/common/tcp_proxy/tcp_proxy.h"

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/config/accesslog/v3/accesslog.pb.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.validate.h"
#include "envoy/extensions/request_id/uuid/v3/uuid.pb.h"
#include "envoy/registry/registry.h"
#include "envoy/stats/scope.h"
#include "envoy/stream_info/bool_accessor.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/upstream.h"

#include "source/common/access_log/access_log_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/fmt.h"
#include "source/common/common/macros.h"
#include "source/common/common/utility.h"
#include "source/common/config/metadata.h"
#include "source/common/config/utility.h"
#include "source/common/config/well_known_names.h"
#include "source/common/formatter/substitution_format_string.h"
#include "source/common/http/request_id_extension_impl.h"
#include "source/common/network/application_protocol.h"
#include "source/common/network/proxy_protocol_filter_state.h"
#include "source/common/network/socket_option_factory.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_socket_options_filter_state.h"
#include "source/common/router/metadatamatchcriteria_impl.h"
#include "source/common/router/shadow_writer_impl.h"
#include "source/common/stream_info/stream_id_provider_impl.h"
#include "source/common/stream_info/uint64_accessor_impl.h"
#include "source/common/tracing/http_tracer_impl.h"
#include "source/server/generic_factory_context.h"

#include "absl/container/flat_hash_set.h"

namespace Envoy {
namespace TcpProxy {

// Type alias for UpstreamConnectMode to simplify usage throughout this file.
using UpstreamConnectMode = envoy::extensions::filters::network::tcp_proxy::v3::UpstreamConnectMode;

const std::string& PerConnectionCluster::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.cluster");
}

class PerConnectionClusterFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override { return PerConnectionCluster::key(); }
  std::unique_ptr<StreamInfo::FilterState::Object>
  createFromBytes(absl::string_view data) const override {
    return std::make_unique<PerConnectionCluster>(data);
  }
};

REGISTER_FACTORY(PerConnectionClusterFactory, StreamInfo::FilterState::ObjectFactory);

class PerConnectionIdleTimeoutMsObjectFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override { return std::string(PerConnectionIdleTimeoutMs); }
  std::unique_ptr<StreamInfo::FilterState::Object>
  createFromBytes(absl::string_view data) const override {
    uint64_t duration_in_milliseconds = 0;
    if (absl::SimpleAtoi(data, &duration_in_milliseconds)) {
      return std::make_unique<StreamInfo::UInt64AccessorImpl>(duration_in_milliseconds);
    }

    return nullptr;
  }
};

REGISTER_FACTORY(PerConnectionIdleTimeoutMsObjectFactory, StreamInfo::FilterState::ObjectFactory);

Config::SimpleRouteImpl::SimpleRouteImpl(const Config& parent, absl::string_view cluster_name)
    : parent_(parent), cluster_name_(cluster_name) {}

Config::WeightedClusterEntry::WeightedClusterEntry(
    const Config& parent, const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::
                              WeightedCluster::ClusterWeight& config)
    : parent_(parent), cluster_name_(config.name()), cluster_weight_(config.weight()) {
  if (config.has_metadata_match()) {
    const auto filter_it = config.metadata_match().filter_metadata().find(
        Envoy::Config::MetadataFilters::get().ENVOY_LB);
    if (filter_it != config.metadata_match().filter_metadata().end()) {
      if (parent.cluster_metadata_match_criteria_) {
        metadata_match_criteria_ =
            parent.cluster_metadata_match_criteria_->mergeMatchCriteria(filter_it->second);
      } else {
        metadata_match_criteria_ =
            std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
      }
    }
  }
}

OnDemandConfig::OnDemandConfig(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy_OnDemand& on_demand_message,
    Server::Configuration::FactoryContext& context, Stats::Scope& scope)
    : odcds_([&]() -> Upstream::OdCdsApiHandlePtr {
        if (Runtime::runtimeFeatureEnabled(
                "envoy.reloadable_features.tcp_proxy_odcds_over_ads_fix") &&
            on_demand_message.odcds_config().config_source_specifier_case() ==
                envoy::config::core::v3::ConfigSource::ConfigSourceSpecifierCase::kAds) {
          return THROW_OR_RETURN_VALUE(
              context.serverFactoryContext().clusterManager().allocateOdCdsApi(
                  &Upstream::XdstpOdCdsApiImpl::create, on_demand_message.odcds_config(),
                  OptRef<xds::core::v3::ResourceLocator>(), context.messageValidationVisitor()),
              Upstream::OdCdsApiHandlePtr);
        }
        return THROW_OR_RETURN_VALUE(
            context.serverFactoryContext().clusterManager().allocateOdCdsApi(
                &Upstream::OdCdsApiImpl::create, on_demand_message.odcds_config(),
                OptRef<xds::core::v3::ResourceLocator>(), context.messageValidationVisitor()),
            Upstream::OdCdsApiHandlePtr);
      }()),
      lookup_timeout_(
          std::chrono::milliseconds(PROTOBUF_GET_MS_OR_DEFAULT(on_demand_message, timeout, 60000))),
      stats_(generateStats(scope)) {}

OnDemandStats OnDemandConfig::generateStats(Stats::Scope& scope) {
  return {ON_DEMAND_TCP_PROXY_STATS(POOL_COUNTER(scope))};
}

Config::SharedConfig::SharedConfig(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
    Server::Configuration::FactoryContext& context)
    : stats_scope_(context.scope().createScope(fmt::format("tcp.{}", config.stat_prefix()))),
      stats_(generateStats(*stats_scope_)),
      flush_access_log_on_start_(config.access_log_options().flush_access_log_on_start()),
      proxy_protocol_tlv_merge_policy_(config.proxy_protocol_tlv_merge_policy()) {
  if (config.has_idle_timeout()) {
    const uint64_t timeout = DurationUtil::durationToMilliseconds(config.idle_timeout());
    if (timeout > 0) {
      idle_timeout_ = std::chrono::milliseconds(timeout);
    }
  } else {
    idle_timeout_ = std::chrono::hours(1);
  }
  if (config.has_tunneling_config()) {
    tunneling_config_helper_ =
        std::make_unique<TunnelingConfigHelperImpl>(*stats_scope_.get(), config, context);
  }
  if (config.has_max_downstream_connection_duration()) {
    const uint64_t connection_duration =
        DurationUtil::durationToMilliseconds(config.max_downstream_connection_duration());
    max_downstream_connection_duration_ = std::chrono::milliseconds(connection_duration);
  }
  if (config.has_max_downstream_connection_duration_jitter_percentage()) {
    max_downstream_connection_duration_jitter_percentage_ =
        config.max_downstream_connection_duration_jitter_percentage().value();
  }

  if (config.has_access_log_options()) {
    if (config.flush_access_log_on_connected() /* deprecated */) {
      throw EnvoyException(
          "Only one of flush_access_log_on_connected or access_log_options can be specified.");
    }

    if (config.has_access_log_flush_interval() /* deprecated */) {
      throw EnvoyException(
          "Only one of access_log_flush_interval or access_log_options can be specified.");
    }

    flush_access_log_on_connected_ = config.access_log_options().flush_access_log_on_connected();

    if (config.access_log_options().has_access_log_flush_interval()) {
      const uint64_t flush_interval = DurationUtil::durationToMilliseconds(
          config.access_log_options().access_log_flush_interval());
      access_log_flush_interval_ = std::chrono::milliseconds(flush_interval);
    }
  } else {
    flush_access_log_on_connected_ = config.flush_access_log_on_connected();

    if (config.has_access_log_flush_interval()) {
      const uint64_t flush_interval =
          DurationUtil::durationToMilliseconds(config.access_log_flush_interval());
      access_log_flush_interval_ = std::chrono::milliseconds(flush_interval);
    }
  }

  if (config.has_on_demand() && config.on_demand().has_odcds_config()) {
    on_demand_config_ =
        std::make_unique<OnDemandConfig>(config.on_demand(), context, *stats_scope_);
  }

  if (config.has_backoff_options()) {
    const uint64_t base_interval_ms =
        PROTOBUF_GET_MS_REQUIRED(config.backoff_options(), base_interval);
    const uint64_t max_interval_ms =
        PROTOBUF_GET_MS_OR_DEFAULT(config.backoff_options(), max_interval, base_interval_ms * 10);

    if (max_interval_ms < base_interval_ms) {
      throw EnvoyException(
          "max_backoff_interval must be greater or equal to base_backoff_interval");
    }

    backoff_strategy_ = std::make_unique<JitteredExponentialBackOffStrategy>(
        base_interval_ms, max_interval_ms, context.serverFactoryContext().api().randomGenerator());
  }

  if (!config.proxy_protocol_tlvs().empty()) {
    proxy_protocol_tlvs_ =
        parseTLVs(config.proxy_protocol_tlvs(), context, dynamic_tlv_formatters_);
  }
}

Config::Config(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
               Server::Configuration::FactoryContext& context)
    : max_connect_attempts_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, max_connect_attempts, 1)),
      upstream_drain_manager_slot_(context.serverFactoryContext().threadLocal().allocateSlot()),
      upstream_pool_slot_(context.serverFactoryContext().threadLocal().allocateSlot()),
      shared_config_(std::make_shared<SharedConfig>(config, context)),
      random_generator_(context.serverFactoryContext().api().randomGenerator()),
      regex_engine_(context.serverFactoryContext().regexEngine()),
      drain_decision_(context.drainDecision()),
      drain_close_scope_(context.listenerInfo().direction() ==
                                 envoy::config::core::v3::TrafficDirection::INBOUND
                             ? Network::DrainDirection::InboundOnly
                             : Network::DrainDirection::All),
      check_drain_close_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, check_drain_close, false)) {
  upstream_drain_manager_slot_->set([](Event::Dispatcher&) {
    ThreadLocal::ThreadLocalObjectSharedPtr drain_manager =
        std::make_shared<UpstreamDrainManager>();
    return drain_manager;
  });

  // Fail-closed gate for the Phase-2 warm upstream connection pool (UPSTREAM_POOL_DESIGN.md). The
  // slot is only populated -- and therefore the pool only ever consulted -- when this reloadable
  // feature is enabled; it defaults OFF so the filter stays strictly 1:1. (The eventual home for
  // this switch is a typed proto field on the TcpProxy config; the runtime feature is the
  // intermediate, ship-dark control while the path is validated.)
  if (Runtime::runtimeFeatureEnabled("envoy.reloadable_features.tcp_proxy_l4_connection_pool")) {
    // Capture the ClusterManager by pointer to the server-lifetime object (NOT by reference to a
    // local), because the slot's InitializeCb may run later when a new worker thread registers.
    Upstream::ClusterManager* cluster_manager = &context.serverFactoryContext().clusterManager();
    upstream_pool_slot_->set([cluster_manager](Event::Dispatcher& dispatcher)
                                 -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<UpstreamPool>(dispatcher, *cluster_manager);
    });
    l4_pool_enabled_ = true;
  }

  if (!config.cluster().empty()) {
    default_route_ = std::make_shared<const SimpleRouteImpl>(*this, config.cluster());
  }

  if (config.has_metadata_match()) {
    const auto& filter_metadata = config.metadata_match().filter_metadata();

    const auto filter_it = filter_metadata.find(Envoy::Config::MetadataFilters::get().ENVOY_LB);

    if (filter_it != filter_metadata.end()) {
      cluster_metadata_match_criteria_ =
          std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
    }
  }

  // Weighted clusters will be enabled only if the default cluster is absent.
  if (default_route_ == nullptr && config.has_weighted_clusters()) {
    total_cluster_weight_ = 0;
    for (const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::WeightedCluster::
             ClusterWeight& cluster_desc : config.weighted_clusters().clusters()) {
      WeightedClusterEntryConstSharedPtr cluster_entry(
          std::make_shared<const WeightedClusterEntry>(*this, cluster_desc));
      weighted_clusters_.emplace_back(std::move(cluster_entry));
      total_cluster_weight_ += weighted_clusters_.back()->clusterWeight();
    }
  }

  for (const envoy::config::accesslog::v3::AccessLog& log_config : config.access_log()) {
    access_logs_.emplace_back(AccessLog::AccessLogFactory::fromProto(log_config, context));
  }

  if (!config.hash_policy().empty()) {
    hash_policy_ = std::make_unique<Network::HashPolicyImpl>(config.hash_policy());
  }

  // Parse upstream connection establishment configuration.
  upstream_connect_mode_ = config.upstream_connect_mode();

  if (config.has_max_early_data_bytes()) {
    max_early_data_bytes_ = config.max_early_data_bytes().value();
  }

  // Validate: Non-IMMEDIATE modes require max_early_data_bytes to be set.
  // Setting it to zero is allowed and will disable early data buffering.
  if (upstream_connect_mode_ != UpstreamConnectMode::IMMEDIATE &&
      !max_early_data_bytes_.has_value()) {
    throw EnvoyException(
        "max_early_data_bytes must be set when upstream_connect_mode is not IMMEDIATE");
  }
}

RouteConstSharedPtr Config::getRegularRouteFromEntries(Network::Connection& connection) {
  // First check if the per-connection state to see if we need to route to a pre-selected cluster
  if (const auto* per_connection_cluster =
          connection.streamInfo().filterState()->getDataReadOnly<PerConnectionCluster>(
              PerConnectionCluster::key());
      per_connection_cluster != nullptr) {
    return std::make_shared<const SimpleRouteImpl>(*this, per_connection_cluster->value());
  }

  if (default_route_ != nullptr) {
    return default_route_;
  }

  // no match, no more routes to try
  return nullptr;
}

RouteConstSharedPtr Config::getRouteFromEntries(Network::Connection& connection) {
  if (weighted_clusters_.empty()) {
    return getRegularRouteFromEntries(connection);
  }
  return WeightedClusterUtil::pickCluster(weighted_clusters_, total_cluster_weight_,
                                          random_generator_.random(), false);
}

const absl::optional<std::chrono::milliseconds>
Config::calculateMaxDownstreamConnectionDurationWithJitter() {
  const auto& max_downstream_connection_duration = maxDownstreamConnectionDuration();
  if (!max_downstream_connection_duration) {
    return max_downstream_connection_duration;
  }

  const auto& jitter_percentage = maxDownstreamConnectionDurationJitterPercentage();
  if (!jitter_percentage) {
    return max_downstream_connection_duration;
  }

  // Apply jitter: base_duration * (1 + random(0, jitter_factor));
  const uint64_t max_jitter_ms = std::ceil(max_downstream_connection_duration.value().count() *
                                           (jitter_percentage.value() / 100.0));

  if (max_jitter_ms == 0) {
    return max_downstream_connection_duration;
  }

  const uint64_t jitter_ms = randomGenerator().random() % max_jitter_ms;
  return std::chrono::milliseconds(
      static_cast<uint64_t>(max_downstream_connection_duration.value().count() + jitter_ms));
}

UpstreamDrainManager& Config::drainManager() {
  return upstream_drain_manager_slot_->getTyped<UpstreamDrainManager>();
}

OptRef<UpstreamPool> Config::upstreamPool() {
  // The slot is only populated when the l4_connection_pool runtime feature was enabled at config
  // load (see the constructor). When it is off, the slot was allocated but never set(), so get()
  // returns nullptr on every worker and callers fall back to the strictly-1:1 path. (Guarding on
  // get() rather than currentThreadRegistered() is deliberate: the latter is true on every worker
  // thread regardless of whether set() was ever called.)
  if (!l4_pool_enabled_) {
    // Slot was allocated but never set() (feature off). Do not call get() on an unset slot.
    return {};
  }
  return makeOptRef(upstream_pool_slot_->getTyped<UpstreamPool>());
}

Filter::Filter(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager)
    : tracing_config_(Tracing::EgressConfig::get()), config_(config),
      cluster_manager_(cluster_manager), downstream_callbacks_(*this),
      upstream_callbacks_(new UpstreamCallbacks(this)),
      upstream_decoder_filter_callbacks_(HttpStreamDecoderFilterCallbacks(this)) {
  ASSERT(config != nullptr);
}

Filter::~Filter() {
  // Disable access log flush timer if it is enabled.
  disableAccessLogFlushTimer();

  disableRetryTimer();

  // Flush the final end stream access log entry.
  flushAccessLog(AccessLog::AccessLogType::TcpConnectionEnd);

  ASSERT(generic_conn_pool_ == nullptr);
  ASSERT(upstream_ == nullptr);
}

TcpProxyStats Config::SharedConfig::generateStats(Stats::Scope& scope) {
  return {ALL_TCP_PROXY_STATS(POOL_COUNTER(scope), POOL_GAUGE(scope))};
}

Network::ProxyProtocolTLVVector
Config::SharedConfig::parseTLVs(absl::Span<const envoy::config::core::v3::TlvEntry* const> tlvs,
                                Server::Configuration::GenericFactoryContext& context,
                                std::vector<TlvFormatter>& dynamic_tlvs) {
  Network::ProxyProtocolTLVVector tlv_vector;
  for (const auto& tlv : tlvs) {
    const uint8_t tlv_type = static_cast<uint8_t>(tlv->type());

    // Validate that only one of value or format_string is set.
    const bool has_value = !tlv->value().empty();
    const bool has_format_string = tlv->has_format_string();

    if (has_value && has_format_string) {
      throw EnvoyException(
          "Invalid TLV configuration: only one of 'value' or 'format_string' may be set.");
    }

    if (!has_value && !has_format_string) {
      throw EnvoyException(
          "Invalid TLV configuration: one of 'value' or 'format_string' must be set.");
    }

    if (has_value) {
      // Static TLV value must be at least one byte long.
      if (tlv->value().empty()) {
        throw EnvoyException("Invalid TLV configuration: 'value' must be at least one byte long.");
      }
      tlv_vector.push_back(
          {tlv_type, std::vector<unsigned char>(tlv->value().begin(), tlv->value().end())});
    } else {
      // Dynamic TLV value using formatter.
      auto formatter_or_error =
          Formatter::SubstitutionFormatStringUtils::fromProtoConfig(tlv->format_string(), context);
      if (!formatter_or_error.ok()) {
        throw EnvoyException(absl::StrCat("Failed to parse TLV format string: ",
                                          formatter_or_error.status().ToString()));
      }
      dynamic_tlvs.push_back({tlv_type, std::move(*formatter_or_error)});
    }
  }
  return tlv_vector;
}

Network::ProxyProtocolTLVVector
Config::SharedConfig::evaluateDynamicTLVs(const StreamInfo::StreamInfo& stream_info) const {
  Network::ProxyProtocolTLVVector result = proxy_protocol_tlvs_;

  // Evaluate dynamic TLV formatters.
  for (const auto& tlv_formatter : dynamic_tlv_formatters_) {
    const std::string formatted_value = tlv_formatter.formatter->format({}, stream_info);

    // Convert formatted string to bytes and add to result.
    result.push_back({tlv_formatter.type,
                      std::vector<unsigned char>(formatted_value.begin(), formatted_value.end())});
  }

  return result;
}

void Filter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  initialize(callbacks, true);
}

void Filter::initialize(Network::ReadFilterCallbacks& callbacks, bool set_connection_stats) {
  read_callbacks_ = &callbacks;
  ENVOY_CONN_LOG(debug, "new tcp proxy session", read_callbacks_->connection());

  read_callbacks_->connection().addConnectionCallbacks(downstream_callbacks_);
  read_callbacks_->connection().enableHalfClose(true);

  // Check that we are generating only the byte meters we need.
  // The Downstream should be unset and the Upstream should be populated.
  ASSERT(getStreamInfo().getDownstreamBytesMeter() == nullptr);
  ASSERT(getStreamInfo().getUpstreamBytesMeter() != nullptr);

  // Initialize connection establishment mode.
  connect_mode_ = config_->upstreamConnectMode();

  // Check if early data buffering is enabled.
  if (config_->maxEarlyDataBytes().has_value()) {
    receive_before_connect_ = true;
    max_buffered_bytes_ = config_->maxEarlyDataBytes().value();
    ENVOY_CONN_LOG(debug, "receive_before_connect enabled with max buffer size: {}",
                   read_callbacks_->connection(), max_buffered_bytes_);
  } else {
    // Legacy behavior: check filter state for receive_before_connect.
    const StreamInfo::BoolAccessor* receive_before_connect =
        read_callbacks_->connection()
            .streamInfo()
            .filterState()
            ->getDataReadOnly<StreamInfo::BoolAccessor>(ReceiveBeforeConnectKey);

    if (receive_before_connect != nullptr && receive_before_connect->value()) {
      ENVOY_CONN_LOG(debug, "receive_before_connect is enabled (legacy)",
                     read_callbacks_->connection());
      receive_before_connect_ = true;
      // Use 0 buffer size for legacy mode to always read-disable immediately.
      max_buffered_bytes_ = 0;
    }
  }

  // Handle TLS handshake wait mode.
  if (connect_mode_ == UpstreamConnectMode::ON_DOWNSTREAM_TLS_HANDSHAKE) {
    const auto ssl_connection = read_callbacks_->connection().ssl();
    if (ssl_connection != nullptr) {
      waiting_for_tls_handshake_ = true;
      ENVOY_CONN_LOG(debug, "waiting for downstream TLS handshake before connecting",
                     read_callbacks_->connection());
      // TODO: Register callback for TLS handshake completion.
    } else {
      // Non-TLS connection - TLS handshake mode behaves as IMMEDIATE.
      ENVOY_CONN_LOG(debug,
                     "downstream connection is not TLS, treating TLS handshake mode as IMMEDIATE",
                     read_callbacks_->connection());
      connect_mode_ = UpstreamConnectMode::IMMEDIATE;
    }
  }

  if (!receive_before_connect_) {
    // Need to disable reads so that we don't write to an upstream that might fail
    // in onData(). This will get re-enabled when the upstream connection is
    // established.
    read_callbacks_->connection().readDisable(true);
  }

  getStreamInfo().setDownstreamBytesMeter(std::make_shared<StreamInfo::BytesMeter>());
  getStreamInfo().setUpstreamInfo(std::make_shared<StreamInfo::UpstreamInfoImpl>());

  config_->stats().downstream_cx_total_.inc();
  if (set_connection_stats) {
    read_callbacks_->connection().setConnectionStats(
        {config_->stats().downstream_cx_rx_bytes_total_,
         config_->stats().downstream_cx_rx_bytes_buffered_,
         config_->stats().downstream_cx_tx_bytes_total_,
         config_->stats().downstream_cx_tx_bytes_buffered_, nullptr, nullptr});
  }
}

void Filter::onInitFailure(UpstreamFailureReason reason) {
  // If ODCDS fails, the filter will not attempt to create a connection to
  // upstream, as it does not have an assigned upstream. As such the filter will
  // not have started attempting to connect to an upstream and there is no
  // connection pool callback latency to record.
  if (initial_upstream_connection_start_time_.has_value()) {
    if (!getStreamInfo().upstreamInfo()->upstreamTiming().connectionPoolCallbackLatency()) {
      getStreamInfo().upstreamInfo()->upstreamTiming().recordConnectionPoolCallbackLatency(
          initial_upstream_connection_start_time_.value(),
          read_callbacks_->connection().dispatcher().timeSource());
    }
  }
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::NoFlush,
      absl::StrCat(StreamInfo::LocalCloseReasons::get().TcpProxyInitializationFailure,
                   enumToInt(reason)));
}

void Filter::readDisableUpstream(bool disable) {
  // The splice fast-path removed the connection FileEvents, so readDisable would touch a null
  // file_event_ and hit an ENVOY_BUG. The watermark callbacks that drive it cannot fire while
  // spliced because no buffered write feeds them, so this guard also future-proofs other callers.
  if (splice_pump_ != nullptr) {
    return;
  }
  bool success = false;
  if (upstream_) {
    success = upstream_->readDisable(disable);
  }
  if (!success) {
    return;
  }
  if (disable) {
    read_callbacks_->upstreamHost()
        ->cluster()
        .trafficStats()
        ->upstream_flow_control_paused_reading_total_.inc();
  } else {
    read_callbacks_->upstreamHost()
        ->cluster()
        .trafficStats()
        ->upstream_flow_control_resumed_reading_total_.inc();
  }
}

void Filter::readDisableDownstream(bool disable) {
  // See readDisableUpstream. The spliced connection has no FileEvents to toggle.
  if (splice_pump_ != nullptr) {
    return;
  }
  if (read_callbacks_->connection().state() != Network::Connection::State::Open) {
    // During idle timeouts, we close both upstream and downstream with NoFlush.
    // Envoy still does a best-effort flush which can case readDisableDownstream to be called
    // despite the downstream connection being closed.
    return;
  }

  const Network::Connection::ReadDisableStatus read_disable_status =
      read_callbacks_->connection().readDisable(disable);

  if (read_disable_status == Network::Connection::ReadDisableStatus::TransitionedToReadDisabled) {
    config_->stats().downstream_flow_control_paused_reading_total_.inc();
  } else if (read_disable_status ==
             Network::Connection::ReadDisableStatus::TransitionedToReadEnabled) {
    config_->stats().downstream_flow_control_resumed_reading_total_.inc();
  }
}

StreamInfo::StreamInfo& Filter::getStreamInfo() {
  return read_callbacks_->connection().streamInfo();
}

void Filter::DownstreamCallbacks::onAboveWriteBufferHighWatermark() {
  ASSERT(!on_high_watermark_called_);
  on_high_watermark_called_ = true;
  // If downstream has too much data buffered, stop reading on the upstream connection.
  parent_.readDisableUpstream(true);
}

void Filter::DownstreamCallbacks::onBelowWriteBufferLowWatermark() {
  ASSERT(on_high_watermark_called_);
  on_high_watermark_called_ = false;
  // The downstream buffer has been drained. Resume reading from upstream.
  parent_.readDisableUpstream(false);
}

void Filter::UpstreamCallbacks::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected ||
      event == Network::ConnectionEvent::ConnectedZeroRtt) {
    return;
  }
  if (drainer_ == nullptr) {
    parent_->onUpstreamEvent(event);
  } else {
    drainer_->onEvent(event);
  }
}

void Filter::UpstreamCallbacks::onAboveWriteBufferHighWatermark() {
  // In case when upstream connection is draining `parent_` will be set to nullptr.
  // TCP Tunneling may call on high/low watermark multiple times.
  ASSERT(parent_ == nullptr || parent_->config_->tunnelingConfigHelper() ||
         !on_high_watermark_called_);
  on_high_watermark_called_ = true;

  if (parent_ != nullptr) {
    // There's too much data buffered in the upstream write buffer, so stop reading.
    parent_->readDisableDownstream(true);
  }
}

void Filter::UpstreamCallbacks::onBelowWriteBufferLowWatermark() {
  // In case when upstream connection is draining `parent_` will be set to nullptr.
  // TCP Tunneling may call on high/low watermark multiple times.
  ASSERT(parent_ == nullptr || parent_->config_->tunnelingConfigHelper() ||
         on_high_watermark_called_);
  on_high_watermark_called_ = false;

  if (parent_ != nullptr) {
    // The upstream write buffer is drained. Resume reading.
    parent_->readDisableDownstream(false);
  }
}

void Filter::UpstreamCallbacks::onUpstreamData(Buffer::Instance& data, bool end_stream) {
  if (parent_) {
    parent_->onUpstreamData(data, end_stream);
  } else {
    drainer_->onData(data, end_stream);
  }
}

void Filter::UpstreamCallbacks::onBytesSent() {
  if (drainer_ == nullptr) {
    parent_->resetIdleTimer();
  } else {
    drainer_->onBytesSent();
  }
}

void Filter::UpstreamCallbacks::onIdleTimeout() {
  if (drainer_ == nullptr) {
    parent_->onIdleTimeout();
  } else {
    drainer_->onIdleTimeout();
  }
}

void Filter::UpstreamCallbacks::drain(Drainer& drainer) {
  ASSERT(drainer_ == nullptr); // This should only get set once.
  drainer_ = &drainer;
  parent_ = nullptr;
}

Network::FilterStatus Filter::establishUpstreamConnection() {
  const std::string& cluster_name = route_ ? route_->clusterName() : EMPTY_STRING;
  ENVOY_CONN_LOG(debug, "establishUpstreamConnection called: cluster_name={}, route_={}",
                 read_callbacks_->connection(), cluster_name, route_ != nullptr);
  Upstream::ThreadLocalCluster* thread_local_cluster =
      cluster_manager_.getThreadLocalCluster(cluster_name);

  ENVOY_CONN_LOG(debug, "establishUpstreamConnection: thread_local_cluster={}",
                 read_callbacks_->connection(), thread_local_cluster != nullptr);

  if (!thread_local_cluster) {
    auto odcds = config_->onDemandCds();
    if (!odcds.has_value()) {
      // No ODCDS? It means that on-demand discovery is disabled.
      ENVOY_CONN_LOG(debug, "Cluster not found {} and no on demand cluster set.",
                     read_callbacks_->connection(), cluster_name);
      config_->stats().downstream_cx_no_route_.inc();
      getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::NoClusterFound);
      onInitFailure(UpstreamFailureReason::NoRoute);
    } else {
      ASSERT(!cluster_discovery_handle_);
      auto callback = std::make_unique<Upstream::ClusterDiscoveryCallback>(
          [this](Upstream::ClusterDiscoveryStatus cluster_status) {
            onClusterDiscoveryCompletion(cluster_status);
          });
      config_->onDemandStats().on_demand_cluster_attempt_.inc();
      cluster_discovery_handle_ = odcds->requestOnDemandClusterDiscovery(
          cluster_name, std::move(callback), config_->odcdsTimeout());
    }
    return Network::FilterStatus::StopIteration;
  }

  ENVOY_CONN_LOG(debug, "Creating connection to cluster {}", read_callbacks_->connection(),
                 cluster_name);
  if (!initial_upstream_connection_start_time_.has_value()) {
    initial_upstream_connection_start_time_.emplace(
        read_callbacks_->connection().dispatcher().timeSource().monotonicTime());
  }

  const Upstream::ClusterInfoConstSharedPtr& cluster = thread_local_cluster->info();
  getStreamInfo().setUpstreamClusterInfo(cluster);

  // Check this here because the TCP conn pool will queue our request waiting for a connection that
  // will never be released.
  if (!cluster->resourceManager(Upstream::ResourcePriority::Default).connections().canCreate()) {
    getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::UpstreamOverflow);
    cluster->trafficStats()->upstream_cx_overflow_.inc();
    onInitFailure(UpstreamFailureReason::ResourceLimitExceeded);
    return Network::FilterStatus::StopIteration;
  }

  auto& downstream_connection = read_callbacks_->connection();
  auto& filter_state = downstream_connection.streamInfo().filterState();

  auto* existing_state = filter_state->getDataMutable<Network::ProxyProtocolFilterState>(
      Network::ProxyProtocolFilterState::key());

  if (existing_state == nullptr) {
    // No downstream proxy protocol state exists - create new state with tcp_proxy TLVs.
    const auto tlvs = config_->sharedConfig()->evaluateDynamicTLVs(getStreamInfo());
    filter_state->setData(
        Network::ProxyProtocolFilterState::key(),
        std::make_shared<Network::ProxyProtocolFilterState>(Network::ProxyProtocolData{
            downstream_connection.connectionInfoProvider().remoteAddress(),
            downstream_connection.connectionInfoProvider().localAddress(), tlvs}),
        StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
  } else if (config_->sharedConfig()->proxyProtocolTlvMergePolicy() !=
             envoy::extensions::filters::network::tcp_proxy::v3::ADD_IF_ABSENT) {
    // Existing state found and merge policy is not ADD_IF_ABSENT - merge TLVs.
    const auto& existing_data = existing_state->value();
    const auto configured_tlvs = config_->sharedConfig()->evaluateDynamicTLVs(getStreamInfo());

    Network::ProxyProtocolTLVVector merged_tlvs;

    if (config_->sharedConfig()->proxyProtocolTlvMergePolicy() ==
        envoy::extensions::filters::network::tcp_proxy::v3::OVERWRITE_BY_TYPE_IF_EXISTS_OR_ADD) {
      // Overwrite by type: configured TLVs take precedence for matching types.
      absl::flat_hash_set<uint8_t> configured_tlv_types;
      for (const auto& tlv : configured_tlvs) {
        configured_tlv_types.insert(tlv.type);
      }

      for (const auto& tlv : configured_tlvs) {
        merged_tlvs.push_back(tlv);
      }

      for (const auto& tlv : existing_data.tlv_vector_) {
        if (!configured_tlv_types.contains(tlv.type)) {
          merged_tlvs.push_back(tlv);
        }
      }
    } else if (config_->sharedConfig()->proxyProtocolTlvMergePolicy() ==
               envoy::extensions::filters::network::tcp_proxy::v3::APPEND_IF_EXISTS_OR_ADD) {
      // Append: preserve all existing TLVs, then add configured TLVs.
      for (const auto& tlv : existing_data.tlv_vector_) {
        merged_tlvs.push_back(tlv);
      }

      for (const auto& tlv : configured_tlvs) {
        merged_tlvs.push_back(tlv);
      }
    }

    // Update filter state with merged TLVs, preserving existing addresses and version.
    filter_state->setData(
        Network::ProxyProtocolFilterState::key(),
        std::make_shared<Network::ProxyProtocolFilterState>(Network::ProxyProtocolDataWithVersion{
            {existing_data.src_addr_, existing_data.dst_addr_, merged_tlvs},
            existing_data.version_}),
        StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
  }
  // else: ADD_IF_ABSENT policy with existing state - keep existing state as-is.
  transport_socket_options_ =
      Network::TransportSocketOptionsUtility::fromFilterState(*filter_state);

  if (auto typed_state = filter_state->getDataReadOnly<Network::UpstreamSocketOptionsFilterState>(
          Network::UpstreamSocketOptionsFilterState::key());
      typed_state != nullptr) {
    auto downstream_options = typed_state->value();
    if (!upstream_options_) {
      upstream_options_ = std::make_shared<Network::Socket::Options>();
    }
    Network::Socket::appendOptions(upstream_options_, downstream_options);
  }

  if (!maybeTunnel(*thread_local_cluster)) {
    // Either cluster is unknown, factory doesn't exist, there are no healthy hosts, or
    // createGenericConnPool returned nullptr. Handle this gracefully.
    getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::NoHealthyUpstream);
    onInitFailure(UpstreamFailureReason::NoHealthyUpstream);
    return Network::FilterStatus::StopIteration;
  }
  // Determine the return status based on whether we can receive data before connection.
  // Return Continue if we're allowing data to be read (either for buffering or to trigger
  // connection). Return StopIteration if we need to wait for the upstream connection first.
  return receive_before_connect_ ? Network::FilterStatus::Continue
                                 : Network::FilterStatus::StopIteration;
}

void Filter::onClusterDiscoveryCompletion(Upstream::ClusterDiscoveryStatus cluster_status) {
  // Clear the cluster_discovery_handle_ before calling establishUpstreamConnection since we may
  // request cluster again.
  cluster_discovery_handle_.reset();
  const std::string& cluster_name = route_ ? route_->clusterName() : EMPTY_STRING;
  switch (cluster_status) {
  case Upstream::ClusterDiscoveryStatus::Missing:
    ENVOY_CONN_LOG(debug, "On demand cluster {} is missing", read_callbacks_->connection(),
                   cluster_name);
    config_->onDemandStats().on_demand_cluster_missing_.inc();
    break;
  case Upstream::ClusterDiscoveryStatus::Timeout:
    ENVOY_CONN_LOG(debug, "On demand cluster {} was not found before timeout.",
                   read_callbacks_->connection(), cluster_name);
    config_->onDemandStats().on_demand_cluster_timeout_.inc();
    break;
  case Upstream::ClusterDiscoveryStatus::Available:
    // cluster_discovery_handle_ would have been cancelled if the downstream were closed.
    ASSERT(!downstream_closed_);
    ENVOY_CONN_LOG(debug, "On demand cluster {} is found. Establishing connection.",
                   read_callbacks_->connection(), cluster_name);
    config_->onDemandStats().on_demand_cluster_success_.inc();
    establishUpstreamConnection();
    return;
  }
  // Failure path.
  config_->stats().downstream_cx_no_route_.inc();
  getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::NoClusterFound);
  onInitFailure(UpstreamFailureReason::NoRoute);
}

bool Filter::maybeTunnel(Upstream::ThreadLocalCluster& cluster) {
  GenericConnPoolFactory* factory = nullptr;
  if (cluster.info()->upstreamConfig().has_value()) {
    factory = Envoy::Config::Utility::getFactory<GenericConnPoolFactory>(
        cluster.info()->upstreamConfig().ref());
  } else {
    factory = Envoy::Config::Utility::getFactoryByName<GenericConnPoolFactory>(
        "envoy.filters.connection_pools.tcp.generic");
  }
  if (!factory) {
    return false;
  }
  if (Runtime::runtimeFeatureEnabled(
          "envoy.restart_features.upstream_http_filters_with_tcp_proxy")) {
    // TODO(vikaschoudhary16): Initialize route_ once per cluster.
    upstream_decoder_filter_callbacks_.route_ = THROW_OR_RETURN_VALUE(
        Http::NullRouteImpl::create(cluster.info()->name(),
                                    Router::RetryPolicyImpl::DefaultRetryPolicy,
                                    config_->regexEngine()),
        std::unique_ptr<Http::NullRouteImpl>);
  }
  Upstream::HostConstSharedPtr host =
      Upstream::LoadBalancer::onlyAllowSynchronousHostSelection(cluster.chooseHost(this));
  if (host) {
    // Track attempted hosts for access logging
    getStreamInfo().upstreamInfo()->addUpstreamHostAttempted(host);

    // Phase-2 warm connection pool (buffered relay path only; see UPSTREAM_POOL_DESIGN.md). Only
    // raw-TCP (non-tunneling) upstreams are poolable -- HTTP/tunneling upstreams frame their own
    // bodies and expose no spliceable/pooled socket. When the l4_connection_pool feature is on and
    // the chosen host has an address, arm the per-Filter frame tracker for this host and try to
    // adopt a warm, already-handshaked connection instead of opening a fresh one.
    if (!config_->tunnelingConfigHelper().has_value() && config_->upstreamPool().has_value() &&
        host->address() != nullptr) {
      pool_host_key_ = std::string(host->address()->asStringView());
      pool_eligible_ = true;
      frame_tracker_ = std::make_unique<HttpFrameTracker>();
      if (tryCheckoutPooledUpstream(pool_host_key_, host)) {
        // Adopted a warm connection: upstream_ is already set and onUpstreamConnection() has run.
        // Skip the newStream path entirely.
        return true;
      }
    }

    generic_conn_pool_ = factory->createGenericConnPool(
        host, cluster, config_->tunnelingConfigHelper(), this, *upstream_callbacks_,
        upstream_decoder_filter_callbacks_, getStreamInfo());
  }
  if (generic_conn_pool_) {
    connecting_ = true;
    connect_attempts_++;
    getStreamInfo().setAttemptCount(connect_attempts_);
    generic_conn_pool_->newStream(*this);
    // Because we never return open connections to the pool, this either has a handle waiting on
    // connection completion, or onPoolFailure has been invoked. Either way, stop iteration.
    return true;
  }
  return false;
}

void Filter::onGenericPoolFailure(ConnectionPool::PoolFailureReason reason,
                                  absl::string_view failure_reason,
                                  Upstream::HostDescriptionConstSharedPtr host) {
  if (Runtime::runtimeFeatureEnabled(
          "envoy.restart_features.upstream_http_filters_with_tcp_proxy")) {
    // generic_conn_pool_ is an instance of TcpProxy::HttpConnPool.
    // generic_conn_pool_->newStream() is called in maybeTunnel() which initializes an instance of
    // Router::UpstreamRequest. If Router::UpstreamRequest receives headers from the upstream which
    // results in end_stream=true, then via callbacks passed to Router::UpstreamRequest,
    // TcpProxy::Filter::onGenericPoolFailure() gets invoked. If we do not do deferredDelete here,
    // then the same instance of UpstreamRequest which is under execution will go out of scope.
    read_callbacks_->connection().dispatcher().deferredDelete(std::move(generic_conn_pool_));
  } else {
    generic_conn_pool_.reset();
  }

  read_callbacks_->upstreamHost(host);
  getStreamInfo().upstreamInfo()->setUpstreamHost(host);
  getStreamInfo().upstreamInfo()->setUpstreamTransportFailureReason(failure_reason);

  switch (reason) {
  case ConnectionPool::PoolFailureReason::Overflow:
  case ConnectionPool::PoolFailureReason::LocalConnectionFailure:
    upstream_callbacks_->onEvent(Network::ConnectionEvent::LocalClose);
    break;
  case ConnectionPool::PoolFailureReason::RemoteConnectionFailure:
    upstream_callbacks_->onEvent(Network::ConnectionEvent::RemoteClose);
    break;
  case ConnectionPool::PoolFailureReason::Timeout:
    onConnectTimeout();
    break;
  }
}

void Filter::onGenericPoolReady(StreamInfo::StreamInfo* info,
                                std::unique_ptr<GenericUpstream>&& upstream,
                                Upstream::HostDescriptionConstSharedPtr& host,
                                const Network::ConnectionInfoProvider& address_provider,
                                Ssl::ConnectionInfoConstSharedPtr ssl_info) {
  StreamInfo::UpstreamInfo& upstream_info = *getStreamInfo().upstreamInfo();
  if (!upstream_info.upstreamTiming().connectionPoolCallbackLatency()) {
    upstream_info.upstreamTiming().recordConnectionPoolCallbackLatency(
        initial_upstream_connection_start_time_.value(),
        read_callbacks_->connection().dispatcher().timeSource());
  }
  upstream_ = std::move(upstream);
  generic_conn_pool_.reset();
  read_callbacks_->upstreamHost(host);
  // No need to set information using address_provider in case routing via Router::UpstreamRequest
  // because in that case, information is already set by the
  // Router::UpstreamRequest::onPoolReady() method before reaching here.
  if (upstream_info.upstreamLocalAddress() == nullptr) {
    upstream_info.setUpstreamLocalAddress(address_provider.localAddress());
    upstream_info.setUpstreamRemoteAddress(address_provider.remoteAddress());
  }
  upstream_info.setUpstreamHost(host);
  upstream_info.setUpstreamSslConnection(ssl_info);

  onUpstreamConnection();
  read_callbacks_->continueReading();
  if (info) {
    upstream_info.setUpstreamFilterState(info->filterState());
  }
} // namespace TcpProxy

const Router::MetadataMatchCriteria* Filter::metadataMatchCriteria() {
  const Router::MetadataMatchCriteria* route_criteria =
      (route_ != nullptr) ? route_->metadataMatchCriteria() : nullptr;

  const auto& request_metadata = getStreamInfo().dynamicMetadata().filter_metadata();
  const auto filter_it = request_metadata.find(Envoy::Config::MetadataFilters::get().ENVOY_LB);

  if (filter_it != request_metadata.end() && route_criteria != nullptr) {
    metadata_match_criteria_ = route_criteria->mergeMatchCriteria(filter_it->second);
    return metadata_match_criteria_.get();
  } else if (filter_it != request_metadata.end()) {
    metadata_match_criteria_ =
        std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
    return metadata_match_criteria_.get();
  } else {
    return route_criteria;
  }
}

const std::string& TunnelResponseHeaders::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.propagate_response_headers");
}

const std::string& TunnelResponseTrailers::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.propagate_response_trailers");
}

Router::HeaderParserPtr buildTunnelingHeaderParser(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::TunnelingConfig&
        tunneling_config,
    Server::Configuration::FactoryContext& context) {
  if (tunneling_config.formatters().empty()) {
    return THROW_OR_RETURN_VALUE(
        Envoy::Router::HeaderParser::configure(tunneling_config.headers_to_add()),
        Router::HeaderParserPtr);
  }

  Server::GenericFactoryContextImpl generic_context(context);
  auto command_parsers =
      THROW_OR_RETURN_VALUE(Formatter::SubstitutionFormatStringUtils::parseFormatters(
                                tunneling_config.formatters(), generic_context),
                            Formatter::CommandParserPtrVector);
  return THROW_OR_RETURN_VALUE(
      Envoy::Router::HeaderParser::configure(tunneling_config.headers_to_add(), command_parsers),
      Router::HeaderParserPtr);
}

TunnelingConfigHelperImpl::TunnelingConfigHelperImpl(
    Stats::Scope& stats_scope,
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config_message,
    Server::Configuration::FactoryContext& context)
    : header_parser_(buildTunnelingHeaderParser(config_message.tunneling_config(), context)),
      propagate_response_headers_(config_message.tunneling_config().propagate_response_headers()),
      propagate_response_trailers_(config_message.tunneling_config().propagate_response_trailers()),
      post_path_(config_message.tunneling_config().post_path()),
      route_stat_name_storage_("tcpproxy_tunneling", context.scope().symbolTable()),
      // TODO(vikaschoudhary16): figure out which of the following router_config_ members are
      // not required by tcp_proxy and move them to a different class
      router_config_(context.serverFactoryContext(), route_stat_name_storage_.statName(),
                     stats_scope, context.serverFactoryContext().clusterManager(),
                     context.serverFactoryContext().runtime(),
                     context.serverFactoryContext().api().randomGenerator(),
                     std::make_unique<Router::ShadowWriterImpl>(
                         context.serverFactoryContext().clusterManager()),
                     true, false, false, false, false, false, false, {},
                     context.serverFactoryContext().api().timeSource(),
                     context.serverFactoryContext().httpContext(),
                     context.serverFactoryContext().routerContext()),
      server_factory_context_(context.serverFactoryContext()) {
  if (!post_path_.empty() && !config_message.tunneling_config().use_post()) {
    throw EnvoyException("Can't set a post path when POST method isn't used");
  }
  if (config_message.tunneling_config().use_post()) {
    post_path_ = post_path_.empty() ? "/" : post_path_;
  }

  envoy::config::core::v3::SubstitutionFormatString substitution_format_config;
  substitution_format_config.mutable_text_format_source()->set_inline_string(
      config_message.tunneling_config().hostname());
  hostname_fmt_ = THROW_OR_RETURN_VALUE(Formatter::SubstitutionFormatStringUtils::fromProtoConfig(
                                            substitution_format_config, context),
                                        Formatter::FormatterPtr);

  // Initialize request ID extension if explicitly configured.
  const auto& rid_config = config_message.tunneling_config().request_id_extension();
  if (rid_config.has_typed_config()) {
    auto extension_or_error = Http::RequestIDExtensionFactory::fromProto(rid_config, context);
    if (!extension_or_error.ok()) {
      throw EnvoyException(absl::StrCat("Failed to create request ID extension: ",
                                        extension_or_error.status().ToString()));
    }
    request_id_extension_ = extension_or_error.value();
  }

  // Populate optional request ID customization fields if provided.
  if (!config_message.tunneling_config().request_id_header().empty()) {
    request_id_header_ = config_message.tunneling_config().request_id_header();
  }
  if (!config_message.tunneling_config().request_id_metadata_key().empty()) {
    request_id_metadata_key_ = config_message.tunneling_config().request_id_metadata_key();
  }
}

std::string TunnelingConfigHelperImpl::host(const StreamInfo::StreamInfo& stream_info) const {
  return hostname_fmt_->format({}, stream_info);
}

void TunnelingConfigHelperImpl::propagateResponseHeaders(
    Http::ResponseHeaderMapPtr&& headers,
    const StreamInfo::FilterStateSharedPtr& filter_state) const {
  if (!propagate_response_headers_) {
    return;
  }
  filter_state->setData(
      TunnelResponseHeaders::key(), std::make_shared<TunnelResponseHeaders>(std::move(headers)),
      StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
}

void TunnelingConfigHelperImpl::propagateResponseTrailers(
    Http::ResponseTrailerMapPtr&& trailers,
    const StreamInfo::FilterStateSharedPtr& filter_state) const {
  if (!propagate_response_trailers_) {
    return;
  }
  filter_state->setData(
      TunnelResponseTrailers::key(), std::make_shared<TunnelResponseTrailers>(std::move(trailers)),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);
}

void Filter::onConnectTimeout() {
  ENVOY_CONN_LOG(debug, "connect timeout", read_callbacks_->connection());
  read_callbacks_->upstreamHost()->outlierDetector().putResult(
      Upstream::Outlier::Result::LocalOriginTimeout);
  getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::UpstreamConnectionFailure);

  // Raise LocalClose, which will trigger a reconnect if needed/configured.
  upstream_callbacks_->onEvent(Network::ConnectionEvent::LocalClose);
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(debug,
                 "onData: received {} bytes, end_stream={}, has upstream {}, "
                 "receive_before_connect_={}, connect_mode_={}",
                 read_callbacks_->connection(), data.length(), end_stream, upstream_ != nullptr,
                 receive_before_connect_, static_cast<int>(connect_mode_));
  // Once the splice fast-path owns the sockets, the buffered path must not touch them.
  if (splice_pump_ != nullptr) {
    return Network::FilterStatus::StopIteration;
  }
  // Phase-2 pool routing. On a fresh, pool-eligible connection, observe the request framing up
  // front so this exchange can be routed by method and size before we decide whether to splice. The
  // frame tracker is a pure observer (it does not drain `data`), so a splice chosen below still
  // takes the same bytes -- preserving the large-upload first-chunk splice. This is the only
  // request-direction feed on the still-undecided pool path; the buffered write below re-feeds only
  // once the route is decided, so every request byte is framed exactly once.
  bool request_framed_here = false;
  if (upstream_ != nullptr && pool_eligible_ && !adopted_from_pool_ && !pool_route_decided_) {
    feedFrameTracker(data, /*from_upstream=*/false);
    maybePickPoolRoute();
    request_framed_here = true;
  }
  // L4 kernel-splice fast-path for the upload direction. Engage on the first downstream data once
  // the upstream rustls socket has installed kTLS and before any byte has been written upstream, so
  // the request and a PUT body move in-kernel like a GET response. The upstream_write_started_
  // guard guarantees the upstream write buffer is empty, so spliced bytes cannot reorder ahead of
  // buffered ones; on a connection where kTLS is not yet installed at the first data the buffered
  // path below carries the upload instead. maybeEngageSplice drains `data` into the pump on
  // success.
  // splicePermitted() gates the pool coexistence: an adopted warm connection and a connection
  // routed to the buffered pool path (a small upload) never splice so they stay returnable; a
  // GET/HEAD or large upload, or any connection the pool feature never armed, splices as before.
  if (upstream_ != nullptr && splicePermitted() && !end_stream && data.length() > 0 &&
      read_callbacks_->connection().state() == Network::Connection::State::Open) {
    OptRef<Network::Connection> up = upstream_->upstreamConnection();
    if (up.has_value()) {
      OptRef<const Network::KtlsBytestreamInfo> info = up->ktlsBytestreamInfo();
      const bool ktls_ready = info.has_value() && info->installed && info->trusted_peer;
      // Engage the upload splice once kTLS is installed and ordering is safe: the first chunk is
      // trivially safe (nothing written yet); a later chunk -- a PUT body after buffered request
      // headers -- is safe once those small headers have flushed, which maybeEngageSplice gates via
      // the upstream high-watermark.
      if (ktls_ready && (!upstream_write_started_ || !up->aboveHighWatermark()) &&
          maybeEngageSplice(data, /*from_upstream=*/false)) {
        return Network::FilterStatus::StopIteration;
      }
      // A PUT body that beat the kTLS install: hold it and poll until kTLS installs, then splice
      // it. Only LATER chunks are held (upstream_write_started_ -- the request headers already went
      // out on the buffered path), so a GET, which sends only the request and no body, is never
      // held and its latency is unchanged. Only a kTLS-capable upstream still installing (info
      // present, not installed) is held, so non-kTLS/mock upstreams stay on the buffered path. This
      // recovers the large-PUT in-kernel splice without the GET cost of deferring the first chunk.
      // The headers flush during the poll, and the engage's watermark check keeps the spliced body
      // ordered after them; AWS SigV4 signs the payload, so any reorder fails at S3 and shows as a
      // succ drop.
      if (upstream_write_started_ && info.has_value() && !info->installed &&
          !upload_engage_deferred_) {
        upload_engage_deferred_ = true;
        deferred_upload_buffer_.move(data);
        read_callbacks_->connection().readDisable(true);
        if (ktls_engage_schedulable_ == nullptr) {
          ktls_engage_schedulable_ =
              read_callbacks_->connection().dispatcher().createSchedulableCallback(
                  [this]() { onKtlsEngageRetry(); });
        }
        ktls_engage_schedulable_->scheduleCallbackNextIteration();
        return Network::FilterStatus::StopIteration;
      }
    }
  }
  getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(data.length());

  if (upstream_) {
    // Observe the request-direction bytes for HTTP/1.1 framing before they are encoded (encodeData
    // drains `data`). Skip when the route-decision block above already framed this same chunk, so
    // each request byte is framed exactly once. Only active on the poolable buffered path; a no-op
    // once a splice engages.
    if (!request_framed_here) {
      feedFrameTracker(data, /*from_upstream=*/false);
    }
    getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(data.length());
    upstream_->encodeData(data, end_stream);
    upstream_write_started_ = true;
    resetIdleTimer(); // TODO(ggreenway) PERF: do we need to reset timer on both send and receive?
  } else if (receive_before_connect_) {
    // Buffer data received before upstream connection exists.
    early_data_buffer_.move(data);

    // Track end_stream even if buffer is empty so we can propagate it to upstream later.
    if (!early_data_end_stream_) {
      early_data_end_stream_ = end_stream;
    }

    // Mark that we've received initial data and trigger connection if needed.
    // Don't trigger connection if downstream is closing without sending any data.
    if (!initial_data_received_ && !(end_stream && early_data_buffer_.length() == 0)) {
      initial_data_received_ = true;
      // For ON_DOWNSTREAM_DATA mode, establish the upstream connection now.
      if (connect_mode_ == UpstreamConnectMode::ON_DOWNSTREAM_DATA) {
        ENVOY_CONN_LOG(debug,
                       "Initial data received, establishing upstream connection. "
                       "early_data_buffer_.length()={}",
                       read_callbacks_->connection(), early_data_buffer_.length());
        // Route should already be set in onNewConnection().
        ASSERT(route_ != nullptr);
        establishUpstreamConnection();
      }
    }

    // Read-disable downstream when receiving early data to prevent excessive buffering.
    // For legacy mode (max_buffered_bytes_ == 0), always read-disable (backward compatibility).
    // For new API, read-disable only when buffer exceeds limit to prevent excessive memory usage.
    // Note: We track read_disabled_due_to_buffer_ to know whether to re-enable reading
    // when the upstream connection is established.
    if (early_data_buffer_.length() >= max_buffered_bytes_) {
      // Read-disable when buffer exceeds limit to prevent excessive memory usage.
      // Note: For legacy mode (max_buffered_bytes_ == 0), this will always trigger.
      ENVOY_CONN_LOG(debug, "Early data buffer exceeded max size {}, read-disabling downstream",
                     read_callbacks_->connection(), max_buffered_bytes_);
      read_callbacks_->connection().readDisable(true);
      read_disabled_due_to_buffer_ = true;
    }

    config_->stats().early_data_received_count_total_.inc();
  }
  // The upstream should consume all of the data.
  // Before there is an upstream the connection should be readDisabled. If the upstream is
  // destroyed, there should be no further reads as well.
  ASSERT(0 == data.length());
  maybeCloseDownstreamForDrainClose();
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onNewConnection() {
  const auto& max_downstream_connection_duration =
      config_->calculateMaxDownstreamConnectionDurationWithJitter();
  if (max_downstream_connection_duration) {
    connection_duration_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { onMaxDownstreamConnectionDuration(); });
    connection_duration_timer_->enableTimer(max_downstream_connection_duration.value());
  }

  if (config_->accessLogFlushInterval().has_value()) {
    access_log_flush_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { onAccessLogFlushInterval(); });
    resetAccessLogFlushTimer();
  }

  idle_timeout_ = config_->idleTimeout();
  if (const auto* per_connection_idle_timeout =
          getStreamInfo().filterState()->getDataReadOnly<StreamInfo::UInt64Accessor>(
              PerConnectionIdleTimeoutMs);
      per_connection_idle_timeout != nullptr) {
    idle_timeout_ = std::chrono::milliseconds(per_connection_idle_timeout->value());
  }

  if (idle_timeout_) {
    // The idle_timer_ can be moved to a Drainer, so related callbacks call into
    // the UpstreamCallbacks, which has the same lifetime as the timer, and can dispatch
    // the call to either TcpProxy or to Drainer, depending on the current state.
    idle_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [upstream_callbacks = upstream_callbacks_]() { upstream_callbacks->onIdleTimeout(); });

    // Start the idle timer immediately so that if no response is received from the upstream,
    // the downstream connection will time out.
    resetIdleTimer();
  }

  // Set UUID for the connection. This is used for logging and tracing.
  getStreamInfo().setStreamIdProvider(
      std::make_shared<StreamInfo::StreamIdProviderImpl>(config_->randomGenerator().uuid()));
  if (config_->flushAccessLogOnStart()) {
    flushAccessLog(AccessLog::AccessLogType::TcpConnectionStart);
  }

  ASSERT(upstream_ == nullptr);

  // Check if we should delay upstream connection establishment.
  if (connect_mode_ == UpstreamConnectMode::IMMEDIATE) {
    // Immediate connection establishment. This is the default behavior.
    route_ = pickRoute();
    return establishUpstreamConnection();
  }

  // For ON_DOWNSTREAM_DATA or ON_DOWNSTREAM_TLS_HANDSHAKE modes, delay the connection.
  // Pre-pick the route so it's available when connection is triggered.
  route_ = pickRoute();

  // Log the specific delay reason.
  if (connect_mode_ == UpstreamConnectMode::ON_DOWNSTREAM_DATA) {
    ENVOY_CONN_LOG(debug, "Delaying upstream connection establishment until initial data received",
                   read_callbacks_->connection());
  } else if (connect_mode_ == UpstreamConnectMode::ON_DOWNSTREAM_TLS_HANDSHAKE) {
    ENVOY_CONN_LOG(debug,
                   "Delaying upstream connection establishment until TLS handshake completes",
                   read_callbacks_->connection());
  }

  // Use receive_before_connect_ to determine whether to continue reading or stop iteration.
  return receive_before_connect_ ? Network::FilterStatus::Continue
                                 : Network::FilterStatus::StopIteration;
}

bool Filter::startUpstreamSecureTransport() {
  bool switched_to_tls = upstream_->startUpstreamSecureTransport();
  if (switched_to_tls) {
    StreamInfo::UpstreamInfo& upstream_info = *getStreamInfo().upstreamInfo();
    upstream_info.setUpstreamSslConnection(upstream_->getUpstreamConnectionSslInfo());
  }
  return switched_to_tls;
}

void Filter::onDownstreamEvent(Network::ConnectionEvent event) {
  // Handle TLS handshake completion for connections where we're waiting for it.
  if (event == Network::ConnectionEvent::Connected && waiting_for_tls_handshake_) {
    // The Connected event for SSL connections is fired after TLS handshake completes.
    ENVOY_CONN_LOG(debug, "downstream TLS handshake completed via Connected event",
                   read_callbacks_->connection());
    onDownstreamTlsHandshakeComplete();
    return;
  }

  // A downstream close while a splice is engaged tears the pump down and force-closes the hijacked
  // upstream before its fd is released, so the code below discards it instead of draining it.
  if ((event == Network::ConnectionEvent::RemoteClose ||
       event == Network::ConnectionEvent::LocalClose) &&
      splice_pump_ != nullptr) {
    tearDownSplice();
  }

  if (event == Network::ConnectionEvent::LocalClose ||
      event == Network::ConnectionEvent::RemoteClose) {
    downstream_closed_ = true;
    // Cancel the potential odcds callback.
    cluster_discovery_handle_ = nullptr;
  }

  ENVOY_CONN_LOG(trace, "on downstream event {}, has upstream = {}", read_callbacks_->connection(),
                 static_cast<int>(event), upstream_ != nullptr);

  if (upstream_) {
    absl::string_view downstream_close_details = read_callbacks_->connection().localCloseReason();
    Tcp::ConnectionPool::ConnectionDataPtr conn_data(
        upstream_->onDownstreamEvent(event, downstream_close_details));
    if (conn_data != nullptr &&
        conn_data->connection().state() != Network::Connection::State::Closed) {
      config_->drainManager().add(config_->sharedConfig(), std::move(conn_data),
                                  std::move(upstream_callbacks_), std::move(idle_timer_),
                                  idle_timeout_, read_callbacks_->upstreamHost());
    }
    if (event == Network::ConnectionEvent::LocalClose ||
        event == Network::ConnectionEvent::RemoteClose) {
      upstream_.reset();
      disableIdleTimer();
    }
  }

  if (generic_conn_pool_) {
    if (event == Network::ConnectionEvent::LocalClose ||
        event == Network::ConnectionEvent::RemoteClose) {
      // Cancel the conn pool request and close any excess pending requests.
      generic_conn_pool_.reset();
    }
  }
}

void Filter::onUpstreamData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "upstream connection received {} bytes, end_stream={}",
                 read_callbacks_->connection(), data.length(), end_stream);
  // L4 kernel-splice fast-path. On the first upstream data, once the upstream rustls socket has
  // installed kTLS, which happens lazily on its first read, detach both sockets and hand them to a
  // SplicePump that moves bytes in-kernel and bypasses the userspace buffers and filter chain.
  // Engaging here rather than at pool-ready guarantees kTLS is installed. Falls back transparently
  // when ineligible.
  // splicePermitted() keeps the pool path on the buffered relay: an adopted warm connection and a
  // connection routed to the buffered pool path (a small upload) never splice the response, so they
  // stay returnable. A GET/HEAD download, a large upload's response, or any connection the pool
  // feature never armed splices as before.
  if (splice_pump_ == nullptr && splicePermitted() && !end_stream && upstream_ != nullptr) {
    OptRef<Network::Connection> up = upstream_->upstreamConnection();
    if (up.has_value()) {
      // We only ever query the upstream leg, so info->trusted_peer is always true here. It is kept
      // as a defensive invariant so a future caller cannot splice an untrusted downstream socket.
      OptRef<const Network::KtlsBytestreamInfo> info = up->ktlsBytestreamInfo();
      if (info.has_value() && info->installed && info->trusted_peer &&
          read_callbacks_->connection().state() == Network::Connection::State::Open &&
          maybeEngageSplice(data, /*from_upstream=*/true)) {
        // Engaged. The pump now owns both sockets and accounts the bytes including this chunk.
        return;
      }
      // Not engaged because it is ineligible or setup failed. `data` is untouched and the buffered
      // path below handles it.
    }
  }
  // An upstream half-close (end_stream) means the peer is tearing the connection down -- it is not
  // reusable, so it must not be pooled. The pool's check-in MSG_PEEK clean-check would also catch a
  // FIN'd socket, but drop the tracker up front to skip the wasted check-in attempt.
  if (end_stream && frame_tracker_ != nullptr) {
    frame_tracker_.reset();
    pool_eligible_ = false;
  }
  // Observe the response-direction bytes for HTTP/1.1 framing before they are written downstream
  // (write drains `data`). Only active on the poolable buffered path; a no-op once a splice
  // engages. When the tracker reports ExchangeComplete this checks the warm connection back into
  // the pool, which nulls upstream_. The code below this point only touches the downstream
  // connection and the byte meters (not upstream_), so a null upstream_ after check-in is fine;
  // `data` is still the response chunk to forward downstream.
  feedFrameTracker(data, /*from_upstream=*/true);
  getStreamInfo().getUpstreamBytesMeter()->addWireBytesReceived(data.length());
  getStreamInfo().getDownstreamBytesMeter()->addWireBytesSent(data.length());
  read_callbacks_->connection().write(data, end_stream);
  ASSERT(0 == data.length());
  resetIdleTimer(); // TODO(ggreenway) PERF: do we need to reset timer on both send and receive?
  maybeCloseDownstreamForDrainClose();
}

void Filter::maybeCloseDownstreamForDrainClose() {
  if (!config_->checkDrainClose() || downstream_closed_ ||
      read_callbacks_->connection().state() != Network::Connection::State::Open ||
      !config_->drainDecision().drainClose(config_->drainCloseScope())) {
    return;
  }

  ENVOY_CONN_LOG(debug, "drain closing tcp_proxy connection", read_callbacks_->connection());
  config_->stats().downstream_cx_drain_close_.inc();
  read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite,
                                      StreamInfo::LocalCloseReasons::get().TcpProxyDrainClose);
}

bool Filter::maybeEngageSplice(Buffer::Instance& data, bool from_upstream) {
  Network::Connection& down = read_callbacks_->connection();
  OptRef<Network::Connection> up = upstream_->upstreamConnection();
  ASSERT(up.has_value());
  // Both legs must be real OS sockets. An internal-listener connection uses a user-space IoHandle
  // with no fd to splice on, so fall back to the buffered path before touching the fds.
  if (down.connectionInfoProvider().localAddress()->type() ==
          Network::Address::Type::EnvoyInternal ||
      up->connectionInfoProvider().localAddress()->type() ==
          Network::Address::Type::EnvoyInternal) {
    return false;
  }
  const os_fd_t down_fd = down.getSocket()->ioHandle().fdDoNotUse();
  const os_fd_t up_fd = up->getSocket()->ioHandle().fdDoNotUse();
  if (down_fd == INVALID_SOCKET || up_fd == INVALID_SOCKET) {
    return false;
  }
  // Do not engage while the upstream write buffer is backed up. The pump relays the request and
  // upload direction straight from the downstream socket and cannot see bytes still queued in the
  // upstream connection write buffer, so engaging under write backpressure would strand them. The
  // download pattern this targets flushes the request before the response arrives.
  if (up->aboveHighWatermark()) {
    ENVOY_CONN_LOG(debug, "L4 splice skip: upstream above high watermark", down);
    return false;
  }
  auto pump = std::make_unique<SplicePump>(
      down_fd, up_fd, /*up_is_ktls=*/true, down.dispatcher(),
      [this](Network::ConnectionEvent event) { onSpliceComplete(event); },
      [this](uint64_t n) {
        getStreamInfo().getUpstreamBytesMeter()->addWireBytesReceived(n);
        getStreamInfo().getDownstreamBytesMeter()->addWireBytesSent(n);
        resetIdleTimer();
      },
      [this](uint64_t n) {
        getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(n);
        getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(n);
        resetIdleTimer();
      });
  // Phase 1 is fallible setup, the pipe and the queued pre-engage chunk, run before detaching
  // anything. On failure the connection stays on the buffered path with `data` untouched. Route
  // the pre-engage chunk to its destination by direction.
  std::string initial = data.toString();
  std::string init_u2d;
  std::string init_d2u;
  if (from_upstream) {
    init_u2d = std::move(initial);
  } else {
    init_d2u = std::move(initial);
  }
  if (!pump->prepare(std::move(init_u2d), std::move(init_d2u))) {
    ENVOY_CONN_LOG(warn, "L4 splice setup failed, staying on buffered path", down);
    return false;
  }
  // Commit. Consume the chunk the pump now owns, then remove both ConnectionImpl FileEvents so the
  // pump is the only FileEvent on each fd. Removing rather than disabling matters because a
  // disabled second registration drops the next connection's edges after fd reuse and wedges its
  // handshake. Nulling file_event_ is safe because tearDownSplice closes with NoFlush and never
  // enters the write path that would touch it.
  data.drain(data.length());
  down.getSocket()->ioHandle().resetFileEvents();
  up->getSocket()->ioHandle().resetFileEvents();
  splice_pump_ = std::move(pump);
  splice_pump_->arm();
  config_->stats().splice_pump_active_.inc();
  config_->stats().splice_pump_engaged_total_.inc();
  ENVOY_CONN_LOG(debug, "L4 kernel-splice fast-path engaged (down_fd={}, up_fd={})", down, down_fd,
                 up_fd);
  return true;
}

void Filter::tearDownSplice() {
  if (splice_pump_ == nullptr) {
    return;
  }
  // Reset the pump first so its FileEvents and pipes are gone before the socket fds close.
  splice_pump_.reset();
  config_->stats().splice_pump_active_.dec();
  config_->stats().splice_pump_torndown_total_.inc();
  if (upstream_ == nullptr) {
    return;
  }
  // The pump hijacked the upstream socket with raw fds and removed its FileEvents, so the
  // connection must not be reused. Force it closed with NoFlush. That marks it Closed before the
  // pool or drain manager inspects it, so both discard it instead of re-arming the removed event,
  // and NoFlush keeps the close off the write path. A spliced connection therefore always closes
  // gracefully, so an upstream RST is reported downstream as a normal close rather than a reset.
  OptRef<Network::Connection> up = upstream_->upstreamConnection();
  if (up.has_value() && up->state() != Network::Connection::State::Closed) {
    up->close(Network::ConnectionCloseType::NoFlush);
  }
}

bool Filter::tryCheckoutPooledUpstream(absl::string_view host_key,
                                       const Upstream::HostDescriptionConstSharedPtr& host) {
  OptRef<UpstreamPool> pool = config_->upstreamPool();
  if (!pool.has_value()) {
    return false;
  }
  GenericUpstreamPtr upstream = pool->checkout(host_key);
  if (upstream == nullptr) {
    return false; // pool miss (or every warm entry was stale); fall back to a fresh connection.
  }

  // Adopt the warm connection. It already finished its TLS handshake and kTLS install on a previous
  // exchange, so this request pays neither cost. Re-point its read callbacks at THIS Filter -- the
  // connection outlived the Filter that minted it, and its callbacks still pointed at that (now
  // destroyed) object -- and re-enable reads, which were disabled at check-in to keep idle bytes
  // from being delivered to the dead Filter.
  upstream->rebindUpstreamCallbacks(*upstream_callbacks_);
  OptRef<Network::Connection> conn = upstream->upstreamConnection();
  if (conn.has_value()) {
    conn->readDisable(false);
  }
  upstream_ = std::move(upstream);
  adopted_from_pool_ = true;
  connecting_ = true;
  connect_attempts_++;
  getStreamInfo().setAttemptCount(connect_attempts_);

  StreamInfo::UpstreamInfo& upstream_info = *getStreamInfo().upstreamInfo();
  read_callbacks_->upstreamHost(host);
  upstream_info.setUpstreamHost(host);
  if (conn.has_value() && upstream_info.upstreamLocalAddress() == nullptr) {
    upstream_info.setUpstreamLocalAddress(conn->connectionInfoProvider().localAddress());
    upstream_info.setUpstreamRemoteAddress(conn->connectionInfoProvider().remoteAddress());
  }
  upstream_info.setUpstreamSslConnection(upstream_->getUpstreamConnectionSslInfo());

  ENVOY_CONN_LOG(debug, "tcp_proxy: adopted warm pooled upstream for {}",
                 read_callbacks_->connection(), host_key);
  // Drive the same post-connect path the fresh-connection callback uses: flush any early data,
  // re-enable downstream reads, arm idle/bytes-sent callbacks, and resume the read filter chain.
  onUpstreamConnection();
  read_callbacks_->continueReading();
  return true;
}

namespace {
// Phase-2 pool routing threshold. An upload (PUT/POST body) at or below this many bytes takes the
// buffered, poolable path so its connection can be reused across the high request churn that makes
// the per-request TLS+kTLS handshake dominate; a larger upload takes the L4 splice fast-path, where
// the in-kernel zero-copy of the body dominates and 1:1 connection churn is negligible. 1 MiB sits
// between the small-object PUT churn workload (<=256 KiB) and the large-object PUT workload
// (>=4 MiB).
constexpr uint64_t kPoolMaxUploadBytes = 1024 * 1024;
} // namespace

bool Filter::splicePermitted() const {
  // An adopted warm connection must stay on the buffered path so it remains returnable to the pool.
  if (adopted_from_pool_) {
    return false;
  }
  // A connection the pool feature never armed splices exactly as it did before Phase 2 (this is the
  // feature-off production path, which must stay byte-for-byte identical).
  if (!pool_eligible_) {
    return true;
  }
  // A fresh pool-eligible connection holds the splice off until its first request is framed and
  // routed, then splices only if it routed away from the buffered pool path (a GET/HEAD or a large
  // upload). A small upload keeps route_buffered_for_pool_ set and never splices.
  return pool_route_decided_ && !route_buffered_for_pool_;
}

void Filter::maybePickPoolRoute() {
  if (pool_route_decided_ || !pool_eligible_ || frame_tracker_ == nullptr) {
    return;
  }
  // Decide only once the request line + headers are in (method and Content-Length known). While the
  // headers are still arriving, stay undecided -- splicePermitted() holds the splice off meanwhile,
  // so a small upload is never spliced before its size can be read.
  if (!frame_tracker_->requestHeadersParsed()) {
    return;
  }
  pool_route_decided_ = true;
  const absl::string_view method = frame_tracker_->requestMethod();
  const uint64_t upload_bytes = frame_tracker_->requestContentLength();
  const bool small_upload = (method == "PUT" || method == "POST") && upload_bytes > 0 &&
                            upload_bytes <= kPoolMaxUploadBytes;
  if (small_upload) {
    // Keep this exchange on the buffered, returnable path. The frame tracker keeps observing it;
    // when it reaches ExchangeComplete the connection checks back into the warm pool.
    route_buffered_for_pool_ = true;
    ENVOY_CONN_LOG(debug, "tcp_proxy: routing {}-byte {} upload to buffered pool path",
                   read_callbacks_->connection(), upload_bytes, method);
    return;
  }
  // A GET/HEAD, a zero-body request, or a large upload: prefer the L4 splice fast-path. Abandon the
  // pool path so splicePermitted() lets the splice engage and we never try to check this connection
  // in. (HEAD/DELETE and smuggling requests were already dropped to NotPoolable by
  // feedFrameTracker, which cleared pool_eligible_ before we got here.)
  route_buffered_for_pool_ = false;
  frame_tracker_.reset();
  pool_eligible_ = false;
  ENVOY_CONN_LOG(debug, "tcp_proxy: routing {} request to L4 splice fast-path",
                 read_callbacks_->connection(), method);
}

void Filter::feedFrameTracker(const Buffer::Instance& data, bool from_upstream) {
  // The buffered relay is the only poolable path: a spliced connection's fd is hijacked by the pump
  // and can never be returned (see UPSTREAM_POOL_DESIGN.md "Coexistence"). So once a splice
  // engages, abandon framing/pooling for this connection. Likewise skip when the pool path was
  // never armed.
  if (!pool_eligible_ || frame_tracker_ == nullptr) {
    return;
  }
  if (splice_pump_ != nullptr) {
    // A splice engaged after we started framing: this connection is no longer returnable. Drop the
    // tracker so we neither frame nor check it in; teardown closes it as a normal spliced upstream.
    frame_tracker_.reset();
    pool_eligible_ = false;
    return;
  }
  if (data.length() == 0) {
    return;
  }

  // Feed the bytes as they flow on the buffered path, slice by slice. getRawSlices() is const and
  // does not coalesce or consume the buffer, so the tracker stays a pure observer that never
  // mutates the relay's data. Feed EVERY slice (do not stop at the first ExchangeComplete):
  // trailing bytes in a later slice are pipelined/smuggled data that the tracker must see and
  // reject. Stop only on NotPoolable, which is sticky. The final verdict is what we act on.
  HttpFrameTracker::Verdict verdict = frame_tracker_->verdict();
  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    if (slice.len_ == 0) {
      continue;
    }
    const absl::string_view view(static_cast<const char*>(slice.mem_), slice.len_);
    verdict =
        from_upstream ? frame_tracker_->onResponseData(view) : frame_tracker_->onRequestData(view);
    if (verdict == HttpFrameTracker::Verdict::NotPoolable) {
      break;
    }
  }

  if (verdict == HttpFrameTracker::Verdict::NotPoolable) {
    // A framing/smuggling signal, or a non-Content-Length-framable exchange. Never pool this
    // connection; let the normal teardown close it.
    ENVOY_CONN_LOG(debug, "tcp_proxy: upstream not poolable ({}), abandoning pool path",
                   read_callbacks_->connection(), frame_tracker_->notPoolableReason());
    frame_tracker_.reset();
    pool_eligible_ = false;
    return;
  }
  if (verdict == HttpFrameTracker::Verdict::ExchangeComplete) {
    maybeCheckinPooledUpstream();
  }
}

void Filter::maybeCheckinPooledUpstream() {
  if (!pool_eligible_ || checked_in_to_pool_ || upstream_ == nullptr || frame_tracker_ == nullptr) {
    return;
  }
  if (frame_tracker_->verdict() != HttpFrameTracker::Verdict::ExchangeComplete) {
    return;
  }
  // Defensive: a spliced connection is never returnable. feedFrameTracker already drops the tracker
  // when a splice engages, but guard here too because check-in transfers ownership.
  if (splice_pump_ != nullptr) {
    return;
  }

  OptRef<UpstreamPool> pool = config_->upstreamPool();
  if (!pool.has_value()) {
    return;
  }

  // Read-disable the upstream before releasing it so no read event fires on the dead-Filter
  // callbacks during the idle window between check-in and the next checkout (checkout rebinds and
  // re-enables). The pool's check-in clean-check (MSG_PEEK) and the checkout clean-check both run
  // on the raw ioHandle, independent of this read-disable.
  OptRef<Network::Connection> conn = upstream_->upstreamConnection();
  if (conn.has_value()) {
    conn->readDisable(true);
  }

  // Transfer ownership to the pool. Null upstream_ FIRST (release the unique_ptr) so ~Filter does
  // not close the connection -- the pool now owns the close. This is the ownership invariant the
  // design calls out: mis-release is a double-close / UAF.
  checked_in_to_pool_ = true;
  disableIdleTimer();
  GenericUpstreamPtr upstream = std::move(upstream_);
  ASSERT(upstream_ == nullptr);
  ENVOY_CONN_LOG(debug, "tcp_proxy: checking warm upstream back into pool for {}",
                 read_callbacks_->connection(), pool_host_key_);
  pool->checkin(pool_host_key_, std::move(upstream), /*is_clean=*/true);
  pool_eligible_ = false;
  frame_tracker_.reset();
}

void Filter::onSpliceComplete(Network::ConnectionEvent event) {
  ENVOY_CONN_LOG(debug, "L4 splice complete, scheduling teardown", read_callbacks_->connection());
  splice_complete_event_ = event;
  // Defer teardown via a member callback. It must not destroy the pump synchronously from inside
  // the pump's own FileEvent callback, and a Filter destroyed before it fires cancels it.
  if (splice_complete_schedulable_ == nullptr) {
    splice_complete_schedulable_ =
        read_callbacks_->connection().dispatcher().createSchedulableCallback([this]() {
          tearDownSplice();
          // tearDownSplice closed the upstream, whose close event drives onUpstreamEvent and
          // resets upstream_. If the upstream was already gone it did not, so drive teardown here.
          if (upstream_ != nullptr) {
            onUpstreamEvent(splice_complete_event_);
          }
        });
  }
  splice_complete_schedulable_->scheduleCallbackNextIteration();
}

namespace {
// Upper bound on per-iteration retries waiting for the upstream kTLS to install before splicing a
// held PUT body. The install completes within a handful of dispatcher iterations after the
// handshake; the cap only guards a connection that never installs, in which case the held body is
// flushed on the normal path.
constexpr uint32_t kMaxKtlsEngageAttempts = 64;
} // namespace

void Filter::onKtlsEngageRetry() {
  if (splice_pump_ != nullptr || upstream_ == nullptr) {
    return;
  }
  ++ktls_engage_attempts_;
  OptRef<Network::Connection> up = upstream_->upstreamConnection();
  if (up.has_value() && read_callbacks_->connection().state() == Network::Connection::State::Open) {
    OptRef<const Network::KtlsBytestreamInfo> info = up->ktlsBytestreamInfo();
    // Engage only when kTLS is installed AND the upstream is not backed up, so the buffered request
    // headers have flushed and the spliced body cannot reorder ahead of them.
    if (info.has_value() && info->installed && info->trusted_peer && !up->aboveHighWatermark() &&
        maybeEngageSplice(deferred_upload_buffer_, /*from_upstream=*/false)) {
      return; // engaged; the pump owns the held body and the raw fds.
    }
    if (ktls_engage_attempts_ < kMaxKtlsEngageAttempts) {
      ktls_engage_schedulable_->scheduleCallbackNextIteration();
      return;
    }
  }
  // Exhausted (kTLS never installed) or the connection closed: flush the held body on the normal
  // path so the upload still completes -- no worse than before -- and re-enable downstream reads.
  if (upstream_ != nullptr && deferred_upload_buffer_.length() > 0) {
    getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(deferred_upload_buffer_.length());
    upstream_->encodeData(deferred_upload_buffer_, /*end_stream=*/false);
  }
  if (read_callbacks_->connection().state() == Network::Connection::State::Open) {
    read_callbacks_->connection().readDisable(false);
  }
}

void Filter::onUpstreamEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::ConnectedZeroRtt) {
    return;
  }
  // Defensive. If a splice is still engaged when an upstream close arrives, reset the pump before
  // the fd is released below so its FileEvents never outlive the socket. The normal teardown paths
  // already reset the pump first, so this only matters if some other path closes the upstream
  // directly. tearDownSplice is idempotent and a no-op when no splice is engaged.
  if ((event == Network::ConnectionEvent::RemoteClose ||
       event == Network::ConnectionEvent::LocalClose) &&
      splice_pump_ != nullptr) {
    tearDownSplice();
  }
  // Update the connecting flag before processing the event because we may start a new connection
  // attempt in establishUpstreamConnection.
  bool connecting = connecting_;
  connecting_ = false;

  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    // Propagate the upstream local close reason to the downstream stream info's upstreamInfo.
    if (upstream_) {
      getStreamInfo().upstreamInfo()->setUpstreamLocalCloseReason(upstream_->localCloseReason());
    }
    // Capture upstream detected close type before upstream is moved/reset.
    const auto upstream_detected_close_type =
        upstream_ ? upstream_->detectedCloseType() : StreamInfo::DetectedCloseType::Normal;
    if (Runtime::runtimeFeatureEnabled(
            "envoy.restart_features.upstream_http_filters_with_tcp_proxy")) {
      read_callbacks_->connection().dispatcher().deferredDelete(std::move(upstream_));
    } else if (upstream_) {
      getStreamInfo().upstreamInfo()->setUpstreamDetectedCloseType(upstream_detected_close_type);
      upstream_.reset();
    }
    disableIdleTimer();

    if (connecting) {
      if (event == Network::ConnectionEvent::RemoteClose) {
        getStreamInfo().setResponseFlag(StreamInfo::UpstreamConnectionFailure);
        // upstreamHost can be nullptr if we received a disconnect from the upstream before
        // receiving any response
        if (read_callbacks_->upstreamHost() != nullptr) {
          read_callbacks_->upstreamHost()->outlierDetector().putResult(
              Upstream::Outlier::Result::LocalOriginConnectFailed);
        }
      }
      if (!downstream_closed_) {
        // Always defer retry to a different event loop iteration via the retry timer.
        if (connect_attempts_ >= config_->maxConnectAttempts()) {
          onConnectMaxAttempts();
          return;
        }

        enableRetryTimer();
      }
    } else {
      if (read_callbacks_->connection().state() == Network::Connection::State::Open) {
        // Propagate upstream RST to downstream.
        if (upstream_detected_close_type == StreamInfo::DetectedCloseType::RemoteReset &&
            Runtime::runtimeFeatureEnabled("envoy.reloadable_features."
                                           "propagate_upstream_rst_through_tunneled_tcp_proxy")) {
          ENVOY_CONN_LOG(trace, "TCP:onUpstreamEvent(): propagating upstream RST to downstream",
                         read_callbacks_->connection());
          getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::UpstreamRemoteReset);
          read_callbacks_->connection().close(Network::ConnectionCloseType::AbortReset);
        } else {
          read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
        }
      }
    }
  }
}

void Filter::onConnectMaxAttempts() {
  getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::UpstreamRetryLimitExceeded);
  const std::string& cluster_name = route_ ? route_->clusterName() : EMPTY_STRING;
  Upstream::ThreadLocalCluster* thread_local_cluster =
      cluster_manager_.getThreadLocalCluster(cluster_name);
  if (thread_local_cluster) {
    thread_local_cluster->info()->trafficStats()->upstream_cx_connect_attempts_exceeded_.inc();
  }

  onInitFailure(UpstreamFailureReason::ConnectFailed);
}

void Filter::onUpstreamConnection() {
  connecting_ = false;

  // If we have received any data before upstream connection is established, or if the downstream
  // has indicated end of stream, send the data and/or end_stream to the upstream connection.
  if (early_data_buffer_.length() > 0 || early_data_end_stream_) {
    // Early data should only happen when receive_before_connect is enabled.
    ASSERT(receive_before_connect_);

    if (early_data_buffer_.length() > 0) {
      getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(early_data_buffer_.length());
    }
    upstream_->encodeData(early_data_buffer_, early_data_end_stream_);
    // Early data went upstream on the buffered path, so the upload-splice can no longer engage
    // without risking reordering ahead of these bytes.
    upstream_write_started_ = true;
    // Those request bytes bypassed the frame tracker (they flushed straight to the upstream), so
    // this exchange can no longer be framed for pooling. Abandon the pool path: with pool_eligible_
    // cleared the connection relays buffered and is never checked in. On a FRESH (non-adopted)
    // connection a later large-upload chunk may still splice via splicePermitted(); an adopted
    // connection stays buffered (splicePermitted() short-circuits on adopted_from_pool_). Pre-empt
    // maybePickPoolRoute too.
    if (pool_eligible_) {
      pool_eligible_ = false;
      pool_route_decided_ = true;
      frame_tracker_.reset();
    }
    ASSERT(0 == early_data_buffer_.length());
  }

  // Re-enable downstream reads if we disabled reading.
  // Reading can be disabled in two cases:
  // 1. Buffer overflow when receive_before_connect is enabled (tracked by
  // read_disabled_due_to_buffer_)
  // 2. In establishUpstreamConnection() when receive_before_connect is disabled
  if (read_disabled_due_to_buffer_) {
    read_callbacks_->connection().readDisable(false);
    read_disabled_due_to_buffer_ = false;
  } else if (!receive_before_connect_) {
    // Re-enable downstream reads that were disabled in establishUpstreamConnection()
    // when early data reception was NOT enabled.
    read_callbacks_->connection().readDisable(false);
  }

  read_callbacks_->upstreamHost()->outlierDetector().putResult(
      Upstream::Outlier::Result::LocalOriginConnectSuccessFinal);

  ENVOY_CONN_LOG(debug, "TCP:onUpstreamEvent(), requestedServerName: {}",
                 read_callbacks_->connection(),
                 getStreamInfo().downstreamAddressProvider().requestedServerName());

  if (idle_timeout_) {
    resetIdleTimer();
    read_callbacks_->connection().addBytesSentCallback([this](uint64_t) {
      resetIdleTimer();
      return true;
    });
    if (upstream_) {
      upstream_->addBytesSentCallback([upstream_callbacks = upstream_callbacks_](uint64_t) -> bool {
        upstream_callbacks->onBytesSent();
        return true;
      });
    }
  }

  if (config_->flushAccessLogOnConnected()) {
    flushAccessLog(AccessLog::AccessLogType::TcpUpstreamConnected);
  }
}

void Filter::onIdleTimeout() {
  ENVOY_CONN_LOG(debug, "Session timed out", read_callbacks_->connection());
  config_->stats().idle_timeout_.inc();

  // Closing the downstream also closes the upstream. When a splice is engaged onDownstreamEvent
  // tears the pump down and force-closes the hijacked upstream.
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush,
                                      StreamInfo::LocalCloseReasons::get().TcpSessionIdleTimeout);
}

void Filter::onMaxDownstreamConnectionDuration() {
  ENVOY_CONN_LOG(debug, "max connection duration reached", read_callbacks_->connection());
  getStreamInfo().setResponseFlag(StreamInfo::CoreResponseFlag::DurationTimeout);
  config_->stats().max_downstream_connection_duration_.inc();
  // Closing the downstream tears down an engaged splice via onDownstreamEvent (see onIdleTimeout).
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::NoFlush,
      StreamInfo::LocalCloseReasons::get().MaxConnectionDurationReached);
}

void Filter::onAccessLogFlushInterval() {
  flushAccessLog(AccessLog::AccessLogType::TcpPeriodic);
  const SystemTime now = read_callbacks_->connection().dispatcher().timeSource().systemTime();
  getStreamInfo().getDownstreamBytesMeter()->takeDownstreamPeriodicLoggingSnapshot(now);
  if (getStreamInfo().getUpstreamBytesMeter()) {
    getStreamInfo().getUpstreamBytesMeter()->takeDownstreamPeriodicLoggingSnapshot(now);
  }
  resetAccessLogFlushTimer();
}

void Filter::flushAccessLog(AccessLog::AccessLogType access_log_type) {
  const Formatter::Context log_context{nullptr, nullptr, nullptr, {}, access_log_type};

  for (const auto& access_log : config_->accessLogs()) {
    access_log->log(log_context, getStreamInfo());
  }
}

void Filter::resetAccessLogFlushTimer() {
  if (access_log_flush_timer_ != nullptr) {
    ASSERT(config_->accessLogFlushInterval().has_value());
    access_log_flush_timer_->enableTimer(config_->accessLogFlushInterval().value());
  }
}

void Filter::disableAccessLogFlushTimer() {
  if (access_log_flush_timer_ != nullptr) {
    access_log_flush_timer_->disableTimer();
    access_log_flush_timer_.reset();
  }
}

void Filter::resetIdleTimer() {
  // Lazily (re)create the idle timer. It can be gone after a pooled check-in disabled+reset it, or
  // after a Drainer moved it out; without this, a reused/adopted-from-pool connection would run
  // with no idle-timeout protection and could wedge the pool.
  if (idle_timer_ == nullptr && idle_timeout_.has_value()) {
    idle_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [upstream_callbacks = upstream_callbacks_]() { upstream_callbacks->onIdleTimeout(); });
  }
  if (idle_timer_ != nullptr) {
    ASSERT(idle_timeout_);
    idle_timer_->enableTimer(idle_timeout_.value());
  }
}

void Filter::disableIdleTimer() {
  if (idle_timer_ != nullptr) {
    idle_timer_->disableTimer();
    idle_timer_.reset();
  }
}

void Filter::onRetryTimer() {
  route_ = pickRoute();
  establishUpstreamConnection();
}

void Filter::enableRetryTimer() {
  // Create the retry timer on the first retry.
  if (!retry_timer_) {
    retry_timer_ =
        read_callbacks_->connection().dispatcher().createTimer([this] { onRetryTimer(); });
  }

  // If the backoff strategy is not configured, the next backoff time will be 0.
  // This will allow the retry to happen on different event loop iteration, which
  // will allow the connection pool to be cleaned up from the previous closed connection.
  uint64_t next_backoff_ms = 0;

  if (config_->backoffStrategy()) {
    next_backoff_ms = config_->backoffStrategy()->nextBackOffMs();
  }

  retry_timer_->enableTimer(std::chrono::milliseconds(next_backoff_ms));
}

void Filter::disableRetryTimer() {
  if (retry_timer_ != nullptr) {
    retry_timer_->disableTimer();
    retry_timer_.reset();
  }
}

void Filter::onDownstreamTlsHandshakeComplete() {
  ENVOY_CONN_LOG(debug, "downstream TLS handshake complete", read_callbacks_->connection());
  tls_handshake_complete_ = true;
  waiting_for_tls_handshake_ = false;

  // For ON_DOWNSTREAM_TLS_HANDSHAKE mode, establish the upstream connection now.
  if (connect_mode_ == UpstreamConnectMode::ON_DOWNSTREAM_TLS_HANDSHAKE) {
    // Route should already be set in onNewConnection().
    ASSERT(route_ != nullptr);
    establishUpstreamConnection();
  }
}

Filter::HttpStreamDecoderFilterCallbacks::HttpStreamDecoderFilterCallbacks(Filter* parent)
    : parent_(parent), request_trailer_map_(Http::RequestTrailerMapImpl::create()) {}

UpstreamDrainManager::~UpstreamDrainManager() {
  // If connections aren't closed before they are destructed an ASSERT fires,
  // so cancel all pending drains, which causes the connections to be closed.
  if (!drainers_.empty()) {
    auto& dispatcher = drainers_.begin()->second->dispatcher();
    while (!drainers_.empty()) {
      auto begin = drainers_.begin();
      Drainer* key = begin->first;
      begin->second->cancelDrain();

      // cancelDrain() should cause that drainer to be removed from drainers_.
      // ASSERT so that we don't end up in an infinite loop.
      ASSERT(drainers_.find(key) == drainers_.end());
    }

    // This destructor is run when shutting down `ThreadLocal`. The destructor of some objects use
    // earlier `ThreadLocal` slots (for accessing the runtime snapshot) so they must run before that
    // slot is destructed. Clear the list to enforce that ordering.
    dispatcher.clearDeferredDeleteList();
  }
}

void UpstreamDrainManager::add(const Config::SharedConfigSharedPtr& config,
                               Tcp::ConnectionPool::ConnectionDataPtr&& upstream_conn_data,
                               const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks,
                               Event::TimerPtr&& idle_timer,
                               absl::optional<std::chrono::milliseconds> idle_timeout,
                               const Upstream::HostDescriptionConstSharedPtr& upstream_host) {
  DrainerPtr drainer(new Drainer(*this, config, callbacks, std::move(upstream_conn_data),
                                 std::move(idle_timer), idle_timeout, upstream_host));
  callbacks->drain(*drainer);

  // Use temporary to ensure we get the pointer before we move it out of drainer
  Drainer* ptr = drainer.get();
  drainers_[ptr] = std::move(drainer);
}

void UpstreamDrainManager::remove(Drainer& drainer, Event::Dispatcher& dispatcher) {
  auto it = drainers_.find(&drainer);
  ASSERT(it != drainers_.end());
  dispatcher.deferredDelete(std::move(it->second));
  drainers_.erase(it);
}

Drainer::Drainer(UpstreamDrainManager& parent, const Config::SharedConfigSharedPtr& config,
                 const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks,
                 Tcp::ConnectionPool::ConnectionDataPtr&& conn_data, Event::TimerPtr&& idle_timer,
                 absl::optional<std::chrono::milliseconds> idle_timeout,
                 const Upstream::HostDescriptionConstSharedPtr& upstream_host)
    : parent_(parent), callbacks_(callbacks), upstream_conn_data_(std::move(conn_data)),
      idle_timer_(std::move(idle_timer)), idle_timeout_(idle_timeout),
      upstream_host_(upstream_host), config_(config) {
  ENVOY_CONN_LOG(trace, "draining the upstream connection", upstream_conn_data_->connection());
  config_->stats().upstream_flush_total_.inc();
  config_->stats().upstream_flush_active_.inc();
}

void Drainer::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    if (idle_timer_ != nullptr) {
      idle_timer_->disableTimer();
    }
    config_->stats().upstream_flush_active_.dec();
    parent_.remove(*this, upstream_conn_data_->connection().dispatcher());
  }
}

void Drainer::onData(Buffer::Instance& data, bool) {
  if (data.length() > 0) {
    // There is no downstream connection to send any data to, but the upstream
    // sent some data. Try to behave similar to what the kernel would do
    // when it receives data on a connection where the application has closed
    // the socket or ::shutdown(fd, SHUT_RD), and close/reset the connection.
    cancelDrain();
  }
}

void Drainer::onIdleTimeout() {
  config_->stats().idle_timeout_.inc();
  cancelDrain();
}

void Drainer::onBytesSent() {
  if (idle_timer_ != nullptr) {
    idle_timer_->enableTimer(idle_timeout_.value());
  }
}

void Drainer::cancelDrain() {
  // This sends onEvent(LocalClose).
  upstream_conn_data_->connection().close(Network::ConnectionCloseType::NoFlush);
}

Event::Dispatcher& Drainer::dispatcher() { return upstream_conn_data_->connection().dispatcher(); }

} // namespace TcpProxy
} // namespace Envoy
