#include "source/common/tcp_proxy/tcp_proxy.h"

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/config/accesslog/v3/accesslog.pb.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.validate.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/upstream.h"

#include "source/common/access_log/access_log_impl.h"
#include "source/common/common/assert.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/fmt.h"
#include "source/common/common/macros.h"
#include "source/common/common/utility.h"
#include "source/common/config/metadata.h"
#include "source/common/config/utility.h"
#include "source/common/config/well_known_names.h"
#include "source/common/network/application_protocol.h"
#include "source/common/network/proxy_protocol_filter_state.h"
#include "source/common/network/socket_option_factory.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_socket_options_filter_state.h"
#include "source/common/router/metadatamatchcriteria_impl.h"
#include "source/common/stream_info/stream_id_provider_impl.h"

namespace Envoy {
namespace TcpProxy {

const std::string& PerConnectionCluster::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.cluster");
}

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

OnDemandStats OnDemandConfig::generateStats(Stats::Scope& scope) {
  return {ON_DEMAND_TCP_PROXY_STATS(POOL_COUNTER(scope))};
}

Config::SharedConfig::SharedConfig(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
    Server::Configuration::FactoryContext& context)
    : stats_scope_(context.scope().createScope(fmt::format("tcp.{}", config.stat_prefix()))),
      stats_(generateStats(*stats_scope_)),
      flush_access_log_on_connected_(config.flush_access_log_on_connected()) {
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
        std::make_unique<TunnelingConfigHelperImpl>(config.tunneling_config(), context);
  }
  if (config.has_max_downstream_connection_duration()) {
    const uint64_t connection_duration =
        DurationUtil::durationToMilliseconds(config.max_downstream_connection_duration());
    max_downstream_connection_duration_ = std::chrono::milliseconds(connection_duration);
  }

  if (config.has_access_log_flush_interval()) {
    const uint64_t flush_interval =
        DurationUtil::durationToMilliseconds(config.access_log_flush_interval());
    access_log_flush_interval_ = std::chrono::milliseconds(flush_interval);
  }

  if (config.has_on_demand() && config.on_demand().has_odcds_config()) {
    on_demand_config_ =
        std::make_unique<OnDemandConfig>(config.on_demand(), context, *stats_scope_);
  }
}

Config::Config(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
               Server::Configuration::FactoryContext& context)
    : max_connect_attempts_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, max_connect_attempts, 1)),
      upstream_drain_manager_slot_(context.threadLocal().allocateSlot()),
      shared_config_(std::make_shared<SharedConfig>(config, context)),
      random_generator_(context.api().randomGenerator()) {
  upstream_drain_manager_slot_->set([](Event::Dispatcher&) {
    ThreadLocal::ThreadLocalObjectSharedPtr drain_manager =
        std::make_shared<UpstreamDrainManager>();
    return drain_manager;
  });

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

UpstreamDrainManager& Config::drainManager() {
  return upstream_drain_manager_slot_->getTyped<UpstreamDrainManager>();
}

Filter::Filter(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager)
    : config_(config), cluster_manager_(cluster_manager), downstream_callbacks_(*this),
      upstream_callbacks_(new UpstreamCallbacks(this)) {
  ASSERT(config != nullptr);
}

Filter::~Filter() {
  // Disable access log flush timer if it is enabled.
  disableAccessLogFlushTimer();

  // Flush the final end stream access log entry.
  for (const auto& access_log : config_->accessLogs()) {
    access_log->log(nullptr, nullptr, nullptr, getStreamInfo());
  }

  ASSERT(generic_conn_pool_ == nullptr);
  ASSERT(upstream_ == nullptr);
}

TcpProxyStats Config::SharedConfig::generateStats(Stats::Scope& scope) {
  return {ALL_TCP_PROXY_STATS(POOL_COUNTER(scope), POOL_GAUGE(scope))};
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

  // Need to disable reads so that we don't write to an upstream that might fail
  // in onData(). This will get re-enabled when the upstream connection is
  // established.
  read_callbacks_->connection().readDisable(true);
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
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::NoFlush,
      absl::StrCat(StreamInfo::LocalCloseReasons::get().TcpProxyInitializationFailure,
                   enumToInt(reason)));
}

void Filter::readDisableUpstream(bool disable) {
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
  if (read_callbacks_->connection().state() != Network::Connection::State::Open) {
    // During idle timeouts, we close both upstream and downstream with NoFlush.
    // Envoy still does a best-effort flush which can case readDisableDownstream to be called
    // despite the downstream connection being closed.
    return;
  }
  read_callbacks_->connection().readDisable(disable);

  if (disable) {
    config_->stats().downstream_flow_control_paused_reading_total_.inc();
  } else {
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
  ASSERT(!on_high_watermark_called_);
  on_high_watermark_called_ = true;

  if (parent_ != nullptr) {
    // There's too much data buffered in the upstream write buffer, so stop reading.
    parent_->readDisableDownstream(true);
  }
}

void Filter::UpstreamCallbacks::onBelowWriteBufferLowWatermark() {
  ASSERT(on_high_watermark_called_);
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
  Upstream::ThreadLocalCluster* thread_local_cluster =
      cluster_manager_.getThreadLocalCluster(cluster_name);

  if (!thread_local_cluster) {
    auto odcds = config_->onDemandCds();
    if (!odcds.has_value()) {
      // No ODCDS? It means that on-demand discovery is disabled.
      ENVOY_CONN_LOG(debug, "Cluster not found {} and no on demand cluster set.",
                     read_callbacks_->connection(), cluster_name);
      config_->stats().downstream_cx_no_route_.inc();
      getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::NoClusterFound);
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

  const Upstream::ClusterInfoConstSharedPtr& cluster = thread_local_cluster->info();
  getStreamInfo().setUpstreamClusterInfo(cluster);

  // Check this here because the TCP conn pool will queue our request waiting for a connection that
  // will never be released.
  if (!cluster->resourceManager(Upstream::ResourcePriority::Default).connections().canCreate()) {
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamOverflow);
    cluster->trafficStats()->upstream_cx_overflow_.inc();
    onInitFailure(UpstreamFailureReason::ResourceLimitExceeded);
    return Network::FilterStatus::StopIteration;
  }

  const uint32_t max_connect_attempts = config_->maxConnectAttempts();
  if (connect_attempts_ >= max_connect_attempts) {
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamRetryLimitExceeded);
    cluster->trafficStats()->upstream_cx_connect_attempts_exceeded_.inc();
    onInitFailure(UpstreamFailureReason::ConnectFailed);
    return Network::FilterStatus::StopIteration;
  }

  auto& downstream_connection = read_callbacks_->connection();
  auto& filter_state = downstream_connection.streamInfo().filterState();
  if (!filter_state->hasData<Network::ProxyProtocolFilterState>(
          Network::ProxyProtocolFilterState::key())) {
    filter_state->setData(
        Network::ProxyProtocolFilterState::key(),
        std::make_shared<Network::ProxyProtocolFilterState>(Network::ProxyProtocolData{
            downstream_connection.connectionInfoProvider().remoteAddress(),
            downstream_connection.connectionInfoProvider().localAddress()}),
        StreamInfo::FilterState::StateType::ReadOnly,
        StreamInfo::FilterState::LifeSpan::Connection);
  }
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
    // Either cluster is unknown or there are no healthy hosts. tcpConnPool() increments
    // cluster->trafficStats()->upstream_cx_none_healthy in the latter case.
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::NoHealthyUpstream);
    onInitFailure(UpstreamFailureReason::NoHealthyUpstream);
  }
  return Network::FilterStatus::StopIteration;
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
  getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::NoClusterFound);
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

  generic_conn_pool_ = factory->createGenericConnPool(cluster, config_->tunnelingConfigHelper(),
                                                      this, *upstream_callbacks_, getStreamInfo());
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
  generic_conn_pool_.reset();
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
  upstream_ = std::move(upstream);
  generic_conn_pool_.reset();
  read_callbacks_->upstreamHost(host);
  StreamInfo::UpstreamInfo& upstream_info = *getStreamInfo().upstreamInfo();
  upstream_info.setUpstreamHost(host);
  upstream_info.setUpstreamLocalAddress(address_provider.localAddress());
  upstream_info.setUpstreamRemoteAddress(address_provider.remoteAddress());
  upstream_info.setUpstreamSslConnection(ssl_info);
  onUpstreamConnection();
  read_callbacks_->continueReading();
  if (info) {
    upstream_info.setUpstreamFilterState(info->filterState());
  }
}

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

ProtobufTypes::MessagePtr TunnelResponseHeadersOrTrailers::serializeAsProto() const {
  auto proto_out = std::make_unique<envoy::config::core::v3::HeaderMap>();
  value().iterate([&proto_out](const Http::HeaderEntry& e) -> Http::HeaderMap::Iterate {
    auto* new_header = proto_out->add_headers();
    new_header->set_key(std::string(e.key().getStringView()));
    new_header->set_value(std::string(e.value().getStringView()));
    return Http::HeaderMap::Iterate::Continue;
  });
  return proto_out;
}

const std::string& TunnelResponseHeaders::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.propagate_response_headers");
}

const std::string& TunnelResponseTrailers::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.propagate_response_trailers");
}

TunnelingConfigHelperImpl::TunnelingConfigHelperImpl(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy_TunnelingConfig&
        config_message,
    Server::Configuration::FactoryContext& context)
    : use_post_(config_message.use_post()),
      header_parser_(Envoy::Router::HeaderParser::configure(config_message.headers_to_add())),
      propagate_response_headers_(config_message.propagate_response_headers()),
      propagate_response_trailers_(config_message.propagate_response_trailers()),
      post_path_(config_message.post_path()) {
  if (!post_path_.empty() && !use_post_) {
    throw EnvoyException("Can't set a post path when POST method isn't used");
  }
  post_path_ = post_path_.empty() ? "/" : post_path_;

  envoy::config::core::v3::SubstitutionFormatString substitution_format_config;
  substitution_format_config.mutable_text_format_source()->set_inline_string(
      config_message.hostname());
  hostname_fmt_ = Formatter::SubstitutionFormatStringUtils::fromProtoConfig(
      substitution_format_config, context);
}

std::string TunnelingConfigHelperImpl::host(const StreamInfo::StreamInfo& stream_info) const {
  return hostname_fmt_->format(*Http::StaticEmptyHeaders::get().request_headers,
                               *Http::StaticEmptyHeaders::get().response_headers,
                               *Http::StaticEmptyHeaders::get().response_trailers, stream_info,
                               absl::string_view());
}

void TunnelingConfigHelperImpl::propagateResponseHeaders(
    Http::ResponseHeaderMapPtr&& headers,
    const StreamInfo::FilterStateSharedPtr& filter_state) const {
  if (!propagate_response_headers_) {
    return;
  }
  filter_state->setData(
      TunnelResponseHeaders::key(), std::make_shared<TunnelResponseHeaders>(std::move(headers)),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);
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
  getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);

  // Raise LocalClose, which will trigger a reconnect if needed/configured.
  upstream_callbacks_->onEvent(Network::ConnectionEvent::LocalClose);
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "downstream connection received {} bytes, end_stream={}",
                 read_callbacks_->connection(), data.length(), end_stream);

  // ROHIT: Manual Processing
  ENVOY_LOG(info, "ROHIT: onData() = {}", data.length());
  if (data.length() == 335) {
    // ROHIT: Drain Data
    ENVOY_LOG(info, "ROHIT: Draining Data.");
    data.drain(data.length());

    // ROHIT: Disable Reads
    ENVOY_LOG(info, "ROHIT: Disabling Reads.");
    read_callbacks_->connection().readDisable(true);

    Buffer::OwnedImpl out_buffer_0{};
    // 20 00 00 01 8d ae ff 19 00 00 00 01 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    const uint8_t buff_val_0[36]{32, 0, 0, 1, 141, 174, 255, 25, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0,
                                 0,  0, 0, 0, 0,   0,   0,   0,  0, 0, 0, 0, 0,   0, 0, 0, 0, 0};
    out_buffer_0.add(buff_val_0, 36);

    getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(36);
    ENVOY_LOG(info, "ROHIT: Sending 36 Bytes.");
    if (upstream_) {
      getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(36);
      upstream_->encodeData(out_buffer_0, end_stream);
    }

    // Buffer::OwnedImpl out_buffer_1{};
    // e2 00 00 01 8d a6 ff 19 00 00 00 01 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 6f 6f 74 00 20 f3 e8 37 af d3 18 ba d7 56 94 33 e5 86 42 10 05 e2 b2 3d fe c9 42 fb 95 dc d7 82 da 64 3f b6 c7 6d 79 73 71 6c 00 63 61 63 68 69 6e 67 5f 73 68 61 32 5f 70 61 73 73 77 6f 72 64 00 7f 03 5f 6f 73 09 6d 61 63 6f 73 31 33 2e 30 09 5f 70 6c 61 74 66 6f 72 6d 05 61 72 6d 36 34 0f 5f 63 6c 69 65 6e 74 5f 76 65 72 73 69 6f 6e 06 38 2e 30 2e 33 32 0c 5f 63 6c 69 65 6e 74 5f 6e 61 6d 65 08 6c 69 62 6d 79 73 71 6c 04 5f 70 69 64 05 32 38 37 34 32 07 6f 73 5f 75 73 65 72 0d 72 6f 68 69 74 2e 61 67 72 61 77 61 6c 0c 70 72 6f 67 72 61 6d 5f 6e 61 6d 65 05 6d 79 73 71 6c
    // const uint8_t buff_val_1[230]{226, 0, 0, 1, 141, 166, 255, 25, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 111, 111, 116, 0, 32, 243, 232, 55, 175, 211, 24, 186, 215, 86, 148, 51, 229, 134, 66, 16, 5, 226, 178, 61, 254, 201, 66, 251, 149, 220, 215, 130, 218, 100, 63, 182, 199, 109, 121, 115, 113, 108, 0, 99, 97, 99, 104, 105, 110, 103, 95, 115, 104, 97, 50, 95, 112, 97, 115, 115, 119, 111, 114, 100, 0, 127, 3, 95, 111, 115, 9, 109, 97, 99, 111, 115, 49, 51, 46, 48, 9, 95, 112, 108, 97, 116, 102, 111, 114, 109, 5, 97, 114, 109, 54, 52, 15, 95, 99, 108, 105, 101, 110, 116, 95, 118, 101, 114, 115, 105, 111, 110, 6, 56, 46, 48, 46, 51, 50, 12, 95, 99, 108, 105, 101, 110, 116, 95, 110, 97, 109, 101, 8, 108, 105, 98, 109, 121, 115, 113, 108, 4, 95, 112, 105, 100, 5, 50, 56, 55, 52, 50, 7, 111, 115, 95, 117, 115, 101, 114, 13, 114, 111, 104, 105, 116, 46, 97, 103, 114, 97, 119, 97, 108, 12, 112, 114, 111, 103, 114, 97, 109, 95, 110, 97, 109, 101, 5, 109, 121, 115, 113, 108};
    // out_buffer_1.add(buff_val_1, 230);

    // 16 03 01 01 26 01 00 01 22 03 03 7e 22 94 97 72 be cb de 19 f0 7e 9d 30 15 1f c6 48 ba f3 3d 38 05 56 88 73 6f 7a aa c1 6e 00 86 20 9b 94 1e a9 9c 6a 47 68 4f 36 8f a5 75 a5 31 f5 f1 5c 8b 7f b6 00 26 d6 3e 47 15 26 65 59 64 24 00 48 13 02 13 03 13 01 c0 2b c0 2c c0 2f c0 23 c0 27 c0 30 c0 24 c0 28 00 9e 00 a2 00 67 00 40 00 a3 00 6b 00 6a 00 9f c0 13 c0 09 c0 14 c0 0a 00 32 00 33 00 38 00 39 00 35 00 84 00 41 00 9c 00 9d 00 3c 00 3d 00 2f 00 ff 01 00 00 91 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03 02 03 03 01 02 01 03 02 02 02 04 02 05 02 06 02 00 2b 00 05 04 03 04 03 03 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 b6 c1 be b1 7a 6e 56 a1 60 73 bb ad 7e 07 aa a9 64 60 fc 22 3e 68 3e d8 bc f1 50 ad 41 5e 7b 4b
    // const uint8_t buff_val_1[299]{22, 3, 1, 1, 38, 1, 0, 1, 34, 3, 3, 126, 34, 148, 151, 114, 190, 203, 222, 25, 240, 126, 157, 48, 21, 31, 198, 72, 186, 243, 61, 56, 5, 86, 136, 115, 111, 122, 170, 193, 110, 0, 134, 32, 155, 148, 30, 169, 156, 106, 71, 104, 79, 54, 143, 165, 117, 165, 49, 245, 241, 92, 139, 127, 182, 0, 38, 214, 62, 71, 21, 38, 101, 89, 100, 36, 0, 72, 19, 2, 19, 3, 19, 1, 192, 43, 192, 44, 192, 47, 192, 35, 192, 39, 192, 48, 192, 36, 192, 40, 0, 158, 0, 162, 0, 103, 0, 64, 0, 163, 0, 107, 0, 106, 0, 159, 192, 19, 192, 9, 192, 20, 192, 10, 0, 50, 0, 51, 0, 56, 0, 57, 0, 53, 0, 132, 0, 65, 0, 156, 0, 157, 0, 60, 0, 61, 0, 47, 0, 255, 1, 0, 0, 145, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 12, 0, 10, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 0, 35, 0, 0, 0, 22, 0, 0, 0, 23, 0, 0, 0, 13, 0, 48, 0, 46, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 2, 3, 3, 1, 2, 1, 3, 2, 2, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 182, 193, 190, 177, 122, 110, 86, 161, 96, 115, 187, 173, 126, 7, 170, 169, 100, 96, 252, 34, 62, 104, 62, 216, 188, 241, 80, 173, 65, 94, 123, 75};
    // out_buffer_1.add(buff_val_1, 299);

    //getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(299);

    if (upstream_) {
      //getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(299);
      upstream_->addBytesSentCallback([upstream_callbacks = upstream_callbacks_, read_callbacks = read_callbacks_, this](uint64_t) -> bool {
        ENVOY_LOG(info, "ROHIT: ****************** Complete Sent *********************************");
        if (init_) {
          ENVOY_LOG(info, "ROHIT: Switching -> SSL.");
          if (read_callbacks->startUpstreamSecureTransport()) {
            ENVOY_CONN_LOG(trace, "ROHIT: onSslState()", read_callbacks->connection());
            ENVOY_CONN_LOG(trace, "ROHIT: upstream SSL enabled.", read_callbacks->connection());
            ENVOY_LOG(info, "ROHIT: Sending 230 Bytes.");
            Buffer::OwnedImpl out_buffer_1{};
            // e20000028daeff1900000001ff0000000000000000000000000000000000000000000000726f6f740020fff5d0df9049082440d970924423cc6ecc2f061aa56032307c50106813e92bbd6d7973716c0063616368696e675f736861325f70617373776f7264007f035f6f73096d61636f7331332e30095f706c6174666f726d0561726d36340f5f636c69656e745f76657273696f6e06382e302e33320c5f636c69656e745f6e616d65086c69626d7973716c045f706964053431393730076f735f757365720d726f6869742e6167726177616c0c70726f6772616d5f6e616d65056d7973716c
            //const uint8_t buff_val_1[230]{226, 0, 0, 1, 141, 166, 255, 25, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 111, 111, 116, 0, 32, 243, 232, 55, 175, 211, 24, 186, 215, 86, 148, 51, 229, 134, 66, 16, 5, 226, 178, 61, 254, 201, 66, 251, 149, 220, 215, 130, 218, 100, 63, 182, 199, 109, 121, 115, 113, 108, 0, 99, 97, 99, 104, 105, 110, 103, 95, 115, 104, 97, 50, 95, 112, 97, 115, 115, 119, 111, 114, 100, 0, 127, 3, 95, 111, 115, 9, 109, 97, 99, 111, 115, 49, 51, 46, 48, 9, 95, 112, 108, 97, 116, 102, 111, 114, 109, 5, 97, 114, 109, 54, 52, 15, 95, 99, 108, 105, 101, 110, 116, 95, 118, 101, 114, 115, 105, 111, 110, 6, 56, 46, 48, 46, 51, 50, 12, 95, 99, 108, 105, 101, 110, 116, 95, 110, 97, 109, 101, 8, 108, 105, 98, 109, 121, 115, 113, 108, 4, 95, 112, 105, 100, 5, 50, 56, 55, 52, 50, 7, 111, 115, 95, 117, 115, 101, 114, 13, 114, 111, 104, 105, 116, 46, 97, 103, 114, 97, 119, 97, 108, 12, 112, 114, 111, 103, 114, 97, 109, 95, 110, 97, 109, 101, 5, 109, 121, 115, 113, 108};
            //out_buffer_1.add(buff_val_1, 230);
            const uint8_t buff_val_1[230]{226, 0, 0, 2, 141, 174, 255, 25, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 111, 111, 116, 0, 32, 255, 245, 208, 223, 144, 73, 8, 36, 64, 217, 112, 146, 68, 35, 204, 110, 204, 47, 6, 26, 165, 96, 50, 48, 124, 80, 16, 104, 19, 233, 43, 189, 109, 121, 115, 113, 108, 0, 99, 97, 99, 104, 105, 110, 103, 95, 115, 104, 97, 50, 95, 112, 97, 115, 115, 119, 111, 114, 100, 0, 127, 3, 95, 111, 115, 9, 109, 97, 99, 111, 115, 49, 51, 46, 48, 9, 95, 112, 108, 97, 116, 102, 111, 114, 109, 5, 97, 114, 109, 54, 52, 15, 95, 99, 108, 105, 101, 110, 116, 95, 118, 101, 114, 115, 105, 111, 110, 6, 56, 46, 48, 46, 51, 50, 12, 95, 99, 108, 105, 101, 110, 116, 95, 110, 97, 109, 101, 8, 108, 105, 98, 109, 121, 115, 113, 108, 4, 95, 112, 105, 100, 5, 52, 49, 57, 55, 48, 7, 111, 115, 95, 117, 115, 101, 114, 13, 114, 111, 104, 105, 116, 46, 97, 103, 114, 97, 119, 97, 108, 12, 112, 114, 111, 103, 114, 97, 109, 95, 110, 97, 109, 101, 5, 109, 121, 115, 113, 108};
            out_buffer_1.add(buff_val_1, 230);
            this->upstream_->encodeData(out_buffer_1, false);
            ENVOY_LOG(info, "ROHIT: Enabling Reads.");
            read_callbacks_->connection().readDisable(false);
          } else {
            ENVOY_CONN_LOG(info,
                           "ROHIT: cannot enable upstream secure transport. Check "
                           "configuration. Terminating.",
                           read_callbacks->connection());
            read_callbacks->connection().close(Network::ConnectionCloseType::NoFlush);
          }
          // DO NOT REPEAT THIS
          init_ = false;
        }
        return true;
      });
    }
  } else {
    getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(data.length());
    if (upstream_) {
      getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(data.length());
      upstream_->encodeData(data, end_stream);
    }
  }

  // The upstream should consume all of the data.
  // Before there is an upstream the connection should be readDisabled. If the upstream is
  // destroyed, there should be no further reads as well.
  ASSERT(0 == data.length());
  resetIdleTimer(); // TODO(ggreenway) PERF: do we need to reset timer on both send and receive?
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onNewConnection() {
  if (config_->maxDownstreamConnectionDuration()) {
    connection_duration_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { onMaxDownstreamConnectionDuration(); });
    connection_duration_timer_->enableTimer(config_->maxDownstreamConnectionDuration().value());
  }

  if (config_->accessLogFlushInterval().has_value()) {
    access_log_flush_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { onAccessLogFlushInterval(); });
    resetAccessLogFlushTimer();
  }

  // Set UUID for the connection. This is used for logging and tracing.
  getStreamInfo().setStreamIdProvider(
      std::make_shared<StreamInfo::StreamIdProviderImpl>(config_->randomGenerator().uuid()));

  ASSERT(upstream_ == nullptr);
  route_ = pickRoute();
  return establishUpstreamConnection();
}

bool Filter::startUpstreamSecureTransport() { return upstream_->startUpstreamSecureTransport(); }

void Filter::onDownstreamEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::LocalClose ||
      event == Network::ConnectionEvent::RemoteClose) {
    downstream_closed_ = true;
    // Cancel the potential odcds callback.
    cluster_discovery_handle_ = nullptr;
  }

  ENVOY_CONN_LOG(trace, "on downstream event {}, has upstream = {}", read_callbacks_->connection(),
                 static_cast<int>(event), upstream_ != nullptr);

  if (upstream_) {
    Tcp::ConnectionPool::ConnectionDataPtr conn_data(upstream_->onDownstreamEvent(event));
    if (conn_data != nullptr &&
        conn_data->connection().state() != Network::Connection::State::Closed) {
      config_->drainManager().add(config_->sharedConfig(), std::move(conn_data),
                                  std::move(upstream_callbacks_), std::move(idle_timer_),
                                  read_callbacks_->upstreamHost());
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
  getStreamInfo().getUpstreamBytesMeter()->addWireBytesReceived(data.length());
  getStreamInfo().getDownstreamBytesMeter()->addWireBytesSent(data.length());
  read_callbacks_->connection().write(data, end_stream);
  ASSERT(0 == data.length());
  resetIdleTimer(); // TODO(ggreenway) PERF: do we need to reset timer on both send and receive?
}

void Filter::onUpstreamEvent(Network::ConnectionEvent event) {
  ENVOY_LOG(debug, "TCP:onUpstreamEvent(), event: {}", static_cast<int>(event));
  if (event == Network::ConnectionEvent::ConnectedZeroRtt) {
    return;
  }
  // Update the connecting flag before processing the event because we may start a new connection
  // attempt in establishUpstreamConnection.
  bool connecting = connecting_;
  connecting_ = false;

  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    upstream_.reset();
    disableIdleTimer();

    if (connecting) {
      if (event == Network::ConnectionEvent::RemoteClose) {
        getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);
        read_callbacks_->upstreamHost()->outlierDetector().putResult(
            Upstream::Outlier::Result::LocalOriginConnectFailed);
      }
      if (!downstream_closed_) {
        route_ = pickRoute();
        establishUpstreamConnection();
      }
    } else {
      if (read_callbacks_->connection().state() == Network::Connection::State::Open) {
        read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
      }
    }
  }
}

void Filter::onUpstreamConnection() {
  connecting_ = false;
  // Re-enable downstream reads now that the upstream connection is established
  // so we have a place to send downstream data to.
  read_callbacks_->connection().readDisable(false);

  read_callbacks_->upstreamHost()->outlierDetector().putResult(
      Upstream::Outlier::Result::LocalOriginConnectSuccessFinal);

  ENVOY_CONN_LOG(debug, "TCP:onUpstreamEvent(), requestedServerName: {}",
                 read_callbacks_->connection(),
                 getStreamInfo().downstreamAddressProvider().requestedServerName());

  if (config_->idleTimeout()) {
    // The idle_timer_ can be moved to a Drainer, so related callbacks call into
    // the UpstreamCallbacks, which has the same lifetime as the timer, and can dispatch
    // the call to either TcpProxy or to Drainer, depending on the current state.
    idle_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [upstream_callbacks = upstream_callbacks_]() { upstream_callbacks->onIdleTimeout(); });
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
    for (const auto& access_log : config_->accessLogs()) {
      access_log->log(nullptr, nullptr, nullptr, getStreamInfo());
    }
  }
}

void Filter::onIdleTimeout() {
  ENVOY_CONN_LOG(debug, "Session timed out", read_callbacks_->connection());
  config_->stats().idle_timeout_.inc();

  // This results in also closing the upstream connection.
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush,
                                      StreamInfo::LocalCloseReasons::get().TcpSessionIdleTimeout);
}

void Filter::onMaxDownstreamConnectionDuration() {
  ENVOY_CONN_LOG(debug, "max connection duration reached", read_callbacks_->connection());
  getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  config_->stats().max_downstream_connection_duration_.inc();
  read_callbacks_->connection().close(
      Network::ConnectionCloseType::NoFlush,
      StreamInfo::LocalCloseReasons::get().MaxConnectionDurationReached);
}

void Filter::onAccessLogFlushInterval() {
  for (const auto& access_log : config_->accessLogs()) {
    access_log->log(nullptr, nullptr, nullptr, getStreamInfo());
  }
  resetAccessLogFlushTimer();
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
  if (idle_timer_ != nullptr) {
    ASSERT(config_->idleTimeout());
    idle_timer_->enableTimer(config_->idleTimeout().value());
  }
}

void Filter::disableIdleTimer() {
  if (idle_timer_ != nullptr) {
    idle_timer_->disableTimer();
    idle_timer_.reset();
  }
}

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
                               const Upstream::HostDescriptionConstSharedPtr& upstream_host) {
  DrainerPtr drainer(new Drainer(*this, config, callbacks, std::move(upstream_conn_data),
                                 std::move(idle_timer), upstream_host));
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
                 const Upstream::HostDescriptionConstSharedPtr& upstream_host)
    : parent_(parent), callbacks_(callbacks), upstream_conn_data_(std::move(conn_data)),
      timer_(std::move(idle_timer)), upstream_host_(upstream_host), config_(config) {
  ENVOY_CONN_LOG(trace, "draining the upstream connection", upstream_conn_data_->connection());
  config_->stats().upstream_flush_total_.inc();
  config_->stats().upstream_flush_active_.inc();
}

void Drainer::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    if (timer_ != nullptr) {
      timer_->disableTimer();
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
  if (timer_ != nullptr) {
    timer_->enableTimer(config_->idleTimeout().value());
  }
}

void Drainer::cancelDrain() {
  // This sends onEvent(LocalClose).
  upstream_conn_data_->connection().close(Network::ConnectionCloseType::NoFlush);
}

Event::Dispatcher& Drainer::dispatcher() { return upstream_conn_data_->connection().dispatcher(); }

} // namespace TcpProxy
} // namespace Envoy
