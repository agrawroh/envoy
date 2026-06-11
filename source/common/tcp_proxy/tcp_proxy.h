#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/access_log/access_log.h"
#include "envoy/common/random_generator.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.pb.h"
#include "envoy/http/codec.h"
#include "envoy/http/header_evaluator.h"
#include "envoy/http/request_id_extension.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/runtime/runtime.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/stats/timespan.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/upstream.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/formatter/substitution_format_string.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/network/cidr_range.h"
#include "source/common/network/filter_impl.h"
#include "source/common/network/hash_policy.h"
#include "source/common/network/utility.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/common/tcp_proxy/http_frame_tracker.h"
#include "source/common/tcp_proxy/splice_pump.h"
#include "source/common/tcp_proxy/upstream.h"
#include "source/common/tcp_proxy/upstream_pool.h"
#include "source/common/upstream/load_balancer_context_base.h"
#include "source/common/upstream/od_cds_api_impl.h"

#include "absl/container/node_hash_map.h"

namespace Envoy {
namespace TcpProxy {

constexpr absl::string_view PerConnectionIdleTimeoutMs =
    "envoy.tcp_proxy.per_connection_idle_timeout_ms";
/**
 * ReceiveBeforeConnectKey is the key for the receive_before_connect filter state. The
 * filter state value is a ``StreamInfo::BoolAccessor`` indicating whether the
 * receive_before_connect functionality should be enabled. Network filters setting this filter
 * state should return `StopIteration` in their `onNewConnection` and `onData` methods until they
 * have read the data they need before the upstream connection establishment, and only then allow
 * the filter chain to proceed to the TCP_PROXY filter.
 */
constexpr absl::string_view ReceiveBeforeConnectKey = "envoy.tcp_proxy.receive_before_connect";

/**
 * All tcp proxy stats. @see stats_macros.h
 */
#define ALL_TCP_PROXY_STATS(COUNTER, GAUGE)                                                        \
  COUNTER(downstream_cx_drain_close)                                                               \
  COUNTER(downstream_cx_no_route)                                                                  \
  COUNTER(downstream_cx_rx_bytes_total)                                                            \
  COUNTER(downstream_cx_total)                                                                     \
  COUNTER(downstream_cx_tx_bytes_total)                                                            \
  COUNTER(downstream_flow_control_paused_reading_total)                                            \
  COUNTER(downstream_flow_control_resumed_reading_total)                                           \
  COUNTER(early_data_received_count_total)                                                         \
  COUNTER(idle_timeout)                                                                            \
  COUNTER(max_downstream_connection_duration)                                                      \
  COUNTER(upstream_flush_total)                                                                    \
  COUNTER(route_delayed_total)                                                                     \
  COUNTER(splice_pump_engaged_total)                                                               \
  COUNTER(splice_pump_torndown_total)                                                              \
  GAUGE(downstream_cx_rx_bytes_buffered, Accumulate)                                               \
  GAUGE(downstream_cx_tx_bytes_buffered, Accumulate)                                               \
  GAUGE(upstream_flush_active, Accumulate)                                                         \
  GAUGE(splice_pump_active, Accumulate)

/**
 * Tcp proxy stats for on-demand. These stats are generated only if the tcp proxy enables on demand.
 */
#define ON_DEMAND_TCP_PROXY_STATS(COUNTER)                                                         \
  COUNTER(on_demand_cluster_attempt)                                                               \
  COUNTER(on_demand_cluster_missing)                                                               \
  COUNTER(on_demand_cluster_timeout)                                                               \
  COUNTER(on_demand_cluster_success)

/**
 * Struct definition for all tcp proxy stats. @see stats_macros.h
 */
struct TcpProxyStats {
  ALL_TCP_PROXY_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

/**
 * Struct definition for on-demand related tcp proxy stats. @see stats_macros.h
 * These stats are available if and only if the tcp proxy enables on-demand.
 * Note that these stats has the same prefix as `TcpProxyStats`.
 */
struct OnDemandStats {
  ON_DEMAND_TCP_PROXY_STATS(GENERATE_COUNTER_STRUCT)
};

class Drainer;
class UpstreamDrainManager;

// Derives the Phase-2 warm-connection-pool checkout/checkin key from the cluster name, the upstream
// "ip:port" address, and the FULL per-connection transport-socket trust identity (not just SNI).
// The upstream-TLS TRUST decision depends on the whole TransportSocketOptions: the server-name
// (SNI) override, the verify-SAN list the peer cert is validated against, the ALPN override and
// fallback, and any shared filter-state objects. All of these are folded in (using the same fields
// and order as Network::CommonUpstreamTransportSocketFactory::hashKey) so a connection handshaked
// under one trust identity (or for a different cluster) at an address is never checked out for a
// request needing a different one at that same address (which could validate against the wrong SAN
// list or present the wrong certificate / protocol). `options` may be null when no override
// applies. Free function so the exact byte layout is directly unit-testable. The NUL separators and
// the length-prefixed options blob are part of the contract; differing trust identity must produce
// a different key.
std::string poolHostKey(absl::string_view cluster, absl::string_view addr,
                        const Network::TransportSocketOptionsConstSharedPtr& options);

/**
 * Route is an individual resolved route for a connection.
 */
class Route {
public:
  virtual ~Route() = default;

  /**
   * Check whether this route matches a given connection.
   * @param connection supplies the connection to test against.
   * @return bool true if this route matches a given connection.
   */
  virtual bool matches(Network::Connection& connection) const PURE;

  /**
   * @return const std::string& the upstream cluster that owns the route.
   */
  virtual const std::string& clusterName() const PURE;

  /**
   * @return MetadataMatchCriteria* the metadata that a subset load balancer should match when
   * selecting an upstream host
   */
  virtual const Router::MetadataMatchCriteria* metadataMatchCriteria() const PURE;
};

using RouteConstSharedPtr = std::shared_ptr<const Route>;
using TunnelingConfig =
    envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy_TunnelingConfig;

/**
 * Response headers for the tunneling connections.
 */
class TunnelResponseHeaders : public Http::TunnelResponseHeadersOrTrailersImpl {
public:
  TunnelResponseHeaders(Http::ResponseHeaderMapPtr&& response_headers)
      : response_headers_(std::move(response_headers)) {}
  const Http::HeaderMap& value() const override { return *response_headers_; }
  static const std::string& key();

private:
  const Http::ResponseHeaderMapPtr response_headers_;
};

/**
 * Response trailers for the tunneling connections.
 */
class TunnelResponseTrailers : public Http::TunnelResponseHeadersOrTrailersImpl {
public:
  TunnelResponseTrailers(Http::ResponseTrailerMapPtr&& response_trailers)
      : response_trailers_(std::move(response_trailers)) {}
  const Http::HeaderMap& value() const override { return *response_trailers_; }
  static const std::string& key();

private:
  const Http::ResponseTrailerMapPtr response_trailers_;
};

class Config;
class TunnelingConfigHelperImpl : public TunnelingConfigHelper,
                                  protected Logger::Loggable<Logger::Id::filter> {
public:
  TunnelingConfigHelperImpl(
      Stats::Scope& scope,
      const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config_message,
      Server::Configuration::FactoryContext& context);
  std::string host(const StreamInfo::StreamInfo& stream_info) const override;
  bool usePost() const override { return !post_path_.empty(); }
  const std::string& postPath() const override { return post_path_; }
  Envoy::Http::HeaderEvaluator& headerEvaluator() const override { return *header_parser_; }
  const Envoy::Http::RequestIDExtensionSharedPtr& requestIDExtension() const override {
    return request_id_extension_;
  }

  const Envoy::Router::FilterConfig& routerFilterConfig() const override { return router_config_; }
  void
  propagateResponseHeaders(Http::ResponseHeaderMapPtr&& headers,
                           const StreamInfo::FilterStateSharedPtr& filter_state) const override;
  void
  propagateResponseTrailers(Http::ResponseTrailerMapPtr&& trailers,
                            const StreamInfo::FilterStateSharedPtr& filter_state) const override;
  Server::Configuration::ServerFactoryContext& serverFactoryContext() const override {
    return server_factory_context_;
  }
  const std::string& requestIDHeader() const override { return request_id_header_; }
  const std::string& requestIDMetadataKey() const override { return request_id_metadata_key_; }

private:
  std::unique_ptr<Envoy::Router::HeaderParser> header_parser_;
  Formatter::FormatterPtr hostname_fmt_;
  const bool propagate_response_headers_;
  const bool propagate_response_trailers_;
  std::string post_path_;
  // Request ID extension for tunneling requests. If null, no request ID is generated.
  Envoy::Http::RequestIDExtensionSharedPtr request_id_extension_;
  // Optional overrides for request ID header name and metadata key.
  std::string request_id_header_;
  std::string request_id_metadata_key_;
  Stats::StatNameManagedStorage route_stat_name_storage_;
  const Router::FilterConfig router_config_;
  Server::Configuration::ServerFactoryContext& server_factory_context_;
};

/**
 * On demand configurations.
 */
class OnDemandConfig {
public:
  OnDemandConfig(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy_OnDemand&
                     on_demand_message,
                 Server::Configuration::FactoryContext& context, Stats::Scope& scope);
  Upstream::OdCdsApiHandle& onDemandCds() const { return *odcds_; }
  std::chrono::milliseconds timeout() const { return lookup_timeout_; }
  const OnDemandStats& stats() const { return stats_; }

private:
  static OnDemandStats generateStats(Stats::Scope& scope);
  Upstream::OdCdsApiHandlePtr odcds_;
  // The timeout of looking up the on-demand cluster.
  std::chrono::milliseconds lookup_timeout_;
  // On demand stats.
  OnDemandStats stats_;
};
using OnDemandConfigOptConstRef = OptRef<const OnDemandConfig>;

/**
 * Filter configuration.
 *
 * This configuration holds a TLS slot, and therefore it must be destructed
 * on the main thread.
 */
class Config {
public:
  /**
   * Configuration that can be shared and have an arbitrary lifetime safely.
   */
  class SharedConfig {
  public:
    SharedConfig(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
                 Server::Configuration::FactoryContext& context);
    const TcpProxyStats& stats() { return stats_; }
    const absl::optional<std::chrono::milliseconds>& idleTimeout() { return idle_timeout_; }
    bool flushAccessLogOnConnected() const { return flush_access_log_on_connected_; }
    bool flushAccessLogOnStart() const { return flush_access_log_on_start_; }
    const absl::optional<std::chrono::milliseconds>& maxDownstreamConnectionDuration() const {
      return max_downstream_connection_duration_;
    }
    const absl::optional<double>& maxDownstreamConnectionDurationJitterPercentage() const {
      return max_downstream_connection_duration_jitter_percentage_;
    }
    const absl::optional<std::chrono::milliseconds>& accessLogFlushInterval() const {
      return access_log_flush_interval_;
    }
    TunnelingConfigHelperOptConstRef tunnelingConfigHelper() {
      return makeOptRefFromPtr<const TunnelingConfigHelper>(tunneling_config_helper_.get());
    }
    OnDemandConfigOptConstRef onDemandConfig() {
      return makeOptRefFromPtr<const OnDemandConfig>(on_demand_config_.get());
    }
    const BackOffStrategyPtr& backoffStrategy() const { return backoff_strategy_; };
    const Network::ProxyProtocolTLVVector& proxyProtocolTLVs() const {
      return proxy_protocol_tlvs_;
    }
    envoy::extensions::filters::network::tcp_proxy::v3::ProxyProtocolTlvMergePolicy
    proxyProtocolTlvMergePolicy() const {
      return proxy_protocol_tlv_merge_policy_;
    }

    // Evaluate dynamic TLV formatters and combine with static TLVs.
    Network::ProxyProtocolTLVVector
    evaluateDynamicTLVs(const StreamInfo::StreamInfo& stream_info) const;

  private:
    // Structure to hold TLV formatter information.
    struct TlvFormatter {
      uint8_t type;
      Formatter::FormatterPtr formatter;
    };

    static TcpProxyStats generateStats(Stats::Scope& scope);

    static Network::ProxyProtocolTLVVector
    parseTLVs(absl::Span<const envoy::config::core::v3::TlvEntry* const> tlvs,
              Server::Configuration::GenericFactoryContext& context,
              std::vector<TlvFormatter>& dynamic_tlvs);

    // Hold a Scope for the lifetime of the configuration because connections in
    // the UpstreamDrainManager can live longer than the listener.
    const Stats::ScopeSharedPtr stats_scope_;

    const TcpProxyStats stats_;
    bool flush_access_log_on_connected_ : 1;
    const bool flush_access_log_on_start_ : 1;
    absl::optional<std::chrono::milliseconds> idle_timeout_;
    absl::optional<std::chrono::milliseconds> max_downstream_connection_duration_;
    absl::optional<double> max_downstream_connection_duration_jitter_percentage_;
    absl::optional<std::chrono::milliseconds> access_log_flush_interval_;
    std::unique_ptr<TunnelingConfigHelper> tunneling_config_helper_;
    std::unique_ptr<OnDemandConfig> on_demand_config_;
    BackOffStrategyPtr backoff_strategy_;
    Network::ProxyProtocolTLVVector proxy_protocol_tlvs_;
    std::vector<TlvFormatter> dynamic_tlv_formatters_;
    envoy::extensions::filters::network::tcp_proxy::v3::ProxyProtocolTlvMergePolicy
        proxy_protocol_tlv_merge_policy_{
            envoy::extensions::filters::network::tcp_proxy::v3::ADD_IF_ABSENT};
  };

  using SharedConfigSharedPtr = std::shared_ptr<SharedConfig>;

  Config(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config,
         Server::Configuration::FactoryContext& context);

  /**
   * Find out which cluster an upstream connection should be opened to based on the
   * parameters of a downstream connection.
   * @param connection supplies the parameters of the downstream connection for
   * which the proxy needs to open the corresponding upstream.
   * @return the route to be used for the upstream connection.
   * If no route applies, returns nullptr.
   */
  RouteConstSharedPtr getRouteFromEntries(Network::Connection& connection);
  RouteConstSharedPtr getRegularRouteFromEntries(Network::Connection& connection);

  const TcpProxyStats& stats() { return shared_config_->stats(); }
  const AccessLog::InstanceSharedPtrVector& accessLogs() { return access_logs_; }
  uint32_t maxConnectAttempts() const { return max_connect_attempts_; }
  const absl::optional<std::chrono::milliseconds>& idleTimeout() {
    return shared_config_->idleTimeout();
  }
  const absl::optional<std::chrono::milliseconds>& maxDownstreamConnectionDuration() const {
    return shared_config_->maxDownstreamConnectionDuration();
  }
  const absl::optional<double>& maxDownstreamConnectionDurationJitterPercentage() const {
    return shared_config_->maxDownstreamConnectionDurationJitterPercentage();
  }
  const absl::optional<std::chrono::milliseconds>
  calculateMaxDownstreamConnectionDurationWithJitter();
  const absl::optional<std::chrono::milliseconds>& accessLogFlushInterval() const {
    return shared_config_->accessLogFlushInterval();
  }
  // Return nullptr if there is no tunneling config.
  TunnelingConfigHelperOptConstRef tunnelingConfigHelper() {
    return shared_config_->tunnelingConfigHelper();
  }
  UpstreamDrainManager& drainManager();
  // Per-worker warm upstream connection pool (Phase 2). Lives in a
  // thread-local slot like the drain manager, so it is single-worker-confined and needs no mutex.
  // Returns nullopt when the l4_connection_pool runtime feature is off (the slot is then never
  // populated), so callers stay on the strictly-1:1 path.
  OptRef<UpstreamPool> upstreamPool();
  SharedConfigSharedPtr sharedConfig() { return shared_config_; }
  const Router::MetadataMatchCriteria* metadataMatchCriteria() const {
    return cluster_metadata_match_criteria_.get();
  }
  const Network::HashPolicy* hashPolicy() { return hash_policy_.get(); }
  OptRef<Upstream::OdCdsApiHandle> onDemandCds() const {
    auto on_demand_config = shared_config_->onDemandConfig();
    return on_demand_config.has_value() ? makeOptRef(on_demand_config->onDemandCds())
                                        : OptRef<Upstream::OdCdsApiHandle>();
  }
  // This function must not be called if on demand is disabled.
  std::chrono::milliseconds odcdsTimeout() const {
    return shared_config_->onDemandConfig()->timeout();
  }
  // This function must not be called if on demand is disabled.
  const OnDemandStats& onDemandStats() const { return shared_config_->onDemandConfig()->stats(); }
  Random::RandomGenerator& randomGenerator() { return random_generator_; }
  bool flushAccessLogOnConnected() const { return shared_config_->flushAccessLogOnConnected(); }
  bool flushAccessLogOnStart() const { return shared_config_->flushAccessLogOnStart(); }
  Regex::Engine& regexEngine() const { return regex_engine_; }
  const BackOffStrategyPtr& backoffStrategy() const { return shared_config_->backoffStrategy(); };
  const Network::ProxyProtocolTLVVector& proxyProtocolTLVs() const {
    return shared_config_->proxyProtocolTLVs();
  }

  envoy::extensions::filters::network::tcp_proxy::v3::UpstreamConnectMode
  upstreamConnectMode() const {
    return upstream_connect_mode_;
  }

  const absl::optional<uint32_t>& maxEarlyDataBytes() const { return max_early_data_bytes_; }
  bool checkDrainClose() const { return check_drain_close_; }
  const Network::DrainDecision& drainDecision() const { return drain_decision_; }
  Network::DrainDirection drainCloseScope() const { return drain_close_scope_; }

private:
  struct SimpleRouteImpl : public Route {
    SimpleRouteImpl(const Config& parent, absl::string_view cluster_name);

    // Route
    bool matches(Network::Connection&) const override { return true; }
    const std::string& clusterName() const override { return cluster_name_; }
    const Router::MetadataMatchCriteria* metadataMatchCriteria() const override {
      return parent_.metadataMatchCriteria();
    }

    const Config& parent_;
    std::string cluster_name_;
  };

  class WeightedClusterEntry : public Route {
  public:
    WeightedClusterEntry(const Config& parent,
                         const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::
                             WeightedCluster::ClusterWeight& config);

    uint64_t clusterWeight() const { return cluster_weight_; }

    // Route
    bool matches(Network::Connection&) const override { return false; }
    const std::string& clusterName() const override { return cluster_name_; }
    const Router::MetadataMatchCriteria* metadataMatchCriteria() const override {
      if (metadata_match_criteria_) {
        return metadata_match_criteria_.get();
      }
      return parent_.metadataMatchCriteria();
    }

  private:
    const Config& parent_;
    const std::string cluster_name_;
    const uint64_t cluster_weight_;
    Router::MetadataMatchCriteriaConstPtr metadata_match_criteria_;
  };
  using WeightedClusterEntryConstSharedPtr = std::shared_ptr<const WeightedClusterEntry>;

  RouteConstSharedPtr default_route_;
  std::vector<WeightedClusterEntryConstSharedPtr> weighted_clusters_;
  uint64_t total_cluster_weight_;
  AccessLog::InstanceSharedPtrVector access_logs_;
  const uint32_t max_connect_attempts_;
  ThreadLocal::SlotPtr upstream_drain_manager_slot_;
  // Thread-local slot for the Phase-2 warm upstream connection pool. Allocated unconditionally
  // (like upstream_drain_manager_slot_) but only set() (i.e. populated with an UpstreamPool)
  // when the l4_connection_pool runtime feature is enabled, so the pool is fail-closed by default.
  ThreadLocal::SlotPtr upstream_pool_slot_;
  // True iff the l4_connection_pool runtime feature was enabled at config load (the slot was
  // set()). upstreamPool() gates on this so it never calls get() on an unset slot.
  bool l4_pool_enabled_{false};
  SharedConfigSharedPtr shared_config_;
  std::unique_ptr<const Router::MetadataMatchCriteria> cluster_metadata_match_criteria_;
  Random::RandomGenerator& random_generator_;
  std::unique_ptr<const Network::HashPolicyImpl> hash_policy_;
  Regex::Engine& regex_engine_; // Static lifetime object, safe to store as a reference
  envoy::extensions::filters::network::tcp_proxy::v3::UpstreamConnectMode upstream_connect_mode_{
      envoy::extensions::filters::network::tcp_proxy::v3::IMMEDIATE};
  absl::optional<uint32_t> max_early_data_bytes_;
  const Network::DrainDecision& drain_decision_;
  const Network::DrainDirection drain_close_scope_{};
  const bool check_drain_close_{false};
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Per-connection TCP Proxy Cluster configuration.
 */
class PerConnectionCluster : public StreamInfo::FilterState::Object {
public:
  PerConnectionCluster(absl::string_view cluster) : cluster_(cluster) {}
  const std::string& value() const { return cluster_; }
  absl::optional<std::string> serializeAsString() const override { return cluster_; }
  static const std::string& key();

private:
  const std::string cluster_;
};

/**
 * An implementation of a TCP (L3/L4) proxy. This filter will instantiate a new outgoing TCP
 * connection using the defined load balancing proxy for the configured cluster. All data will
 * be proxied back and forth between the two connections.
 */
class Filter : public Network::ReadFilter,
               public Upstream::LoadBalancerContextBase,
               protected Logger::Loggable<Logger::Id::filter>,
               public GenericConnectionPoolCallbacks {
public:
  Filter(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager);
  ~Filter() override;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  bool startUpstreamSecureTransport() override;

  // GenericConnectionPoolCallbacks
  void onGenericPoolReady(StreamInfo::StreamInfo* info, std::unique_ptr<GenericUpstream>&& upstream,
                          Upstream::HostDescriptionConstSharedPtr& host,
                          const Network::ConnectionInfoProvider& address_provider,
                          Ssl::ConnectionInfoConstSharedPtr ssl_info) override;
  void onGenericPoolFailure(ConnectionPool::PoolFailureReason reason,
                            absl::string_view failure_reason,
                            Upstream::HostDescriptionConstSharedPtr host) override;

  // Upstream::LoadBalancerContext
  const Router::MetadataMatchCriteria* metadataMatchCriteria() override;
  absl::optional<uint64_t> computeHashKey() override {
    auto hash_policy = config_->hashPolicy();
    if (hash_policy) {
      return hash_policy->generateHash(*downstreamConnection());
    }

    return {};
  }
  const Network::Connection* downstreamConnection() const override {
    return &read_callbacks_->connection();
  }

  StreamInfo::StreamInfo* requestStreamInfo() const override {
    return &read_callbacks_->connection().streamInfo();
  }

  Network::TransportSocketOptionsConstSharedPtr upstreamTransportSocketOptions() const override {
    return transport_socket_options_;
  }

  Network::Socket::OptionsSharedPtr upstreamSocketOptions() const override {
    return upstream_options_;
  }

  // These two functions allow enabling/disabling reads on the upstream and downstream connections.
  // They are called by the Downstream/Upstream Watermark callbacks to limit buffering.
  void readDisableUpstream(bool disable);
  void readDisableDownstream(bool disable);

  struct UpstreamCallbacks : public Tcp::ConnectionPool::UpstreamCallbacks {
    UpstreamCallbacks(Filter* parent) : parent_(parent) {}

    // Tcp::ConnectionPool::UpstreamCallbacks
    void onUpstreamData(Buffer::Instance& data, bool end_stream) override;
    void onEvent(Network::ConnectionEvent event) override;
    void onAboveWriteBufferHighWatermark() override;
    void onBelowWriteBufferLowWatermark() override;

    void onBytesSent();
    void onIdleTimeout();
    void drain(Drainer& drainer);

    // Either parent_ or drainer_ will be non-NULL, but never both. This could be
    // logically be represented as a union, but saving one pointer of memory is
    // outweighed by more type safety/better error handling.
    //
    // Parent starts out as non-NULL. If the downstream connection is closed while
    // the upstream connection still has buffered data to flush, drainer_ becomes
    // non-NULL and parent_ is set to NULL.
    Filter* parent_{};
    Drainer* drainer_{};

    bool on_high_watermark_called_{false};
  };

  StreamInfo::StreamInfo& getStreamInfo();
  class HttpStreamDecoderFilterCallbacks : public Http::StreamDecoderFilterCallbacks,
                                           public ScopeTrackedObject {
  public:
    HttpStreamDecoderFilterCallbacks(Filter* parent);
    // Http::StreamDecoderFilterCallbacks
    OptRef<const Network::Connection> connection() override {
      return parent_->read_callbacks_->connection();
    }
    StreamInfo::StreamInfo& streamInfo() override { return parent_->getStreamInfo(); }
    const ScopeTrackedObject& scope() override { return *this; }
    Event::Dispatcher& dispatcher() override {
      return parent_->read_callbacks_->connection().dispatcher();
    }
    void resetStream(Http::StreamResetReason, absl::string_view) override {
      IS_ENVOY_BUG("Not implemented. Unexpected call to resetStream()");
    };
    OptRef<const Router::Route> route() override { return makeOptRefFromPtr(route_.get()); }
    Router::RouteConstSharedPtr routeSharedPtr() override { return route_; }
    OptRef<const Upstream::ClusterInfo> clusterInfo() override {
      const auto info =
          parent_->cluster_manager_.getThreadLocalCluster(parent_->route_->clusterName())->info();
      return makeOptRefFromPtr<const Upstream::ClusterInfo>(info.get());
    }
    Upstream::ClusterInfoConstSharedPtr clusterInfoSharedPtr() override {
      return parent_->cluster_manager_.getThreadLocalCluster(parent_->route_->clusterName())
          ->info();
    }
    uint64_t streamId() const override {
      auto sip = parent_->getStreamInfo().getStreamIdProvider();
      if (sip) {
        return sip->toInteger().value();
      }
      return 0;
    }
    Tracing::Span& activeSpan() override { return parent_->active_span_; }
    OptRef<const Tracing::Config> tracingConfig() const override {
      return makeOptRef<const Tracing::Config>(parent_->tracing_config_);
    }
    void continueDecoding() override {}
    void addDecodedData(Buffer::Instance&, bool) override {}
    void injectDecodedDataToFilterChain(Buffer::Instance&, bool) override {}
    Http::RequestTrailerMap& addDecodedTrailers() override { return *request_trailer_map_; }
    Http::MetadataMapVector& addDecodedMetadata() override {
      static Http::MetadataMapVector metadata_map_vector;
      return metadata_map_vector;
    }
    const Buffer::Instance* decodingBuffer() override { return nullptr; }
    void modifyDecodingBuffer(std::function<void(Buffer::Instance&)>) override {}
    void sendLocalReply(Http::Code, absl::string_view,
                        std::function<void(Http::ResponseHeaderMap& headers)>,
                        const absl::optional<Grpc::Status::GrpcStatus>,
                        absl::string_view) override {}
    void sendGoAwayAndClose(bool graceful [[maybe_unused]] = false) override {}
    void encode1xxHeaders(Http::ResponseHeaderMapPtr&&) override {}
    Http::ResponseHeaderMapOptRef informationalHeaders() override { return {}; }
    void encodeHeaders(Http::ResponseHeaderMapPtr&&, bool, absl::string_view) override {}
    Http::ResponseHeaderMapOptRef responseHeaders() override { return {}; }
    void encodeData(Buffer::Instance&, bool) override {}
    Http::RequestHeaderMapOptRef requestHeaders() override { return {}; }
    Http::RequestTrailerMapOptRef requestTrailers() override { return {}; }
    void encodeTrailers(Http::ResponseTrailerMapPtr&&) override {}
    Http::ResponseTrailerMapOptRef responseTrailers() override { return {}; }
    void encodeMetadata(Http::MetadataMapPtr&&) override {}
    void onDecoderFilterAboveWriteBufferHighWatermark() override {
      parent_->upstream_callbacks_->onAboveWriteBufferHighWatermark();
    }
    void onDecoderFilterBelowWriteBufferLowWatermark() override {
      parent_->upstream_callbacks_->onBelowWriteBufferLowWatermark();
    }
    void addDownstreamWatermarkCallbacks(Http::DownstreamWatermarkCallbacks&) override {}
    void removeDownstreamWatermarkCallbacks(Http::DownstreamWatermarkCallbacks&) override {}
    void setBufferLimit(uint64_t) override {}
    uint64_t bufferLimit() override { return 0; }
    bool recreateStream(const Http::ResponseHeaderMap*) override { return false; }
    void addUpstreamSocketOptions(const Network::Socket::OptionsSharedPtr&) override {}
    Network::Socket::OptionsSharedPtr getUpstreamSocketOptions() const override { return nullptr; }
    const Router::RouteSpecificFilterConfig* mostSpecificPerFilterConfig() const override {
      return nullptr;
    }
    Router::RouteSpecificFilterConfigs perFilterConfigs() const override { return {}; }
    Buffer::BufferMemoryAccountSharedPtr account() const override { return nullptr; }
    void setUpstreamOverrideHost(Upstream::LoadBalancerContext::OverrideHost) override {}
    OptRef<const Upstream::LoadBalancerContext::OverrideHost>
    upstreamOverrideHost() const override {
      return {};
    }
    bool shouldLoadShed() const override { return false; }
    void restoreContextOnContinue(ScopeTrackedObjectStack& tracked_object_stack) override {
      tracked_object_stack.add(*this);
    }
    Http::Http1StreamEncoderOptionsOptRef http1StreamEncoderOptions() override { return {}; }
    OptRef<Http::DownstreamStreamFilterCallbacks> downstreamCallbacks() override { return {}; }
    OptRef<Http::UpstreamStreamFilterCallbacks> upstreamCallbacks() override { return {}; }
    void resetIdleTimer() override {}
    // absl::optional<absl::string_view> upstreamOverrideHost() const override {
    //   return absl::nullopt;
    // }
    absl::string_view filterConfigName() const override { return ""; }

    // ScopeTrackedObject
    void dumpState(std::ostream& os, int indent_level) const override {
      const char* spaces = spacesForLevel(indent_level);
      os << spaces << "TcpProxy " << this << DUMP_MEMBER(streamId()) << "\n";
      DUMP_DETAILS(parent_->getStreamInfo().upstreamInfo());
    }
    Filter* parent_{};
    Http::RequestTrailerMapPtr request_trailer_map_;
    std::shared_ptr<Http::NullRouteImpl> route_;
  };
  Tracing::NullSpan active_span_;
  const Tracing::Config& tracing_config_;

protected:
  struct DownstreamCallbacks : public Network::ConnectionCallbacks {
    DownstreamCallbacks(Filter& parent) : parent_(parent) {}

    // Network::ConnectionCallbacks
    void onEvent(Network::ConnectionEvent event) override { parent_.onDownstreamEvent(event); }
    void onAboveWriteBufferHighWatermark() override;
    void onBelowWriteBufferLowWatermark() override;

    Filter& parent_;
    bool on_high_watermark_called_{false};
  };

  enum class UpstreamFailureReason {
    ConnectFailed,
    NoHealthyUpstream,
    ResourceLimitExceeded,
    NoRoute,
  };

  // Callbacks for different error and success states during connection establishment
  virtual RouteConstSharedPtr pickRoute() {
    return config_->getRouteFromEntries(read_callbacks_->connection());
  }

  virtual void onInitFailure(UpstreamFailureReason reason);
  void initialize(Network::ReadFilterCallbacks& callbacks, bool set_connection_stats);

  // Create connection to the upstream cluster. This function can be repeatedly called on upstream
  // connection failure.
  Network::FilterStatus establishUpstreamConnection();

  // The callback upon on demand cluster discovery response.
  void onClusterDiscoveryCompletion(Upstream::ClusterDiscoveryStatus cluster_status);

  bool maybeTunnel(Upstream::ThreadLocalCluster& cluster);
  void onConnectMaxAttempts();
  void onConnectTimeout();
  void onDownstreamEvent(Network::ConnectionEvent event);
  void onUpstreamData(Buffer::Instance& data, bool end_stream);
  void onUpstreamEvent(Network::ConnectionEvent event);
  void maybeCloseDownstreamForDrainClose();
  void onUpstreamConnection();
  // Tries to engage the L4 kernel-splice fast-path. Sets up the pump (fallible) before detaching.
  // On success it drains `data`, removes both socket FileEvents, arms the pump and returns true.
  // On failure it leaves `data` untouched and returns false so the buffered path handles it.
  // `from_upstream` selects the engaging direction: true means `data` is the upstream chunk bound
  // downstream (a GET/HEAD response); false means `data` is the downstream chunk bound upstream (a
  // PUT request and upload body). It queues `data` to its destination as the pre-engage chunk.
  bool maybeEngageSplice(Buffer::Instance& data, bool from_upstream);
  // Resets the splice pump and force-closes the hijacked upstream connection so the pool and drain
  // manager discard it rather than reuse a socket whose FileEvents the pump removed. A no-op when
  // no splice is engaged.
  void tearDownSplice();
  // Phase-2 connection pool integration (buffered relay path only).
  //
  // tryCheckoutPooledUpstream: at upstream-establishment time, if the l4_connection_pool feature is
  // on, try to adopt a warm, already-handshaked (kTLS-installed) connection to `host` (keyed by
  // host_key) instead of opening a fresh one. Returns true if a warm connection was adopted
  // (upstream_ is set, onUpstreamConnection() has run, and the normal newStream path must be
  // skipped).
  bool tryCheckoutPooledUpstream(absl::string_view host_key,
                                 const Upstream::HostDescriptionConstSharedPtr& host);
  // feedFrameTracker: on the buffered path, observe request-/response-direction bytes so the
  // tracker can find the HTTP/1.1 message boundary that makes the connection returnable. No-op once
  // a splice is engaged (a spliced connection is never poolable) or the pool path is not active.
  void feedFrameTracker(const Buffer::Instance& data, bool from_upstream);
  // maybeCheckinPooledUpstream: once the frame tracker reports ExchangeComplete, release ownership
  // of upstream_ (so ~Filter does not close it) and hand it to the pool, which owns the close from
  // then on. On NotPoolable, abandon pooling for this connection (it is dropped by the normal
  // teardown). Safe to call repeatedly; only acts on a state transition.
  void maybeCheckinPooledUpstream();
  // maybePickPoolRoute: on the first request bytes of a fresh, pool-eligible connection, decide,
  // once the frame tracker has parsed the request line, whether this exchange stays on the
  // buffered, returnable pool path (a small framable PUT/POST upload, where amortizing the TLS+kTLS
  // handshake across reused connections is the win) or routes to the L4 splice fast-path (GET/HEAD,
  // a zero-body request, or a large upload, where in-kernel zero-copy wins and 1:1 connection churn
  // is negligible). Idempotent: a no-op once the route is decided or the pool path is inactive.
  // This is what lets the pool bootstrap from empty: the first small-upload connection takes the
  // buffered path instead of splicing, completes a framed exchange, and checks in.
  void maybePickPoolRoute();
  // splicePermitted: whether the L4 splice fast-path may engage on this connection. A connection
  // the pool feature never armed (feature off, tunneling, no pooled host) splices exactly as it did
  // before Phase 2. An adopted warm connection never splices (it must stay returnable). A fresh
  // pool-eligible connection holds the splice off until maybePickPoolRoute has run, then splices
  // only if it routed away from the buffered pool path.
  bool splicePermitted() const;
  // SplicePump completion callback. Schedules deferred teardown via a member callback so a Filter
  // destroyed before it fires cancels it.
  void onSpliceComplete(Network::ConnectionEvent event);
  // Polls until the upstream kTLS installs, then splices the held PUT body chunk; on exhaustion
  // flushes it on the normal path and re-enables downstream reads. Only ever holds a later (body)
  // chunk on a kTLS-capable upstream, so a GET request is never delayed by it.
  void onKtlsEngageRetry();
  void onIdleTimeout();
  void resetIdleTimer();
  void disableIdleTimer();
  void onMaxDownstreamConnectionDuration();
  void onAccessLogFlushInterval();
  void resetAccessLogFlushTimer();
  void flushAccessLog(AccessLog::AccessLogType access_log_type);
  void disableAccessLogFlushTimer();
  void onRetryTimer();
  void enableRetryTimer();
  void disableRetryTimer();

public:
  // Public for testing purposes
  void onDownstreamTlsHandshakeComplete();

protected:
  const ConfigSharedPtr config_;
  Upstream::ClusterManager& cluster_manager_;
  Network::ReadFilterCallbacks* read_callbacks_{};

  DownstreamCallbacks downstream_callbacks_;
  Event::TimerPtr idle_timer_;
  Event::TimerPtr connection_duration_timer_;
  Event::TimerPtr access_log_flush_timer_;
  Event::TimerPtr retry_timer_;

  // A pointer to the on demand cluster lookup when lookup is in flight.
  Upstream::ClusterDiscoveryCallbackHandlePtr cluster_discovery_handle_;

  std::shared_ptr<UpstreamCallbacks> upstream_callbacks_; // shared_ptr required for passing as a
                                                          // read filter.
  // The upstream handle (either TCP or HTTP). This is set in onGenericPoolReady and should persist
  // until either the upstream or downstream connection is terminated.
  std::unique_ptr<GenericUpstream> upstream_;
  // Kernel splice() fast-path pump for the L4 kTLS bytestream. Declared after upstream_ so it
  // destructs first and its FileEvents and pipes are torn down before the upstream fd is closed.
  SplicePumpPtr splice_pump_;
  // True once any downstream byte has been sent to the upstream (encodeData or the early-data
  // flush). The upload-direction splice can only engage while this is false, which guarantees the
  // upstream write buffer is empty so spliced bytes cannot reorder ahead of buffered ones.
  bool upstream_write_started_{false};
  // Deferred teardown of a completed/aborted splice. Member-owned so it is cancelled if the Filter
  // is destroyed first (avoids a use-after-free from a deferred completion).
  Event::SchedulableCallbackPtr splice_complete_schedulable_;
  Network::ConnectionEvent splice_complete_event_{Network::ConnectionEvent::LocalClose};
  // True once an engaged splice removed the downstream ConnectionImpl FileEvent (as it did the
  // upstream's). The upstream is force-closed NoFlush at teardown for this reason; the detached
  // downstream outlives teardown and is closed on the upstream-close path, which must also close it
  // NoFlush so it never re-arms the removed FileEvent on the write/flush path.
  bool downstream_splice_detached_{false};
  // The connection pool used to set up |upstream_|.
  // This will be non-null from when an upstream connection is attempted until
  // it either succeeds or fails.
  std::unique_ptr<GenericConnPool> generic_conn_pool_;
  // Time the filter first attempted to connect to the upstream after the
  // cluster is discovered. Capture the first time as the filter may try multiple times to connect
  // to the upstream.
  absl::optional<MonotonicTime> initial_upstream_connection_start_time_;
  RouteConstSharedPtr route_;
  Router::MetadataMatchCriteriaConstPtr metadata_match_criteria_;
  Network::TransportSocketOptionsConstSharedPtr transport_socket_options_;
  Network::Socket::OptionsSharedPtr upstream_options_;
  absl::optional<std::chrono::milliseconds> idle_timeout_;
  uint32_t connect_attempts_{};
  bool connecting_{};
  bool downstream_closed_{};
  // Stores the ReceiveBeforeConnect filter state value which can be set by preceding
  // filters in the filter chain. When the filter state is set, TCP_PROXY doesn't disable
  // downstream read during initialization. This feature can hence be used by preceding filters
  // in the filter chain to read data from the downstream connection (for eg: to parse SNI) before
  // the upstream connection is established.
  bool receive_before_connect_{false};
  bool early_data_end_stream_{false};
  Buffer::OwnedImpl early_data_buffer_;
  HttpStreamDecoderFilterCallbacks upstream_decoder_filter_callbacks_;

  // Deferred upload-splice engage for a PUT body that arrives before the upstream finishes
  // installing kTLS (it raises Connected at handshake completion, then installs kTLS a moment
  // later). Only a LATER chunk (a body that follows request headers already sent on the buffered
  // path) is held: a GET sends just the request (one chunk, no body) so it is never delayed, and
  // only a kTLS-capable upstream still installing is held, so non-kTLS/mock upstreams stay on the
  // buffered path. The held body is spliced once kTLS installs and the (small) headers have flushed
  // (maybeEngageSplice's watermark check enforces ordering). Bounded retries; on exhaustion the
  // body is flushed normally. SIZE IS BOUNDED to a single downstream read: the move() that fills
  // this buffer is immediately followed by readDisable(true) on the downstream connection, so no
  // further reads accumulate here while the poll runs; reads are re-enabled when the body is
  // spliced or flushed.
  Buffer::OwnedImpl deferred_upload_buffer_;
  Event::SchedulableCallbackPtr ktls_engage_schedulable_;
  uint32_t ktls_engage_attempts_{0};
  bool upload_engage_deferred_{false};

  // Phase-2 warm-connection-pool state. Only ever populated when the
  // l4_connection_pool runtime feature is on. The frame tracker observes the buffered relay to find
  // the HTTP/1.1 message boundary; when it reaches ExchangeComplete, upstream_ is released into the
  // pool. pool_eligible_ is the "buffered+framed+pooled" path selector: it is mutually exclusive
  // with the splice path (splice_pump_ != nullptr), so engaging a splice clears it and a pooled
  // connection never splices.
  std::unique_ptr<HttpFrameTracker> frame_tracker_;
  // Checkout/checkin key: cluster name, the per-connection SNI override, and the upstream
  // "ip:port", NUL-separated. SNI/cluster are folded in so a connection handshaked for one SNI (or
  // cluster) at an address is never reused for another at that same address.
  std::string pool_host_key_;
  // True while this Filter is on the poolable buffered path (frame_tracker_ active, no splice).
  bool pool_eligible_{false};
  // True when upstream_ was adopted from the warm pool (vs. freshly opened). An adopted connection
  // must stay on the buffered path so it remains returnable, so splice is suppressed for it. A
  // fresh pool-eligible connection routes by its first request (maybePickPoolRoute): a small upload
  // stays buffered and poolable; a GET/HEAD or large upload splices and feedFrameTracker drops the
  // tracker so it is simply not pooled. Either way a given connection is EITHER spliced OR pooled,
  // never both (the clean XOR).
  bool adopted_from_pool_{false};
  // True once upstream_ has been handed to the pool, so ~Filter must not close it (the pool owns
  // the close). Guards against a double check-in / double-close.
  bool checked_in_to_pool_{false};
  // Phase-2 pool route decision for a fresh connection. pool_route_decided_ flips true once the
  // first request has been framed enough to choose a path (see maybePickPoolRoute);
  // route_buffered_for_pool_ then records which path was chosen. Until decided, splicePermitted()
  // holds the splice off so a small upload is never spliced before its size is known. Both stay
  // false on an adopted or never-eligible connection, which splicePermitted() handles directly.
  bool pool_route_decided_{false};
  bool route_buffered_for_pool_{false};

  // Connection establishment mode configuration.
  envoy::extensions::filters::network::tcp_proxy::v3::UpstreamConnectMode connect_mode_{
      envoy::extensions::filters::network::tcp_proxy::v3::IMMEDIATE};
  bool waiting_for_tls_handshake_{false};
  bool tls_handshake_complete_{false};
  bool initial_data_received_{false};
  bool read_disabled_due_to_buffer_{false}; // Track if we disabled reading due to buffer overflow.
  uint32_t max_buffered_bytes_{65536};      // Default 64KB.
  bool delay_route_selection_{false};
};

// This class deals with an upstream connection that needs to finish flushing, when the downstream
// connection has been closed. The TcpProxy is destroyed when the downstream connection is closed,
// so handling the upstream connection here allows it to finish draining or timeout.
class Drainer : public Event::DeferredDeletable, protected Logger::Loggable<Logger::Id::filter> {
public:
  Drainer(UpstreamDrainManager& parent, const Config::SharedConfigSharedPtr& config,
          const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks,
          Tcp::ConnectionPool::ConnectionDataPtr&& conn_data, Event::TimerPtr&& idle_timer,
          absl::optional<std::chrono::milliseconds> idle_timeout,
          const Upstream::HostDescriptionConstSharedPtr& upstream_host);

  void onEvent(Network::ConnectionEvent event);
  void onData(Buffer::Instance& data, bool end_stream);
  void onIdleTimeout();
  void onBytesSent();
  void cancelDrain();
  Event::Dispatcher& dispatcher();

private:
  UpstreamDrainManager& parent_;
  std::shared_ptr<Filter::UpstreamCallbacks> callbacks_;
  Tcp::ConnectionPool::ConnectionDataPtr upstream_conn_data_;
  Event::TimerPtr idle_timer_;
  absl::optional<std::chrono::milliseconds> idle_timeout_;
  Upstream::HostDescriptionConstSharedPtr upstream_host_;
  Config::SharedConfigSharedPtr config_;
};

using DrainerPtr = std::unique_ptr<Drainer>;

class UpstreamDrainManager : public ThreadLocal::ThreadLocalObject {
public:
  ~UpstreamDrainManager() override;
  void add(const Config::SharedConfigSharedPtr& config,
           Tcp::ConnectionPool::ConnectionDataPtr&& upstream_conn_data,
           const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks,
           Event::TimerPtr&& idle_timer, absl::optional<std::chrono::milliseconds> idle_timeout,
           const Upstream::HostDescriptionConstSharedPtr& upstream_host);
  void remove(Drainer& drainer, Event::Dispatcher& dispatcher);

private:
  // This must be a map instead of set because there is no way to move elements
  // out of a set, and these elements get passed to deferredDelete() instead of
  // being deleted in-place. The key and value will always be equal.
  absl::node_hash_map<Drainer*, DrainerPtr> drainers_;
};

} // namespace TcpProxy
} // namespace Envoy
