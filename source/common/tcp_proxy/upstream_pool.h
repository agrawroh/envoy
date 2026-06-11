#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/common/time.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/tcp/conn_pool.h"
#include "envoy/thread_local/thread_local_object.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/tcp_proxy/upstream.h"

#include "absl/container/flat_hash_map.h"

namespace Envoy {
namespace TcpProxy {

// Phase 2 of the kTLS-splice work: a per-worker warm upstream connection pool so PUT connection
// churn reuses already-handshaked, kTLS-installed upstream connections instead of paying a TLS
// handshake + kTLS install per request. Ported in spirit from OSD's zerocopy-proxy
// connection_pool.rs, but as a thread-local (single-worker-confined) object, so no mutex is needed.
//
// Only the BUFFERED relay path pools: a spliced connection cannot be returned because the splice
// pump hijacks its raw fd. The Filter decides per request whether to splice (large GET, 1:1,
// unpooled) or take the buffered+framed+pooled path (high-churn small PUT). This class owns only
// the warm-idle connections between requests; an in-flight connection is owned by its Filter.
class UpstreamPool : public ThreadLocal::ThreadLocalObject,
                     public Logger::Loggable<Logger::Id::pool> {
public:
  // Sizing mirrors OSD connection_pool.rs:24-36. IDLE_TTL stays under S3's ~5s idle close.
  static constexpr size_t MinPoolSize = 32;
  static constexpr size_t MaxPoolSizePerHost = 64;
  static constexpr std::chrono::seconds IdleTtl{4};
  static constexpr std::chrono::seconds MaintenanceInterval{1};

  struct Stats {
    uint64_t checkout_hit{0};
    uint64_t checkout_miss{0};
    uint64_t evicted_idle{0};
    uint64_t checkin_dropped{
        0}; // dropped on check-in because the host pool was at MaxPoolSizePerHost
    uint64_t stale_discarded{0}; // failed the check-out clean-check
  };

  UpstreamPool(Event::Dispatcher& dispatcher, Upstream::ClusterManager& cluster_manager);
  ~UpstreamPool() override;

  // Check out a warm connection for `host_key` ("ip:port"). Returns nullptr on a miss (the caller
  // then establishes a fresh connection via the normal newStream path). LIFO: hands back the
  // freshest entry (least likely to have been idle-closed by S3), and discards entries that fail
  // the clean-check.
  GenericUpstreamPtr checkout(absl::string_view host_key);

  // Return a connection to the pool after a completed, cleanly-framed exchange. Caller must have
  // already released ownership (nulled its own handle) so the pool owns the close. `is_clean` is
  // false if the connection errored mid-exchange or carried `Connection: close`; such connections
  // are dropped, not pooled.
  void checkin(absl::string_view host_key, GenericUpstreamPtr upstream, bool is_clean);

  const Stats& stats() const { return stats_; }
  size_t size(absl::string_view host_key) const;

private:
  // Callbacks installed on a connection while it sits idle in the pool, between the check-in that
  // released it and the next checkout that rebinds it to a live Filter. A pooled GenericUpstream
  // outlives the Filter that minted it; without this sink the connection's read callbacks would
  // still point at that destroyed Filter, so an idle-window upstream byte OR close event would
  // deref freed memory (use-after-free). This sink belongs to the pool (stable lifetime) and is
  // intentionally INERT: it only logs. It does NOT close the connection or touch pools_, because it
  // can fire synchronously while a pools_ scan (e.g. a checkout clean-check) is mid-iteration, and
  // a close would re-enter and corrupt the deque/map. Disposal is therefore deferred: leaving an
  // unexpected byte buffered (not draining it) makes the next checkout's MSG_PEEK clean-check see
  // it and discard the entry, and a peer close leaves the connection Closed for the checkout/
  // maintenance clean-checks to evict. The same instance is shared by every idle connection (it is
  // stateless).
  class IdleUpstreamCallbacks : public Tcp::ConnectionPool::UpstreamCallbacks,
                                public Logger::Loggable<Logger::Id::pool> {
  public:
    // Tcp::ConnectionPool::UpstreamCallbacks
    void onUpstreamData(Buffer::Instance& data, bool end_stream) override;
    // Network::ConnectionCallbacks
    void onEvent(Network::ConnectionEvent event) override;
    void onAboveWriteBufferHighWatermark() override {}
    void onBelowWriteBufferLowWatermark() override {}
  };

  struct Entry {
    GenericUpstreamPtr upstream;
    MonotonicTime idle_since;
  };

  // Maintenance timer body: evict entries idle longer than IdleTtl. Pre-warming (replenish to
  // MinPoolSize off the request path) is Phase 3 and intentionally not done here yet.
  void onMaintenance();
  // Non-blocking MSG_PEEK health probe (OSD is_connection_clean, server.rs:926-932): EAGAIN =>
  // clean.
  bool isClean(GenericUpstream& upstream) const;
  // Cleanly close a pooled connection the pool owns (NoFlush), if it is not already closed.
  static void closeConnection(GenericUpstream& upstream);

  Event::Dispatcher& dispatcher_;
  // Held for Phase 3 off-path pre-warming (Filter-less newStream via the cluster's conn pool); not
  // yet exercised by the eviction-only Phase 2.0 maintenance loop.
  [[maybe_unused]] Upstream::ClusterManager& cluster_manager_;
  Event::TimerPtr maintenance_timer_;
  IdleUpstreamCallbacks idle_callbacks_;
  absl::flat_hash_map<std::string, std::deque<Entry>> pools_;
  Stats stats_;
};

} // namespace TcpProxy
} // namespace Envoy
