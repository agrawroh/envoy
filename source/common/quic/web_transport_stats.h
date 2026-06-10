#pragma once

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/thread.h"

namespace Envoy {
namespace Quic {

// Stats for WebTransport over HTTP/3 sessions. These live in their own webtransport sub-scope, a
// peer of the http3 codec scope. sessions_total counts accepted sessions, sessions_rejected counts
// sessions refused by the per-connection limit, and sessions_unclaimed counts negotiated CONNECTs
// that reached a 2xx with no filter to terminate them. @see stats_macros.h
#define ALL_WEB_TRANSPORT_STATS(COUNTER, GAUGE)                                                    \
  COUNTER(sessions_total)                                                                          \
  COUNTER(sessions_rejected)                                                                       \
  COUNTER(sessions_unclaimed)                                                                      \
  COUNTER(datagrams_rx)                                                                            \
  COUNTER(datagrams_tx)                                                                            \
  GAUGE(sessions_active, Accumulate)

// Wrapper struct for the WebTransport stats. @see stats_macros.h
struct WebTransportStats {
  using AtomicPtr =
      Thread::AtomicPtr<WebTransportStats, Thread::AtomicPtrAllocMode::DeleteOnDestruct>;

  static WebTransportStats& atomicGet(AtomicPtr& ptr, Stats::Scope& scope) {
    return *ptr.get([&scope]() -> WebTransportStats* {
      return new WebTransportStats{ALL_WEB_TRANSPORT_STATS(
          POOL_COUNTER_PREFIX(scope, "webtransport."), POOL_GAUGE_PREFIX(scope, "webtransport."))};
    });
  }

  ALL_WEB_TRANSPORT_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

} // namespace Quic
} // namespace Envoy
