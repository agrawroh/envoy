#pragma once

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/thread.h"

namespace Envoy {
namespace Quic {

// Stats for WebTransport over HTTP/3 sessions. These live in their own webtransport sub-scope. On a
// terminating listener they live under the listener scope and count sessions ending here and
// datagrams to and from the client. On a proxying cluster they live under the cluster scope and
// count relayed sessions and datagrams forwarded each way. sessions_total counts accepted or
// relayed sessions, sessions_rejected counts sessions refused by the per-connection limit or by the
// relay, and sessions_unclaimed counts negotiated CONNECTs that reached a 2xx with no filter to
// terminate them. @see stats_macros.h
#define ALL_WEB_TRANSPORT_STATS(COUNTER, GAUGE)                                                    \
  COUNTER(sessions_total)                                                                          \
  COUNTER(sessions_rejected)                                                                       \
  COUNTER(sessions_unclaimed)                                                                      \
  COUNTER(streams_rejected_per_session)                                                            \
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
