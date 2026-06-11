#include "source/common/tcp_proxy/upstream_pool.h"

#include <chrono>
#include <iterator>
#include <utility>

#include "envoy/api/io_error.h"
#include "envoy/network/connection.h"
#include "envoy/network/io_handle.h"
#include "envoy/network/socket.h"

#include "source/common/common/assert.h"

#if defined(__linux__)
#include <sys/socket.h>
#endif

namespace Envoy {
namespace TcpProxy {

namespace {
// MSG_PEEK is the only flag we pass to recv (mirrors the listener-filter peek path). It is defined
// by <sys/socket.h> on Linux; provide a fallback so a non-Linux build still compiles (isClean
// degrades to a plain non-blocking probe there, which is acceptable because the pool only ships on
// Linux/kTLS).
#ifndef MSG_PEEK
#define MSG_PEEK 0
#endif
} // namespace

UpstreamPool::UpstreamPool(Event::Dispatcher& dispatcher, Upstream::ClusterManager& cluster_manager)
    : dispatcher_(dispatcher), cluster_manager_(cluster_manager) {
  // Eviction-only maintenance for now (Phase 2.0): sweep idle entries every MaintenanceInterval.
  // Off-path pre-warming (replenish to MinPoolSize) is Phase 3 and intentionally not done here.
  maintenance_timer_ = dispatcher_.createTimer([this]() { onMaintenance(); });
  maintenance_timer_->enableTimer(
      std::chrono::duration_cast<std::chrono::milliseconds>(MaintenanceInterval));
}

UpstreamPool::~UpstreamPool() {
  // Close every pooled connection cleanly before the deques drop the unique_ptrs. The pool owns
  // these connections (the Filters that minted them released ownership on check-in), so we must
  // close them here; otherwise ~GenericUpstream would tear them down without a graceful NoFlush
  // close.
  for (auto& [host_key, entries] : pools_) {
    for (auto& entry : entries) {
      closeConnection(*entry.upstream);
    }
  }
}

void UpstreamPool::closeConnection(GenericUpstream& upstream) {
  OptRef<Network::Connection> conn = upstream.upstreamConnection();
  if (conn.has_value() && conn->state() != Network::Connection::State::Closed) {
    // NoFlush keeps the close off the write path and marks the connection Closed immediately,
    // matching how the splice path force-closes a hijacked upstream (tcp_proxy.cc tearDownSplice).
    conn->close(Network::ConnectionCloseType::NoFlush);
  }
}

GenericUpstreamPtr UpstreamPool::checkout(absl::string_view host_key) {
  auto it = pools_.find(host_key);
  if (it == pools_.end()) {
    ++stats_.checkout_miss;
    return nullptr;
  }

  std::deque<Entry>& entries = it->second;
  // LIFO: pop the freshest entry off the back first. It has been idle the shortest time and so is
  // the least likely to have been closed by S3's idle timeout. Discard any entry that fails the
  // clean-check and keep going until we find a clean one or exhaust the host pool.
  while (!entries.empty()) {
    Entry entry = std::move(entries.back());
    entries.pop_back();

    if (!isClean(*entry.upstream)) {
      ++stats_.stale_discarded;
      // Failed the clean-check: the peer closed it or left poisoning bytes. Close and drop it.
      closeConnection(*entry.upstream);
      continue;
    }

    ++stats_.checkout_hit;
    GenericUpstreamPtr upstream = std::move(entry.upstream);
    if (entries.empty()) {
      // Keep the map free of empty host buckets so size()/maintenance stay cheap.
      pools_.erase(it);
    }
    return upstream;
  }

  // The host bucket existed but every entry was stale.
  pools_.erase(it);
  ++stats_.checkout_miss;
  return nullptr;
}

void UpstreamPool::checkin(absl::string_view host_key, GenericUpstreamPtr upstream, bool is_clean) {
  ASSERT(upstream != nullptr);

  // The caller must have released ownership already (nulled its own handle) so the pool owns the
  // close from here on. A connection that errored mid-exchange or carried Connection: close is not
  // reusable; drop it (closing cleanly) rather than poison the next request on it.
  if (!is_clean) {
    ++stats_.checkin_dropped;
    closeConnection(*upstream);
    return;
  }

  // A non-blocking peek catches the case where the peer half-closed or sent unexpected bytes
  // between the framed exchange completing and check-in. Such a connection cannot be safely reused.
  if (!isClean(*upstream)) {
    ++stats_.stale_discarded;
    closeConnection(*upstream);
    return;
  }

  std::deque<Entry>& entries = pools_[std::string(host_key)];
  if (entries.size() >= MaxPoolSizePerHost) {
    // At capacity: evict the oldest entry (front) to make room, mirroring OSD's put().
    ++stats_.checkin_dropped;
    closeConnection(*entries.front().upstream);
    entries.pop_front();
  }

  // Rebind the connection's read callbacks to the pool-owned idle sink so an upstream byte or close
  // event arriving while the connection sits idle (after the checking-in Filter is destroyed,
  // before the next checkout rebinds) is handled safely instead of dereferencing the dead Filter.
  // The sink closes the connection on any such event; the next checkout's clean-check then discards
  // it.
  upstream->rebindUpstreamCallbacks(idle_callbacks_);

  Entry entry;
  entry.upstream = std::move(upstream);
  entry.idle_since = dispatcher_.timeSource().monotonicTime();
  entries.push_back(std::move(entry));
}

void UpstreamPool::IdleUpstreamCallbacks::onUpstreamData(Buffer::Instance& data, bool end_stream) {
  // This sink exists only to keep an idle pooled connection from delivering bytes to the destroyed
  // Filter that minted it. In practice it never fires: the connection is read-disabled at check-in,
  // so no read event is delivered while it sits in the pool. If it ever does fire, do NOT drain the
  // bytes. Leaving them buffered is what makes the next checkout's MSG_PEEK clean-check see
  // leftover data and discard the connection (draining would hide the leftover and risk reuse). We
  // also do not close here, to avoid mutating pools_ from inside a connection callback; the
  // clean-check handles disposal.
  ENVOY_LOG(
      debug,
      "tcp_proxy upstream pool: unexpected {} bytes on idle pooled connection (end_stream={});"
      " will be discarded at next clean-check",
      data.length(), end_stream);
}

void UpstreamPool::IdleUpstreamCallbacks::onEvent(Network::ConnectionEvent event) {
  // The peer closed (or half-closed) an idle pooled connection. Nothing to do here: the entry stays
  // in the deque with a now-Closed connection, and the next checkout (or maintenance eviction) sees
  // it as not-clean / Closed and discards it. We must NOT touch pools_ from inside this callback
  // (it can fire during a checkout's clean-check), so eviction is deferred to those scans.
  ENVOY_LOG(debug, "tcp_proxy upstream pool: event {} on idle pooled connection",
            static_cast<int>(event));
}

void UpstreamPool::onMaintenance() {
  const MonotonicTime now = dispatcher_.timeSource().monotonicTime();

  // Evict entries idle longer than IdleTtl. Entries within a host bucket are ordered oldest-front
  // to newest-back (push_back on check-in), so once we hit a fresh-enough entry the rest of the
  // bucket is fresher and we can stop scanning it.
  for (auto it = pools_.begin(); it != pools_.end();) {
    std::deque<Entry>& entries = it->second;
    while (!entries.empty() && (now - entries.front().idle_since) > IdleTtl) {
      ++stats_.evicted_idle;
      closeConnection(*entries.front().upstream);
      entries.pop_front();
    }
    if (entries.empty()) {
      // absl::flat_hash_map::erase returns void (unlike std::unordered_map), so capture the next
      // iterator before erasing. erase() does not invalidate other live iterators.
      auto next = std::next(it);
      pools_.erase(it);
      it = next;
    } else {
      ++it;
    }
  }

  // Re-arm for the next sweep.
  maintenance_timer_->enableTimer(
      std::chrono::duration_cast<std::chrono::milliseconds>(MaintenanceInterval));
}

bool UpstreamPool::isClean(GenericUpstream& upstream) const {
  // OSD is_connection_clean (server.rs:926-932): a non-blocking MSG_PEEK of one byte.
  //   - EAGAIN/Again      => no pending data, peer has not closed => clean.
  //   - return_value_ == 0 => peer performed an orderly close                => stale.
  //   - return_value_ > 0  => unexpected pending bytes (response over-read,
  //                           pipelined/smuggled data)                       => stale.
  //   - any other error    => the socket is unusable                         => stale.
  // The peek runs through the upstream connection's ioHandle, so for a kTLS-installed connection it
  // peeks the already-decrypted plaintext stream (the connection stays kTLS-installed across reuse
  // because the buffered relay path never tears the transport socket down).
  OptRef<Network::Connection> conn = upstream.upstreamConnection();
  if (!conn.has_value() || conn->state() == Network::Connection::State::Closed) {
    return false;
  }

  Network::IoHandle& io_handle = conn->getSocket()->ioHandle();
  if (!io_handle.isOpen()) {
    return false;
  }

  uint8_t probe = 0;
  const Api::IoCallUint64Result result = io_handle.recv(&probe, 1, MSG_PEEK);
  if (result.wouldBlock()) {
    return true;
  }
  // Any successful return (including 0 == orderly close, or >0 == leftover/poisoning bytes) or any
  // non-EAGAIN error means the connection is not cleanly reusable.
  return false;
}

size_t UpstreamPool::size(absl::string_view host_key) const {
  auto it = pools_.find(host_key);
  return it == pools_.end() ? 0 : it->second.size();
}

} // namespace TcpProxy
} // namespace Envoy
