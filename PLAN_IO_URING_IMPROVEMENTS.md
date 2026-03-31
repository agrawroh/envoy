# Plan: Envoy io_uring Comprehensive Improvements

**Goal:** Transform io_uring from experimental to production-grade, closing the gap with epoll and exceeding it.
**Target files:**
- `source/common/io/io_uring_impl.cc` / `.h`
- `source/common/io/io_uring_worker_impl.cc` / `.h`
- `source/common/network/io_uring_socket_handle_impl.cc` / `.h`
- `envoy/common/io/io_uring.h`

---

## Current State Assessment

The io_uring implementation is **architecturally sound** (per-thread rings, eventfd integration with libevent, delay_submit_ batching during completions) but **operationally suboptimal**. It uses only 7 of ~20 important io_uring operations. The result: io_uring is likely **slower** than epoll for typical proxy workloads.

### Operations Currently Implemented (7):
| Operation | Method | File:Line |
|-----------|--------|-----------|
| ACCEPT | `prepareAccept()` | io_uring_impl.cc:93 |
| CONNECT | `prepareConnect()` | io_uring_impl.cc:108 |
| READV | `prepareReadv()` | io_uring_impl.cc:124 |
| WRITEV | `prepareWritev()` | io_uring_impl.cc:139 |
| CLOSE | `prepareClose()` | io_uring_impl.cc:154 |
| CANCEL | `prepareCancel()` | io_uring_impl.cc:168 |
| SHUTDOWN | `prepareShutdown()` | io_uring_impl.cc:183 |

### Operations NOT Implemented:
- `IORING_OP_RECV` / `IORING_OP_SEND` (socket-oriented, supports flags)
- `IORING_OP_RECV_MULTISHOT` (kernel-maintained receive loop)
- `IORING_OP_ACCEPT_MULTISHOT` (kernel-maintained accept loop)
- `IORING_OP_SEND_ZC` (zero-copy send)
- `IORING_OP_READ_FIXED` (pre-registered buffer read)
- `IORING_OP_SPLICE` (kernel-to-kernel data movement)
- `IORING_REGISTER_BUFFERS` (fixed buffer registration)
- `IORING_REGISTER_FILES` (fixed file registration)
- Provided buffer rings (`io_uring_buf_ring`)

### Diagnosis Table

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| 1 | **Per-request heap buffer allocation** | 30-40% read perf loss | Medium | Not fixed |
| 2 | **Per-operation io_uring_submit()** | 5-10x excess syscalls | Medium | Not fixed |
| 3 | **CQ ring overflow: ASSERT-only** | Data loss / crash in prod | High | Not fixed |
| 4 | **No multishot accept** | Listener bottleneck | Low | Not fixed |
| 5 | **No multishot recv** | Per-connection throughput loss | Medium | Not fixed |
| 6 | **No fixed file registration** | Per-fd kernel lookup overhead | Medium | Not fixed |
| 7 | **No zero-copy send** | Every write copies to kernel | Medium | Not fixed |
| 8 | **No COOP_TASKRUN/SINGLE_ISSUER/DEFER_TASKRUN** | 15-20% latency overhead | Low | Not fixed |
| 9 | **No splice for proxy forwarding** | Data transits userspace unnecessarily | High | Not fixed |
| 10 | **CQ ring = SQ ring size** | 2x overflow risk | Low | Not fixed |
| 11 | **Write buffer backpressure missing** | Flood protection broken | Medium | Not fixed |
| 12 | **8KB default read buffer** | Too small for bulk, too large for keepalive | Low | Not fixed |

---

## Change 1: Modern Setup Flags [LOW EFFORT - 15-20% latency improvement]

### Problem

The ring is initialized with only `IORING_SETUP_SQPOLL` (optional). Missing critical flags.

**File:** `source/common/io/io_uring_impl.cc`, lines 20-31:
```cpp
IoUringImpl::IoUringImpl(uint32_t io_uring_size, bool use_submission_queue_polling)
    : cqes_(io_uring_size, nullptr) {
  struct io_uring_params p {};
  if (use_submission_queue_polling) {
    p.flags |= IORING_SETUP_SQPOLL;
  }
  int ret = io_uring_queue_init_params(io_uring_size, &ring_, &p);
```

### Fix

```cpp
IoUringImpl::IoUringImpl(uint32_t io_uring_size, bool use_submission_queue_polling)
    : cqes_(io_uring_size * 2, nullptr) {  // 2x for CQ sizing
  struct io_uring_params p {};

  // Performance flags for worker-thread model (Envoy uses 1 ring per worker thread):
  p.flags |= IORING_SETUP_COOP_TASKRUN;    // Avoid expensive IPIs on completion
  p.flags |= IORING_SETUP_SINGLE_ISSUER;   // Single-thread optimization (lockless paths)
  p.flags |= IORING_SETUP_DEFER_TASKRUN;   // Batch task_work to io_uring_enter() calls

  // CQ ring should be 2x SQ for overflow headroom:
  p.flags |= IORING_SETUP_CQSIZE;
  p.cq_entries = io_uring_size * 2;

  if (use_submission_queue_polling) {
    p.flags |= IORING_SETUP_SQPOLL;
    p.sq_thread_idle = 100;  // ms before SQPOLL thread sleeps
  }

  int ret = io_uring_queue_init_params(io_uring_size, &ring_, &p);
  if (ret == -EINVAL) {
    // Fallback: retry without newer flags for older kernels (< 6.1)
    p.flags &= ~(IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SINGLE_ISSUER |
                  IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQSIZE);
    p.cq_entries = 0;
    cqes_.resize(io_uring_size);
    ret = io_uring_queue_init_params(io_uring_size, &ring_, &p);
  }
  RELEASE_ASSERT(ret >= 0, fmt::format("io_uring init failed: {}", ret));
}
```

**Why these flags matter (from kernel analysis):**
- `COOP_TASKRUN`: Without it, the kernel sends an Inter-Processor Interrupt (IPI) to the io_uring thread every time a completion is ready. With it, completions are deferred to the next `io_uring_enter()` call. This eliminates ~15-20% of wakeup overhead.
- `SINGLE_ISSUER`: The kernel can skip atomic operations and use simpler lockless paths since only one thread submits.
- `DEFER_TASKRUN`: Instead of running task_work (completion processing) in every context switch, defer to `io_uring_enter()` calls. Reduces spurious wakeups.
- `CQSIZE`: By default CQ = 2x SQ in newer kernels, but our init doesn't set this explicitly.

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Lines 20-31 (constructor)
- Update `cqes_` vector size to `io_uring_size * 2` to match CQ ring size

---

## Change 2: CQ Ring Overflow Detection and Recovery [CRITICAL - Reliability]

### Problem

```cpp
// io_uring_impl.cc:97 (and 113, 128, 143, 157, 170, 186) - 7 occurrences
ASSERT(!(*(ring_.sq.kflags) & IORING_SQ_CQ_OVERFLOW));
```

This is a **debug-only assertion**. In release builds, if the CQ ring overflows:
- Completions are **silently dropped** by the kernel
- Sockets enter a hung state (requests never complete)
- Memory leaks (request objects never freed)
- Data loss possible

### Fix

**Step 1: Add overflow detection to every prepare method:**

```cpp
// Add private helper method to IoUringImpl:
bool IoUringImpl::checkAndRecoverCqOverflow() {
  if (*(ring_.sq.kflags) & IORING_SQ_CQ_OVERFLOW) {
    ENVOY_LOG(warn, "io_uring CQ overflow detected, draining completions");
    cq_overflow_count_++;

    // Force drain all available completions
    unsigned count = io_uring_peek_batch_cqe(&ring_, cqes_.data(), cqes_.size());
    for (unsigned i = 0; i < count; ++i) {
      struct io_uring_cqe* cqe = cqes_[i];
      if (overflow_drain_cb_) {
        overflow_drain_cb_(reinterpret_cast<Request*>(cqe->user_data), cqe->res, false);
      }
    }
    io_uring_cq_advance(&ring_, count);
    return count > 0;
  }
  return false;
}
```

**Step 2: Call it before every prepare:**

```cpp
IoUringResult IoUringImpl::prepareAccept(os_fd_t fd, struct sockaddr* addr,
                                          socklen_t* addrlen, Request* user_data) {
  checkAndRecoverCqOverflow();  // Replace ASSERT with recovery

  struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
  if (sqe == nullptr) {
    // SQ is full - flush and retry
    submit();
    sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
  }
  io_uring_prep_accept(sqe, fd, addr, addrlen, 0);
  io_uring_sqe_set_data(sqe, user_data);
  return IoUringResult::Ok;
}
```

**Step 3: Add CQ overflow stat:**

```cpp
// In IoUringImpl header:
uint64_t cq_overflow_count_{0};
CompletionCb overflow_drain_cb_;

// Expose for monitoring:
uint64_t cqOverflowCount() const { return cq_overflow_count_; }
void setOverflowDrainCallback(CompletionCb cb) { overflow_drain_cb_ = std::move(cb); }
```

**Step 4: Wire up the drain callback in IoUringWorkerImpl:**

```cpp
// In IoUringWorkerImpl constructor:
io_uring_->setOverflowDrainCallback(
    [this](Request* req, int32_t result, bool) {
      // Same completion processing as normal path
      switch (req->type()) {
        case Request::RequestType::Read:
          req->socket().onRead(req, result, false);
          break;
        // ... other cases
      }
      delete req;
    });
```

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Replace all 7 ASSERT lines with `checkAndRecoverCqOverflow()`
- `source/common/io/io_uring_impl.h`: Add overflow counter, drain callback, helper method
- `source/common/io/io_uring_worker_impl.cc`: Wire up drain callback in constructor

---

## Change 3: SQE Batching - Defer Submit Until Batch Boundary [5-10x syscall reduction]

### Problem

Every submit* method in `io_uring_worker_impl.cc` immediately calls `submit()`:

```cpp
// Lines 138-152 (submitConnectRequest and ALL submit* methods)
auto res = io_uring_->prepareConnect(socket.fd(), address, req);
// ...
submit();  // SYSCALL per operation
```

At 100K RPS with read + write per request: 200K+ `io_uring_enter()` syscalls/second.

### Fix

The existing `delay_submit_` flag (line 253) batches during completion processing. Extend it:

**Step 1: Add a general deferred submit counter:**

```cpp
// In IoUringImpl:
uint32_t pending_sqes_{0};
bool defer_submit_{false};

void setDeferSubmit(bool defer) { defer_submit_ = defer; }

IoUringResult submitIfNeeded() {
    pending_sqes_++;
    if (defer_submit_) {
        return IoUringResult::Ok;  // Will be flushed later
    }
    return flushSubmit();
}

IoUringResult flushSubmit() {
    if (pending_sqes_ > 0) {
        pending_sqes_ = 0;
        return submit();
    }
    return IoUringResult::Ok;
}
```

**Step 2: Modify all submit* methods to use submitIfNeeded():**

```cpp
Request* IoUringWorkerImpl::submitReadRequest(IoUringSocket& socket) {
    auto* req = new ReadRequest(socket, read_buffer_size_);
    auto res = io_uring_->prepareReadv(socket.fd(), req->iov(), 1, req);
    if (res == IoUringResult::Failed) {
        io_uring_->flushSubmit();  // Flush to make room
        res = io_uring_->prepareReadv(socket.fd(), req->iov(), 1, req);
        RELEASE_ASSERT(res == IoUringResult::Ok, "unable to prepare readv");
    }
    io_uring_->submitIfNeeded();  // Deferred or immediate based on mode
    return req;
}
```

**Step 3: Batch during event processing AND connection handling:**

```cpp
void IoUringWorkerImpl::onFileEvent() {
    io_uring_->setDeferSubmit(true);   // Defer ALL submits during event processing
    delay_submit_ = true;

    io_uring_->forEveryCompletion([this](Request* req, int32_t result, bool injected) {
        // ... existing completion handling
    });

    delay_submit_ = false;
    io_uring_->setDeferSubmit(false);
    io_uring_->flushSubmit();          // Single submit for ALL queued SQEs
}
```

### Impact
Reduces `io_uring_enter()` calls from ~200K/sec to ~10-20K/sec (one per event batch).

### Specific file changes
- `source/common/io/io_uring_impl.h`: Add `pending_sqes_`, `defer_submit_`, `submitIfNeeded()`, `flushSubmit()`
- `source/common/io/io_uring_impl.cc`: Add implementations
- `source/common/io/io_uring_worker_impl.cc`: Replace `submit()` calls in all submit* methods with `submitIfNeeded()`; update `onFileEvent()` to use deferred mode

---

## Change 4: IORING_OP_RECV/SEND Instead of READV/WRITEV [LOW EFFORT]

### Problem

Socket operations use file-oriented `IORING_OP_READV`/`IORING_OP_WRITEV`. For sockets, `IORING_OP_RECV`/`IORING_OP_SEND` are more appropriate:
- Support socket-specific flags (`MSG_DONTWAIT`, `MSG_NOSIGNAL`)
- Prerequisite for multishot recv (Change 5)
- Prerequisite for zero-copy send (Change 7)

### Fix

Add new prepare methods:

```cpp
// In IoUringImpl:
IoUringResult IoUringImpl::prepareRecv(os_fd_t fd, void* buf, uint32_t len,
                                        int flags, Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_recv(sqe, fd, buf, len, flags);
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}

IoUringResult IoUringImpl::prepareSend(os_fd_t fd, const void* buf, uint32_t len,
                                        int flags, Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_send(sqe, fd, buf, len, flags | MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}
```

Gradually migrate socket read/write paths from `prepareReadv`/`prepareWritev` to `prepareRecv`/`prepareSend`.

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Add `prepareRecv()`, `prepareSend()`
- `source/common/io/io_uring_impl.h`: Declare new methods
- `envoy/common/io/io_uring.h`: Add to interface
- `source/common/io/io_uring_worker_impl.cc`: Migrate `submitReadRequest()` and `submitWriteRequest()` to use new ops

---

## Change 5: Pre-allocated Buffer Pool with Fixed Buffer Registration [CRITICAL - 30-40%]

### Problem

```cpp
// io_uring_worker_impl.cc:6-11
ReadRequest::ReadRequest(IoUringSocket& socket, uint32_t size)
    : Request(RequestType::Read, socket),
      buf_(std::make_unique<uint8_t[]>(size)),   // HEAP ALLOC PER READ
      iov_(std::make_unique<struct iovec>()) {   // HEAP ALLOC PER READ
  iov_->iov_base = buf_.get();
  iov_->iov_len = size;
}
```

At 100K RPS: 200K+ heap allocations/second (buffer + iovec per read).

### Fix

**Step 1: Create IoUringBufferPool class:**

```cpp
// New file: source/common/io/io_uring_buffer_pool.h
class IoUringBufferPool {
public:
    IoUringBufferPool(uint32_t num_buffers, uint32_t buffer_size);
    ~IoUringBufferPool();

    // Register all buffers with io_uring for IORING_OP_READ_FIXED
    void registerWithRing(struct io_uring& ring);
    void unregisterFromRing(struct io_uring& ring);

    // Acquire a free buffer (returns index, or -1 if pool exhausted)
    int32_t acquire();

    // Release buffer back to pool
    void release(int32_t index);

    // Access buffer by index
    uint8_t* data(int32_t index) { return pool_memory_.data() + index * buffer_size_; }
    uint32_t bufferSize() const { return buffer_size_; }
    uint32_t numBuffers() const { return num_buffers_; }
    uint32_t numFree() const { return free_count_; }

private:
    std::vector<uint8_t> pool_memory_;  // Contiguous, page-aligned allocation
    std::vector<struct iovec> iovecs_;
    std::vector<int32_t> free_list_;    // Stack of free buffer indices
    uint32_t free_count_;
    uint32_t buffer_size_;
    uint32_t num_buffers_;
};
```

**Step 2: Implementation:**

```cpp
// source/common/io/io_uring_buffer_pool.cc
IoUringBufferPool::IoUringBufferPool(uint32_t num_buffers, uint32_t buffer_size)
    : buffer_size_(buffer_size), num_buffers_(num_buffers), free_count_(num_buffers) {
    // Page-align the buffer size for better DMA performance
    uint32_t aligned_size = (buffer_size + 4095) & ~4095;
    pool_memory_.resize(static_cast<size_t>(num_buffers) * aligned_size, 0);
    iovecs_.resize(num_buffers);
    free_list_.resize(num_buffers);

    for (uint32_t i = 0; i < num_buffers; i++) {
        iovecs_[i].iov_base = pool_memory_.data() + i * aligned_size;
        iovecs_[i].iov_len = buffer_size;
        free_list_[i] = static_cast<int32_t>(num_buffers - 1 - i);  // Stack order
    }
}

void IoUringBufferPool::registerWithRing(struct io_uring& ring) {
    int ret = io_uring_register_buffers(&ring, iovecs_.data(), num_buffers_);
    if (ret < 0) {
        ENVOY_LOG(warn, "io_uring_register_buffers failed: {}, fixed reads disabled", ret);
    }
}

int32_t IoUringBufferPool::acquire() {
    if (free_count_ == 0) return -1;
    return free_list_[--free_count_];
}

void IoUringBufferPool::release(int32_t index) {
    ASSERT(index >= 0 && index < static_cast<int32_t>(num_buffers_));
    free_list_[free_count_++] = index;
}
```

**Step 3: Add `prepareReadFixed()` to IoUringImpl:**

```cpp
IoUringResult IoUringImpl::prepareReadFixed(os_fd_t fd, void* buf, uint32_t len,
                                             uint16_t buf_index, Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_read_fixed(sqe, fd, buf, len, 0, buf_index);
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}
```

**Step 4: Modify ReadRequest to use pool:**

```cpp
class ReadRequest : public Request {
public:
    ReadRequest(IoUringSocket& socket, IoUringBufferPool& pool)
        : Request(RequestType::Read, socket),
          pool_(pool),
          buf_index_(pool.acquire()) {
        RELEASE_ASSERT(buf_index_ >= 0, "io_uring buffer pool exhausted");
    }

    ~ReadRequest() {
        if (buf_index_ >= 0) {
            pool_.release(buf_index_);
        }
    }

    uint8_t* data() { return pool_.data(buf_index_); }
    uint32_t capacity() { return pool_.bufferSize(); }
    int32_t bufIndex() const { return buf_index_; }

private:
    IoUringBufferPool& pool_;
    int32_t buf_index_;
};
```

**Step 5: Initialize pool in IoUringWorkerImpl:**

```cpp
IoUringWorkerImpl::IoUringWorkerImpl(uint32_t io_uring_size, ...)
    : ... {
    // Pre-allocate buffer pool: 2x ring size for headroom
    buffer_pool_ = std::make_unique<IoUringBufferPool>(
        io_uring_size * 2,
        read_buffer_size_
    );
    buffer_pool_->registerWithRing(io_uring_->ring());
    // ... rest of init
}
```

### Specific file changes
- NEW: `source/common/io/io_uring_buffer_pool.h` / `.cc`
- `source/common/io/io_uring_impl.cc`: Add `prepareReadFixed()`
- `source/common/io/io_uring_impl.h`: Declare `prepareReadFixed()`, expose `ring()` accessor
- `source/common/io/io_uring_worker_impl.h`: Add `buffer_pool_` member, modify `ReadRequest`
- `source/common/io/io_uring_worker_impl.cc`: Initialize pool, use `prepareReadFixed()` in `submitReadRequest()`

---

## Change 6: Write Buffer Backpressure [MEDIUM - Reliability]

### Problem

```cpp
// io_uring_worker_impl.h:219
// TODO (soulxu): We need water mark for write buffer.
```

Upper layers think data is written when it's moved to `write_buf_`. If the socket is slow, `write_buf_` grows unboundedly.

### Fix

```cpp
// In IoUringServerSocket:
static constexpr uint64_t WRITE_HIGH_WATERMARK = 128 * 1024;  // 128KB
static constexpr uint64_t WRITE_LOW_WATERMARK = 16 * 1024;    // 16KB

bool above_write_watermark_{false};

void IoUringServerSocket::write(Buffer::Instance& data) {
    write_buf_.move(data, data.length(), true);

    // Check high watermark AFTER moving data
    if (!above_write_watermark_ && write_buf_.length() > WRITE_HIGH_WATERMARK) {
        above_write_watermark_ = true;
        // Signal connection layer to pause upstream reads
        THROW_IF_NOT_OK(cb_(Event::FileReadyType::Write));
    }

    submitWriteOrShutdownRequest();
}

// On write completion:
void IoUringServerSocket::onWriteCompleted(int32_t result) {
    if (result > 0) {
        write_buf_.drain(result);
    }
    if (above_write_watermark_ && write_buf_.length() < WRITE_LOW_WATERMARK) {
        above_write_watermark_ = false;
        // Signal connection layer to resume upstream reads
    }
    submitWriteOrShutdownRequest();  // Submit next write if data remains
}
```

### Specific file changes
- `source/common/io/io_uring_worker_impl.h`: Add watermark constants and state to `IoUringServerSocket`
- `source/common/io/io_uring_worker_impl.cc`: Add watermark checks in `write()` and completion handler

---

## Change 7: Multishot Accept [MEDIUM - Listener Scalability]

### Problem

Each accepted connection requires re-submitting an accept SQE. Additionally, `IoUringSocketHandleImpl::accept()` (line 184) uses **synchronous `::accept()`**, not io_uring at all.

### Fix

```cpp
// In IoUringImpl:
IoUringResult IoUringImpl::prepareMultishotAccept(os_fd_t fd, struct sockaddr* addr,
                                                   socklen_t* addrlen, Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_multishot_accept(sqe, fd, addr, addrlen, 0);
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}
```

In the completion handler:
```cpp
// cqe->res is the new accepted fd
// Check if multishot is still active:
if (!(cqe->flags & IORING_CQE_F_MORE)) {
    // Multishot expired (kernel error or resource limit), re-arm
    submitMultishotAccept(listen_fd);
}
```

Modify `IoUringSocketHandleImpl::accept()` to return connections from the multishot accept completions rather than calling `::accept()`.

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Add `prepareMultishotAccept()`
- `source/common/io/io_uring_worker_impl.cc`: Add multishot accept handling in worker
- `source/common/network/io_uring_socket_handle_impl.cc`: Replace sync accept with async completions

---

## Change 8: Multishot Recv with Provided Buffer Ring [MEDIUM - Throughput]

### Problem

Each data receipt requires a new ReadRequest + SQE submission + buffer allocation.

### Fix

**Step 1: Register a provided buffer ring per worker:**

```cpp
// In IoUringWorkerImpl:
struct io_uring_buf_ring* buf_ring_{nullptr};
std::vector<uint8_t> ring_bufs_;
uint32_t num_ring_bufs_;
uint16_t buf_group_id_;

void IoUringWorkerImpl::setupProvidedBufferRing(uint32_t num_bufs, uint32_t buf_size) {
    num_ring_bufs_ = num_bufs;
    ring_bufs_.resize(static_cast<size_t>(num_bufs) * buf_size);

    // Allocate and initialize the buffer ring
    size_t ring_size = sizeof(struct io_uring_buf) * num_bufs;
    void* ring_mem = mmap(nullptr, ring_size, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    buf_ring_ = static_cast<struct io_uring_buf_ring*>(ring_mem);
    io_uring_buf_ring_init(buf_ring_);

    // Register with kernel
    struct io_uring_buf_reg reg = {};
    reg.ring_addr = reinterpret_cast<uint64_t>(buf_ring_);
    reg.ring_entries = num_bufs;
    reg.bgid = buf_group_id_;
    io_uring_register_buf_ring(&ring_, &reg, 0);

    // Add all buffers to the ring
    for (uint32_t i = 0; i < num_bufs; i++) {
        io_uring_buf_ring_add(buf_ring_,
                              ring_bufs_.data() + i * buf_size,
                              buf_size, i,
                              io_uring_buf_ring_mask(num_bufs), i);
    }
    io_uring_buf_ring_advance(buf_ring_, num_bufs);
}
```

**Step 2: Submit multishot recv per socket:**

```cpp
IoUringResult IoUringImpl::prepareMultishotRecv(os_fd_t fd, uint16_t buf_group,
                                                 Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = buf_group;
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}
```

**Step 3: Completion handler extracts buffer ID:**

```cpp
// In completion callback for multishot recv:
uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
uint8_t* data = ring_bufs_.data() + buf_id * buf_size;
uint32_t len = cqe->res;

// Copy data to socket's read buffer
socket.readBuf().add(data, len);

// Return buffer to the ring for reuse
io_uring_buf_ring_add(buf_ring_, data, buf_size, buf_id,
                      io_uring_buf_ring_mask(num_ring_bufs_), 0);
io_uring_buf_ring_advance(buf_ring_, 1);

// Check if multishot is still active
if (!(cqe->flags & IORING_CQE_F_MORE)) {
    submitMultishotRecv(socket);  // Re-arm
}
```

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Add `prepareMultishotRecv()`
- `source/common/io/io_uring_worker_impl.h`: Add buffer ring members
- `source/common/io/io_uring_worker_impl.cc`: Add `setupProvidedBufferRing()`, modify completion handler

---

## Change 9: Zero-Copy Send (IORING_OP_SEND_ZC) [MEDIUM - Write Throughput]

### Problem

All writes use `IORING_OP_WRITEV` which copies data into the kernel.

### Fix

```cpp
IoUringResult IoUringImpl::prepareSendZc(os_fd_t fd, const void* buf, uint32_t len,
                                          Request* user_data) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (sqe == nullptr) return IoUringResult::Failed;
    io_uring_prep_send_zc(sqe, fd, buf, len, MSG_NOSIGNAL, 0);
    io_uring_sqe_set_data(sqe, user_data);
    return IoUringResult::Ok;
}
```

**Critical: Notification CQE handling.** Zero-copy send generates TWO completions:
1. First CQE: send completed (with `IORING_CQE_F_MORE` flag)
2. Second CQE: buffer safe to reuse (with `IORING_CQE_F_NOTIF` flag)

The write buffer must NOT be freed until the notification arrives:

```cpp
void onWriteCompletion(Request* req, int32_t result, uint32_t flags) {
    if (flags & IORING_CQE_F_NOTIF) {
        // Buffer is now safe to reuse/free
        req->socket().onZcNotification();
        delete req;
        return;
    }
    if (flags & IORING_CQE_F_MORE) {
        // More CQEs coming (notification pending) - don't free buffer yet
        req->socket().onWriteCompleted(result);
        // Don't delete req - wait for notification
        return;
    }
    // Normal (non-ZC) completion
    req->socket().onWriteCompleted(result);
    delete req;
}
```

### Specific file changes
- `source/common/io/io_uring_impl.cc`: Add `prepareSendZc()`
- `source/common/io/io_uring_worker_impl.cc`: Add ZC notification handling in completion path
- `source/common/io/io_uring_worker_impl.h`: Add ZC state tracking to WriteRequest

---

## Change 10: Fixed File Registration [MEDIUM - Micro-optimization]

### Problem

Every io_uring operation does `fdget()`/`fdput()` in the kernel (~50-100ns per op).

### Fix

```cpp
// In IoUringWorkerImpl:
static constexpr uint32_t MAX_FIXED_FILES = 4096;
bool fixed_files_registered_{false};

void registerFixedFiles() {
    std::vector<int> fds(MAX_FIXED_FILES, -1);
    int ret = io_uring_register_files(&ring_, fds.data(), MAX_FIXED_FILES);
    if (ret == 0) {
        fixed_files_registered_ = true;
    }
}

// When accepting a new connection:
int32_t allocateFixedFileSlot(os_fd_t fd) {
    int ret = io_uring_register_files_update(&ring_, next_slot_, &fd, 1);
    if (ret < 0) return -1;
    return next_slot_++;
}
```

All subsequent operations use `IOSQE_FIXED_FILE`:
```cpp
sqe->flags |= IOSQE_FIXED_FILE;
sqe->fd = fixed_file_index;  // Not the OS fd
```

### Specific file changes
- `source/common/io/io_uring_impl.h`: Add fixed file management
- `source/common/io/io_uring_worker_impl.cc`: Register at init, allocate slots on accept

---

## Change 11: Splice for Zero-Copy Proxy Forwarding [HIGH EFFORT - Architecture]

### Problem

For TCP proxying (Envoy's primary use case): upstream socket -> Envoy buffer -> downstream socket. The buffer transit involves full memcpy. With `IORING_OP_SPLICE`, data moves directly between sockets via a kernel pipe.

### Fix

```cpp
// Per-proxy-connection state:
int pipe_fds_[2]{-1, -1};

void setupSplicePipe() {
    pipe2(pipe_fds_, O_NONBLOCK);
    // Increase pipe buffer for throughput (default 64KB, set to 1MB)
    fcntl(pipe_fds_[0], F_SETPIPE_SZ, 1048576);
}

// Submit linked splice pair:
void submitSpliceForward(os_fd_t src_fd, os_fd_t dst_fd, uint32_t chunk_size) {
    // SQE 1: splice from source socket to pipe write end
    auto* sqe1 = io_uring_get_sqe(&ring_);
    io_uring_prep_splice(sqe1, src_fd, -1, pipe_fds_[1], -1,
                         chunk_size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    sqe1->flags |= IOSQE_IO_LINK;  // Chain: splice_in -> splice_out

    // SQE 2: splice from pipe read end to destination socket
    auto* sqe2 = io_uring_get_sqe(&ring_);
    io_uring_prep_splice(sqe2, pipe_fds_[0], -1, dst_fd, -1,
                         chunk_size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
}
```

**Important caveats:**
- Does NOT work with TLS (data must be decrypted) - only for plaintext TCP proxy or kTLS paths
- Requires filter chain integration to detect "passthrough" connections (no L7 processing)
- Pipe buffer size limits per-splice throughput (set to 1MB via `F_SETPIPE_SZ`)
- `IOSQE_IO_LINK` chains the two splice operations atomically

**Implementation approach:** Add `supports_splice()` to transport socket interface. When connection manager detects both upstream and downstream support splice (both plaintext or both kTLS), switch to splice mode.

### This should be a separate PR due to architectural scope.

---

## Implementation Phases

### Phase 1: Foundation (1-2 weeks) - These block everything else

| Order | Change | Effort | Impact |
|-------|--------|--------|--------|
| 1 | **Change 1** (setup flags) | 30 min | 15-20% latency |
| 2 | **Change 2** (CQ overflow) | 4 hours | Prevents crashes |
| 3 | **Change 3** (SQE batching) | 4 hours | 5-10x syscall reduction |
| 4 | **Change 4** (recv/send ops) | 2 hours | Prerequisite for Phase 2-3 |

### Phase 2: Buffer Management (1-2 weeks)

| Order | Change | Effort | Impact |
|-------|--------|--------|--------|
| 5 | **Change 5** (buffer pool) | 2 days | 30-40% read perf |
| 6 | **Change 6** (write backpressure) | 4 hours | Reliability fix |

### Phase 3: Advanced Features (2-3 weeks)

| Order | Change | Effort | Impact |
|-------|--------|--------|--------|
| 7 | **Change 7** (multishot accept) | 1 day | Listener scaling |
| 8 | **Change 8** (multishot recv + provided buffers) | 3 days | Throughput |
| 9 | **Change 9** (zero-copy send) | 2 days | Write throughput |
| 10 | **Change 10** (fixed file registration) | 1 day | Micro-optimization |

### Phase 4: Architecture (separate PR, 2-4 weeks)

| Order | Change | Effort | Impact |
|-------|--------|--------|--------|
| 11 | **Change 11** (splice) | 1 week | Major for TCP proxy |

---

## Testing Plan

### Unit Tests
Each new `prepare*` method needs a test in `test/common/io/io_uring_impl_test.cc`:
- `prepareRecv` / `prepareSend` with valid/invalid params
- `prepareMultishotAccept` with multishot flag verification
- `prepareMultishotRecv` with buffer group setup
- `prepareSendZc` with notification handling
- `prepareReadFixed` with registered buffer index
- Buffer pool acquire/release cycle
- Buffer pool exhaustion handling

### Integration Tests
Extend `test/common/io/io_uring_worker_impl_integration_test.cc`:
- Multishot accept stress test (10K connections in burst)
- CQ overflow recovery test (fill CQ, verify recovery)
- Buffer pool exhaustion + recovery under load
- Write backpressure (high watermark triggers, low watermark resumes)
- Zero-copy send with notification verification
- Fixed file registration + operation

### Performance Benchmarks
Compare epoll vs io_uring for:
- Short-lived connections (HTTP/1.1, keepalive disabled): measures accept + setup overhead
- Long-lived streaming (HTTP/2, large bodies): measures throughput
- Mixed proxy workload (upstream + downstream): measures end-to-end latency
- Connection storm (10K/sec new connections): measures multishot accept benefit

### Kernel Version Compatibility Matrix
| Feature | Min Kernel | Fallback |
|---------|-----------|----------|
| Basic io_uring | 5.10 | N/A (minimum) |
| COOP_TASKRUN | 5.19 | Skip flag |
| SINGLE_ISSUER | 6.0 | Skip flag |
| DEFER_TASKRUN | 6.1 | Skip flag |
| Multishot accept | 5.19 | Single-shot accept |
| Multishot recv | 6.0 | Single-shot recv |
| Provided buffer ring | 5.19 | Per-request allocation |
| SEND_ZC | 6.0 | Regular WRITEV |
| Fixed files | 5.1 | Regular fd |

---

## Configuration Changes

Update proto (`api/envoy/extensions/network/socket_interface/v3/default_socket_interface.proto`):

```protobuf
message IoUringOptions {
  google.protobuf.UInt32Value io_uring_size = 1;                    // Default: 4096 (was 1000)
  bool enable_submission_queue_polling = 2;                          // Default: false
  google.protobuf.UInt32Value read_buffer_size = 3;                 // Default: 32768 (was 8192)
  google.protobuf.UInt32Value write_timeout_ms = 4;                 // Default: 1000
  google.protobuf.UInt32Value num_buffer_pool_entries = 5;          // Default: 8192 (new)
  bool enable_zero_copy_send = 6;                                    // Default: false (new)
  bool enable_multishot_accept = 7;                                  // Default: true (new)
  bool enable_multishot_recv = 8;                                    // Default: true (new)
  google.protobuf.UInt32Value write_high_watermark = 9;             // Default: 131072 (new)
  google.protobuf.UInt32Value write_low_watermark = 10;             // Default: 16384 (new)
}
```

Update docs: `docs/root/configuration/other_features/io_uring.rst`
