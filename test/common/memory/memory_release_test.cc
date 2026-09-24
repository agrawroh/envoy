#include "source/common/memory/stats.h"

#include "test/test_common/logging.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#if defined(GPERFTOOLS_TCMALLOC)
#include "gperftools/malloc_extension.h"
#endif

namespace Envoy {
namespace Memory {

class AllocatorManagerPeer {
public:
  static std::chrono::milliseconds
  memoryReleaseInterval(const AllocatorManager& allocator_manager) {
    return allocator_manager.memory_release_interval_msec_;
  }
  static uint64_t bytesToRelease(const AllocatorManager& allocator_manager) {
    return allocator_manager.bytes_to_release_;
  }
  static size_t backgroundReleaseRateBytesPerSecond(const AllocatorManager& allocator_manager) {
    return allocator_manager.background_release_rate_bytes_per_second_;
  }
  static bool hasBackgroundThread(const AllocatorManager& allocator_manager) {
    return allocator_manager.tcmalloc_thread_ != nullptr;
  }
  static bool hasReleaseTimer(const AllocatorManager& allocator_manager) {
    return allocator_manager.tcmalloc_routine_dispatcher_ != nullptr &&
           allocator_manager.memory_release_timer_ != nullptr;
  }
};

namespace {

static const int MB = 1048576;

#if defined(GPERFTOOLS_TCMALLOC)
class MockMallocExtension : public MallocExtension {
public:
  MOCK_METHOD(void, ReleaseToSystem, (size_t num_bytes), (override));
};

// Installs a process-wide MallocExtension for the lifetime of the guard and restores the original
// afterwards, so a failing test cannot leave a dangling mock installed. The replacement must
// outlive the guard.
class ScopedMallocExtension {
public:
  explicit ScopedMallocExtension(MallocExtension& replacement)
      : original_(MallocExtension::instance()) {
    MallocExtension::Register(&replacement);
  }
  ~ScopedMallocExtension() { MallocExtension::Register(original_); }

private:
  MallocExtension* const original_;
};
#endif

class MemoryReleaseTest : public testing::Test {
protected:
  MemoryReleaseTest() : api_(Api::createApiForTest(time_system_)) {}

  void initialiseAllocatorManager(uint64_t bytes_to_release, float release_interval_s) {
    const std::string yaml_config = (release_interval_s > 0)
                                        ? fmt::format(R"EOF(
  bytes_to_release: {}
  memory_release_interval: {}s
)EOF",
                                                      bytes_to_release, release_interval_s)
                                        : fmt::format(R"EOF(
  bytes_to_release: {}
)EOF",
                                                      bytes_to_release);
    initialiseAllocatorManager(yaml_config);
  }

  void initialiseAllocatorManager(const std::string& yaml_config) {
    const auto proto_config =
        TestUtility::parseYaml<envoy::config::bootstrap::v3::MemoryAllocatorManager>(yaml_config);
    allocator_manager_ = std::make_unique<Memory::AllocatorManager>(*api_, proto_config);
  }

  // Advances simulated time and blocks until every timer that became due has run its callback.
  void step(const std::chrono::milliseconds& duration) { time_system_.advanceTimeWait(duration); }

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  // Declared last so that the background thread is stopped before the API and time system that
  // it depends on are destroyed.
  std::unique_ptr<Memory::AllocatorManager> allocator_manager_;
};

TEST_F(MemoryReleaseTest, ReleaseRateAboveZeroDefaultIntervalMemoryReleased) {
#if defined(GPERFTOOLS_TCMALLOC)
  testing::StrictMock<MockMallocExtension> mock_malloc_extension;
  ScopedMallocExtension scoped_malloc_extension(mock_malloc_extension);
  EXPECT_LOG_CONTAINS("info",
                      "Configured gperftools tcmalloc with background release rate: 1048576 bytes "
                      "every 1000 milliseconds.",
                      initialiseAllocatorManager(MB /*bytes per default interval*/, 0));
  EXPECT_EQ(MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
  EXPECT_EQ(std::chrono::milliseconds(1000),
            AllocatorManagerPeer::memoryReleaseInterval(*allocator_manager_));
  EXPECT_TRUE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
  EXPECT_TRUE(AllocatorManagerPeer::hasReleaseTimer(*allocator_manager_));
  // The strict mock fails the test if anything is released before the interval elapses.
  step(std::chrono::milliseconds(999));
  // Exactly `bytes_to_release` is requested once the interval elapses, and again every interval.
  EXPECT_CALL(mock_malloc_extension, ReleaseToSystem(MB)).Times(3);
  step(std::chrono::milliseconds(1));
  step(std::chrono::milliseconds(1000));
  step(std::chrono::milliseconds(1000));
  // Stop the background thread before the mock goes out of scope.
  allocator_manager_.reset();
#elif defined(TCMALLOC)
  size_t initial_allocated_bytes = Stats::totalCurrentlyAllocated();
  auto a = std::make_unique<unsigned char[]>(MB);
  auto b = std::make_unique<unsigned char[]>(MB);
  if (Stats::totalCurrentlyAllocated() <= initial_allocated_bytes) {
    GTEST_SKIP() << "Skipping test, cannot measure memory usage precisely on this platform.";
  }
  auto initial_unmapped_bytes = Stats::totalPageHeapUnmapped();
  EXPECT_LOG_CONTAINS("info",
                      "Configured tcmalloc with background release rate: 1048576 bytes per second.",
                      initialiseAllocatorManager(MB /*bytes per second*/, 0));
  EXPECT_EQ(MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
  EXPECT_EQ(std::chrono::milliseconds(1000),
            AllocatorManagerPeer::memoryReleaseInterval(*allocator_manager_));
  EXPECT_EQ(static_cast<size_t>(MB),
            AllocatorManagerPeer::backgroundReleaseRateBytesPerSecond(*allocator_manager_));
  EXPECT_TRUE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
  a.reset();
  b.reset();
  // Wait for ProcessBackgroundActions to release memory. The default sleep interval is 1 second.
  absl::SleepFor(absl::Seconds(3));
  auto final_released_bytes = Stats::totalPageHeapUnmapped();
  EXPECT_LT(initial_unmapped_bytes, final_released_bytes);
#else
  EXPECT_LOG_CONTAINS("warn",
                      "Background memory release is only supported with Google's tcmalloc or "
                      "gperftools tcmalloc, ignoring.",
                      initialiseAllocatorManager(MB /*bytes per default interval*/, 0));
  EXPECT_EQ(MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
  EXPECT_FALSE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
  EXPECT_FALSE(AllocatorManagerPeer::hasReleaseTimer(*allocator_manager_));
#endif
}

TEST_F(MemoryReleaseTest, ReleaseRateZeroNoBackgroundThread) {
  EXPECT_LOG_NOT_CONTAINS("info", "Configured", initialiseAllocatorManager(0 /*bytes*/, 0));
  EXPECT_LOG_NOT_CONTAINS("warn", "Background memory release", initialiseAllocatorManager(0, 0));
  EXPECT_FALSE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
  EXPECT_FALSE(AllocatorManagerPeer::hasReleaseTimer(*allocator_manager_));
}

TEST_F(MemoryReleaseTest, ReleaseIntervalZeroNoBackgroundThread) {
  // An explicit zero interval, or one that truncates to zero milliseconds, disables background
  // release instead of scheduling it continuously.
  for (const std::string interval : {"0s", "0.0005s"}) {
    const std::string yaml_config = fmt::format(R"EOF(
  bytes_to_release: {}
  memory_release_interval: {}
)EOF",
                                                MB, interval);
#if defined(GPERFTOOLS_TCMALLOC) || defined(TCMALLOC)
    EXPECT_LOG_CONTAINS("warn",
                        "Memory release interval is less than one millisecond, no memory releasing "
                        "will be configured.",
                        initialiseAllocatorManager(yaml_config));
#else
    EXPECT_LOG_CONTAINS("warn",
                        "Background memory release is only supported with Google's tcmalloc or "
                        "gperftools tcmalloc, ignoring.",
                        initialiseAllocatorManager(yaml_config));
#endif
    EXPECT_EQ(MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
    EXPECT_EQ(std::chrono::milliseconds(0),
              AllocatorManagerPeer::memoryReleaseInterval(*allocator_manager_));
    EXPECT_FALSE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
    EXPECT_FALSE(AllocatorManagerPeer::hasReleaseTimer(*allocator_manager_));
    allocator_manager_.reset();
  }
}

TEST_F(MemoryReleaseTest, ReleaseRateAboveZeroCustomIntervalMemoryReleased) {
#if defined(GPERFTOOLS_TCMALLOC)
  testing::StrictMock<MockMallocExtension> mock_malloc_extension;
  ScopedMallocExtension scoped_malloc_extension(mock_malloc_extension);
  EXPECT_LOG_CONTAINS(
      "info",
      "Configured gperftools tcmalloc with background release rate: 16777216 bytes every 2000 "
      "milliseconds.",
      initialiseAllocatorManager(16 * MB /*bytes per 2 seconds*/, 2));
  EXPECT_EQ(16 * MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
  EXPECT_EQ(std::chrono::milliseconds(2000),
            AllocatorManagerPeer::memoryReleaseInterval(*allocator_manager_));
  EXPECT_TRUE(AllocatorManagerPeer::hasBackgroundThread(*allocator_manager_));
  // The default interval elapsing must not trigger a release when a custom interval is configured.
  step(std::chrono::milliseconds(1000));
  EXPECT_CALL(mock_malloc_extension, ReleaseToSystem(16 * MB));
  step(std::chrono::milliseconds(1000));
  // Stop the background thread before the mock goes out of scope.
  allocator_manager_.reset();
#elif defined(TCMALLOC)
  size_t initial_allocated_bytes = Stats::totalCurrentlyAllocated();
  auto a = std::make_unique<uint32_t[]>(40 * MB);
  auto b = std::make_unique<uint32_t[]>(40 * MB);
  if (Stats::totalCurrentlyAllocated() <= initial_allocated_bytes) {
    GTEST_SKIP() << "Skipping test, cannot measure memory usage precisely on this platform.";
  }
  auto initial_unmapped_bytes = Stats::totalPageHeapUnmapped();
  // 16 MB every 2 seconds = 8 MB/s.
  EXPECT_LOG_CONTAINS("info",
                      "Configured tcmalloc with background release rate: 8388608 bytes per second.",
                      initialiseAllocatorManager(16 * MB /*bytes per 2 seconds*/, 2));
  EXPECT_EQ(16 * MB, AllocatorManagerPeer::bytesToRelease(*allocator_manager_));
  EXPECT_EQ(std::chrono::milliseconds(2000),
            AllocatorManagerPeer::memoryReleaseInterval(*allocator_manager_));
  // Verify the computed release rate: 16 MB * 1000 / 2000 = 8 MB/s.
  EXPECT_EQ(static_cast<size_t>(8 * MB),
            AllocatorManagerPeer::backgroundReleaseRateBytesPerSecond(*allocator_manager_));
  a.reset();
  b.reset();
  // Wait for ProcessBackgroundActions to release memory.
  absl::SleepFor(absl::Seconds(3));
  auto final_released_bytes = Stats::totalPageHeapUnmapped();
  EXPECT_LT(initial_unmapped_bytes, final_released_bytes);
#endif
}

TEST_F(MemoryReleaseTest, BackgroundReleaseRateComputedCorrectly) {
  // 4 MB every 500ms = 8 MB/s.
  initialiseAllocatorManager(4 * MB, 0.5);
  EXPECT_EQ(static_cast<size_t>(8 * MB),
            AllocatorManagerPeer::backgroundReleaseRateBytesPerSecond(*allocator_manager_));
  allocator_manager_.reset();

  // 1 MB every 1s (default) = 1 MB/s.
  initialiseAllocatorManager(MB, 0);
  EXPECT_EQ(static_cast<size_t>(MB),
            AllocatorManagerPeer::backgroundReleaseRateBytesPerSecond(*allocator_manager_));
  allocator_manager_.reset();

  // 10 MB every 5s = 2 MB/s.
  initialiseAllocatorManager(10 * MB, 5);
  EXPECT_EQ(static_cast<size_t>(2 * MB),
            AllocatorManagerPeer::backgroundReleaseRateBytesPerSecond(*allocator_manager_));
  allocator_manager_.reset();
}

TEST_F(MemoryReleaseTest, MaxUnfreedMemoryBytesConfigured) {
  EXPECT_EQ(DEFAULT_MAX_UNFREED_MEMORY_BYTES, maxUnfreedMemoryBytes());
  const std::string yaml_config = R"EOF(
  max_unfreed_memory_bytes: 52428800
)EOF";
  const auto proto_config =
      TestUtility::parseYaml<envoy::config::bootstrap::v3::MemoryAllocatorManager>(yaml_config);
  EXPECT_LOG_CONTAINS("info", "Set max unfreed memory threshold to 52428800 bytes.",
                      allocator_manager_ =
                          std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
  EXPECT_EQ(52428800, maxUnfreedMemoryBytes());
  // Reset to default for other tests.
  setMaxUnfreedMemoryBytes(DEFAULT_MAX_UNFREED_MEMORY_BYTES);
}

TEST_F(MemoryReleaseTest, MaxUnfreedMemoryBytesDefaultWhenZero) {
  setMaxUnfreedMemoryBytes(DEFAULT_MAX_UNFREED_MEMORY_BYTES);
  const std::string yaml_config = R"EOF(
  max_unfreed_memory_bytes: 0
)EOF";
  const auto proto_config =
      TestUtility::parseYaml<envoy::config::bootstrap::v3::MemoryAllocatorManager>(yaml_config);
  EXPECT_LOG_NOT_CONTAINS("info", "Set max unfreed memory threshold",
                          allocator_manager_ =
                              std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
  EXPECT_EQ(DEFAULT_MAX_UNFREED_MEMORY_BYTES, maxUnfreedMemoryBytes());
}

TEST_F(MemoryReleaseTest, SoftMemoryLimitConfigured) {
  const std::string yaml_config = R"EOF(
  soft_memory_limit_bytes: 1073741824
)EOF";
  const auto proto_config =
      TestUtility::parseYaml<envoy::config::bootstrap::v3::MemoryAllocatorManager>(yaml_config);
#if defined(TCMALLOC)
  EXPECT_LOG_CONTAINS("info", "Set tcmalloc soft memory limit to 1073741824 bytes.",
                      allocator_manager_ =
                          std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
#else
  EXPECT_LOG_CONTAINS(
      "warn", "Soft memory limit is only supported with Google's tcmalloc, ignoring.",
      allocator_manager_ = std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
#endif
}

TEST_F(MemoryReleaseTest, MaxPerCpuCacheSizeConfigured) {
  const std::string yaml_config = R"EOF(
  max_per_cpu_cache_size_bytes: 2097152
)EOF";
  const auto proto_config =
      TestUtility::parseYaml<envoy::config::bootstrap::v3::MemoryAllocatorManager>(yaml_config);
#if defined(TCMALLOC)
  EXPECT_LOG_CONTAINS("info", "Set tcmalloc max per-CPU cache size to 2097152 bytes.",
                      allocator_manager_ =
                          std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
#else
  EXPECT_LOG_CONTAINS(
      "warn", "Max per-CPU cache size is only supported with Google's tcmalloc, ignoring.",
      allocator_manager_ = std::make_unique<Memory::AllocatorManager>(*api_, proto_config));
#endif
}

} // namespace
} // namespace Memory
} // namespace Envoy
