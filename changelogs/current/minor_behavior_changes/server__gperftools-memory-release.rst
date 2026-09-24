Envoy builds using ``gperftools`` tcmalloc now honor
:ref:`memory_allocator_manager.bytes_to_release
<envoy_v3_api_field_config.bootstrap.v3.MemoryAllocatorManager.bytes_to_release>`. Previously a
non-zero value only logged an error. Such builds now start a background thread named
``gperf_release`` that asks the allocator to release the configured number of bytes once per
:ref:`memory_release_interval
<envoy_v3_api_field_config.bootstrap.v3.MemoryAllocatorManager.memory_release_interval>`. Set
``bytes_to_release`` to ``0`` before upgrading to opt out. A ``memory_release_interval`` of zero, or
shorter than one millisecond, now disables background release for both Google's tcmalloc and
``gperftools`` tcmalloc. For Google's tcmalloc this means Envoy no longer starts its background
actions thread in that case.
