//! The Tokio half of the configuration pipeline that `xds_offload_speed_test` compares against delta
//! xDS.
//!
//! A batch of resources arrives in a length-prefixed framing: for each resource, its name, its
//! version and its serialized protobuf, each preceded by its length as a little-endian `u32`. One
//! Tokio worker parses and coalesces the batch, then the workers process it in parallel chunks. For
//! every resource a worker applies policy and has Envoy decode and validate it, so that all the main
//! thread is left to do is apply the result.

use std::collections::HashMap;
use std::ffi::c_void;
use std::ops::Range;
use std::sync::Arc;

use tokio::runtime::Runtime;

/// The callbacks through which Envoy decodes the resources of a batch and learns which ones were
/// rejected before being decoded. Tokio workers call them concurrently, but never twice for the
/// same `index`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Callbacks {
  pub context: *mut c_void,
  /// Decodes and validates the resource at `index` of the batch.
  pub decode: unsafe extern "C" fn(
    context: *mut c_void,
    index: usize,
    name: *const u8,
    name_length: usize,
    version: *const u8,
    version_length: usize,
    resource: *const u8,
    resource_length: usize,
  ),
  /// Records why the resource at `index` of the batch was rejected without being decoded.
  pub reject: unsafe extern "C" fn(
    context: *mut c_void,
    index: usize,
    reason: *const u8,
    reason_length: usize,
  ),
}

// SAFETY: Envoy allows the callbacks to be called from any thread, and keeps `context` valid until
// `xds_offload_prepare` returns, which it only does once every task has completed.
unsafe impl Send for Callbacks {}
unsafe impl Sync for Callbacks {}

/// A batch borrowed from Envoy for the duration of `xds_offload_prepare`.
#[derive(Clone, Copy)]
struct Batch {
  data: *const u8,
  length: usize,
}

// SAFETY: The batch is only ever read, and outlives every task, as `Callbacks` explains.
unsafe impl Send for Batch {}
unsafe impl Sync for Batch {}

impl Batch {
  /// # Safety
  ///
  /// Must only be called before `xds_offload_prepare` returns.
  unsafe fn bytes(&self) -> &[u8] {
    if self.length == 0 {
      &[]
    } else {
      // SAFETY: Envoy guarantees `data` points to `length` readable bytes until then.
      unsafe { std::slice::from_raw_parts(self.data, self.length) }
    }
  }
}

struct Record {
  name: Range<usize>,
  version: Range<usize>,
  resource: Range<usize>,
  // Set when a later record of the same batch updates the same resource.
  superseded: bool,
}

const MAX_NAME_LENGTH: usize = 255;
const MAX_RESOURCE_LENGTH: usize = 1 << 20;
const PROTECTED_NAMES: &[&[u8]] = &[b"xds_cluster"];

pub struct Offload {
  runtime: Runtime,
  workers: usize,
  // The fingerprint of the last applied version of each resource, which lets a resource that did
  // not change be skipped without decoding it. The benchmark only applies new resources, so it
  // stays empty, but every resource is still fingerprinted and looked up.
  applied: Arc<HashMap<Vec<u8>, u64>>,
}

fn field(bytes: &[u8], offset: &mut usize) -> Option<Range<usize>> {
  let start = offset.checked_add(4)?;
  let length = u32::from_le_bytes(bytes.get(*offset..start)?.try_into().ok()?) as usize;
  let end = start.checked_add(length)?;
  if end > bytes.len() {
    return None;
  }
  *offset = end;
  Some(start..end)
}

fn parse(bytes: &[u8]) -> Option<Vec<Record>> {
  let mut records = Vec::new();
  let mut offset = 0;
  while offset < bytes.len() {
    records.push(Record {
      name: field(bytes, &mut offset)?,
      version: field(bytes, &mut offset)?,
      resource: field(bytes, &mut offset)?,
      superseded: false,
    });
  }
  // Only the last update of a resource within a batch is applied.
  let mut latest: HashMap<&[u8], usize> = HashMap::with_capacity(records.len());
  for index in 0..records.len() {
    if let Some(previous) = latest.insert(&bytes[records[index].name.clone()], index) {
      records[previous].superseded = true;
    }
  }
  Some(records)
}

fn check_policy(bytes: &[u8], record: &Record) -> Result<(), &'static str> {
  let name = &bytes[record.name.clone()];
  if name.is_empty() || name.len() > MAX_NAME_LENGTH {
    return Err("resource name length is out of range");
  }
  if !name.iter().all(u8::is_ascii_graphic) {
    return Err("resource name is not printable ASCII");
  }
  if record.version.is_empty() {
    return Err("resource version is missing");
  }
  if record.resource.len() > MAX_RESOURCE_LENGTH {
    return Err("resource is too large");
  }
  if PROTECTED_NAMES.contains(&name) {
    return Err("resource is protected");
  }
  Ok(())
}

// FNV-1a.
fn fingerprint(bytes: &[u8]) -> u64 {
  bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
    (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
  })
}

fn process(
  bytes: &[u8],
  records: &[Record],
  index: usize,
  applied: &HashMap<Vec<u8>, u64>,
  callbacks: &Callbacks,
) {
  let reject = |reason: &str| {
    // SAFETY: See `Callbacks`.
    unsafe { (callbacks.reject)(callbacks.context, index, reason.as_ptr(), reason.len()) }
  };
  let record = &records[index];
  if record.superseded {
    return reject("superseded by a later update in the same batch");
  }
  if let Err(reason) = check_policy(bytes, record) {
    return reject(reason);
  }
  let name = &bytes[record.name.clone()];
  let resource = &bytes[record.resource.clone()];
  if applied.get(name) == Some(&fingerprint(resource)) {
    return reject("unchanged");
  }
  let version = &bytes[record.version.clone()];
  // SAFETY: See `Callbacks`.
  unsafe {
    (callbacks.decode)(
      callbacks.context,
      index,
      name.as_ptr(),
      name.len(),
      version.as_ptr(),
      version.len(),
      resource.as_ptr(),
      resource.len(),
    )
  }
}

/// Creates a pipeline backed by a Tokio runtime with `workers` worker threads.
#[no_mangle]
pub extern "C" fn xds_offload_new(workers: usize) -> *mut Offload {
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(workers)
    .build()
    .expect("failed to build the Tokio runtime");
  Box::into_raw(Box::new(Offload {
    runtime,
    workers,
    applied: Arc::default(),
  }))
}

/// # Safety
///
/// `offload` must come from `xds_offload_new`, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn xds_offload_delete(offload: *mut Offload) {
  // SAFETY: Guaranteed by the caller.
  drop(unsafe { Box::from_raw(offload) });
}

/// Prepares a batch for the main thread to apply, and returns once every resource has been either
/// decoded or rejected. Returns the number of resources in the batch, or -1 if the framing is
/// malformed, in which case no callback is called.
///
/// # Safety
///
/// `offload` must come from `xds_offload_new`, `data` must point to `length` readable bytes, and the
/// callbacks must be safe to call from any thread. All of them must stay valid until this returns.
#[no_mangle]
pub unsafe extern "C" fn xds_offload_prepare(
  offload: *const Offload,
  data: *const u8,
  length: usize,
  callbacks: Callbacks,
) -> i64 {
  // SAFETY: Guaranteed by the caller.
  let offload = unsafe { &*offload };
  let batch = Batch { data, length };
  let chunks_per_worker = 4;
  let max_chunk_size = 256;
  let workers = offload.workers;
  let applied = offload.applied.clone();
  offload.runtime.block_on(async move {
    // The parsing runs on a worker as well, so that the calling thread does nothing but wait.
    // SAFETY: `block_on` does not return before this task completes.
    let parsed = tokio::spawn(async move { parse(unsafe { batch.bytes() }) });
    let Some(records) = parsed.await.expect("parsing panicked") else {
      return -1;
    };
    let records = Arc::new(records);
    let chunk_size = records
      .len()
      .div_ceil(workers * chunks_per_worker)
      .clamp(1, max_chunk_size);
    let mut tasks = Vec::with_capacity(records.len().div_ceil(chunk_size));
    for start in (0..records.len()).step_by(chunk_size) {
      let end = (start + chunk_size).min(records.len());
      let records = records.clone();
      let applied = applied.clone();
      tasks.push(tokio::spawn(async move {
        // SAFETY: `block_on` does not return before every task completes.
        let bytes = unsafe { batch.bytes() };
        for index in start..end {
          process(bytes, &records, index, &applied, &callbacks);
        }
      }));
    }
    for task in tasks {
      task.await.expect("a worker panicked");
    }
    records.len() as i64
  })
}
