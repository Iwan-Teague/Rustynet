//! Dev-only counting global allocator for perf measurement.
//!
//! Delegates every operation to [`std::alloc::System`] and counts
//! allocation calls + bytes requested. Used by the `perfprobe_*`
//! example binaries to report allocations-per-operation for the
//! MEMORY baseline dimension. Never compiled into shipped binaries:
//! only example/bench targets install it via `#[global_allocator]`.
//!
//! Lives in `third_party/` because implementing `GlobalAlloc`
//! requires `unsafe`, which the first-party workspace forbids. The
//! `unsafe` here is pure delegation — no pointer arithmetic beyond
//! forwarding the calls.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

/// Counting allocator. Install in a measurement binary with:
/// `#[global_allocator] static A: CountingAllocator = CountingAllocator;`
pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Counter snapshot: (allocation calls, bytes requested).
pub fn snapshot() -> (u64, u64) {
    (
        ALLOC_CALLS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

/// Delta between two snapshots as (calls, bytes).
pub fn delta(before: (u64, u64), after: (u64, u64)) -> (u64, u64) {
    (after.0 - before.0, after.1 - before.1)
}
