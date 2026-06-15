//! Fixed-work measurement probe for the dataplane engine hot path.
//!
//! Runs N encrypt+decrypt round trips through a handshaken engine
//! pair and prints wall time, per-op time, and allocations/bytes per
//! op (via the dev-only counting allocator). Run it under
//! `/usr/bin/time -l` (macOS) or `perf stat` / `strace -c` (Linux)
//! to capture the HARDWARE dimension (instructions, cycles, CPU
//! time, syscalls) and peak RSS:
//!
//! ```sh
//! cargo build --release -p rustynet-backend-wireguard \
//!   --features test-harness --example perfprobe_engine
//! /usr/bin/time -l target/release/examples/perfprobe_engine
//! ```

use std::hint::black_box;
use std::time::Instant;

use rustynet_backend_wireguard::bench_support::DataplaneEnginePair;

#[global_allocator]
static ALLOC_METER: rustynet_alloc_meter::CountingAllocator =
    rustynet_alloc_meter::CountingAllocator;

const WARMUP_OPS: u64 = 10_000;
const MEASURED_OPS: u64 = 200_000;

fn main() {
    let mut pair = DataplaneEnginePair::handshaken();

    for _ in 0..WARMUP_OPS {
        black_box(pair.forward_one());
    }

    let alloc_before = rustynet_alloc_meter::snapshot();
    let started = Instant::now();
    let mut delivered = 0u64;
    for _ in 0..MEASURED_OPS {
        delivered += pair.forward_one() as u64;
    }
    let elapsed = started.elapsed();
    let (alloc_calls, alloc_bytes) =
        rustynet_alloc_meter::delta(alloc_before, rustynet_alloc_meter::snapshot());

    assert_eq!(delivered, MEASURED_OPS, "every frame must round-trip");
    println!("probe=engine_forward_one_1400b ops={MEASURED_OPS}");
    println!(
        "wall_s={:.3} ns_per_op={:.0}",
        elapsed.as_secs_f64(),
        elapsed.as_nanos() as f64 / MEASURED_OPS as f64
    );
    println!(
        "allocs_per_op={:.2} alloc_bytes_per_op={:.0}",
        alloc_calls as f64 / MEASURED_OPS as f64,
        alloc_bytes as f64 / MEASURED_OPS as f64
    );
}
