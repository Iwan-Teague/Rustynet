#![forbid(unsafe_code)]

use std::hint::black_box;
use std::time::Instant;

#[test]
fn phase1_runtime_baseline_skeleton_compiles_and_executes() {
    let started = Instant::now();
    let mut value = 0usize;
    for item in 0usize..100_000 {
        value ^= black_box(item);
    }
    let elapsed = started.elapsed();
    let _sink = black_box(value);
    assert!(elapsed.as_nanos() > 0);
}
