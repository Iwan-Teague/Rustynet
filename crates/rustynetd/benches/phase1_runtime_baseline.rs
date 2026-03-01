#![forbid(unsafe_code)]

use std::hint::black_box;
#[test]
fn phase1_runtime_baseline_workload_is_deterministic() {
    const ITERATIONS: usize = 100_000;
    let mut value = 0usize;
    for item in 0usize..ITERATIONS {
        value ^= black_box(item);
    }
    let sink = black_box(value);
    assert_eq!(sink, 0);
}
