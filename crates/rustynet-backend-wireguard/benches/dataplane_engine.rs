//! Criterion benchmark for the userspace-shared dataplane engine
//! hot path (the real per-packet forwarding cost — boringtun
//! encrypt/decrypt plus the engine's buffer/copy/dispatch overhead).
//!
//! Run with:
//!   cargo bench -p rustynet-backend-wireguard --features test-harness
//!
//! The bench drives a completed Noise handshake once, then measures
//! steady-state per-packet operations. No sockets, TUN, root, or
//! tokio runtime — it calls the engine seam directly via
//! `bench_support` (feature-gated, never in production builds).

use criterion::{Criterion, criterion_group, criterion_main};
use rustynet_backend_wireguard::bench_support::{DataplaneEnginePair, SAMPLE_PLAINTEXT_LEN};
use std::hint::black_box;

fn bench_encrypt(c: &mut Criterion) {
    let mut pair = DataplaneEnginePair::handshaken();
    c.bench_function("engine_encrypt_outbound_1400b", |b| {
        b.iter(|| {
            let ciphertext = pair.encrypt_sample();
            black_box(ciphertext);
        });
    });
}

fn bench_forward_roundtrip(c: &mut Criterion) {
    let mut pair = DataplaneEnginePair::handshaken();
    c.bench_function("engine_forward_one_1400b", |b| {
        b.iter(|| {
            let delivered = pair.forward_one();
            black_box(delivered);
        });
    });
}

criterion_group! {
    name = dataplane;
    config = Criterion::default().sample_size(200);
    targets = bench_encrypt, bench_forward_roundtrip
}
criterion_main!(dataplane);

// Keep the unused import meaningful in case the bench is trimmed.
#[allow(dead_code)]
const _SAMPLE_LEN_PIN: usize = SAMPLE_PLAINTEXT_LEN;
