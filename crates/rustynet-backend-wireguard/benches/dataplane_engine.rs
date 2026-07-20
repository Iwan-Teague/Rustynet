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

/// P4 (DataplanePerfBacklog): parameterised peer-count case named by the
/// backlog item's "Measure" line. NOTE: steady-state WireGuard data packets
/// carry a receiver index and resolve via `find_node_id_by_receiver_index`
/// (a linear scan too, but out of scope for P4 and unaffected by this
/// change), so this end-to-end forward does NOT exercise the endpoint
/// reverse index on its hot loop — see `bench_has_endpoint_miss_peers64` /
/// `bench_find_node_id_by_endpoint_hit_peers64` below for benches that
/// isolate the actual P4 code path. This one instead confirms the change
/// doesn't regress the dominant (receiver-index) per-packet cost at scale.
fn bench_forward_roundtrip_64_peers(c: &mut Criterion) {
    let mut pair = DataplaneEnginePair::handshaken_with_extra_peers(63);
    c.bench_function("engine_forward_one_1400b_peers64", |b| {
        b.iter(|| {
            let delivered = pair.forward_one();
            black_box(delivered);
        });
    });
}

/// P4: isolates `UserspaceEngine::has_endpoint` — the check feeding
/// `reject_round_trip_target`'s fail-closed comparison — at N=64 configured
/// peers, probing an endpoint that matches none of them (the worst case for
/// the former linear scan, which had to compare against every peer before
/// concluding no match).
fn bench_has_endpoint_miss_peers64(c: &mut Criterion) {
    let pair = DataplaneEnginePair::handshaken_with_extra_peers(63);
    let unmatched_addr: std::net::SocketAddr = "127.0.0.1:1".parse().expect("addr");
    c.bench_function("engine_has_endpoint_miss_peers64", |b| {
        b.iter(|| {
            let found = pair.probe_has_endpoint(black_box(unmatched_addr));
            black_box(found);
        });
    });
}

/// P4: isolates `UserspaceEngine::find_node_id_by_endpoint` at N=64
/// configured peers, probing the endpoint of the peer that sorts LAST in
/// ascending NodeId order (`filler-0062`) — the worst case for the former
/// linear scan over the NodeId-ordered `peer_states` map, which had to walk
/// past every other peer first.
fn bench_find_node_id_by_endpoint_hit_peers64(c: &mut Criterion) {
    let pair = DataplaneEnginePair::handshaken_with_extra_peers(63);
    let last_filler_addr = DataplaneEnginePair::filler_endpoint(62);
    c.bench_function("engine_find_node_id_by_endpoint_hit_peers64", |b| {
        b.iter(|| {
            let node_id = pair.probe_find_node_id_by_endpoint(black_box(last_filler_addr));
            black_box(node_id);
        });
    });
}

criterion_group! {
    name = dataplane;
    config = Criterion::default().sample_size(200);
    targets = bench_encrypt, bench_forward_roundtrip, bench_forward_roundtrip_64_peers,
        bench_has_endpoint_miss_peers64, bench_find_node_id_by_endpoint_hit_peers64
}
criterion_main!(dataplane);

// Keep the unused import meaningful in case the bench is trimmed.
#[allow(dead_code)]
const _SAMPLE_LEN_PIN: usize = SAMPLE_PLAINTEXT_LEN;
