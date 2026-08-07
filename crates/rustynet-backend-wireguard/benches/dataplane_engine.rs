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

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustynet_backend_wireguard::bench_support::{DataplaneEnginePair, SAMPLE_PLAINTEXT_LEN};
use std::hint::black_box;

/// Plaintext sizes swept by the throughput benches.
///
/// All sit at or below the safe bring-up tunnel MTU, so none of them
/// exercises fragmentation — that is a separate concern and would make the
/// per-size numbers incomparable. The point of the sweep is to show how much
/// of the per-packet cost is fixed overhead versus proportional to payload,
/// which a single fixed size cannot answer: it is the input to deciding
/// whether any of this is worth SIMD or hand assembly at all.
const SWEEP_SIZES: [usize; 5] = [64, 256, 576, 1024, 1400];

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

/// Outbound encrypt cost across payload sizes.
///
/// `Throughput::Bytes` uses the PLAINTEXT length deliberately: it reports
/// payload goodput, which is the number a capacity question is asked in.
/// Ciphertext on the wire is larger by the 16-byte Poly1305 tag plus the
/// transport header, so a ciphertext-denominated figure would flatter the
/// small sizes.
fn bench_encrypt_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_encrypt_outbound");
    let mut pair = DataplaneEnginePair::handshaken();
    for len in SWEEP_SIZES {
        pair.set_sample_len(len);
        group.throughput(Throughput::Bytes(pair.sample_len() as u64));
        group.bench_function(BenchmarkId::from_parameter(len), |b| {
            b.iter(|| {
                let ciphertext = pair.encrypt_sample();
                black_box(ciphertext);
            });
        });
    }
    group.finish();
}

/// Full encrypt-then-decrypt round trip across payload sizes — the cost a
/// forwarded packet actually pays end to end, as opposed to encrypt alone.
fn bench_forward_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_forward_roundtrip");
    let mut pair = DataplaneEnginePair::handshaken();
    for len in SWEEP_SIZES {
        pair.set_sample_len(len);
        group.throughput(Throughput::Bytes(pair.sample_len() as u64));
        group.bench_function(BenchmarkId::from_parameter(len), |b| {
            b.iter(|| {
                let delivered = pair.forward_one();
                black_box(delivered);
            });
        });
    }
    group.finish();
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
    targets = bench_encrypt, bench_forward_roundtrip, bench_encrypt_sizes,
        bench_forward_sizes, bench_forward_roundtrip_64_peers,
        bench_has_endpoint_miss_peers64, bench_find_node_id_by_endpoint_hit_peers64
}
criterion_main!(dataplane);

// Keep the unused import meaningful in case the bench is trimmed.
#[allow(dead_code)]
const _SAMPLE_LEN_PIN: usize = SAMPLE_PLAINTEXT_LEN;
