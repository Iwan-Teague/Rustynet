//! Fixed-work measurement probe for the relay forward path.
//!
//! Runs N `forward_packet` resolutions through a paired transport
//! and prints wall time, per-op time, and allocations/bytes per op.
//! Run under `/usr/bin/time -l` (macOS) or `perf stat` / `strace -c`
//! (Linux) for the HARDWARE dimension and peak RSS:
//!
//! ```sh
//! cargo build --release -p rustynet-relay --example perfprobe_relay
//! /usr/bin/time -l target/release/examples/perfprobe_relay
//! ```

use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rustynet_control::RelaySessionToken;
use rustynet_relay::transport::{RelayHello, RelayHelloResponse, RelayTransport};

#[global_allocator]
static ALLOC_METER: rustynet_alloc_meter::CountingAllocator =
    rustynet_alloc_meter::CountingAllocator;

const RELAY_ID: [u8; 16] = [0xB7; 16];
const WARMUP_OPS: u64 = 100_000;
const MEASURED_OPS: u64 = 2_000_000;

fn make_hello(signing_key: &SigningKey, node_id: &str, peer_node_id: &str) -> RelayHello {
    RelayHello {
        node_id: node_id.to_owned(),
        peer_node_id: peer_node_id.to_owned(),
        session_token: RelaySessionToken::sign(signing_key, node_id, peer_node_id, RELAY_ID, 90),
    }
}

fn accept(
    transport: &mut RelayTransport,
    signing_key: &SigningKey,
    node_id: &str,
    peer_node_id: &str,
    from_addr: SocketAddr,
    allocated_port: u16,
) -> rustynet_relay::SessionId {
    let hello = make_hello(signing_key, node_id, peer_node_id);
    transport
        .validate_hello_from_tuple(&hello, from_addr)
        .expect("hello should validate");
    match transport.handle_hello_from_tuple_with_allocated_port(hello, from_addr, allocated_port) {
        RelayHelloResponse::Accepted(ack) => ack.session_id,
        other => panic!("hello rejected: {other:?}"),
    }
}

fn main() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let mut transport = RelayTransport::new(RELAY_ID, signing_key.verifying_key(), 8, 90);
    transport
        .set_rate_limits(u64::MAX / 2, u64::MAX / 2)
        .expect("probe rate limits");

    let hello_a: SocketAddr = "198.51.100.10:40000".parse().expect("addr");
    let data_a: SocketAddr = "198.51.100.10:51820".parse().expect("addr");
    let hello_b: SocketAddr = "203.0.113.20:41000".parse().expect("addr");
    let data_b: SocketAddr = "203.0.113.20:51821".parse().expect("addr");
    let sid_a = accept(&mut transport, &signing_key, "a", "b", hello_a, 55_001);
    let sid_b = accept(&mut transport, &signing_key, "b", "a", hello_b, 55_002);

    let payload = vec![0xA5u8; 1400];
    let _ = transport.forward_packet(sid_a, &payload, data_a);
    let _ = transport.forward_packet(sid_b, &payload, data_b);

    for _ in 0..WARMUP_OPS {
        black_box(
            transport
                .forward_packet(sid_a, &payload, data_a)
                .expect("forward should not error"),
        );
    }

    let alloc_before = rustynet_alloc_meter::snapshot();
    let started = Instant::now();
    let mut forwarded = 0u64;
    for _ in 0..MEASURED_OPS {
        if transport
            .forward_packet(sid_a, &payload, data_a)
            .expect("forward should not error")
            .is_some()
        {
            forwarded += 1;
        }
    }
    let elapsed = started.elapsed();
    let (alloc_calls, alloc_bytes) =
        rustynet_alloc_meter::delta(alloc_before, rustynet_alloc_meter::snapshot());

    assert_eq!(forwarded, MEASURED_OPS, "every frame must resolve a target");
    println!("probe=relay_forward_packet_1400b ops={MEASURED_OPS}");
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
