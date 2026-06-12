//! Criterion benchmark for the relay per-frame forward path
//! (`RelayTransport::forward_packet`): session lookup, source-tuple
//! authorisation, rate limiting, and pair resolution — the
//! everything-but-the-syscall cost of relaying one ciphertext frame.
//!
//! Run with: cargo bench -p rustynet-relay

use std::hint::black_box;
use std::net::SocketAddr;

use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use rustynet_control::RelaySessionToken;
use rustynet_relay::transport::{RelayHello, RelayHelloResponse, RelayTransport};

const RELAY_ID: [u8; 16] = [0xB7; 16];

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

/// Two paired, source-bound sessions ready to forward.
fn paired_transport() -> (
    RelayTransport,
    rustynet_relay::SessionId,
    SocketAddr,
    Vec<u8>,
) {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let mut transport = RelayTransport::new(RELAY_ID, signing_key.verifying_key(), 8, 90);
    // Lift the per-node rate limits far above bench iteration speed so the
    // bench measures the forward path, not token-bucket drops. (Must happen
    // before the first forward: buckets capture limits at first use.)
    transport
        .set_rate_limits(u64::MAX / 2, u64::MAX / 2)
        .expect("bench rate limits");

    let hello_a: SocketAddr = "198.51.100.10:40000".parse().expect("addr");
    let data_a: SocketAddr = "198.51.100.10:51820".parse().expect("addr");
    let hello_b: SocketAddr = "203.0.113.20:41000".parse().expect("addr");
    let data_b: SocketAddr = "203.0.113.20:51821".parse().expect("addr");

    let sid_a = accept(&mut transport, &signing_key, "a", "b", hello_a, 55_001);
    let sid_b = accept(&mut transport, &signing_key, "b", "a", hello_b, 55_002);

    // Bind both source tuples (first packet binds; b's also forwards).
    let payload = vec![0xA5u8; 1400];
    let _ = transport.forward_packet(sid_a, &payload, data_a);
    let _ = transport.forward_packet(sid_b, &payload, data_b);

    (transport, sid_a, data_a, payload)
}

fn bench_forward(c: &mut Criterion) {
    let (mut transport, sid_a, data_a, payload) = paired_transport();
    c.bench_function("relay_forward_packet_1400b", |b| {
        b.iter(|| {
            let target = transport
                .forward_packet(sid_a, &payload, data_a)
                .expect("forward should not error")
                .expect("paired session should forward");
            black_box(target);
        });
    });
}

criterion_group! {
    name = relay;
    config = Criterion::default().sample_size(200);
    targets = bench_forward
}
criterion_main!(relay);
