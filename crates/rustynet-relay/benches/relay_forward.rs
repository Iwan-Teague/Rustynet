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
        addr_validation_artifact: None,
    }
}

fn accept(
    transport: &mut RelayTransport,
    signing_key: &SigningKey,
    node_id: &str,
    peer_node_id: &str,
    from_addr: SocketAddr,
    allocated_port: u16,
) -> Result<rustynet_relay::SessionId, String> {
    let hello = make_hello(signing_key, node_id, peer_node_id);
    transport
        .validate_hello_from_tuple(&hello, from_addr)
        .map_err(|reason| format!("hello rejected: {reason:?}"))?;
    match transport.handle_hello_from_tuple_with_allocated_port(hello, from_addr, allocated_port) {
        RelayHelloResponse::Accepted(ack) => Ok(ack.session_id),
        other => Err(format!("hello rejected: {other:?}")),
    }
}

/// Two paired, source-bound sessions ready to forward.
fn paired_transport() -> Result<
    (
        RelayTransport,
        rustynet_relay::SessionId,
        SocketAddr,
        Vec<u8>,
    ),
    String,
> {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let mut transport = RelayTransport::new(RELAY_ID, signing_key.verifying_key(), 8, 90)
        .map_err(|err| format!("relay transport init: {err}"))?
        // Probe/bench traffic carries no OI-10 artifacts; the gate has its
        // own dedicated tests in the library.
        .with_require_addr_validation(false);
    // Lift the per-node rate limits far above bench iteration speed so the
    // bench measures the forward path, not token-bucket drops. (Must happen
    // before the first forward: buckets capture limits at first use.)
    transport
        .set_rate_limits(u64::MAX / 2, u64::MAX / 2)
        .map_err(|err| format!("bench rate limits: {err}"))?;

    let hello_a = SocketAddr::from(([198, 51, 100, 10], 40000));
    let data_a = SocketAddr::from(([198, 51, 100, 10], 51820));
    let hello_b = SocketAddr::from(([203, 0, 113, 20], 41000));
    let data_b = SocketAddr::from(([203, 0, 113, 20], 51821));

    let sid_a = accept(&mut transport, &signing_key, "a", "b", hello_a, 55_001)?;
    let sid_b = accept(&mut transport, &signing_key, "b", "a", hello_b, 55_002)?;

    // Bind both source tuples (first packet binds; b's also forwards).
    let payload = vec![0xA5u8; 1400];
    let _ = transport.forward_packet(sid_a, &payload, data_a);
    let _ = transport.forward_packet(sid_b, &payload, data_b);

    Ok((transport, sid_a, data_a, payload))
}

fn bench_forward(c: &mut Criterion) {
    let (mut transport, sid_a, data_a, payload) = paired_transport().unwrap_or_else(|err| {
        eprintln!("bench setup failed: {err}");
        std::process::exit(1);
    });
    c.bench_function("relay_forward_packet_1400b", |b| {
        b.iter(|| {
            let target = transport
                .forward_packet(sid_a, &payload, data_a)
                .unwrap_or_else(|err| {
                    eprintln!("forward error: {err:?}");
                    std::process::exit(1);
                })
                .unwrap_or_else(|| {
                    eprintln!("paired session did not forward");
                    std::process::exit(1);
                });
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
