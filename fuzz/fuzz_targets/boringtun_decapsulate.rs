#![no_main]

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use libfuzzer_sys::fuzz_target;

// AQ-29: the vendored WireGuard implementation's untrusted-datagram entry
// point (third_party/boringtun/src/noise/mod.rs:194 Tunn::new for the fixed
// keys, :276 Tunn::decapsulate for the raw bytes).
//
// ATTACKER: any pre-authentication network peer who can send a UDP datagram
// to the node's WireGuard listen port. `decapsulate` is the first code that
// touches the datagram — packet-type dispatch, handshake record parsing,
// cookie reply parsing, and ChaCha20Poly1305 decapsulation of data packets
// all run on these bytes before any peer identity is established.
// boringtun is vendored upstream code excluded from the panic-family lint
// tables, so fuzzing (not lint review) is its coverage.
fuzz_target!(|data: &[u8]| {
    let static_private = StaticSecret::from([0x42u8; 32]);
    let peer_static_public = PublicKey::from([0x24u8; 32]);
    let mut tunnel = Tunn::new(static_private, peer_static_public, None, None, 1, None);
    let mut dst = vec![0u8; data.len() + 128];
    let _ = tunnel.decapsulate(None, data, &mut dst);
});
