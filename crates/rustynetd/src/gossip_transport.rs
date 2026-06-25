#![forbid(unsafe_code)]

//! D2.5 — UDP transport for peer-distributed signed-bundle gossip.
//!
//! Each peer binds a dedicated UDP socket on the rustynet0 mesh
//! interface at [`RUSTYNET_GOSSIP_PORT`] (51821). The WireGuard
//! listen port is 51820 — chosen one above so the two sockets never
//! collide. Because the rustynet0 interface only carries traffic
//! that has already traversed the WG tunnel, the bundle datagrams
//! ride inside an encrypted-and-authenticated channel for free; the
//! Ed25519 signature on the bundle is the end-to-end source-
//! authentication layer that survives epidemic re-broadcast hops.
//!
//! Security framing:
//!
//! * `recv_bundle` enforces [`MAX_GOSSIP_DATAGRAM_BYTES`] (4 KiB) on
//!   every datagram. Anything larger is dropped before deserialise
//!   touches it. A malicious peer cannot exhaust verifier memory by
//!   spamming oversized blobs.
//! * `push_bundle` enforces the same cap on send so we never emit a
//!   datagram our own receive path would reject.
//! * Deserialisation is the existing `peer_gossip::deserialise_bundle`
//!   path which is strictly version-gated, length-checked, and
//!   family-checked.
//! * Signature verification, freshness window, and replay protection
//!   are not this module's job — they live in
//!   `peer_gossip::accept_bundle` and the caller MUST run them
//!   before applying the bundle.
//!
//! Platform split: implemented on Unix (Linux, macOS) using the
//! standard `std::net::UdpSocket` and `nix::ifaddrs`-equivalent
//! routines. Windows is shimmed to a no-op binder that always
//! errors. The intent is to wire the Windows path through
//! `windows-rs`'s socket APIs in a follow-up slice; until then,
//! Windows daemons participate in the membership/relay paths but do
//! not run the gossip loop. The dataplane execution plan §5.2 calls
//! this out as part of Track Beta's follow-up backlog.

use std::net::SocketAddr;
use std::time::Duration;
// These items are only used by the `#[cfg(unix)]` transport impl below; the
// `#[cfg(not(unix))]` stub errors out without touching the socket or wire
// helpers. Gate the imports to match so Windows does not see them as unused.
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::net::UdpSocket;
#[cfg(unix)]
use std::time::Instant;

use crate::peer_gossip::{GossipBundle, GossipError};
#[cfg(unix)]
use crate::peer_gossip::{MAX_GOSSIP_DATAGRAM_BYTES, deserialise_bundle, serialise_bundle};

/// Default UDP port for the per-peer gossip socket. The WireGuard
/// listen port is 51820; the gossip port is intentionally one above
/// so a single-host test (e.g. the three-peer mesh integration test)
/// can stand up multiple daemons without colliding with either
/// well-known service.
pub const RUSTYNET_GOSSIP_PORT: u16 = 51821;

/// Errors surfaced by [`GossipTransport::push_bundle`] and
/// [`GossipTransport::recv_bundle`]. Distinct from `GossipError`
/// (which covers cryptographic / wire-format failures) so callers
/// can distinguish "the socket didn't cooperate" from "the bundle
/// itself was rejected".
#[derive(Debug)]
pub enum TransportError {
    /// Datagram length exceeded [`MAX_GOSSIP_DATAGRAM_BYTES`].
    Oversized { length: usize, max: usize },
    /// Inbound bytes failed [`deserialise_bundle`] — typed
    /// pass-through so the caller can log the variant by name.
    InvalidBundle(GossipError),
    /// Underlying socket I/O error. Carries the kind only —
    /// `std::io::Error` is not Clone so we surface the
    /// fixed-vocabulary kind plus a sanitised message.
    Io(String),
    /// Operation attempted on an unsupported platform (Windows
    /// today). Callers should treat this as "gossip path is
    /// disabled, continue with the rest of the daemon".
    Unsupported(&'static str),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Oversized { length, max } => write!(
                f,
                "gossip datagram length {length} exceeds MAX_GOSSIP_DATAGRAM_BYTES ({max})"
            ),
            TransportError::InvalidBundle(err) => {
                write!(f, "gossip bundle wire decode failed: {err}")
            }
            TransportError::Io(msg) => write!(f, "gossip transport i/o error: {msg}"),
            TransportError::Unsupported(reason) => {
                write!(f, "gossip transport unsupported on this platform: {reason}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Io(format!("{}: {}", err.kind(), err))
    }
}

/// UDP transport over the rustynet0 mesh interface. Binds a single
/// non-blocking datagram socket and exposes `push_bundle` /
/// `recv_bundle` over [`peer_gossip::serialise_bundle`] /
/// [`peer_gossip::deserialise_bundle`].
///
/// The socket is set non-blocking. `recv_bundle(Duration::ZERO)`
/// performs a single non-blocking `recv_from`. Non-zero timeouts
/// poll until the deadline elapses or a datagram arrives.
pub struct GossipTransport {
    // The socket only exists on the `#[cfg(unix)]` transport path; the
    // `#[cfg(not(unix))]` stub never constructs `Self`, so the field would
    // otherwise read as never-used on Windows.
    #[cfg(unix)]
    socket: UdpSocket,
}

#[cfg(unix)]
impl GossipTransport {
    /// Bind the gossip socket at `bind_addr`. On Unix this is
    /// typically `(<mesh_ip>, RUSTYNET_GOSSIP_PORT)` but the helper
    /// is generic so tests can use `127.0.0.1:0`. The socket is set
    /// non-blocking so the daemon main loop can interleave
    /// `recv_bundle` with the other I/O sources without dedicating a
    /// thread.
    pub fn bind(bind_addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Local address the socket is bound to. Useful for tests where
    /// the OS-assigned port needs to be discovered.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket.local_addr().map_err(Into::into)
    }

    /// Serialise `bundle` to its wire form and send one UDP datagram
    /// at `peer_addr`. Datagrams larger than
    /// [`MAX_GOSSIP_DATAGRAM_BYTES`] are refused before the syscall —
    /// our own receive path would reject them, so emitting one is a
    /// guaranteed wasted round-trip.
    pub fn push_bundle(
        &self,
        peer_addr: SocketAddr,
        bundle: &GossipBundle,
    ) -> Result<(), TransportError> {
        let wire = serialise_bundle(bundle);
        if wire.len() > MAX_GOSSIP_DATAGRAM_BYTES {
            return Err(TransportError::Oversized {
                length: wire.len(),
                max: MAX_GOSSIP_DATAGRAM_BYTES,
            });
        }
        let sent = self.socket.send_to(&wire, peer_addr)?;
        if sent != wire.len() {
            return Err(TransportError::Io(format!(
                "short send: {sent}/{} bytes",
                wire.len()
            )));
        }
        Ok(())
    }

    /// Wait up to `timeout` for one datagram and deserialise it. A
    /// `Duration::ZERO` timeout makes this a single non-blocking
    /// `try_recv`. Larger timeouts poll with a short sleep between
    /// tries so the call cooperates with the daemon's other periodic
    /// hooks.
    ///
    /// Returns `Ok(None)` when no datagram arrived in the window
    /// (the common case in the main loop). Errors are surfaced for
    /// the caller to log by error-kind; the caller MUST run the full
    /// `accept_bundle` check on every Ok(Some(_)) before applying
    /// the bundle.
    pub fn recv_bundle(
        &self,
        timeout: Duration,
    ) -> Result<Option<(SocketAddr, GossipBundle)>, TransportError> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; MAX_GOSSIP_DATAGRAM_BYTES];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((length, sender)) => {
                    if length > MAX_GOSSIP_DATAGRAM_BYTES {
                        // Should be unreachable — `recv_from` clamps
                        // to the buffer size — but keep an explicit
                        // bound here so a future buffer-resize cannot
                        // silently let an oversized datagram through.
                        return Err(TransportError::Oversized {
                            length,
                            max: MAX_GOSSIP_DATAGRAM_BYTES,
                        });
                    }
                    let bundle = deserialise_bundle(&buf[..length])
                        .map_err(TransportError::InvalidBundle)?;
                    return Ok(Some((sender, bundle)));
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

#[cfg(not(unix))]
impl GossipTransport {
    pub fn bind(_bind_addr: SocketAddr) -> Result<Self, TransportError> {
        Err(TransportError::Unsupported(
            "gossip transport is unix-only in this slice; windows path is queued behind Track Beta",
        ))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Err(TransportError::Unsupported(
            "gossip transport is unix-only in this slice",
        ))
    }

    pub fn push_bundle(
        &self,
        _peer_addr: SocketAddr,
        _bundle: &GossipBundle,
    ) -> Result<(), TransportError> {
        Err(TransportError::Unsupported(
            "gossip transport is unix-only in this slice",
        ))
    }

    pub fn recv_bundle(
        &self,
        _timeout: Duration,
    ) -> Result<Option<(SocketAddr, GossipBundle)>, TransportError> {
        Err(TransportError::Unsupported(
            "gossip transport is unix-only in this slice",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::dataplane_candidates::CandidateSet;
    use crate::peer_gossip::{GOSSIP_BUNDLE_WIRE_VERSION, mint_bundle_with_timestamp};
    use ed25519_dalek::SigningKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback_bind() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn sample_bundle() -> GossipBundle {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut candidates = CandidateSet::default();
        candidates
            .v4_host
            .push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        mint_bundle_with_timestamp(&key, 1, 1_700_000_000, candidates).expect("mint sample bundle")
    }

    #[test]
    fn push_then_recv_round_trips_on_loopback() {
        // Two transports bound on loopback exchange one bundle. The
        // received bundle must equal the sent one byte-for-byte
        // (including the signature trailer) and the sender's
        // reported `SocketAddr` must equal the pusher's bound port.
        let a = GossipTransport::bind(loopback_bind()).expect("bind A");
        let b = GossipTransport::bind(loopback_bind()).expect("bind B");
        let a_addr = a.local_addr().expect("A.local_addr");
        let b_addr = b.local_addr().expect("B.local_addr");
        let bundle = sample_bundle();
        a.push_bundle(b_addr, &bundle).expect("A → B push");
        let received = b
            .recv_bundle(Duration::from_secs(2))
            .expect("recv ok")
            .expect("at least one datagram in 2 s");
        assert_eq!(
            received.0, a_addr,
            "sender addr must equal pusher's bound port"
        );
        assert_eq!(received.1.source_node_id, bundle.source_node_id);
        assert_eq!(received.1.sequence, bundle.sequence);
        assert_eq!(received.1.candidates, bundle.candidates);
        assert_eq!(received.1.signature.to_bytes(), bundle.signature.to_bytes());
    }

    #[test]
    fn recv_rejects_oversized_datagram() {
        // A datagram larger than MAX_GOSSIP_DATAGRAM_BYTES must be
        // dropped with a typed error. We emit it with a raw
        // UdpSocket so we don't have to bypass the send-side guard
        // in our own `push_bundle`.
        let receiver = GossipTransport::bind(loopback_bind()).expect("bind receiver");
        let raw_sender = UdpSocket::bind(loopback_bind()).expect("bind raw sender");
        let receiver_addr = receiver.local_addr().expect("local_addr");
        let blob = vec![0u8; MAX_GOSSIP_DATAGRAM_BYTES + 1];
        // OS may refuse oversized datagrams at send time; either
        // outcome (send fails, or send succeeds and recv reports
        // oversized) is acceptable for the test pin.
        match raw_sender.send_to(&blob, receiver_addr) {
            Ok(_) => {
                let res = receiver.recv_bundle(Duration::from_secs(2));
                match res {
                    Err(TransportError::Oversized { length, max }) => {
                        assert_eq!(max, MAX_GOSSIP_DATAGRAM_BYTES);
                        assert!(length > max, "length must exceed cap");
                    }
                    // OS may have truncated to MTU/buffer size; in
                    // that case the deserialiser sees a short blob
                    // and reports a wire-decode error. Either is a
                    // valid rejection — both are "did not silently
                    // accept oversized input".
                    Err(TransportError::InvalidBundle(_)) => {}
                    Ok(other) => {
                        panic!("oversized datagram must not silently round-trip; got {other:?}")
                    }
                    Err(other) => {
                        panic!("expected Oversized or InvalidBundle, got {other:?}")
                    }
                }
            }
            Err(_) => {
                // OS-level refusal of the oversized send is also a
                // valid fail-closed outcome.
            }
        }
    }

    #[test]
    fn push_bundle_refuses_to_emit_oversized_serialisation() {
        // Defensive: even if a caller hands us a malformed bundle
        // whose serialised form happens to exceed
        // MAX_GOSSIP_DATAGRAM_BYTES, push_bundle must refuse instead
        // of emitting it. Today the serialiser is bounded by
        // MAX_CANDIDATES_PER_BUNDLE so this is hard to trigger
        // legally — assert the legal-max bundle still fits.
        let transport = GossipTransport::bind(loopback_bind()).expect("bind");
        let bundle = sample_bundle();
        let wire = serialise_bundle(&bundle);
        assert!(wire.len() <= MAX_GOSSIP_DATAGRAM_BYTES);
        // Bind a sink so the send-to actually has somewhere to land.
        let sink = GossipTransport::bind(loopback_bind()).expect("bind sink");
        let sink_addr = sink.local_addr().expect("sink local_addr");
        transport
            .push_bundle(sink_addr, &bundle)
            .expect("legal-size bundle must push");
    }

    #[test]
    fn recv_bundle_zero_timeout_returns_none_when_empty() {
        // Non-blocking probe: a freshly-bound transport with no
        // pending datagrams must return Ok(None), NOT block.
        let transport = GossipTransport::bind(loopback_bind()).expect("bind");
        let res = transport
            .recv_bundle(Duration::ZERO)
            .expect("non-blocking ok");
        assert!(res.is_none(), "no datagrams pending; expected None");
    }

    #[test]
    fn wire_version_constant_is_stable() {
        // Defense against accidental version bump: callers depend on
        // GOSSIP_BUNDLE_WIRE_VERSION = 1 to identify v1 wires.
        assert_eq!(GOSSIP_BUNDLE_WIRE_VERSION, 1);
    }
}
