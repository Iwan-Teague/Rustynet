use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use rustynet_backend_api::{AuthoritativeTransportIdentity, BackendError};

pub(crate) const AUTHORITATIVE_TRANSPORT_LABEL: &str =
    "wireguard-linux-userspace-shared-authoritative-transport";

/// A received datagram with sender address and payload.
/// Mirrors the same-named type in `userspace_shared_macos::socket`
/// so the shared runtime can use it across both backends.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceivedDatagram {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

static NEXT_TRANSPORT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct AuthoritativeSocket {
    socket: UdpSocket,
    transport_generation: u64,
    // Resolved once at bind: the bound address is immutable for the socket's
    // lifetime, and `local_addr` sits on the per-datagram hot path — caching
    // removes a getsockname syscall per use. Bind fails closed if the address
    // cannot be resolved.
    cached_local_addr: SocketAddr,
}

impl AuthoritativeSocket {
    pub(crate) fn bind(listen_port: u16) -> Result<Self, BackendError> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
        let socket = UdpSocket::bind(bind_addr).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket bind failed on {bind_addr}: {err}"
            ))
        })?;
        socket.set_nonblocking(true).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket nonblocking setup failed on {bind_addr}: {err}"
            ))
        })?;
        let cached_local_addr = socket.local_addr().map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket local_addr failed: {err}"
            ))
        })?;
        Ok(Self {
            socket,
            transport_generation: NEXT_TRANSPORT_GENERATION.fetch_add(1, Ordering::SeqCst),
            cached_local_addr,
        })
    }

    /// Adopt a socket the caller already bound, instead of binding one here.
    ///
    /// Tests need to know the port before the backend exists — to wire it as a
    /// peer endpoint, or to send to it. Deriving that port from a throwaway
    /// `bind(0)` and letting the socket drop releases the port, so the real bind
    /// later races every other process on the box for it; that is the flake this
    /// exists to remove. Reserving the port by keeping the socket bound and
    /// handing it over means the reservation is never released, so there is no
    /// window to lose.
    ///
    /// Test-only. Production still binds the operator's configured port, and
    /// must keep doing so — that path is what `AuthoritativeSocket::bind`
    /// serves, and the fail-closed behaviour when the configured port is taken
    /// is a contract, not an inconvenience.
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn from_bound_socket(socket: UdpSocket) -> Result<Self, BackendError> {
        socket.set_nonblocking(true).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket nonblocking setup failed on a pre-bound socket: {err}"
            ))
        })?;
        let cached_local_addr = socket.local_addr().map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket local_addr failed on a pre-bound socket: {err}"
            ))
        })?;
        Ok(Self {
            socket,
            transport_generation: NEXT_TRANSPORT_GENERATION.fetch_add(1, Ordering::SeqCst),
            cached_local_addr,
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, BackendError> {
        Ok(self.cached_local_addr)
    }

    pub(crate) fn identity(
        &self,
        label: &'static str,
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        Ok(AuthoritativeTransportIdentity {
            local_addr: self.local_addr()?,
            label: label.to_owned(),
        })
    }

    pub(crate) fn transport_generation(&self) -> u64 {
        self.transport_generation
    }

    pub(crate) fn send_to(
        &self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), BackendError> {
        let written = self.socket.send_to(payload, remote_addr).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket send_to failed for {remote_addr}: {err}"
            ))
        })?;
        if written != payload.len() {
            return Err(BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket send_to truncated datagram for {remote_addr}: wrote {written} of {} bytes",
                payload.len()
            )));
        }
        Ok(())
    }

    /// Best-effort dataplane egress: send one ciphertext datagram, DROPPING it
    /// (`Ok(false)`) when the OS refuses in a transient way instead of erroring.
    ///
    /// WireGuard's wire protocol is loss-tolerant — a dropped keepalive,
    /// handshake initiation, or data frame is retried by boringtun's own
    /// timers — but a `BackendError` escaping the worker loop kills the worker
    /// thread outright. A host firewall rejecting egress (netfilter REJECT on
    /// the WG port ⇒ `EPERM`), a link flap (`ENETDOWN`/`ENETUNREACH`), or an
    /// ICMP-reflected refusal are exactly the conditions a VPN daemon must ride
    /// out, not die from: on 2026-08-26 a 35-second nft egress block killed this
    /// worker on its first keepalive tick, the replacement worker died the same
    /// way during recovery replay, and five failed reconciles latched the node
    /// PERMANENTLY restricted — turning a transient block into an unrecoverable
    /// dataplane. Structural failures (bad fd, truncation) still fail loudly.
    ///
    /// This tolerance is dataplane-only. Control-plane round trips keep using
    /// the strict [`Self::send_to`] so their callers see the failure.
    pub(crate) fn send_to_dataplane(
        &self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<bool, BackendError> {
        match self.socket.send_to(payload, remote_addr) {
            Ok(written) if written == payload.len() => Ok(true),
            Ok(written) => Err(BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket send_to truncated datagram for {remote_addr}: wrote {written} of {} bytes",
                payload.len()
            ))),
            Err(err) if is_transient_dataplane_send_error(&err) => Ok(false),
            Err(err) => Err(BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket send_to failed for {remote_addr}: {err}"
            ))),
        }
    }

    /// Receive one datagram into the caller's long-lived scratch buffer
    /// (no per-packet allocation). Returns the filled length and the
    /// sender; `None` when the socket has no pending datagram.
    pub(crate) fn try_recv_into(
        &self,
        scratch: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>, BackendError> {
        match self.socket.recv_from(scratch) {
            Ok((len, remote_addr)) => Ok(Some((len, remote_addr))),
            // ConnectionRefused/ConnectionReset are a peer's ICMP
            // port-unreachable reflected back onto the socket, not a broken
            // socket: there is no datagram, and the peer being briefly
            // unreachable is a routine dataplane condition. Treating them as
            // fatal would kill the worker thread over a condition boringtun's
            // timers already handle by retrying.
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock
                        | ErrorKind::TimedOut
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionReset
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket recv_from failed: {err}"
            ))),
        }
    }

    /// Receive one datagram (allocating convenience wrapper).
    /// Prefer `try_recv_into` with a reused scratch buffer for hot-path use;
    /// this method exists for compatibility with the shared runtime's
    /// `ReceivedDatagram`-based interface.
    #[allow(dead_code)]
    pub(crate) fn try_recv(&self) -> Result<Option<ReceivedDatagram>, BackendError> {
        let mut scratch = vec![0u8; 65536];
        match self.try_recv_into(&mut scratch) {
            Ok(Some((len, remote_addr))) => {
                scratch.truncate(len);
                Ok(Some(ReceivedDatagram {
                    remote_addr,
                    payload: scratch,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Classify an OS send error as a transient egress condition (drop the
/// datagram, keep the worker alive) versus a structural socket failure
/// (fail loudly).
///
/// Transient means "this datagram could not leave the host right now":
/// - `PermissionDenied` — `EPERM`/`EACCES`: a netfilter/nft REJECT or DROP on
///   the egress path refuses locally-generated packets with `EPERM`. This is
///   the exact condition the live-lab `live_network_flap_validation` stage
///   creates on purpose, and the one that killed the worker on 2026-08-26.
/// - `NetworkDown` / `NetworkUnreachable` / `HostUnreachable` /
///   `AddrNotAvailable` — link flaps, route churn, DHCP renumbering.
/// - `ConnectionRefused` / `ConnectionReset` — a peer's ICMP unreachable
///   reflected onto the socket.
/// - `WouldBlock` / `Interrupted` — kernel buffer pressure / signal delivery.
///
/// Everything else (bad fd, `InvalidInput`, message-too-large, …) stays fatal:
/// those indicate the socket or the caller is broken, and continuing would
/// silently blackhole all egress.
fn is_transient_dataplane_send_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::PermissionDenied
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::AddrNotAvailable
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::*;

    #[test]
    fn transient_send_error_classifier_covers_firewall_and_link_conditions() {
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::WouldBlock,
            ErrorKind::Interrupted,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::NetworkDown,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::AddrNotAvailable,
        ] {
            assert!(
                is_transient_dataplane_send_error(&Error::from(kind)),
                "{kind:?} must be tolerated on the dataplane egress path"
            );
        }
    }

    #[test]
    fn structural_send_errors_stay_fatal() {
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::NotFound,
            ErrorKind::BrokenPipe,
            ErrorKind::Other,
        ] {
            assert!(
                !is_transient_dataplane_send_error(&Error::from(kind)),
                "{kind:?} must remain a loud failure"
            );
        }
    }

    #[test]
    fn dataplane_send_drops_firewalled_egress_instead_of_erroring() {
        // Sending to the broadcast address without SO_BROADCAST is refused by
        // the kernel with EACCES -> PermissionDenied: a deterministic stand-in
        // for the nft REJECT (EPERM) that a host firewall produces. The
        // dataplane path must report "dropped", not an error. Bind loopback:
        // this module's tests also compile-and-run on the macOS CI leg, where
        // a wildcard-bound broadcast send is not refused.
        let socket = AuthoritativeSocket::from_bound_socket(
            std::net::UdpSocket::bind("127.0.0.1:0").expect("loopback bind"),
        )
        .expect("bind should succeed");
        let target: SocketAddr = "255.255.255.255:9".parse().expect("valid addr");
        let delivered = socket
            .send_to_dataplane(target, &[0u8; 8])
            .expect("transient egress refusal must be dropped, not fatal");
        assert!(!delivered, "a refused send must report dropped, not sent");

        // The strict control-plane path must keep failing loudly on the same
        // condition — the tolerance is dataplane-only.
        assert!(
            socket.send_to(target, &[0u8; 8]).is_err(),
            "control-plane send_to must stay strict"
        );
    }

    #[test]
    fn dataplane_send_still_delivers_when_egress_is_open() {
        let socket = AuthoritativeSocket::bind(0).expect("bind should succeed");
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
        let target = receiver.local_addr().expect("receiver addr");
        let delivered = socket
            .send_to_dataplane(target, &[7u8; 8])
            .expect("open egress must send");
        assert!(delivered, "an accepted send must report delivered");
    }
}
