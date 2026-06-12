use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use rustynet_backend_api::{AuthoritativeTransportIdentity, BackendError};

pub(crate) const AUTHORITATIVE_TRANSPORT_LABEL: &str =
    "wireguard-linux-userspace-shared-authoritative-transport";

/// A received datagram with sender address and payload.
/// Mirrors the same-named type in `userspace_shared_macos::socket`
/// so the shared runtime can use it across both backends.
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

    /// Receive one datagram into the caller's long-lived scratch buffer
    /// (no per-packet allocation). Returns the filled length and the
    /// sender; `None` when the socket has no pending datagram.
    pub(crate) fn try_recv_into(
        &self,
        scratch: &mut [u8],
    ) -> Result<Option<(usize, SocketAddr)>, BackendError> {
        match self.socket.recv_from(scratch) {
            Ok((len, remote_addr)) => Ok(Some((len, remote_addr))),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
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
