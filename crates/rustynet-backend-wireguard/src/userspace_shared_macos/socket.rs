#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use rustynet_backend_api::{AuthoritativeTransportIdentity, BackendError};

pub(crate) const AUTHORITATIVE_TRANSPORT_LABEL: &str =
    "wireguard-macos-userspace-shared-authoritative-transport";

static NEXT_TRANSPORT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceivedDatagram {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct AuthoritativeSocket {
    socket: UdpSocket,
    transport_generation: u64,
}

impl AuthoritativeSocket {
    pub(crate) fn bind(listen_port: u16) -> Result<Self, BackendError> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
        Self::bind_addr(bind_addr)
    }

    fn bind_addr(bind_addr: SocketAddr) -> Result<Self, BackendError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared authoritative UDP socket bind failed on {bind_addr}: {err}"
            ))
        })?;
        socket.set_nonblocking(true).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared authoritative UDP socket nonblocking setup failed on {bind_addr}: {err}"
            ))
        })?;
        Ok(Self {
            socket,
            transport_generation: NEXT_TRANSPORT_GENERATION.fetch_add(1, Ordering::SeqCst),
        })
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn bind_loopback_for_test() -> Result<Self, BackendError> {
        Self::bind_addr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, BackendError> {
        self.socket.local_addr().map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared authoritative UDP socket local_addr failed: {err}"
            ))
        })
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
                "macos userspace-shared authoritative UDP socket send_to failed for {remote_addr}: {err}"
            ))
        })?;
        if written != payload.len() {
            return Err(BackendError::internal(format!(
                "macos userspace-shared authoritative UDP socket send_to truncated datagram for {remote_addr}: wrote {written} of {} bytes",
                payload.len()
            )));
        }
        Ok(())
    }

    pub(crate) fn try_recv(&self) -> Result<Option<ReceivedDatagram>, BackendError> {
        let mut buffer = vec![0u8; 65_535];
        match self.socket.recv_from(&mut buffer) {
            Ok((len, remote_addr)) => {
                buffer.truncate(len);
                Ok(Some(ReceivedDatagram {
                    remote_addr,
                    payload: buffer,
                }))
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(None)
            }
            Err(err) => Err(BackendError::internal(format!(
                "macos userspace-shared authoritative UDP socket recv_from failed: {err}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn bind_reports_macos_authoritative_identity() {
        let socket = AuthoritativeSocket::bind_loopback_for_test().expect("bind should succeed");
        let identity = socket
            .identity(AUTHORITATIVE_TRANSPORT_LABEL)
            .expect("identity should resolve");
        assert_eq!(identity.label, AUTHORITATIVE_TRANSPORT_LABEL);
        assert_ne!(identity.local_addr.port(), 0);
    }

    #[test]
    fn bind_assigns_monotonic_transport_generation() {
        let first = AuthoritativeSocket::bind_loopback_for_test().expect("first bind");
        let second = AuthoritativeSocket::bind_loopback_for_test().expect("second bind");
        assert!(second.transport_generation() > first.transport_generation());
    }

    #[test]
    fn send_to_uses_bound_socket_identity() {
        let socket = AuthoritativeSocket::bind_loopback_for_test().expect("authoritative bind");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");

        socket
            .send_to(peer.local_addr().expect("peer addr"), b"relay-hello")
            .expect("send should succeed");

        let mut buffer = [0u8; 64];
        let (len, remote) = peer.recv_from(&mut buffer).expect("peer should receive");
        assert_eq!(&buffer[..len], b"relay-hello");
        assert_eq!(
            remote.port(),
            socket.local_addr().expect("socket addr").port()
        );
    }

    #[test]
    fn try_recv_returns_peer_datagram() {
        let socket = AuthoritativeSocket::bind_loopback_for_test().expect("authoritative bind");
        assert!(
            socket
                .try_recv()
                .expect("empty socket should not fail")
                .is_none(),
            "new nonblocking socket should have no datagram"
        );

        let peer = UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        let target = loopback_target(socket.local_addr().expect("socket addr"));
        peer.send_to(b"stun-probe", target).expect("peer send");

        let received = wait_for_datagram(&socket).expect("datagram should arrive");
        assert_eq!(received.remote_addr, peer.local_addr().expect("peer addr"));
        assert_eq!(received.payload, b"stun-probe");
    }

    fn loopback_target(local_addr: SocketAddr) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], local_addr.port()))
    }

    fn wait_for_datagram(socket: &AuthoritativeSocket) -> Option<ReceivedDatagram> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(datagram) = socket.try_recv().expect("recv should not fail") {
                return Some(datagram);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
