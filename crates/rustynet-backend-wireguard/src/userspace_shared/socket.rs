use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use rustynet_backend_api::{AuthoritativeTransportIdentity, BackendError};

pub(crate) const AUTHORITATIVE_TRANSPORT_LABEL: &str =
    "wireguard-linux-userspace-shared-authoritative-transport";

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
        Ok(Self {
            socket,
            transport_generation: NEXT_TRANSPORT_GENERATION.fetch_add(1, Ordering::SeqCst),
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, BackendError> {
        self.socket.local_addr().map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket local_addr failed: {err}"
            ))
        })
    }

    pub(crate) fn identity(
        &self,
        label: &'static str,
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        Ok(AuthoritativeTransportIdentity {
            local_addr: self.local_addr()?,
            label: label.to_string(),
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
        self.socket.send_to(payload, remote_addr).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared authoritative UDP socket send_to failed for {remote_addr}: {err}"
            ))
        })?;
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
                "linux userspace-shared authoritative UDP socket recv_from failed: {err}"
            ))),
        }
    }
}
