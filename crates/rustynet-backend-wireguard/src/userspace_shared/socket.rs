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

/// The OS handle a [`SocketProtector`] is asked to protect: a raw file
/// descriptor on unix (Linux, macOS, Android), a raw socket handle on Windows.
/// This crate is compile-checked for Windows, so the alias must exist there.
#[cfg(unix)]
pub(crate) type TransportFd = std::os::fd::RawFd;
#[cfg(windows)]
pub(crate) type TransportFd = std::os::windows::io::RawSocket;

/// The OS handle of a socket, as a protector is handed it.
pub(crate) fn transport_fd(socket: &UdpSocket) -> TransportFd {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        socket.as_raw_fd()
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        socket.as_raw_socket()
    }
}

/// Platform hook that exempts a transport socket from the VPN's own routes
/// (on Android, `VpnService.protect`).
///
/// The backend calls this itself, on every socket a provider returns, before
/// that socket is handed back to the caller. A provider cannot skip it.
///
/// `generation` is the transport generation the socket was opened under. An
/// implementation must accept only a socket from the generation it currently
/// honours; a stale or foreign generation must be refused. `false` means the
/// protect was refused or timed out.
///
/// Requirements on the MC1c-2 (Android) protector. Not implemented in this slice:
/// - It must protect a DUPLICATE of `fd` that native code closes after the call
///   returns, including after a timeout. The backend drops its own socket on
///   `false`, so the backend cannot keep `fd` alive for the native call.
/// - It must not retain `fd` after returning.
/// - fd numbers are reused after close (ABA). A live (fd, generation) registry
///   is REQUIRED before a protector may trust a bare fd. No such registry exists
///   in this slice.
pub(crate) trait SocketProtector: Send + Sync {
    fn protect(&self, fd: TransportFd, generation: u64) -> bool;
}

/// Creates the authoritative transport socket and nothing else.
///
/// The provider must not protect, connect, or send. Its output is checked and
/// protected by [`open_protected_transport`] before the socket can be used. The
/// socket must be bound to the unspecified address (`0.0.0.0` / `::`).
///
/// Not done in this slice, and required for MC1c-2: a public injection seam and
/// a re-export through `rustynet-backend-userspace`.
pub(crate) trait TransportSocketProvider: Send + Sync {
    fn open_transport(
        &self,
        generation: u64,
        listen_port: u16,
    ) -> Result<UdpSocket, TransportError>;
}

/// Why a transport socket could not be opened and protected.
#[derive(Debug)]
pub(crate) enum TransportError {
    /// No provider is configured for this target. Every target outside the
    /// desktop allow-list gets this, so a build that forgets to inject a
    /// provider fails closed.
    #[cfg_attr(
        any(target_os = "linux", target_os = "macos", target_os = "windows"),
        allow(dead_code)
    )]
    NotConfigured,
    /// The provider returned a socket bound to an address other than the
    /// unspecified address. The authoritative socket must listen on all
    /// interfaces.
    WrongAddress { actual: SocketAddr },
    /// The provider returned a socket bound to a different port than requested.
    WrongPort { expected: u16, actual: u16 },
    /// The provider returned a connected socket. A connected UDP socket cannot
    /// serve as the authoritative listener.
    Connected,
    /// The protector refused, or timed out. The socket was dropped before the
    /// error was returned.
    ProtectDenied { generation: u64 },
    /// The OS refused to create the socket.
    Io(std::io::Error),
}

/// Default provider.
///
/// Linux, macOS and Windows: the same bind as before, followed by read-only
/// `getsockname`/`getpeername` checks in [`open_protected_transport`]. Every
/// other target (Android, iOS, anything else): refuses with
/// [`TransportError::NotConfigured`], so a build that forgets to inject a
/// provider cannot bind.
#[derive(Debug, Default)]
pub(crate) struct DefaultTransportSocketProvider;

impl TransportSocketProvider for DefaultTransportSocketProvider {
    fn open_transport(
        &self,
        _generation: u64,
        listen_port: u16,
    ) -> Result<UdpSocket, TransportError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
            UdpSocket::bind(bind_addr).map_err(TransportError::Io)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = listen_port;
            Err(TransportError::NotConfigured)
        }
    }
}

/// Default protector.
///
/// Linux, macOS and Windows: there is no VPN route to exempt from, so it
/// accepts without any syscall. Every other target refuses. If a mobile build
/// injects a provider but no protector, nothing is protected and the bind fails
/// closed.
#[derive(Debug, Default)]
pub(crate) struct DefaultSocketProtector;

impl SocketProtector for DefaultSocketProtector {
    fn protect(&self, _fd: TransportFd, _generation: u64) -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        ))
    }
}

/// Open a transport socket and make it usable only once it has passed the
/// contract and been protected.
///
/// The order is fixed:
/// 1. The provider creates the socket.
/// 2. The output is checked: bound to the unspecified address, bound to
///    `listen_port` (unless `listen_port` is 0), and unconnected.
/// 3. The protector is called on the socket. Only `true` returns it.
///
/// Every failure drops the socket before returning. A panic in the protector
/// unwinds through this function and drops the socket the same way. Nothing
/// here sends, so the caller can use the socket only after protect returned
/// `true`.
pub(crate) fn open_protected_transport(
    provider: &dyn TransportSocketProvider,
    protector: &dyn SocketProtector,
    generation: u64,
    listen_port: u16,
) -> Result<UdpSocket, TransportError> {
    let socket = provider.open_transport(generation, listen_port)?;
    // Connectedness first: connect() rewrites a UDP socket's local address on
    // Linux (it picks the route's source), so the address check below would
    // misreport a connected socket as a wrong-address one.
    match socket.peer_addr() {
        Ok(_) => return Err(TransportError::Connected),
        Err(err) if err.kind() == ErrorKind::NotConnected => {}
        Err(err) => return Err(TransportError::Io(err)),
    }
    let local = socket.local_addr().map_err(TransportError::Io)?;
    if !local.ip().is_unspecified() {
        return Err(TransportError::WrongAddress { actual: local });
    }
    if listen_port != 0 && local.port() != listen_port {
        return Err(TransportError::WrongPort {
            expected: listen_port,
            actual: local.port(),
        });
    }
    if !protector.protect(transport_fd(&socket), generation) {
        return Err(TransportError::ProtectDenied { generation });
    }
    Ok(socket)
}

fn linux_transport_error(err: TransportError, bind_addr: SocketAddr) -> BackendError {
    match err {
        TransportError::Io(err) => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket bind failed on {bind_addr}: {err}"
        )),
        TransportError::NotConfigured => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket transport provider is not configured; refusing to bind {bind_addr}"
        )),
        TransportError::WrongAddress { actual } => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket transport provider returned a socket bound to {actual}, not the wildcard address for {bind_addr}"
        )),
        TransportError::WrongPort { expected, actual } => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket transport provider returned port {actual} for requested port {expected} on {bind_addr}"
        )),
        TransportError::Connected => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket transport provider returned a connected socket for {bind_addr}"
        )),
        TransportError::ProtectDenied { generation } => BackendError::internal(format!(
            "linux userspace-shared authoritative UDP socket protect refused on {bind_addr} for transport generation {generation}"
        )),
    }
}

#[derive(Debug)]
pub(crate) struct AuthoritativeSocket {
    socket: UdpSocket,
    /// The generation the socket was protected under.
    ///
    /// A live (fd, generation) registry is REQUIRED in MC1c-2 before a protector
    /// may trust a bare fd, because fd numbers are reused after close (ABA). No
    /// such registry exists in this slice.
    transport_generation: u64,
    // Resolved once at bind: the bound address is immutable for the socket's
    // lifetime, and `local_addr` sits on the per-datagram hot path — caching
    // removes a getsockname syscall per use. Bind fails closed if the address
    // cannot be resolved.
    cached_local_addr: SocketAddr,
}

impl AuthoritativeSocket {
    /// Bind through the default provider and protector. Test-only: production
    /// opens its socket through [`Self::bind_with_provider`], so an injected
    /// provider is the one that creates it.
    #[cfg(test)]
    pub(crate) fn bind(listen_port: u16) -> Result<Self, BackendError> {
        Self::bind_with_provider(
            listen_port,
            &DefaultTransportSocketProvider,
            &DefaultSocketProtector,
        )
    }

    /// Open the authoritative socket through `provider`, then protect it with
    /// `protector` under a freshly allocated transport generation, before it is
    /// returned. A refusal fails closed: no socket is kept and nothing is sent.
    pub(crate) fn bind_with_provider(
        listen_port: u16,
        provider: &dyn TransportSocketProvider,
        protector: &dyn SocketProtector,
    ) -> Result<Self, BackendError> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
        // Allocated before the provider runs: the socket is protected under this
        // generation, so the generation must be known before the socket exists.
        let generation = NEXT_TRANSPORT_GENERATION.fetch_add(1, Ordering::SeqCst);
        let socket = open_protected_transport(provider, protector, generation, listen_port)
            .map_err(|err| linux_transport_error(err, bind_addr))?;
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
            transport_generation: generation,
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
    /// is a contract, not an inconvenience. Bypasses the protect step, so it is
    /// never compiled for Android.
    #[cfg(all(any(test, feature = "test-harness"), not(target_os = "android")))]
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

/// Test protector that refuses every socket.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RefuseAllSocketProtector;

#[cfg(test)]
impl SocketProtector for RefuseAllSocketProtector {
    fn protect(&self, _fd: TransportFd, _generation: u64) -> bool {
        false
    }
}

/// Deterministic closure check: can `port` be bound on the wildcard address
/// right now?
///
/// `true` means no socket holds the port, which is what a closed socket looks
/// like. `false` means something still holds it. The probe's own socket is
/// dropped at once. Test-only.
#[cfg(test)]
pub(crate) fn port_is_bindable(port: u16) -> bool {
    UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).is_ok()
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Records every (fd, generation) pair it is asked about and answers with `accept`.
    #[derive(Debug)]
    struct RecordingProtector {
        accept: bool,
        calls: Mutex<Vec<(TransportFd, u64)>>,
    }

    impl RecordingProtector {
        fn new(accept: bool) -> Self {
            Self {
                accept,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(TransportFd, u64)> {
            self.calls.lock().expect("calls lock").clone()
        }

        fn generations(&self) -> Vec<u64> {
            self.calls().into_iter().map(|(_, g)| g).collect()
        }
    }

    impl SocketProtector for RecordingProtector {
        fn protect(&self, fd: TransportFd, generation: u64) -> bool {
            self.calls
                .lock()
                .expect("calls lock")
                .push((fd, generation));
            self.accept
        }
    }

    /// Panics if asked. Used to prove the panic unwinds and drops the socket.
    struct PanickingProtector;

    impl SocketProtector for PanickingProtector {
        fn protect(&self, _fd: TransportFd, _generation: u64) -> bool {
            panic!("protector panicked");
        }
    }

    #[derive(Debug)]
    enum FakeMode {
        /// Bind the unspecified address on the requested port (0 = ephemeral).
        Plain,
        /// Bind the unspecified address on an ephemeral port, ignoring the request.
        WrongPort,
        /// Bind the unspecified address on the requested port, then connect.
        Connected,
        /// Bind loopback, which the contract must refuse.
        LoopbackOnly,
    }

    /// A provider that creates a socket and remembers its port, so a test can
    /// check the port is free once the backend has dropped the socket.
    #[derive(Debug)]
    struct LoopbackProvider {
        mode: FakeMode,
        bound_port: Mutex<Option<u16>>,
        opens: AtomicUsize,
    }

    impl LoopbackProvider {
        fn new(mode: FakeMode) -> Self {
            Self {
                mode,
                bound_port: Mutex::new(None),
                opens: AtomicUsize::new(0),
            }
        }

        fn port(&self) -> u16 {
            self.bound_port
                .lock()
                .expect("port lock")
                .expect("the provider bound a socket")
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }
    }

    impl TransportSocketProvider for LoopbackProvider {
        fn open_transport(
            &self,
            _generation: u64,
            listen_port: u16,
        ) -> Result<UdpSocket, TransportError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let bind_addr = match self.mode {
                FakeMode::Plain | FakeMode::Connected => {
                    SocketAddr::from(([0, 0, 0, 0], listen_port))
                }
                FakeMode::WrongPort => SocketAddr::from(([0, 0, 0, 0], 0)),
                FakeMode::LoopbackOnly => SocketAddr::from(([127, 0, 0, 1], listen_port)),
            };
            let socket = UdpSocket::bind(bind_addr).map_err(TransportError::Io)?;
            *self.bound_port.lock().expect("port lock") =
                Some(socket.local_addr().map_err(TransportError::Io)?.port());
            if matches!(self.mode, FakeMode::Connected) {
                socket
                    .connect(SocketAddr::from(([127, 0, 0, 1], 9)))
                    .map_err(TransportError::Io)?;
            }
            Ok(socket)
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn default_provider_and_protector_bind_an_unconnected_ephemeral_socket() {
        let socket = AuthoritativeSocket::bind(0).expect("default bind should succeed");
        assert_ne!(
            socket.local_addr().expect("local addr").port(),
            0,
            "an ephemeral port must have been assigned"
        );
        assert_eq!(
            socket.socket.peer_addr().err().map(|e| e.kind()),
            Some(ErrorKind::NotConnected),
            "the default socket must be unconnected"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn desktop_bind_error_text_is_unchanged_from_the_base_format() {
        // Hold the port so the default bind fails with the OS's own error. The
        // message must be byte-for-byte the base text with that OS error.
        let held = UdpSocket::bind("0.0.0.0:0").expect("hold a port");
        let port = held.local_addr().expect("held addr").port();
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
        let os_err = UdpSocket::bind(bind_addr).expect_err("the port is held");

        let err = AuthoritativeSocket::bind_with_provider(
            port,
            &DefaultTransportSocketProvider,
            &DefaultSocketProtector,
        )
        .expect_err("binding a held port must fail");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert_eq!(
            err.message,
            format!(
                "linux userspace-shared authoritative UDP socket bind failed on {bind_addr}: {os_err}"
            )
        );
    }

    #[test]
    fn protect_refusal_closes_the_socket_and_fails_the_bind_closed() {
        let provider = LoopbackProvider::new(FakeMode::Plain);
        let err = AuthoritativeSocket::bind_with_provider(0, &provider, &RefuseAllSocketProtector)
            .expect_err("a refused protect must fail the bind");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(
            err.message.contains("protect refused"),
            "the refusal must be named in the error, got: {}",
            err.message
        );
        assert_eq!(provider.opens(), 1);
        // The backend dropped the socket before returning: nothing holds the port.
        assert!(
            port_is_bindable(provider.port()),
            "the refused socket must be closed"
        );
    }

    #[test]
    fn protect_is_called_on_the_socket_the_provider_created_and_only_then_returned() {
        let provider = LoopbackProvider::new(FakeMode::Plain);
        let protector = RecordingProtector::new(true);
        let socket = AuthoritativeSocket::bind_with_provider(0, &provider, &protector)
            .expect("an accepted protect must yield a socket");

        assert_eq!(
            protector.calls(),
            vec![(transport_fd(&socket.socket), socket.transport_generation())],
            "protect must run once, on this socket's fd, under the generation it reports"
        );
        // Control: while the socket is open, its port cannot be bound again.
        assert!(
            !port_is_bindable(provider.port()),
            "an open socket must hold its port"
        );

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("receiver timeout");
        let target = receiver.local_addr().expect("receiver addr");
        socket
            .send_to(target, &[5u8; 8])
            .expect("the protected socket must send");
        let mut buf = [0u8; 16];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .expect("datagram should arrive");
        assert_eq!(&buf[..len], &[5u8; 8]);
    }

    #[test]
    fn each_bind_is_protected_under_its_own_generation() {
        let protector = RecordingProtector::new(true);
        let first = AuthoritativeSocket::bind_with_provider(
            0,
            &LoopbackProvider::new(FakeMode::Plain),
            &protector,
        )
        .expect("first bind");
        let second = AuthoritativeSocket::bind_with_provider(
            0,
            &LoopbackProvider::new(FakeMode::Plain),
            &protector,
        )
        .expect("second bind");

        assert_eq!(
            protector.generations(),
            vec![first.transport_generation(), second.transport_generation()],
            "each socket must be protected under the generation it reports"
        );
        assert!(
            first.transport_generation() < second.transport_generation(),
            "generations must be fresh per bind"
        );
    }

    #[test]
    fn a_panicking_protector_unwinds_and_drops_the_socket() {
        let provider = LoopbackProvider::new(FakeMode::Plain);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AuthoritativeSocket::bind_with_provider(0, &provider, &PanickingProtector)
        }));
        assert!(
            result.is_err(),
            "the protector panic must propagate, not turn into a usable socket"
        );
        assert!(
            port_is_bindable(provider.port()),
            "the socket must be dropped during the unwind"
        );
    }

    #[test]
    fn provider_returning_the_wrong_port_is_refused_and_closed() {
        let provider = LoopbackProvider::new(FakeMode::WrongPort);
        // The provider ignores the requested port 1 and binds an ephemeral one.
        let err = AuthoritativeSocket::bind_with_provider(1, &provider, &RefuseAllSocketProtector)
            .expect_err("a socket on the wrong port must be refused");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(
            err.message.contains("returned port") && err.message.contains("requested port 1"),
            "the port mismatch must be named, got: {}",
            err.message
        );
        assert!(port_is_bindable(provider.port()));
    }

    #[test]
    fn provider_returning_a_connected_socket_is_refused_and_closed() {
        let provider = LoopbackProvider::new(FakeMode::Connected);
        let err = AuthoritativeSocket::bind_with_provider(0, &provider, &RefuseAllSocketProtector)
            .expect_err("a connected socket must be refused");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(
            err.message.contains("connected socket"),
            "the connected socket must be named, got: {}",
            err.message
        );
        assert!(port_is_bindable(provider.port()));
    }

    #[test]
    fn provider_binding_a_specific_address_is_refused_and_closed() {
        let provider = LoopbackProvider::new(FakeMode::LoopbackOnly);
        let err = AuthoritativeSocket::bind_with_provider(0, &provider, &RefuseAllSocketProtector)
            .expect_err("a socket bound to loopback must be refused");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(
            err.message.contains("not the wildcard address"),
            "the non-wildcard address must be named, got: {}",
            err.message
        );
        assert!(port_is_bindable(provider.port()));
    }

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
    #[cfg(not(target_os = "android"))]
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
