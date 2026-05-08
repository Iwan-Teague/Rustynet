//! Boringtun userspace WireGuard backend for Rustynet.
//!
//! Provides [`UserspaceBackend`], a second non-kernel TunnelBackend
//! implementation that drives WireGuard entirely in userspace via the
//! vendored boringtun noise engine. The kernel WireGuard module is not
//! required; this backend can run on hosts where wg(8) is unavailable.
//!
//! On Linux this wraps [`LinuxUserspaceSharedBackend`] from
//! `rustynet-backend-wireguard`. On macOS this wraps
//! [`MacosUserspaceSharedBackend`] (Phase 1 scaffolding — all operational
//! methods return an internal error until the runtime datapath is
//! implemented). On other platforms the type is present but all operations
//! fail with a clear `Internal` error so callers can detect platform
//! capability at runtime rather than compile time.

#![forbid(unsafe_code)]

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};

#[cfg(target_os = "linux")]
use rustynet_backend_wireguard::LinuxUserspaceSharedBackend;

#[cfg(target_os = "macos")]
use rustynet_backend_wireguard::MacosUserspaceSharedBackend;

/// A boringtun-driven userspace WireGuard backend.
///
/// On Linux this delegates all operations to [`LinuxUserspaceSharedBackend`].
/// On macOS this delegates to [`MacosUserspaceSharedBackend`] (Phase 1
/// scaffolding — all operational methods return an internal error until
/// the runtime datapath is implemented in Phase 2+).
/// On other platforms every mutating call returns a `BackendError::internal`
/// with a platform-unavailable message.
pub struct UserspaceBackend {
    #[cfg(target_os = "linux")]
    inner: LinuxUserspaceSharedBackend,
    #[cfg(target_os = "macos")]
    inner: MacosUserspaceSharedBackend,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    _marker: (),
}

impl UserspaceBackend {
    /// Construct a userspace backend for the given WireGuard interface.
    ///
    /// # Arguments
    /// * `interface_name` – TUN interface name (e.g. `"rustynet0"`).
    /// * `private_key_path` – Path to a base64-encoded WireGuard private key.
    /// * `listen_port` – UDP port the userspace engine should bind.
    ///
    /// Returns an error if the platform does not support this backend or if
    /// the constructor arguments are invalid.
    pub fn new(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        #[cfg(target_os = "linux")]
        {
            let inner =
                LinuxUserspaceSharedBackend::new(interface_name, private_key_path, listen_port)?;
            Ok(Self { inner })
        }
        #[cfg(target_os = "macos")]
        {
            let inner =
                MacosUserspaceSharedBackend::new(interface_name, private_key_path, listen_port)?;
            Ok(Self { inner })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (interface_name, private_key_path, listen_port);
            Err(BackendError::internal(
                "UserspaceBackend is only available on Linux and macOS",
            ))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_unavailable() -> BackendError {
    BackendError::internal("UserspaceBackend is only available on Linux and macOS")
}

impl TunnelBackend for UserspaceBackend {
    fn name(&self) -> &'static str {
        "userspace-wireguard"
    }

    fn capabilities(&self) -> BackendCapabilities {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.capabilities()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: false,
            supports_lan_routes: false,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.start(context)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = context;
            Err(platform_unavailable())
        }
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.configure_peer(peer)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = peer;
            Err(platform_unavailable())
        }
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.update_peer_endpoint(node_id, endpoint)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (node_id, endpoint);
            Err(platform_unavailable())
        }
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.current_peer_endpoint(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.peer_latest_handshake_unix(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.remove_peer(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.apply_routes(routes)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = routes;
            Err(platform_unavailable())
        }
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.set_exit_mode(mode)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = mode;
            Err(platform_unavailable())
        }
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.stats()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(platform_unavailable())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.shutdown()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(platform_unavailable())
    }
}
