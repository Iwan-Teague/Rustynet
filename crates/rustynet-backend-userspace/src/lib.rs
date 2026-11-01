#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
//! Boringtun userspace `WireGuard` backend for Rustynet.
//!
//! Provides [`UserspaceBackend`], a second non-kernel `TunnelBackend`
//! implementation that drives `WireGuard` entirely in userspace via the
//! vendored boringtun noise engine. The kernel `WireGuard` module is not
//! required; this backend can run on hosts where wg(8) is unavailable.
//!
//! On Linux this wraps [`LinuxUserspaceSharedBackend`] from
//! `rustynet-backend-wireguard`. On macOS this wraps
//! [`MacosUserspaceSharedBackend`]. On other platforms the type is present but all operations
//! fail with a clear `Internal` error so callers can detect platform
//! capability at runtime rather than compile time.

#![forbid(unsafe_code)]

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use rustynet_backend_wireguard::LinuxUserspaceSharedBackend;

#[cfg(target_os = "macos")]
use rustynet_backend_wireguard::MacosUserspaceSharedBackend;

/// A boringtun-driven userspace `WireGuard` backend.
///
/// On Linux this delegates all operations to [`LinuxUserspaceSharedBackend`].
/// On macOS this delegates to [`MacosUserspaceSharedBackend`].
/// On other platforms every mutating call returns a `BackendError::internal`
/// with a platform-unavailable message.
pub struct UserspaceBackend {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inner: LinuxUserspaceSharedBackend,
    #[cfg(target_os = "macos")]
    inner: MacosUserspaceSharedBackend,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
    _marker: (),
}

impl UserspaceBackend {
    /// Construct a userspace backend for the given `WireGuard` interface.
    ///
    /// # Arguments
    /// * `interface_name` – TUN interface name (e.g. `"rustynet0"`).
    /// * `private_key_path` – Path to a base64-encoded `WireGuard` private key.
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
        #[cfg(target_os = "android")]
        {
            let _ = (interface_name, private_key_path, listen_port);
            Err(BackendError::internal(
                "UserspaceBackend::new is not available on Android: the WireGuard key and the tunnel descriptor arrive in memory through UserspaceBackend::new_android",
            ))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = (interface_name, private_key_path, listen_port);
            Err(BackendError::internal(
                "UserspaceBackend is only available on Linux and macOS",
            ))
        }
    }

    /// Android constructor. The static key is handed in memory and the tunnel
    /// descriptor is adopted from the VPN service, taken once. No key path is
    /// read (N4/N27). Start fails closed until the VPN protect seam is injected
    /// (MC1e), because the default transport socket provider refuses on Android.
    #[cfg(target_os = "android")]
    pub fn new_android(
        interface_name: impl Into<String>,
        private_key: Box<zeroize::Zeroizing<[u8; 32]>>,
        listen_port: u16,
        tun_fd: rustynet_backend_api::TunFdHandoff,
    ) -> Result<Self, BackendError> {
        let inner = LinuxUserspaceSharedBackend::new_adopted(
            interface_name,
            private_key,
            listen_port,
            tun_fd,
        )?;
        Ok(Self { inner })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
fn platform_unavailable() -> BackendError {
    BackendError::internal("UserspaceBackend is only available on Linux and macOS")
}

impl TunnelBackend for UserspaceBackend {
    fn name(&self) -> &'static str {
        "userspace-wireguard"
    }

    fn capabilities(&self) -> BackendCapabilities {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.capabilities()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: false,
            supports_exit_client: false,
            supports_exit_serving: false,
            supports_lan_routes: false,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.start(context)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = context;
            Err(platform_unavailable())
        }
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.configure_peer(peer)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
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
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.update_peer_endpoint(node_id, endpoint)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = (node_id, endpoint);
            Err(platform_unavailable())
        }
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.current_peer_endpoint(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.peer_latest_handshake_unix(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.remove_peer(node_id)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = node_id;
            Err(platform_unavailable())
        }
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.apply_routes(routes)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = routes;
            Err(platform_unavailable())
        }
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.set_exit_mode(mode)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        {
            let _ = mode;
            Err(platform_unavailable())
        }
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.stats()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        Err(platform_unavailable())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]
        {
            self.inner.shutdown()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
        Err(platform_unavailable())
    }
}
