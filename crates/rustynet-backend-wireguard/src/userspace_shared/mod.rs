use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendCapabilities,
    BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint,
    TunnelBackend, TunnelStats,
};

use crate::linux_command::{
    WireguardCommandRunner, validate_interface_name, validate_listen_port,
    validate_private_key_path,
};

mod engine;
mod handshake;
mod runtime;
mod socket;
mod tun;

use engine::UserspaceEngine;
use runtime::{RunningUserspaceRuntime, RuntimeControl};
use socket::AuthoritativeSocket;
use tun::{DirectTunLifecycle, HelperBackedTunLifecycle, TestTunLifecycle, TunLifecycle};

pub(crate) const LINUX_USERSPACE_SHARED_BACKEND_MODE: &str = "linux-wireguard-userspace-shared";
#[allow(dead_code)]
pub(crate) const MACOS_USERSPACE_SHARED_BACKEND_MODE: &str = "macos-wireguard-userspace-shared";

pub struct LinuxUserspaceSharedBackend {
    interface_name: String,
    private_key_path: PathBuf,
    listen_port: u16,
    tun_lifecycle: Box<dyn TunLifecycle>,
    runtime: Option<RunningUserspaceRuntime>,
}

impl LinuxUserspaceSharedBackend {
    pub fn new(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        Self::new_with_tun_lifecycle(
            interface_name,
            private_key_path,
            listen_port,
            Box::<DirectTunLifecycle>::default(),
        )
    }

    pub fn new_with_helper_runner<R>(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
        runner: R,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, BackendError>
    where
        R: WireguardCommandRunner + Send + Sync + 'static,
    {
        Self::new_with_tun_lifecycle(
            interface_name,
            private_key_path,
            listen_port,
            Box::new(HelperBackedTunLifecycle::new(runner, owner_uid, owner_gid)),
        )
    }

    #[doc(hidden)]
    pub fn new_for_test(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        Self::new_with_tun_lifecycle(
            interface_name,
            private_key_path,
            listen_port,
            Box::new(TestTunLifecycle::new()),
        )
    }

    fn new_with_tun_lifecycle(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
        tun_lifecycle: Box<dyn TunLifecycle>,
    ) -> Result<Self, BackendError> {
        let interface_name = interface_name.into();
        let private_key_path = private_key_path.into();
        validate_interface_name(&interface_name)?;
        validate_private_key_path(&private_key_path)?;
        validate_listen_port(listen_port)?;
        Ok(Self {
            interface_name,
            private_key_path: PathBuf::from(private_key_path),
            listen_port,
            tun_lifecycle,
            runtime: None,
        })
    }

    fn ensure_runtime_control(&self) -> Result<&RuntimeControl, BackendError> {
        self.runtime
            .as_ref()
            .map(RunningUserspaceRuntime::control)
            .ok_or_else(|| {
                BackendError::not_running("linux userspace-shared wireguard backend is not running")
            })
    }

    fn later_phase_unavailable(action: &str) -> BackendError {
        BackendError::internal(format!(
            "linux userspace-shared backend does not yet implement {action}; later production transport-owning phases remain open"
        ))
    }

    fn combine_cleanup_error(primary: BackendError, cleanup: BackendError) -> BackendError {
        BackendError::internal(format!(
            "{}; cleanup failed: {}",
            primary.message, cleanup.message
        ))
    }

    fn cleanup_tun_after_failed_start(&mut self, err: BackendError) -> BackendError {
        match self.tun_lifecycle.cleanup(&self.interface_name) {
            Ok(()) => err,
            Err(cleanup_err) => Self::combine_cleanup_error(err, cleanup_err),
        }
    }

    fn validate_peer(peer: &PeerConfig) -> Result<(), BackendError> {
        if peer.allowed_ips.is_empty() {
            return Err(BackendError::invalid_input(
                "peer allowed_ips must not be empty",
            ));
        }

        for cidr in &peer.allowed_ips {
            validate_cidr(cidr)?;
        }

        Ok(())
    }

    #[cfg(test)]
    fn worker_local_addr_for_test(&self) -> Result<Option<SocketAddr>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(None);
        };
        Ok(Some(runtime.control().worker_local_addr_for_test()?))
    }

    #[cfg(test)]
    fn worker_exit_count_for_test(&self) -> Option<usize> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.control().worker_exit_count_for_test())
    }

    #[cfg(test)]
    fn transport_generation_for_test(&self) -> Result<Option<u64>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(None);
        };
        Ok(Some(runtime.control().transport_generation_for_test()?))
    }

    #[cfg(test)]
    fn recorded_authoritative_transport_operations_for_test(
        &self,
    ) -> Result<Vec<runtime::RecordedAuthoritativeTransportOperation>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(Vec::new());
        };
        runtime
            .control()
            .recorded_authoritative_operations_for_test()
    }

    #[cfg(test)]
    fn recorded_peer_ciphertext_ingress_for_test(
        &self,
    ) -> Result<Vec<engine::RecordedPeerCiphertextIngress>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(Vec::new());
        };
        runtime
            .control()
            .recorded_peer_ciphertext_ingress_for_test()
    }

    #[cfg(test)]
    fn recorded_peer_ciphertext_egress_for_test(
        &self,
    ) -> Result<Vec<runtime::RecordedPeerCiphertextEgress>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(Vec::new());
        };
        runtime.control().recorded_peer_ciphertext_egress_for_test()
    }

    #[cfg(test)]
    fn inject_plaintext_packet_for_test(&self, packet: Vec<u8>) -> Result<(), BackendError> {
        let runtime = self.runtime.as_ref().ok_or_else(|| {
            BackendError::not_running("linux userspace-shared wireguard backend is not running")
        })?;
        runtime.control().inject_plaintext_packet_for_test(packet)
    }

    #[cfg(test)]
    fn recorded_tunnel_plaintext_packets_for_test(
        &self,
    ) -> Result<Vec<engine::RecordedTunnelPlaintextPacket>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(Vec::new());
        };
        runtime
            .control()
            .recorded_tunnel_plaintext_packets_for_test()
    }
}

impl TunnelBackend for LinuxUserspaceSharedBackend {
    fn name(&self) -> &'static str {
        LINUX_USERSPACE_SHARED_BACKEND_MODE
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: false,
            supports_lan_routes: false,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        if self.runtime.is_some() {
            return Err(BackendError::already_running(
                "linux userspace-shared wireguard backend already started",
            ));
        }

        let engine =
            UserspaceEngine::from_private_key_file(Path::new(self.private_key_path.as_path()))?;
        let tun_device = self
            .tun_lifecycle
            .prepare_and_open(&self.interface_name, &context)?;
        let socket = match AuthoritativeSocket::bind(self.listen_port) {
            Ok(socket) => socket,
            Err(err) => {
                drop(tun_device);
                return Err(self.cleanup_tun_after_failed_start(err));
            }
        };
        let runtime = match RunningUserspaceRuntime::start(
            &self.interface_name,
            context,
            tun_device,
            socket,
            engine,
        ) {
            Ok(runtime) => runtime,
            Err(err) => return Err(self.cleanup_tun_after_failed_start(err)),
        };
        self.runtime = Some(runtime);
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        Self::validate_peer(&peer)?;
        self.ensure_runtime_control()?.configure_peer(peer)
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        self.ensure_runtime_control()?
            .update_peer_endpoint(node_id.clone(), endpoint)
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.ensure_runtime_control()?
            .current_peer_endpoint(node_id.clone())
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        self.ensure_runtime_control()?
            .peer_latest_handshake_unix(node_id.clone())
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_runtime_control()?.remove_peer(node_id.clone())
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_runtime_control()?.apply_routes(routes)
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_runtime_control()?.set_exit_mode(mode)
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_runtime_control()?.stats()
    }

    fn authoritative_transport_identity(&self) -> Option<AuthoritativeTransportIdentity> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.control().authoritative_identity())
    }

    fn authoritative_transport_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        self.ensure_runtime_control()?
            .authoritative_transport_round_trip(remote_addr, payload.to_vec(), timeout)
    }

    fn authoritative_transport_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.ensure_runtime_control()?
            .authoritative_transport_send(remote_addr, payload.to_vec())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        let runtime = self.runtime.take().ok_or_else(|| {
            BackendError::not_running("linux userspace-shared wireguard backend is not running")
        })?;
        let runtime_result = runtime.shutdown();
        let cleanup_result = self.tun_lifecycle.cleanup(&self.interface_name);
        match (runtime_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(err)) => Err(err),
            (Err(err), Err(cleanup_err)) => Err(Self::combine_cleanup_error(err, cleanup_err)),
        }
    }
}

fn validate_cidr(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || !value.contains('/') {
        return Err(BackendError::invalid_input("invalid cidr value"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == ':' || ch == '/')
    {
        return Err(BackendError::invalid_input(
            "cidr contains invalid characters",
        ));
    }
    Ok(())
}

impl RuntimeControl {
    fn apply_routes(&self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.apply_routes_or_fail_closed(routes, || {
            LinuxUserspaceSharedBackend::later_phase_unavailable("route application")
        })
    }

    fn set_exit_mode(&self, mode: ExitMode) -> Result<(), BackendError> {
        self.set_exit_mode_or_fail_closed(mode, || {
            LinuxUserspaceSharedBackend::later_phase_unavailable("exit-mode programming")
        })
    }

    fn authoritative_transport_round_trip(
        &self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        self.authoritative_round_trip(remote_addr, payload, timeout)
    }

    fn authoritative_transport_send(
        &self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.authoritative_send(remote_addr, payload)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::prelude::*;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use rustynet_backend_api::{
        BackendErrorKind, NodeId, PeerConfig, RuntimeContext, SocketEndpoint, TunnelBackend,
    };

    use super::LinuxUserspaceSharedBackend;
    use super::tun::{TestTunBehavior, TestTunLifecycle};
    use crate::userspace_shared::runtime::RecordedAuthoritativeTransportOperationKind;

    fn runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("phase2-local").expect("valid node id"),
            interface_name: "rustynet0".to_string(),
            mesh_cidr: "100.64.0.0/10".to_string(),
            local_cidr: "100.64.0.1/32".to_string(),
        }
    }

    fn backend_with_test_tun_lifecycle(
        private_key_path: &Path,
        listen_port: u16,
        tun_lifecycle: TestTunLifecycle,
    ) -> LinuxUserspaceSharedBackend {
        LinuxUserspaceSharedBackend::new_with_tun_lifecycle(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
            Box::new(tun_lifecycle),
        )
        .expect("backend should construct")
    }

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rustynet-userspace-shared-{name}-{}-{nanos}.key",
            std::process::id()
        ))
    }

    fn write_private_key(bytes: [u8; 32]) -> PathBuf {
        let path = unique_path("valid");
        fs::write(&path, format!("{}\n", BASE64_STANDARD.encode(bytes)))
            .expect("private key should be written");
        path
    }

    fn write_invalid_private_key() -> PathBuf {
        let path = unique_path("invalid");
        fs::write(&path, "not-a-valid-wireguard-key\n").expect("invalid key should be written");
        path
    }

    fn free_listen_port() -> u16 {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .expect("ephemeral port should be available");
        socket.local_addr().expect("local addr").port()
    }

    fn backend_loopback_addr(listen_port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], listen_port))
    }

    fn sample_peer(name: &str, endpoint: SocketAddr) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: endpoint.ip(),
                port: endpoint.port(),
            },
            public_key: [31; 32],
            allowed_ips: vec!["100.64.1.0/24".to_string()],
        }
    }

    fn peer_public_key(private_key: [u8; 32]) -> [u8; 32] {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);
        *public_key.as_bytes()
    }

    fn peer_config(
        name: &str,
        endpoint: SocketAddr,
        public_key: [u8; 32],
        allowed_ips: Vec<&str>,
    ) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: endpoint.ip(),
                port: endpoint.port(),
            },
            public_key,
            allowed_ips: allowed_ips.into_iter().map(str::to_string).collect(),
        }
    }

    fn build_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + 8 + payload.len();
        let udp_len = 8 + payload.len();
        let mut packet = Vec::with_capacity(total_len);
        packet.extend_from_slice(&[
            0x45,
            0x00, // version/ihl, dscp/ecn
            ((total_len >> 8) & 0xff) as u8,
            (total_len & 0xff) as u8,
            0x00,
            0x01, // identification
            0x00,
            0x00, // flags/fragment
            64,   // ttl
            17,   // udp
            0x00,
            0x00, // checksum ignored by boringtun
        ]);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&[
            0x13,
            0x88, // src port 5000
            0x13,
            0x89, // dst port 5001
            ((udp_len >> 8) & 0xff) as u8,
            (udp_len & 0xff) as u8,
            0x00,
            0x00, // checksum ignored
        ]);
        packet.extend_from_slice(payload);
        packet
    }

    fn wait_for<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
        let start = std::time::Instant::now();
        loop {
            if let Some(value) = check() {
                return value;
            }
            if start.elapsed() >= timeout {
                panic!("condition was not satisfied within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn linux_userspace_shared_backend_identity_is_absent_before_start() {
        let private_key_path = write_private_key([7; 32]);
        let backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            free_listen_port(),
        )
        .expect("backend should construct");

        assert!(backend.authoritative_transport_identity().is_none());

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_reports_worker_owned_identity_after_start() {
        let private_key_path = write_private_key([9; 32]);
        let listen_port = free_listen_port();
        let expected_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
        let tun_lifecycle = TestTunLifecycle::new();
        let tun_state = tun_lifecycle.state();
        let mut backend =
            backend_with_test_tun_lifecycle(private_key_path.as_path(), listen_port, tun_lifecycle);

        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        let identity = backend
            .authoritative_transport_identity()
            .expect("identity should exist after start");
        assert_eq!(identity.local_addr, expected_addr);
        assert_eq!(
            backend
                .worker_local_addr_for_test()
                .expect("worker local addr query should succeed"),
            Some(expected_addr)
        );
        assert_eq!(
            tun_state.snapshot(),
            super::tun::TunTestSnapshot {
                prepare_calls: 1,
                cleanup_calls: 0,
                live_handles: 1,
                last_interface_name: Some("rustynet0".to_string()),
                last_local_cidr: Some("100.64.0.1/32".to_string()),
                last_cleanup_interface_name: None,
            }
        );

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_start_failure_before_tun_open_leaves_socket_unbound() {
        let private_key_path = write_invalid_private_key();
        let listen_port = free_listen_port();
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");

        let err = backend
            .start(runtime_context())
            .expect_err("invalid private key should fail after socket bind");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(backend.authoritative_transport_identity().is_none());
        assert!(backend.worker_exit_count_for_test().is_none());

        let rebound = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
            .expect("listen port should have been released after startup rollback");
        drop(rebound);

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_tun_setup_failure_is_fail_closed_without_worker_or_identity()
    {
        let private_key_path = write_private_key([10; 32]);
        let listen_port = free_listen_port();
        let tun_lifecycle = TestTunLifecycle::with_behavior(TestTunBehavior::FailBeforeOpen(
            "linux userspace-shared test TUN setup failed".to_string(),
        ));
        let tun_state = tun_lifecycle.state();
        let mut backend =
            backend_with_test_tun_lifecycle(private_key_path.as_path(), listen_port, tun_lifecycle);

        let err = backend
            .start(runtime_context())
            .expect_err("TUN setup failure should fail closed");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(
            err.message
                .contains("linux userspace-shared test TUN setup failed")
        );
        assert!(backend.authoritative_transport_identity().is_none());
        assert!(backend.worker_exit_count_for_test().is_none());
        assert_eq!(
            tun_state.snapshot(),
            super::tun::TunTestSnapshot {
                prepare_calls: 1,
                cleanup_calls: 0,
                live_handles: 0,
                last_interface_name: Some("rustynet0".to_string()),
                last_local_cidr: Some("100.64.0.1/32".to_string()),
                last_cleanup_interface_name: None,
            }
        );

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_socket_bind_failure_cleans_up_tun_without_downgrade() {
        let private_key_path = write_private_key([12; 32]);
        let listen_port = free_listen_port();
        let reserved = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
            .expect("listen port should be reservable for bind failure");
        let tun_lifecycle = TestTunLifecycle::new();
        let tun_state = tun_lifecycle.state();
        let mut backend =
            backend_with_test_tun_lifecycle(private_key_path.as_path(), listen_port, tun_lifecycle);

        let err = backend
            .start(runtime_context())
            .expect_err("socket bind failure should fail closed");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(backend.authoritative_transport_identity().is_none());
        assert!(backend.worker_exit_count_for_test().is_none());
        assert_eq!(
            tun_state.snapshot(),
            super::tun::TunTestSnapshot {
                prepare_calls: 1,
                cleanup_calls: 1,
                live_handles: 0,
                last_interface_name: Some("rustynet0".to_string()),
                last_local_cidr: Some("100.64.0.1/32".to_string()),
                last_cleanup_interface_name: Some("rustynet0".to_string()),
            }
        );
        assert!(
            backend.transport_socket_identity_blocker().is_none(),
            "userspace-shared backend must not silently downgrade to the command-only blocker"
        );

        drop(reserved);
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_shutdown_clears_identity() {
        let private_key_path = write_private_key([11; 32]);
        let listen_port = free_listen_port();
        let tun_lifecycle = TestTunLifecycle::new();
        let tun_state = tun_lifecycle.state();
        let mut backend =
            backend_with_test_tun_lifecycle(private_key_path.as_path(), listen_port, tun_lifecycle);

        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend.shutdown().expect("shutdown should succeed");

        assert!(backend.authoritative_transport_identity().is_none());
        assert_eq!(
            tun_state.snapshot(),
            super::tun::TunTestSnapshot {
                prepare_calls: 1,
                cleanup_calls: 1,
                live_handles: 0,
                last_interface_name: Some("rustynet0".to_string()),
                last_local_cidr: Some("100.64.0.1/32".to_string()),
                last_cleanup_interface_name: Some("rustynet0".to_string()),
            }
        );
        let rebound = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
            .expect("listen port should be released after shutdown");
        drop(rebound);

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_round_trip_fails_closed_before_start() {
        let private_key_path = write_private_key([13; 32]);
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            free_listen_port(),
        )
        .expect("backend should construct");

        let err = backend
            .authoritative_transport_round_trip(
                "127.0.0.1:40001".parse().expect("socket addr should parse"),
                b"stun",
                Duration::from_millis(50),
            )
            .expect_err("round trip before start should fail");
        assert_eq!(err.kind, BackendErrorKind::NotRunning);

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_round_trip_fails_closed_after_shutdown() {
        let private_key_path = write_private_key([14; 32]);
        let listen_port = free_listen_port();
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend.shutdown().expect("shutdown should succeed");

        let err = backend
            .authoritative_transport_round_trip(
                backend_loopback_addr(listen_port),
                b"stun",
                Duration::from_millis(50),
            )
            .expect_err("round trip after shutdown should fail");
        assert_eq!(err.kind, BackendErrorKind::NotRunning);

        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_round_trip_rejects_configured_peer_endpoint() {
        let private_key_path = write_private_key([15; 32]);
        let listen_port = free_listen_port();
        let peer_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("peer socket should bind");
        let peer_addr = peer_socket.local_addr().expect("peer addr should resolve");
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(sample_peer("peer-a", peer_addr))
            .expect("peer should configure");

        let err = backend
            .authoritative_transport_round_trip(peer_addr, b"control", Duration::from_millis(100))
            .expect_err("configured peer endpoint must be rejected");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert!(err.message.contains("matches a configured peer endpoint"));

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_second_concurrent_round_trip_is_rejected() {
        let private_key_path = write_private_key([16; 32]);
        let listen_port = free_listen_port();
        let remote_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("remote socket should bind");
        let remote_addr = remote_socket
            .local_addr()
            .expect("remote addr should resolve");
        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let responder = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (len, source) = remote_socket
                .recv_from(&mut buf)
                .expect("first round-trip request should arrive");
            request_seen_tx
                .send(())
                .expect("request signal should be sent");
            thread::sleep(Duration::from_millis(150));
            remote_socket
                .send_to(&buf[..len], source)
                .expect("response should be sent");
        });

        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        let control = backend
            .runtime
            .as_ref()
            .expect("runtime should exist")
            .control()
            .clone();
        let first_control = control.clone();
        let first_round_trip = thread::spawn(move || {
            first_control.authoritative_round_trip(
                remote_addr,
                b"first".to_vec(),
                Duration::from_secs(1),
            )
        });

        request_seen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first round-trip request should be observed");

        let err = control
            .authoritative_round_trip(remote_addr, b"second".to_vec(), Duration::from_secs(1))
            .expect_err("second concurrent round trip should be rejected");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(err.message.contains("already in flight"));

        let response = first_round_trip
            .join()
            .expect("first round-trip thread should join")
            .expect("first round trip should succeed");
        assert_eq!(response.remote_addr, remote_addr);
        assert_eq!(
            response.local_addr,
            SocketAddr::from(([0, 0, 0, 0], listen_port))
        );

        responder.join().expect("responder should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_stun_round_trip_uses_same_transport_generation_as_peer_path()
    {
        let private_key_path = write_private_key([17; 32]);
        let listen_port = free_listen_port();
        let authoritative_addr = backend_loopback_addr(listen_port);
        let peer_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("peer socket should bind");
        let peer_addr = peer_socket.local_addr().expect("peer addr should resolve");
        let stun_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("stun socket should bind");
        let stun_addr = stun_socket.local_addr().expect("stun addr should resolve");
        let stun_responder = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = stun_socket
                .recv_from(&mut buf)
                .expect("stun request should arrive");
            stun_socket
                .send_to(b"stun-response", source)
                .expect("stun response should be sent");
        });

        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(sample_peer("peer-a", peer_addr))
            .expect("peer should configure");

        let generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");
        peer_socket
            .send_to(b"peer-ciphertext", authoritative_addr)
            .expect("peer ciphertext should be sent");
        let peer_ingress = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress query should succeed");
            (records.len() == 1).then_some(records)
        });

        let response = backend
            .authoritative_transport_round_trip(stun_addr, b"stun-request", Duration::from_secs(1))
            .expect("stun round trip should succeed");
        let operations = backend
            .recorded_authoritative_transport_operations_for_test()
            .expect("authoritative operations should be queryable");

        assert_eq!(response.remote_addr, stun_addr);
        assert_eq!(
            response.local_addr,
            SocketAddr::from(([0, 0, 0, 0], listen_port))
        );
        assert_eq!(response.payload, b"stun-response");
        assert_eq!(peer_ingress[0].remote_addr, peer_addr);
        assert_eq!(
            peer_ingress[0].local_addr,
            SocketAddr::from(([0, 0, 0, 0], listen_port))
        );
        assert_eq!(peer_ingress[0].transport_generation, generation);
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].remote_addr, stun_addr);
        assert_eq!(
            operations[0].local_addr,
            SocketAddr::from(([0, 0, 0, 0], listen_port))
        );
        assert_eq!(operations[0].transport_generation, generation);

        stun_responder.join().expect("stun responder should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_relay_round_trip_and_send_use_same_transport_generation_as_peer_path()
     {
        let private_key_path = write_private_key([18; 32]);
        let listen_port = free_listen_port();
        let authoritative_addr = backend_loopback_addr(listen_port);
        let peer_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("peer socket should bind");
        let peer_addr = peer_socket.local_addr().expect("peer addr should resolve");
        let relay_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("relay socket should bind");
        let relay_addr = relay_socket
            .local_addr()
            .expect("relay addr should resolve");
        let (keepalive_tx, keepalive_rx) = mpsc::channel();
        let relay_worker = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = relay_socket
                .recv_from(&mut buf)
                .expect("relay hello should arrive");
            relay_socket
                .send_to(b"relay-ack", source)
                .expect("relay ack should be sent");
            let (len, source) = relay_socket
                .recv_from(&mut buf)
                .expect("relay keepalive should arrive");
            keepalive_tx
                .send((buf[..len].to_vec(), source))
                .expect("keepalive should be recorded");
        });

        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(sample_peer("peer-a", peer_addr))
            .expect("peer should configure");

        let generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");
        peer_socket
            .send_to(b"peer-ciphertext", authoritative_addr)
            .expect("peer ciphertext should be sent");
        let _ = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress query should succeed");
            (records.len() == 1).then_some(records)
        });

        let response = backend
            .authoritative_transport_round_trip(relay_addr, b"relay-hello", Duration::from_secs(1))
            .expect("relay round trip should succeed");
        let identity = backend
            .authoritative_transport_send(relay_addr, b"relay-keepalive")
            .expect("relay keepalive send should succeed");
        let operations = backend
            .recorded_authoritative_transport_operations_for_test()
            .expect("authoritative operations should be queryable");
        let (keepalive_payload, observed_source) = keepalive_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("keepalive should be observed");

        assert_eq!(response.payload, b"relay-ack");
        assert_eq!(
            identity.local_addr,
            SocketAddr::from(([0, 0, 0, 0], listen_port))
        );
        assert_eq!(keepalive_payload, b"relay-keepalive");
        assert_eq!(observed_source.port(), listen_port);
        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].transport_generation, generation);
        assert_eq!(
            operations[1].kind,
            RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(operations[1].transport_generation, generation);

        relay_worker.join().expect("relay worker should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_multi_peer_simulated_proof_uses_one_generation_for_peer_stun_and_relay_paths()
     {
        let left_private_key = [36; 32];
        let right_private_key = [37; 32];
        let left_private_key_path = write_private_key(left_private_key);
        let right_private_key_path = write_private_key(right_private_key);
        let left_port = free_listen_port();
        let right_port = free_listen_port();
        let left_identity_addr = SocketAddr::from(([0, 0, 0, 0], left_port));
        let stun_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("stun socket should bind");
        let stun_addr = stun_socket.local_addr().expect("stun addr should resolve");
        let stun_worker = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = stun_socket
                .recv_from(&mut buf)
                .expect("stun request should arrive");
            stun_socket
                .send_to(b"stun-proof-response", source)
                .expect("stun response should be sent");
        });
        let relay_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("relay socket should bind");
        let relay_addr = relay_socket
            .local_addr()
            .expect("relay addr should resolve");
        let (keepalive_tx, keepalive_rx) = mpsc::channel();
        let relay_worker = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = relay_socket
                .recv_from(&mut buf)
                .expect("relay hello should arrive");
            relay_socket
                .send_to(b"relay-proof-ack", source)
                .expect("relay ack should be sent");
            let (len, source) = relay_socket
                .recv_from(&mut buf)
                .expect("relay keepalive should arrive");
            keepalive_tx
                .send((buf[..len].to_vec(), source))
                .expect("keepalive should be recorded");
        });

        let mut left_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            left_private_key_path.to_string_lossy(),
            left_port,
        )
        .expect("left backend should construct");
        let mut right_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet1",
            right_private_key_path.to_string_lossy(),
            right_port,
        )
        .expect("right backend should construct");
        left_backend
            .start(runtime_context())
            .expect("left backend should start");
        right_backend
            .start(RuntimeContext {
                local_node: NodeId::new("phase6-right").expect("valid node id"),
                interface_name: "rustynet1".to_string(),
                mesh_cidr: "100.64.0.0/10".to_string(),
                local_cidr: "100.64.1.1/32".to_string(),
            })
            .expect("right backend should start");

        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed");
        right_backend
            .configure_peer(peer_config(
                "peer-left",
                backend_loopback_addr(left_port),
                peer_public_key(left_private_key),
                vec!["100.64.1.0/24"],
            ))
            .expect("right peer configure should succeed");

        let left_generation = left_backend
            .transport_generation_for_test()
            .expect("left generation query should succeed")
            .expect("left generation should exist");
        let right_generation = right_backend
            .transport_generation_for_test()
            .expect("right generation query should succeed")
            .expect("right generation should exist");
        assert_ne!(left_generation, right_generation);

        left_backend
            .inject_plaintext_packet_for_test(build_ipv4_udp_packet(
                Ipv4Addr::new(100, 64, 1, 10),
                Ipv4Addr::new(100, 64, 2, 20),
                b"phase6-simulated-proof",
            ))
            .expect("plaintext injection should succeed");

        let left_peer_egress = wait_for(Duration::from_secs(2), || {
            let records = left_backend
                .recorded_peer_ciphertext_egress_for_test()
                .expect("left peer egress query should succeed");
            (!records.is_empty()).then_some(records)
        });
        let right_plaintext_packets = wait_for(Duration::from_secs(2), || {
            let packets = right_backend
                .recorded_tunnel_plaintext_packets_for_test()
                .expect("right tunnel packet query should succeed");
            (!packets.is_empty()).then_some(packets)
        });

        let stun_response = left_backend
            .authoritative_transport_round_trip(
                stun_addr,
                b"stun-proof-request",
                Duration::from_secs(1),
            )
            .expect("stun round trip should succeed");
        let relay_response = left_backend
            .authoritative_transport_round_trip(
                relay_addr,
                b"relay-proof-hello",
                Duration::from_secs(1),
            )
            .expect("relay round trip should succeed");
        let relay_identity = left_backend
            .authoritative_transport_send(relay_addr, b"relay-proof-keepalive")
            .expect("relay keepalive send should succeed");
        let authoritative_operations = left_backend
            .recorded_authoritative_transport_operations_for_test()
            .expect("authoritative operations should be queryable");
        let (keepalive_payload, keepalive_source) = keepalive_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("relay keepalive should be observed");

        assert_eq!(stun_response.payload, b"stun-proof-response");
        assert_eq!(relay_response.payload, b"relay-proof-ack");
        assert_eq!(relay_identity.local_addr, left_identity_addr);
        assert_eq!(keepalive_payload, b"relay-proof-keepalive");
        assert_eq!(keepalive_source.port(), left_identity_addr.port());
        assert!(left_peer_egress.iter().all(|record| record.remote_addr
            == backend_loopback_addr(right_port)
            && record.local_addr == left_identity_addr
            && record.transport_generation == left_generation));
        assert!(
            right_plaintext_packets
                .iter()
                .all(|packet| packet.transport_generation == right_generation)
        );
        assert_eq!(authoritative_operations.len(), 3);
        assert_eq!(
            authoritative_operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(authoritative_operations[0].remote_addr, stun_addr);
        assert_eq!(
            authoritative_operations[1].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(authoritative_operations[1].remote_addr, relay_addr);
        assert_eq!(
            authoritative_operations[2].kind,
            RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(authoritative_operations[2].remote_addr, relay_addr);
        assert!(
            authoritative_operations
                .iter()
                .all(|record| record.local_addr == left_identity_addr
                    && record.transport_generation == left_generation)
        );

        let path_generations = left_peer_egress
            .iter()
            .map(|record| record.transport_generation)
            .chain(
                authoritative_operations
                    .iter()
                    .map(|record| record.transport_generation),
            )
            .collect::<BTreeSet<_>>();
        let path_local_addrs = left_peer_egress
            .iter()
            .map(|record| record.local_addr)
            .chain(
                authoritative_operations
                    .iter()
                    .map(|record| record.local_addr),
            )
            .collect::<BTreeSet<_>>();

        assert_eq!(
            path_generations,
            BTreeSet::from([left_generation]),
            "peer ciphertext, STUN, and relay control must all traverse the same authoritative transport generation"
        );
        assert_eq!(
            path_local_addrs,
            BTreeSet::from([left_identity_addr]),
            "the simulated proof must not rely on any second authority socket in the left backend path"
        );

        stun_worker.join().expect("stun worker should join");
        relay_worker.join().expect("relay worker should join");
        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        right_backend
            .shutdown()
            .expect("right shutdown should succeed");
        let _ = fs::remove_file(left_private_key_path);
        let _ = fs::remove_file(right_private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_same_local_port_after_restart_gets_new_transport_generation()
    {
        let private_key_path = write_private_key([19; 32]);
        let listen_port = free_listen_port();
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");

        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        let first_identity = backend
            .authoritative_transport_identity()
            .expect("identity should exist after start");
        let first_generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");
        backend.shutdown().expect("shutdown should succeed");

        backend
            .start(runtime_context())
            .expect("backend should restart successfully");
        let second_identity = backend
            .authoritative_transport_identity()
            .expect("identity should exist after restart");
        let second_generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");

        assert_eq!(first_identity.local_addr, second_identity.local_addr);
        assert_ne!(first_generation, second_generation);

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_programmed_state_does_not_update_handshake_without_engine_activity()
     {
        let local_private_key = write_private_key([21; 32]);
        let listen_port = free_listen_port();
        let initial_endpoint = SocketAddr::from(([127, 0, 0, 1], free_listen_port()));
        let updated_endpoint = SocketAddr::from(([127, 0, 0, 1], free_listen_port()));
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            local_private_key.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        backend
            .configure_peer(peer_config(
                "peer-a",
                initial_endpoint,
                peer_public_key([22; 32]),
                vec!["100.64.2.0/24"],
            ))
            .expect("peer should configure");
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("current endpoint query should succeed"),
            Some(SocketEndpoint {
                addr: initial_endpoint.ip(),
                port: initial_endpoint.port(),
            })
        );
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );

        backend
            .update_peer_endpoint(
                &peer_node,
                SocketEndpoint {
                    addr: updated_endpoint.ip(),
                    port: updated_endpoint.port(),
                },
            )
            .expect("endpoint update should succeed");
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("current endpoint query should succeed"),
            Some(SocketEndpoint {
                addr: updated_endpoint.ip(),
                port: updated_endpoint.port(),
            })
        );
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );

        let stats = backend.stats().expect("stats should succeed");
        assert_eq!(stats.peer_count, 1);
        assert_eq!(stats.bytes_tx, 0);
        assert_eq!(stats.bytes_rx, 0);
        assert!(!stats.using_relay_path);

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(local_private_key);
    }

    #[test]
    fn linux_userspace_shared_backend_update_unconfigured_peer_fails_closed() {
        let local_private_key = write_private_key([23; 32]);
        let listen_port = free_listen_port();
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            local_private_key.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        let err = backend
            .update_peer_endpoint(
                &NodeId::new("missing-peer").expect("valid node id"),
                SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: free_listen_port(),
                },
            )
            .expect_err("updating an unconfigured peer must fail");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(local_private_key);
    }

    #[test]
    fn linux_userspace_shared_backend_duplicate_configure_replaces_peer_state_without_duplication()
    {
        let local_private_key = write_private_key([24; 32]);
        let listen_port = free_listen_port();
        let first_endpoint = SocketAddr::from(([127, 0, 0, 1], free_listen_port()));
        let second_endpoint = SocketAddr::from(([127, 0, 0, 1], free_listen_port()));
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            local_private_key.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        backend
            .configure_peer(peer_config(
                "peer-a",
                first_endpoint,
                peer_public_key([25; 32]),
                vec!["100.64.2.0/24"],
            ))
            .expect("initial peer configure should succeed");
        backend
            .configure_peer(peer_config(
                "peer-a",
                second_endpoint,
                peer_public_key([25; 32]),
                vec!["100.64.2.0/24"],
            ))
            .expect("duplicate peer configure should safely replace");

        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("current endpoint query should succeed"),
            Some(SocketEndpoint {
                addr: second_endpoint.ip(),
                port: second_endpoint.port(),
            })
        );
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );
        assert_eq!(backend.stats().expect("stats should succeed").peer_count, 1);

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(local_private_key);
    }

    #[test]
    fn linux_userspace_shared_backend_authenticated_engine_activity_updates_handshake_and_stats() {
        let left_private_key = [26; 32];
        let right_private_key = [27; 32];
        let left_private_key_path = write_private_key(left_private_key);
        let right_private_key_path = write_private_key(right_private_key);
        let left_port = free_listen_port();
        let right_port = free_listen_port();
        let left_peer_node = NodeId::new("peer-right").expect("valid node id");
        let right_peer_node = NodeId::new("peer-left").expect("valid node id");
        let mut left_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            left_private_key_path.to_string_lossy(),
            left_port,
        )
        .expect("left backend should construct");
        let mut right_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet1",
            right_private_key_path.to_string_lossy(),
            right_port,
        )
        .expect("right backend should construct");
        left_backend
            .start(runtime_context())
            .expect("left backend should start");
        right_backend
            .start(runtime_context())
            .expect("right backend should start");

        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed");
        right_backend
            .configure_peer(peer_config(
                "peer-left",
                backend_loopback_addr(left_port),
                peer_public_key(left_private_key),
                vec!["100.64.1.0/24"],
            ))
            .expect("right peer configure should succeed");

        assert_eq!(
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("left handshake query should succeed"),
            None
        );
        assert_eq!(
            right_backend
                .peer_latest_handshake_unix(&right_peer_node)
                .expect("right handshake query should succeed"),
            None
        );

        let plaintext_packet = build_ipv4_udp_packet(
            Ipv4Addr::new(100, 64, 1, 10),
            Ipv4Addr::new(100, 64, 2, 20),
            b"phase4-engine-payload",
        );
        left_backend
            .inject_plaintext_packet_for_test(plaintext_packet.clone())
            .expect("plaintext injection should succeed");

        let delivered_packets = wait_for(Duration::from_secs(2), || {
            let packets = right_backend
                .recorded_tunnel_plaintext_packets_for_test()
                .expect("tunnel packet query should succeed");
            (packets.len() == 1).then_some(packets)
        });
        let left_handshake = wait_for(Duration::from_secs(2), || {
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("left handshake query should succeed")
        });
        let right_handshake = wait_for(Duration::from_secs(2), || {
            right_backend
                .peer_latest_handshake_unix(&right_peer_node)
                .expect("right handshake query should succeed")
        });

        assert_eq!(delivered_packets[0].node_id, right_peer_node);
        assert_eq!(delivered_packets[0].packet, plaintext_packet);
        assert!(left_handshake > 0);
        assert!(right_handshake > 0);

        let left_stats = left_backend.stats().expect("left stats should succeed");
        let right_stats = right_backend.stats().expect("right stats should succeed");
        assert_eq!(left_stats.peer_count, 1);
        assert_eq!(right_stats.peer_count, 1);
        assert!(left_stats.bytes_tx >= plaintext_packet.len() as u64);
        assert!(right_stats.bytes_rx >= plaintext_packet.len() as u64);
        assert!(!left_stats.using_relay_path);
        assert!(!right_stats.using_relay_path);

        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        right_backend
            .shutdown()
            .expect("right shutdown should succeed");
        let _ = fs::remove_file(left_private_key_path);
        let _ = fs::remove_file(right_private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_stun_round_trip_does_not_advance_peer_handshake() {
        let local_private_key = write_private_key([28; 32]);
        let listen_port = free_listen_port();
        let stun_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("stun socket should bind");
        let stun_addr = stun_socket.local_addr().expect("stun addr should resolve");
        let responder = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = stun_socket
                .recv_from(&mut buf)
                .expect("stun request should arrive");
            stun_socket
                .send_to(b"stun-ok", source)
                .expect("stun response should be sent");
        });
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            local_private_key.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(peer_config(
                "peer-a",
                SocketAddr::from(([127, 0, 0, 1], free_listen_port())),
                peer_public_key([29; 32]),
                vec!["100.64.2.0/24"],
            ))
            .expect("peer configure should succeed");

        let response = backend
            .authoritative_transport_round_trip(stun_addr, b"stun-probe", Duration::from_secs(1))
            .expect("stun round trip should succeed");
        assert_eq!(response.payload, b"stun-ok");
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );

        responder.join().expect("stun responder should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(local_private_key);
    }

    #[test]
    fn linux_userspace_shared_backend_relay_control_does_not_advance_peer_handshake() {
        let local_private_key = write_private_key([30; 32]);
        let listen_port = free_listen_port();
        let relay_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("relay socket should bind");
        let relay_addr = relay_socket
            .local_addr()
            .expect("relay addr should resolve");
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            local_private_key.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(peer_config(
                "peer-a",
                SocketAddr::from(([127, 0, 0, 1], free_listen_port())),
                peer_public_key([31; 32]),
                vec!["100.64.2.0/24"],
            ))
            .expect("peer configure should succeed");

        let _identity = backend
            .authoritative_transport_send(relay_addr, b"relay-keepalive")
            .expect("relay keepalive send should succeed");
        let mut buf = [0u8; 1024];
        let (len, _source) = relay_socket
            .recv_from(&mut buf)
            .expect("relay keepalive should arrive");
        assert_eq!(&buf[..len], b"relay-keepalive");
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );

        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(local_private_key);
    }

    #[test]
    fn linux_userspace_shared_backend_peer_removal_clears_handshake_telemetry() {
        let left_private_key = [32; 32];
        let right_private_key = [33; 32];
        let left_private_key_path = write_private_key(left_private_key);
        let right_private_key_path = write_private_key(right_private_key);
        let left_port = free_listen_port();
        let right_port = free_listen_port();
        let left_peer_node = NodeId::new("peer-right").expect("valid node id");
        let mut left_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            left_private_key_path.to_string_lossy(),
            left_port,
        )
        .expect("left backend should construct");
        let mut right_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet1",
            right_private_key_path.to_string_lossy(),
            right_port,
        )
        .expect("right backend should construct");
        left_backend
            .start(runtime_context())
            .expect("left backend should start");
        right_backend
            .start(runtime_context())
            .expect("right backend should start");

        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed");
        right_backend
            .configure_peer(peer_config(
                "peer-left",
                backend_loopback_addr(left_port),
                peer_public_key(left_private_key),
                vec!["100.64.1.0/24"],
            ))
            .expect("right peer configure should succeed");
        left_backend
            .inject_plaintext_packet_for_test(build_ipv4_udp_packet(
                Ipv4Addr::new(100, 64, 1, 10),
                Ipv4Addr::new(100, 64, 2, 20),
                b"peer-removal",
            ))
            .expect("plaintext injection should succeed");
        let _ = wait_for(Duration::from_secs(2), || {
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("left handshake query should succeed")
        });

        left_backend
            .remove_peer(&left_peer_node)
            .expect("peer removal should succeed");
        assert_eq!(
            left_backend
                .current_peer_endpoint(&left_peer_node)
                .expect("current endpoint query should succeed"),
            None
        );
        let err = left_backend
            .peer_latest_handshake_unix(&left_peer_node)
            .expect_err("removed peer handshake query should fail");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("peer reconfigure should succeed");
        assert_eq!(
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("reconfigured peer handshake query should succeed"),
            None
        );

        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        right_backend
            .shutdown()
            .expect("right shutdown should succeed");
        let _ = fs::remove_file(left_private_key_path);
        let _ = fs::remove_file(right_private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_restart_does_not_preserve_handshake_freshness() {
        let left_private_key = [34; 32];
        let right_private_key = [35; 32];
        let left_private_key_path = write_private_key(left_private_key);
        let right_private_key_path = write_private_key(right_private_key);
        let left_port = free_listen_port();
        let right_port = free_listen_port();
        let left_peer_node = NodeId::new("peer-right").expect("valid node id");
        let mut left_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            left_private_key_path.to_string_lossy(),
            left_port,
        )
        .expect("left backend should construct");
        let mut right_backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet1",
            right_private_key_path.to_string_lossy(),
            right_port,
        )
        .expect("right backend should construct");
        left_backend
            .start(runtime_context())
            .expect("left backend should start");
        right_backend
            .start(runtime_context())
            .expect("right backend should start");

        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed");
        right_backend
            .configure_peer(peer_config(
                "peer-left",
                backend_loopback_addr(left_port),
                peer_public_key(left_private_key),
                vec!["100.64.1.0/24"],
            ))
            .expect("right peer configure should succeed");
        left_backend
            .inject_plaintext_packet_for_test(build_ipv4_udp_packet(
                Ipv4Addr::new(100, 64, 1, 10),
                Ipv4Addr::new(100, 64, 2, 20),
                b"restart-handshake",
            ))
            .expect("plaintext injection should succeed");
        let _ = wait_for(Duration::from_secs(2), || {
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("left handshake query should succeed")
        });

        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        left_backend
            .start(runtime_context())
            .expect("left backend should restart");
        left_backend
            .configure_peer(peer_config(
                "peer-right",
                backend_loopback_addr(right_port),
                peer_public_key(right_private_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed after restart");
        assert_eq!(
            left_backend
                .peer_latest_handshake_unix(&left_peer_node)
                .expect("left handshake query should succeed"),
            None
        );

        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        right_backend
            .shutdown()
            .expect("right shutdown should succeed");
        let _ = fs::remove_file(left_private_key_path);
        let _ = fs::remove_file(right_private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_restart_cancels_stale_round_trip_and_same_port_new_socket_does_not_reuse_it()
     {
        let private_key_path = write_private_key([38; 32]);
        let listen_port = free_listen_port();
        let stale_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("stale remote socket should bind");
        let stale_addr = stale_socket
            .local_addr()
            .expect("stale remote addr should resolve");
        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (send_late_tx, send_late_rx) = mpsc::channel();
        let stale_worker = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = stale_socket
                .recv_from(&mut buf)
                .expect("initial stale round-trip request should arrive");
            request_seen_tx
                .send(source)
                .expect("stale request signal should be sent");
            send_late_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("late-send signal should arrive");
            stale_socket
                .send_to(b"late-after-rollover", source)
                .expect("late response should be sent");
        });
        let prompt_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("prompt remote socket should bind");
        let prompt_addr = prompt_socket
            .local_addr()
            .expect("prompt remote addr should resolve");
        let prompt_worker = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = prompt_socket
                .recv_from(&mut buf)
                .expect("prompt request should arrive");
            prompt_socket
                .send_to(b"prompt-after-rollover", source)
                .expect("prompt response should be sent");
        });

        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        let first_identity = backend
            .authoritative_transport_identity()
            .expect("identity should exist after start");
        let first_generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");

        let control = backend
            .runtime
            .as_ref()
            .expect("runtime should exist")
            .control()
            .clone();
        let first_round_trip = thread::spawn(move || {
            control.authoritative_round_trip(
                stale_addr,
                b"first-before-rollover".to_vec(),
                Duration::from_secs(2),
            )
        });

        request_seen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("initial stale request should be observed");

        backend.shutdown().expect("shutdown should succeed");
        let canceled_err = first_round_trip
            .join()
            .expect("first round-trip thread should join")
            .expect_err("stale round trip should be canceled during shutdown");
        assert_eq!(canceled_err.kind, BackendErrorKind::Internal);
        assert!(
            canceled_err
                .message
                .contains("canceled during backend shutdown")
        );

        backend
            .start(runtime_context())
            .expect("backend should restart successfully");
        let second_identity = backend
            .authoritative_transport_identity()
            .expect("identity should exist after restart");
        let second_generation = backend
            .transport_generation_for_test()
            .expect("generation query should succeed")
            .expect("generation should exist");
        assert_eq!(first_identity.local_addr, second_identity.local_addr);
        assert_ne!(first_generation, second_generation);

        send_late_tx
            .send(())
            .expect("late-send signal should be delivered");
        stale_worker.join().expect("stale worker should join");

        let stale_ingress = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress query should succeed");
            (records.iter().any(|record| {
                record.remote_addr == stale_addr
                    && record.payload == b"late-after-rollover"
                    && record.transport_generation == second_generation
            }))
            .then_some(records)
        });
        assert!(
            stale_ingress.iter().any(|record| {
                record.remote_addr == stale_addr
                    && record.payload == b"late-after-rollover"
                    && record.transport_generation == second_generation
            }),
            "late packet from the old socket generation must not satisfy the stale waiter"
        );

        let prompt_response = backend
            .authoritative_transport_round_trip(
                prompt_addr,
                b"prompt-after-rollover",
                Duration::from_secs(1),
            )
            .expect("new round trip should succeed after rollover");
        assert_eq!(prompt_response.payload, b"prompt-after-rollover");

        prompt_worker.join().expect("prompt worker should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }

    #[test]
    fn linux_userspace_shared_backend_timeout_clears_waiter_and_late_packet_becomes_peer_input() {
        let private_key_path = write_private_key([20; 32]);
        let listen_port = free_listen_port();
        let remote_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("slow remote socket should bind");
        let remote_addr = remote_socket
            .local_addr()
            .expect("slow remote addr should resolve");
        let slow_responder = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = remote_socket
                .recv_from(&mut buf)
                .expect("slow round-trip request should arrive");
            thread::sleep(Duration::from_millis(150));
            remote_socket
                .send_to(b"late-response", source)
                .expect("late response should be sent");
        });
        let prompt_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("prompt remote socket should bind");
        let prompt_addr = prompt_socket
            .local_addr()
            .expect("prompt remote addr should resolve");
        let prompt_responder = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_len, source) = prompt_socket
                .recv_from(&mut buf)
                .expect("prompt round-trip request should arrive");
            prompt_socket
                .send_to(b"prompt-response", source)
                .expect("prompt response should be sent");
        });

        let mut backend = LinuxUserspaceSharedBackend::new_for_test(
            "rustynet0",
            private_key_path.to_string_lossy(),
            listen_port,
        )
        .expect("backend should construct");
        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        let err = backend
            .authoritative_transport_round_trip(
                remote_addr,
                b"will-timeout",
                Duration::from_millis(50),
            )
            .expect_err("slow round trip should time out");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(err.message.contains("timed out"));

        slow_responder.join().expect("slow responder should join");
        let peer_ingress = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress query should succeed");
            (records
                .iter()
                .any(|record| record.remote_addr == remote_addr))
            .then_some(records)
        });
        assert!(
            peer_ingress
                .iter()
                .any(|record| record.remote_addr == remote_addr
                    && record.payload == b"late-response")
        );

        let response = backend
            .authoritative_transport_round_trip(
                prompt_addr,
                b"prompt-request",
                Duration::from_secs(1),
            )
            .expect("next round trip should succeed after timeout cleanup");
        assert_eq!(response.payload, b"prompt-response");

        prompt_responder
            .join()
            .expect("prompt responder should join");
        backend.shutdown().expect("shutdown should succeed");
        let _ = fs::remove_file(private_key_path);
    }
}
