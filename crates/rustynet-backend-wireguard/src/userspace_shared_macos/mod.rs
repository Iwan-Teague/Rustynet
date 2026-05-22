use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendCapabilities,
    BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint,
    TunnelBackend, TunnelStats,
};

mod runtime;
mod socket;
mod tun;

use crate::linux_command::{
    validate_interface_name, validate_listen_port, validate_private_key_path,
};
use crate::userspace_shared::engine::UserspaceEngine;
use runtime::{RunningUserspaceRuntime, RuntimeControl};
use socket::AuthoritativeSocket;
use tun::{DirectMacosTunLifecycle, MacosTunLifecycle, SharedMacosTunLifecycle};

pub(crate) const MACOS_USERSPACE_SHARED_BACKEND_MODE: &str = "macos-wireguard-userspace-shared";

/// macOS boringtun userspace `WireGuard` backend with shared transport ownership.
///
/// Declares shared-transport support by not overriding
/// `transport_socket_identity_blocker()` (the default returns `None`), signaling
/// that this backend owns its authoritative peer-traffic UDP socket so that
/// STUN and relay control can run on the same transport identity as peer traffic.
pub struct MacosUserspaceSharedBackend {
    interface_name: String,
    private_key_path: PathBuf,
    listen_port: u16,
    tun_lifecycle: SharedMacosTunLifecycle,
    runtime: Option<RunningUserspaceRuntime>,
    runtime_context: Option<RuntimeContext>,
    desired_peers: BTreeMap<NodeId, PeerConfig>,
    desired_routes: Vec<Route>,
    desired_exit_mode: ExitMode,
    cleanup_pending: bool,
    #[cfg(any(test, feature = "test-harness"))]
    test_tun_state: Option<tun::MacosTunTestState>,
    #[cfg(any(test, feature = "test-harness"))]
    bind_loopback_for_test: bool,
}

impl MacosUserspaceSharedBackend {
    pub fn new(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        Self::new_with_tun_lifecycle(
            interface_name,
            private_key_path,
            listen_port,
            Box::<DirectMacosTunLifecycle>::default(),
            false,
        )
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn new_for_test(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        let lifecycle = tun::TestMacosTunLifecycle::new();
        let state = lifecycle.state();
        let mut backend = Self::new_with_tun_lifecycle(
            interface_name,
            private_key_path,
            listen_port,
            Box::new(lifecycle),
            true,
        )?;
        backend.test_tun_state = Some(state);
        Ok(backend)
    }

    fn new_with_tun_lifecycle(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
        tun_lifecycle: Box<dyn MacosTunLifecycle>,
        #[cfg_attr(not(any(test, feature = "test-harness")), allow(unused_variables))]
        bind_loopback_for_test: bool,
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
            tun_lifecycle: SharedMacosTunLifecycle::new(tun_lifecycle),
            runtime: None,
            runtime_context: None,
            desired_peers: BTreeMap::new(),
            desired_routes: Vec::new(),
            desired_exit_mode: ExitMode::Off,
            cleanup_pending: false,
            #[cfg(any(test, feature = "test-harness"))]
            test_tun_state: None,
            #[cfg(any(test, feature = "test-harness"))]
            bind_loopback_for_test,
        })
    }

    fn ensure_runtime_control(&self) -> Result<&RuntimeControl, BackendError> {
        self.runtime
            .as_ref()
            .map(RunningUserspaceRuntime::control)
            .ok_or_else(|| {
                BackendError::not_running("macos userspace-shared wireguard backend is not running")
            })
    }

    fn is_runtime_worker_unavailable(err: &BackendError) -> bool {
        err.kind == rustynet_backend_api::BackendErrorKind::Internal
            && matches!(
                err.message.as_str(),
                "macos userspace-shared runtime worker is unavailable"
                    | "macos userspace-shared runtime worker dropped a reply"
            )
    }

    fn bind_authoritative_socket(&self) -> Result<AuthoritativeSocket, BackendError> {
        #[cfg(any(test, feature = "test-harness"))]
        if self.bind_loopback_for_test {
            return AuthoritativeSocket::bind_loopback_for_test();
        }
        AuthoritativeSocket::bind(self.listen_port)
    }

    fn start_runtime(
        &mut self,
        context: RuntimeContext,
    ) -> Result<RunningUserspaceRuntime, BackendError> {
        let engine =
            UserspaceEngine::from_private_key_file(Path::new(self.private_key_path.as_path()))?;
        let tun_device = self
            .tun_lifecycle
            .prepare_and_open(&self.interface_name, &context)?;
        let socket = match self.bind_authoritative_socket() {
            Ok(socket) => socket,
            Err(err) => {
                drop(tun_device);
                return Err(self.cleanup_tun_after_failed_start(err));
            }
        };
        match RunningUserspaceRuntime::start(
            &self.interface_name,
            context,
            tun_device,
            socket,
            engine,
            self.tun_lifecycle.clone(),
        ) {
            Ok(runtime) => Ok(runtime),
            Err(err) => Err(self.cleanup_tun_after_failed_start(err)),
        }
    }

    fn recover_runtime_after_worker_exit(&mut self) -> Result<(), BackendError> {
        let context = self.runtime_context.clone().ok_or_else(|| {
            BackendError::not_running("macos userspace-shared wireguard backend is not running")
        })?;
        let previous_runtime = self.runtime.take().ok_or_else(|| {
            BackendError::not_running("macos userspace-shared wireguard backend is not running")
        })?;

        if let Err(err) = previous_runtime.shutdown()
            && !Self::is_runtime_worker_unavailable(&err)
        {
            let err = BackendError::internal(format!(
                "macos userspace-shared runtime recovery failed while shutting down stale runtime: {err}"
            ));
            return Err(self.combine_with_runtime_loss_cleanup(err));
        }

        self.cleanup_tun_after_runtime_loss()?;
        let runtime = self.start_runtime(context.clone()).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared runtime recovery failed while starting replacement runtime: {err}"
            ))
        })?;
        self.runtime = Some(runtime);
        self.runtime_context = Some(context);

        let replay_result = (|| -> Result<(), BackendError> {
            for peer in self.desired_peers.values().cloned() {
                self.ensure_runtime_control()?.configure_peer(peer)?;
            }
            if !self.desired_routes.is_empty() {
                self.ensure_runtime_control()?
                    .apply_routes(self.desired_routes.clone())?;
            }
            if self.desired_exit_mode != ExitMode::Off {
                self.ensure_runtime_control()?
                    .set_exit_mode(self.desired_exit_mode)?;
            }
            Ok(())
        })();

        if let Err(err) = replay_result {
            if let Some(runtime) = self.runtime.take()
                && let Err(shutdown_err) = runtime.shutdown()
            {
                return Err(self.combine_with_runtime_loss_cleanup(BackendError::internal(
                    format!(
                        "macos userspace-shared runtime recovery failed while replaying desired state: {err}; replacement shutdown failed: {shutdown_err}"
                    ),
                )));
            }
            let err = BackendError::internal(format!(
                "macos userspace-shared runtime recovery failed while replaying desired state: {err}"
            ));
            return Err(self.combine_with_runtime_loss_cleanup(err));
        }

        Ok(())
    }

    fn with_runtime_recovery<T>(
        &mut self,
        operation: impl Fn(&RuntimeControl) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let first_result = {
            let control = self.ensure_runtime_control()?;
            operation(control)
        };
        match first_result {
            Ok(value) => Ok(value),
            Err(err) if Self::is_runtime_worker_unavailable(&err) => {
                self.recover_runtime_after_worker_exit()?;
                let control = self.ensure_runtime_control()?;
                operation(control)
            }
            Err(err) => Err(err),
        }
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
            Err(cleanup_err) => {
                self.cleanup_pending = true;
                Self::combine_cleanup_error(err, cleanup_err)
            }
        }
    }

    fn cleanup_tun_after_runtime_loss(&mut self) -> Result<(), BackendError> {
        match self.tun_lifecycle.cleanup(&self.interface_name) {
            Ok(()) => {
                self.cleanup_pending = false;
                Ok(())
            }
            Err(err) => {
                self.cleanup_pending = true;
                Err(err)
            }
        }
    }

    fn combine_with_runtime_loss_cleanup(&mut self, primary: BackendError) -> BackendError {
        match self.cleanup_tun_after_runtime_loss() {
            Ok(()) => primary,
            Err(cleanup_err) => Self::combine_cleanup_error(primary, cleanup_err),
        }
    }

    fn clear_stopped_state_after_cleanup(&mut self) {
        self.runtime_context = None;
        self.desired_peers.clear();
        self.desired_routes.clear();
        self.desired_exit_mode = ExitMode::Off;
        self.cleanup_pending = false;
    }

    fn validate_peer(peer: &PeerConfig) -> Result<(), BackendError> {
        if peer.allowed_ips.is_empty() {
            return Err(BackendError::invalid_input(
                "peer allowed_ips must not be empty",
            ));
        }
        runtime::validate_macos_userspace_endpoint(peer.endpoint)?;

        for cidr in &peer.allowed_ips {
            validate_cidr(cidr)?;
        }

        Ok(())
    }

    fn validate_endpoint(endpoint: SocketEndpoint) -> Result<(), BackendError> {
        runtime::validate_macos_userspace_endpoint(endpoint)
    }

    fn validate_runtime_context(&self, context: &RuntimeContext) -> Result<(), BackendError> {
        if context.interface_name != self.interface_name {
            return Err(BackendError::invalid_input(format!(
                "macos userspace-shared runtime context interface mismatch: backend interface is {}, context interface is {}",
                self.interface_name, context.interface_name
            )));
        }
        validate_cidr(&context.mesh_cidr)?;
        validate_ipv4_local_cidr(&context.local_cidr)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn set_next_tun_recv_error_for_test(
        &self,
        message: impl Into<String>,
    ) -> Result<(), BackendError> {
        let Some(state) = self.test_tun_state.as_ref() else {
            return Err(BackendError::invalid_input(
                "macos userspace-shared test TUN state is unavailable",
            ));
        };
        state.set_next_recv_error(message);
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn set_route_add_failure_for_test(
        &self,
        cidr: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<(), BackendError> {
        let Some(state) = self.test_tun_state.as_ref() else {
            return Err(BackendError::invalid_input(
                "macos userspace-shared test TUN state is unavailable",
            ));
        };
        state.set_route_behavior(tun::MacosTestRouteBehavior::FailOnAdd {
            cidr: cidr.into(),
            message: message.into(),
        });
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn clear_route_failure_for_test(&self) -> Result<(), BackendError> {
        let Some(state) = self.test_tun_state.as_ref() else {
            return Err(BackendError::invalid_input(
                "macos userspace-shared test TUN state is unavailable",
            ));
        };
        state.set_route_behavior(tun::MacosTestRouteBehavior::Succeed);
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn set_full_tunnel_failure_for_test(
        &self,
        message: impl Into<String>,
    ) -> Result<(), BackendError> {
        let Some(state) = self.test_tun_state.as_ref() else {
            return Err(BackendError::invalid_input(
                "macos userspace-shared test TUN state is unavailable",
            ));
        };
        state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnFullTunnel {
            message: message.into(),
        });
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    #[doc(hidden)]
    pub fn clear_exit_mode_failure_for_test(&self) -> Result<(), BackendError> {
        let Some(state) = self.test_tun_state.as_ref() else {
            return Err(BackendError::invalid_input(
                "macos userspace-shared test TUN state is unavailable",
            ));
        };
        state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
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
    fn transport_generation_for_test(&self) -> Result<Option<u64>, BackendError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(None);
        };
        Ok(Some(runtime.control().transport_generation_for_test()?))
    }

    #[cfg(test)]
    fn worker_exit_count_for_test(&self) -> Option<usize> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.control().worker_exit_count_for_test())
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
    ) -> Result<Vec<crate::userspace_shared::engine::RecordedPeerCiphertextIngress>, BackendError>
    {
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
}

impl TunnelBackend for MacosUserspaceSharedBackend {
    fn name(&self) -> &'static str {
        MACOS_USERSPACE_SHARED_BACKEND_MODE
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: true,
            supports_exit_client: true,
            supports_exit_serving: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        self.validate_runtime_context(&context)?;
        if self.runtime.is_some() {
            return Err(BackendError::already_running(
                "macos userspace-shared wireguard backend already started",
            ));
        }
        if self.cleanup_pending {
            self.tun_lifecycle.cleanup(&self.interface_name)?;
            self.clear_stopped_state_after_cleanup();
        }
        self.runtime_context = Some(context.clone());
        self.desired_peers.clear();
        self.desired_routes.clear();
        self.desired_exit_mode = ExitMode::Off;
        let runtime = match self.start_runtime(context) {
            Ok(runtime) => runtime,
            Err(err) => {
                self.runtime_context = None;
                return Err(err);
            }
        };
        self.runtime = Some(runtime);
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        Self::validate_peer(&peer)?;
        let node_id = peer.node_id.clone();
        self.with_runtime_recovery(|control| control.configure_peer(peer.clone()))?;
        self.desired_peers.insert(node_id, peer);
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        Self::validate_endpoint(endpoint)?;
        let mut updated_peer = self
            .desired_peers
            .get(node_id)
            .cloned()
            .ok_or_else(|| BackendError::invalid_input("peer is not configured"))?;
        self.with_runtime_recovery(|control| {
            control.update_peer_endpoint(node_id.clone(), endpoint)
        })?;
        updated_peer.endpoint = endpoint;
        self.desired_peers.insert(node_id.clone(), updated_peer);
        Ok(())
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
        self.with_runtime_recovery(|control| control.peer_latest_handshake_unix(node_id.clone()))
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        if !self.desired_peers.contains_key(node_id) {
            return Err(BackendError::invalid_input("peer is not configured"));
        }
        self.with_runtime_recovery(|control| control.remove_peer(node_id.clone()))?;
        self.desired_peers.remove(node_id);
        Ok(())
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.with_runtime_recovery(|control| control.apply_routes(routes.clone()))?;
        self.desired_routes = routes;
        Ok(())
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.with_runtime_recovery(|control| control.set_exit_mode(mode))?;
        self.desired_exit_mode = mode;
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_runtime_control()?.stats()
    }

    fn initiate_peer_handshake(
        &mut self,
        node_id: &NodeId,
        force_resend: bool,
    ) -> Result<(), BackendError> {
        self.with_runtime_recovery(|control| {
            control.initiate_peer_handshake(node_id.clone(), force_resend)
        })
    }

    fn authoritative_transport_identity(&self) -> Option<AuthoritativeTransportIdentity> {
        self.runtime
            .as_ref()
            .filter(|runtime| runtime.control().is_worker_alive())
            .map(|runtime| runtime.control().authoritative_identity())
    }

    fn authoritative_transport_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        let payload = payload.to_vec();
        self.with_runtime_recovery(|control| {
            control.authoritative_transport_round_trip(remote_addr, payload.clone(), timeout)
        })
    }

    fn authoritative_transport_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        let payload = payload.to_vec();
        self.with_runtime_recovery(|control| {
            control.authoritative_transport_send(remote_addr, payload.clone())
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        let runtime_result = match self.runtime.take() {
            Some(runtime) => runtime.shutdown(),
            None if self.cleanup_pending => Ok(()),
            None => {
                return Err(BackendError::not_running(
                    "macos userspace-shared wireguard backend is not running",
                ));
            }
        };
        let cleanup_result = self.tun_lifecycle.cleanup(&self.interface_name);
        match (runtime_result, cleanup_result) {
            (Ok(()), Ok(())) => {
                self.clear_stopped_state_after_cleanup();
                Ok(())
            }
            (Err(err), Ok(())) => {
                self.clear_stopped_state_after_cleanup();
                Err(err)
            }
            (Ok(()), Err(err)) => {
                self.cleanup_pending = true;
                Err(err)
            }
            (Err(err), Err(cleanup_err)) => {
                self.cleanup_pending = true;
                Err(Self::combine_cleanup_error(err, cleanup_err))
            }
        }
    }
}

impl RuntimeControl {
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

fn validate_cidr(value: &str) -> Result<(), BackendError> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
    if address.is_empty() || prefix_len.is_empty() || prefix_len.contains('/') {
        return Err(BackendError::invalid_input("invalid cidr value"));
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| BackendError::invalid_input("invalid cidr address"))?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| BackendError::invalid_input("invalid cidr prefix"))?;
    match address {
        IpAddr::V4(_) if prefix_len <= 32 => Ok(()),
        IpAddr::V4(_) => Err(BackendError::invalid_input("invalid ipv4 prefix")),
        IpAddr::V6(_) if prefix_len <= 128 => Ok(()),
        IpAddr::V6(_) => Err(BackendError::invalid_input("invalid ipv6 prefix")),
    }
}

fn validate_ipv4_local_cidr(value: &str) -> Result<(), BackendError> {
    let (address, prefix_len) = value.split_once('/').ok_or_else(|| {
        BackendError::invalid_input(
            "macos userspace-shared local cidr must contain an address and prefix length",
        )
    })?;
    let _address = address.parse::<Ipv4Addr>().map_err(|_| {
        BackendError::invalid_input(
            "macos userspace-shared backend currently requires an IPv4 local cidr",
        )
    })?;
    let prefix_len = prefix_len.parse::<u8>().map_err(|_| {
        BackendError::invalid_input(
            "macos userspace-shared local cidr prefix length must be numeric",
        )
    })?;
    if prefix_len > 32 {
        return Err(BackendError::invalid_input(
            "macos userspace-shared local cidr prefix length must be <= 32",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use base64::prelude::*;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use rustynet_backend_api::RouteKind;

    use crate::userspace_shared::engine::{ConfigurePeerDisposition, UserspaceEngine};
    use crate::userspace_shared::handshake::HandshakeTelemetry;

    #[test]
    fn macos_userspace_shared_backend_name_matches_mode_constant() {
        let backend = MacosUserspaceSharedBackend::new("utun9", "/tmp/key.pem", 51820)
            .expect("construction should succeed");
        assert_eq!(backend.name(), MACOS_USERSPACE_SHARED_BACKEND_MODE);
    }

    #[test]
    fn macos_userspace_shared_backend_transport_socket_identity_blocker_returns_none() {
        let backend = MacosUserspaceSharedBackend::new("utun9", "/tmp/key.pem", 51820)
            .expect("construction should succeed");
        // Shared-socket intent: no blocker, so STUN/relay can use this backend's socket.
        assert!(backend.transport_socket_identity_blocker().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_reports_worker_owned_identity_after_start() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend =
            MacosUserspaceSharedBackend::new_for_test("utun9", temp_path(&private_key_path), 51820)
                .expect("construction should succeed");
        assert!(backend.authoritative_transport_identity().is_none());

        backend
            .start(runtime_context("utun9"))
            .expect("backend should start");
        let identity = backend
            .authoritative_transport_identity()
            .expect("identity should be present while running");
        assert_eq!(identity.label, socket::AUTHORITATIVE_TRANSPORT_LABEL);
        assert_ne!(identity.local_addr.port(), 0);

        backend.shutdown().expect("shutdown should succeed");
        assert!(backend.authoritative_transport_identity().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_authoritative_round_trip_uses_runtime_socket() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun10",
            temp_path(&private_key_path),
            51821,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun10"))
            .expect("backend should start");
        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("remote timeout");
        let remote_addr = remote.local_addr().expect("remote addr");
        let responder = thread::spawn(move || {
            let mut buffer = [0u8; 128];
            let (len, worker_addr) = remote.recv_from(&mut buffer).expect("request");
            assert_eq!(&buffer[..len], b"stun-request");
            remote
                .send_to(b"stun-response", worker_addr)
                .expect("reply");
            worker_addr
        });

        let response = backend
            .authoritative_transport_round_trip(
                remote_addr,
                b"stun-request",
                Duration::from_secs(1),
            )
            .expect("round trip should complete");
        let observed_worker_addr = responder.join().expect("responder should join");
        assert_eq!(response.local_addr, observed_worker_addr);
        assert_eq!(response.remote_addr, remote_addr);
        assert_eq!(response.payload, b"stun-response");

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_authoritative_send_uses_runtime_socket() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun12",
            temp_path(&private_key_path),
            51823,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun12"))
            .expect("backend should start");
        let generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");
        let worker_local_addr = backend
            .worker_local_addr_for_test()
            .expect("worker local addr should resolve")
            .expect("worker local addr should exist");
        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("remote timeout");

        let identity = backend
            .authoritative_transport_send(
                remote.local_addr().expect("remote addr"),
                b"relay-keepalive",
            )
            .expect("authoritative send should succeed");
        let mut buffer = [0u8; 128];
        let (len, worker_addr) = remote.recv_from(&mut buffer).expect("remote recv");

        assert_eq!(&buffer[..len], b"relay-keepalive");
        assert_eq!(identity.label, socket::AUTHORITATIVE_TRANSPORT_LABEL);
        assert_eq!(identity.local_addr, worker_addr);
        assert_eq!(worker_local_addr, worker_addr);
        let operations = backend
            .recorded_authoritative_transport_operations_for_test()
            .expect("operation records should resolve");
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].kind,
            runtime::RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(operations[0].transport_generation, generation);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_relay_round_trip_and_send_use_same_generation_as_peer_path() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun31",
            temp_path(&private_key_path),
            51841,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun31"))
            .expect("backend should start");
        let worker_addr = backend
            .worker_local_addr_for_test()
            .expect("worker addr should resolve")
            .expect("worker addr should exist");
        let peer_socket = UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_socket.local_addr().expect("peer addr");
        backend
            .configure_peer(sample_peer("peer-a", peer_addr))
            .expect("peer should configure");
        let relay_socket = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        let relay_addr = relay_socket.local_addr().expect("relay addr");
        let relay_worker = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (_len, source) = relay_socket
                .recv_from(&mut buffer)
                .expect("relay hello should arrive");
            relay_socket
                .send_to(b"relay-ack", source)
                .expect("relay ack should send");
            let (len, source) = relay_socket
                .recv_from(&mut buffer)
                .expect("relay keepalive should arrive");
            (buffer[..len].to_vec(), source)
        });

        let generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");
        peer_socket
            .send_to(b"peer-ciphertext", worker_addr)
            .expect("peer ciphertext should send");
        let peer_ingress = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress should resolve");
            (records.len() == 1).then_some(records)
        });

        let response = backend
            .authoritative_transport_round_trip(relay_addr, b"relay-hello", Duration::from_secs(1))
            .expect("relay round trip should succeed");
        let identity = backend
            .authoritative_transport_send(relay_addr, b"relay-keepalive")
            .expect("relay keepalive should send");
        let operations = backend
            .recorded_authoritative_transport_operations_for_test()
            .expect("operations should resolve");
        let (keepalive_payload, keepalive_source) =
            relay_worker.join().expect("relay worker should join");

        assert_eq!(response.payload, b"relay-ack");
        assert_eq!(identity.local_addr, worker_addr);
        assert_eq!(keepalive_payload, b"relay-keepalive");
        assert_eq!(keepalive_source, worker_addr);
        assert_eq!(peer_ingress[0].transport_generation, generation);
        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations[0].kind,
            runtime::RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].transport_generation, generation);
        assert_eq!(
            operations[1].kind,
            runtime::RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(operations[1].transport_generation, generation);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_relay_control_does_not_advance_peer_handshake() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun32",
            temp_path(&private_key_path),
            51842,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun32"))
            .expect("backend should start");
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        backend
            .configure_peer(sample_peer(
                "peer-a",
                SocketAddr::from(([127, 0, 0, 1], 41009)),
            ))
            .expect("peer should configure");
        let relay_socket = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        let relay_addr = relay_socket.local_addr().expect("relay addr");

        backend
            .authoritative_transport_send(relay_addr, b"relay-keepalive")
            .expect("relay keepalive should send");
        let mut buffer = [0u8; 1024];
        let (len, _source) = relay_socket
            .recv_from(&mut buffer)
            .expect("relay keepalive should arrive");

        assert_eq!(&buffer[..len], b"relay-keepalive");
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake query should succeed"),
            None
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_round_trip_fails_closed_before_start() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun13",
            temp_path(&private_key_path),
            51824,
        )
        .expect("construction should succeed");
        let err = backend
            .authoritative_transport_round_trip(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                b"probe",
                Duration::from_millis(10),
            )
            .expect_err("round trip before start should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::NotRunning);
    }

    #[test]
    fn macos_userspace_shared_backend_round_trip_fails_closed_after_shutdown() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun14",
            temp_path(&private_key_path),
            51825,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun14"))
            .expect("backend should start");
        backend.shutdown().expect("shutdown should succeed");

        let err = backend
            .authoritative_transport_round_trip(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                b"probe",
                Duration::from_millis(10),
            )
            .expect_err("round trip after shutdown should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::NotRunning);
    }

    #[test]
    fn macos_userspace_shared_backend_round_trip_rejects_configured_peer_endpoint() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun15",
            temp_path(&private_key_path),
            51826,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun15"))
            .expect("backend should start");
        let peer_endpoint = SocketAddr::from(([127, 0, 0, 1], 51820));
        let peer = sample_peer("peer-a", peer_endpoint);
        backend
            .configure_peer(peer)
            .expect("peer configure should succeed");

        let err = backend
            .authoritative_transport_round_trip(
                peer_endpoint,
                b"stun-request",
                Duration::from_millis(10),
            )
            .expect_err("round trip to peer endpoint should be rejected");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("configured peer endpoint"));
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_authoritative_send_rejects_configured_peer_endpoint() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun45",
            temp_path(&private_key_path),
            51855,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun45"))
            .expect("backend should start");
        let peer_endpoint = SocketAddr::from(([127, 0, 0, 1], 51820));
        backend
            .configure_peer(sample_peer("peer-a", peer_endpoint))
            .expect("peer configure should succeed");

        let err = backend
            .authoritative_transport_send(peer_endpoint, b"relay-keepalive")
            .expect_err("send to peer endpoint should be rejected");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("configured peer endpoint"));
        assert!(
            backend
                .recorded_authoritative_transport_operations_for_test()
                .expect("operation records should resolve")
                .is_empty()
        );
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_restart_gets_new_transport_generation() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun16",
            temp_path(&private_key_path),
            51827,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun16"))
            .expect("backend should start");
        let first_generation = backend
            .transport_generation_for_test()
            .expect("first generation should resolve")
            .expect("first generation should exist");
        backend.shutdown().expect("shutdown should succeed");

        backend
            .start(runtime_context("utun16"))
            .expect("backend should restart");
        let second_generation = backend
            .transport_generation_for_test()
            .expect("second generation should resolve")
            .expect("second generation should exist");

        assert_ne!(first_generation, second_generation);
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_update_unconfigured_peer_fails_closed() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun17",
            temp_path(&private_key_path),
            51828,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun17"))
            .expect("backend should start");

        let err = backend
            .update_peer_endpoint(
                &NodeId::new("missing-peer").expect("valid node id"),
                SocketEndpoint {
                    addr: "127.0.0.1".parse().expect("valid ip"),
                    port: 51820,
                },
            )
            .expect_err("unconfigured peer update should fail");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_malformed_allowed_ips_without_state_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun35",
            temp_path(&private_key_path),
            51845,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun35"))
            .expect("backend should start");

        for bad in [
            "999.64.1.0/24",
            "100.64.1.0/33",
            "fd00::/129",
            "100.64.1.0/24/extra",
            "100.64.1.0/24;rm -rf /",
            "100.64.1.0/24\n",
            "",
            "no-slash",
        ] {
            let err = backend
                .configure_peer(peer_config_with_key(
                    "peer-a",
                    SocketAddr::from(([127, 0, 0, 1], 41010)),
                    peer_public_key([8; 32]),
                    vec![bad],
                ))
                .expect_err("malformed allowed_ips should fail closed");
            assert_eq!(
                err.kind,
                rustynet_backend_api::BackendErrorKind::InvalidInput
            );
            assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
        }

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_context_interface_mismatch_before_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun38", &private_key_path, 51848);

        let err = backend
            .start(runtime_context("utun39"))
            .expect_err("mismatched runtime context interface should fail closed");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("runtime context interface mismatch"));
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.prepare_calls, 0);
        assert_eq!(snapshot.cleanup_calls, 0);
        assert_eq!(snapshot.live_handles, 0);
        assert!(backend.authoritative_transport_identity().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_invalid_mesh_cidr_before_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun42", &private_key_path, 51852);
        let mut context = runtime_context("utun42");
        context.mesh_cidr = "100.64.0.0/99".to_owned();

        let err = backend
            .start(context)
            .expect_err("invalid mesh cidr should fail closed before start");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("invalid ipv4 prefix"));
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.prepare_calls, 0);
        assert_eq!(snapshot.cleanup_calls, 0);
        assert_eq!(snapshot.live_handles, 0);
        assert!(backend.authoritative_transport_identity().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_ipv6_local_cidr_before_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun43", &private_key_path, 51853);
        let mut context = runtime_context("utun43");
        context.local_cidr = "fd00::1/128".to_owned();

        let err = backend
            .start(context)
            .expect_err("ipv6 local cidr should fail closed before start");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("requires an IPv4 local cidr"));
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.prepare_calls, 0);
        assert_eq!(snapshot.cleanup_calls, 0);
        assert_eq!(snapshot.live_handles, 0);
        assert!(backend.authoritative_transport_identity().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_invalid_peer_endpoint_without_state_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, _tun_state) =
            backend_with_test_lifecycle("utun40", &private_key_path, 51850);
        backend
            .start(runtime_context("utun40"))
            .expect("backend should start");

        for (endpoint, expected) in [
            (
                SocketEndpoint {
                    addr: "127.0.0.1".parse().expect("valid ip"),
                    port: 0,
                },
                "port must be non-zero",
            ),
            (
                SocketEndpoint {
                    addr: "0.0.0.0".parse().expect("valid ip"),
                    port: 41010,
                },
                "must not be unspecified",
            ),
            (
                SocketEndpoint {
                    addr: "2001:db8::1".parse().expect("valid ip"),
                    port: 41010,
                },
                "requires IPv4",
            ),
            (
                SocketEndpoint {
                    addr: "224.0.0.1".parse().expect("valid ip"),
                    port: 41010,
                },
                "must not be multicast",
            ),
            (
                SocketEndpoint {
                    addr: "255.255.255.255".parse().expect("valid ip"),
                    port: 41010,
                },
                "must not be broadcast",
            ),
        ] {
            let err = backend
                .configure_peer(peer_config_with_key(
                    "peer-a",
                    SocketAddr::new(endpoint.addr, endpoint.port),
                    peer_public_key([8; 32]),
                    vec!["100.64.1.0/24"],
                ))
                .expect_err("invalid endpoint should fail closed");
            assert_eq!(
                err.kind,
                rustynet_backend_api::BackendErrorKind::InvalidInput
            );
            assert!(err.message.contains(expected));
            assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
        }

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_invalid_endpoint_update_without_state_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, _tun_state) =
            backend_with_test_lifecycle("utun41", &private_key_path, 51851);
        backend
            .start(runtime_context("utun41"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41011)));
        let peer_node = peer.node_id.clone();
        let original_endpoint = peer.endpoint;
        backend
            .configure_peer(peer)
            .expect("initial peer configure should succeed");

        let err = backend
            .update_peer_endpoint(
                &peer_node,
                SocketEndpoint {
                    addr: "127.0.0.1".parse().expect("valid ip"),
                    port: 0,
                },
            )
            .expect_err("invalid endpoint update should fail closed");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("port must be non-zero"));
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("endpoint should resolve"),
            Some(original_endpoint)
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_rejects_ipv6_endpoint_update_without_state_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, _tun_state) =
            backend_with_test_lifecycle("utun44", &private_key_path, 51854);
        backend
            .start(runtime_context("utun44"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41011)));
        let peer_node = peer.node_id.clone();
        let original_endpoint = peer.endpoint;
        backend
            .configure_peer(peer)
            .expect("initial peer configure should succeed");

        let err = backend
            .update_peer_endpoint(
                &peer_node,
                SocketEndpoint {
                    addr: "2001:db8::1".parse().expect("valid ip"),
                    port: 41011,
                },
            )
            .expect_err("ipv6 endpoint update should fail closed");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("requires IPv4"));
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("endpoint should resolve"),
            Some(original_endpoint)
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_duplicate_configure_replaces_peer_without_duplication() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun18",
            temp_path(&private_key_path),
            51829,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun18"))
            .expect("backend should start");
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let first_endpoint = SocketAddr::from(([127, 0, 0, 1], 41001));
        let second_endpoint = SocketAddr::from(([127, 0, 0, 1], 41002));

        backend
            .configure_peer(sample_peer("peer-a", first_endpoint))
            .expect("first peer configure should succeed");
        backend
            .configure_peer(sample_peer("peer-a", second_endpoint))
            .expect("duplicate peer configure should replace");

        assert_eq!(
            backend
                .current_peer_endpoint(&peer_node)
                .expect("endpoint should resolve"),
            Some(SocketEndpoint {
                addr: second_endpoint.ip(),
                port: second_endpoint.port(),
            })
        );
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 1);
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake should resolve"),
            None
        );
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_programmed_state_does_not_update_handshake_without_engine_activity()
     {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun19",
            temp_path(&private_key_path),
            51830,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun19"))
            .expect("backend should start");
        let peer_node = NodeId::new("peer-a").expect("valid node id");
        let initial_endpoint = SocketAddr::from(([127, 0, 0, 1], 41003));
        let updated_endpoint = SocketAddr::from(([127, 0, 0, 1], 41004));

        backend
            .configure_peer(sample_peer("peer-a", initial_endpoint))
            .expect("peer configure should succeed");
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake should resolve"),
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
                .expect("endpoint should resolve"),
            Some(SocketEndpoint {
                addr: updated_endpoint.ip(),
                port: updated_endpoint.port(),
            })
        );
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer_node)
                .expect("handshake should resolve"),
            None
        );
        let stats = backend.stats().expect("stats should resolve");
        assert_eq!(stats.peer_count, 1);
        assert_eq!(stats.bytes_tx, 0);
        assert_eq!(stats.bytes_rx, 0);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_initiate_peer_handshake_uses_authoritative_socket() {
        let left_key = [28; 32];
        let right_key = [29; 32];
        let left_private_key_path = write_private_key(left_key);
        let right_private_key_path = write_private_key(right_key);
        let mut left_backend = MacosUserspaceSharedBackend::new_for_test(
            "utun33",
            temp_path(&left_private_key_path),
            51843,
        )
        .expect("left construction should succeed");
        let mut right_backend = MacosUserspaceSharedBackend::new_for_test(
            "utun34",
            temp_path(&right_private_key_path),
            51844,
        )
        .expect("right construction should succeed");
        left_backend
            .start(runtime_context("utun33"))
            .expect("left backend should start");
        right_backend
            .start(runtime_context("utun34"))
            .expect("right backend should start");
        let left_addr = left_backend
            .worker_local_addr_for_test()
            .expect("left worker addr should resolve")
            .expect("left worker addr should exist");
        let right_addr = right_backend
            .worker_local_addr_for_test()
            .expect("right worker addr should resolve")
            .expect("right worker addr should exist");
        let left_peer_node = NodeId::new("peer-right").expect("valid node id");
        let right_peer_node = NodeId::new("peer-left").expect("valid node id");

        left_backend
            .configure_peer(peer_config_with_key(
                "peer-right",
                right_addr,
                peer_public_key(right_key),
                vec!["100.64.2.0/24"],
            ))
            .expect("left peer configure should succeed");
        right_backend
            .configure_peer(peer_config_with_key(
                "peer-left",
                left_addr,
                peer_public_key(left_key),
                vec!["100.64.1.0/24"],
            ))
            .expect("right peer configure should succeed");
        let left_generation = left_backend
            .transport_generation_for_test()
            .expect("left generation should resolve")
            .expect("left generation should exist");
        let right_generation = right_backend
            .transport_generation_for_test()
            .expect("right generation should resolve")
            .expect("right generation should exist");

        left_backend
            .initiate_peer_handshake(&left_peer_node, false)
            .expect("left handshake initiation should succeed");

        let left_egress = wait_for(Duration::from_secs(2), || {
            let records = left_backend
                .recorded_peer_ciphertext_egress_for_test()
                .expect("left egress should resolve");
            (!records.is_empty()).then_some(records)
        });
        let right_ingress = wait_for(Duration::from_secs(2), || {
            let records = right_backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("right ingress should resolve");
            (!records.is_empty()).then_some(records)
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

        assert_eq!(left_egress[0].local_addr, left_addr);
        assert_eq!(left_egress[0].remote_addr, right_addr);
        assert_eq!(left_egress[0].transport_generation, left_generation);
        assert_eq!(right_ingress[0].local_addr, right_addr);
        assert_eq!(right_ingress[0].remote_addr, left_addr);
        assert_eq!(right_ingress[0].transport_generation, right_generation);
        assert!(left_handshake > 0);
        assert!(right_handshake > 0);

        left_backend
            .shutdown()
            .expect("left shutdown should succeed");
        right_backend
            .shutdown()
            .expect("right shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_timeout_clears_waiter_and_late_packet_becomes_peer_input() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun21",
            temp_path(&private_key_path),
            51831,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun21"))
            .expect("backend should start");
        let remote_socket = UdpSocket::bind("127.0.0.1:0").expect("slow remote bind");
        let remote_addr = remote_socket.local_addr().expect("slow remote addr");
        let slow_responder = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (_len, source) = remote_socket
                .recv_from(&mut buffer)
                .expect("slow request should arrive");
            thread::sleep(Duration::from_millis(150));
            remote_socket
                .send_to(b"late-response", source)
                .expect("late response should send");
        });
        let prompt_socket = UdpSocket::bind("127.0.0.1:0").expect("prompt remote bind");
        let prompt_addr = prompt_socket.local_addr().expect("prompt remote addr");
        let prompt_responder = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (_len, source) = prompt_socket
                .recv_from(&mut buffer)
                .expect("prompt request should arrive");
            prompt_socket
                .send_to(b"prompt-response", source)
                .expect("prompt response should send");
        });

        let err = backend
            .authoritative_transport_round_trip(
                remote_addr,
                b"will-timeout",
                Duration::from_millis(50),
            )
            .expect_err("slow round trip should time out");
        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("timed out"));

        slow_responder.join().expect("slow responder should join");
        let peer_ingress = wait_for(Duration::from_secs(1), || {
            let records = backend
                .recorded_peer_ciphertext_ingress_for_test()
                .expect("peer ingress should resolve");
            records
                .iter()
                .any(|record| {
                    record.remote_addr == remote_addr && record.payload == b"late-response"
                })
                .then_some(records)
        });
        assert!(peer_ingress.iter().any(|record| {
            record.remote_addr == remote_addr && record.payload == b"late-response"
        }));

        let response = backend
            .authoritative_transport_round_trip(
                prompt_addr,
                b"prompt-request",
                Duration::from_secs(1),
            )
            .expect("next round trip should succeed");
        assert_eq!(response.payload, b"prompt-response");

        prompt_responder
            .join()
            .expect("prompt responder should join");
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_apply_routes_preserves_transport_identity() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun22", &private_key_path, 51832);
        backend
            .start(runtime_context("utun22"))
            .expect("backend should start");
        let identity_before = backend
            .authoritative_transport_identity()
            .expect("identity should exist");
        let generation_before = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");
        let mesh_route = route("100.64.20.0/24", RouteKind::Mesh);
        let exit_default = route("0.0.0.0/0", RouteKind::ExitNodeDefault);

        backend
            .apply_routes(vec![mesh_route.clone(), exit_default.clone()])
            .expect("route apply should succeed");

        let identity_after = backend
            .authoritative_transport_identity()
            .expect("identity should remain");
        let generation_after = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");
        let snapshot = tun_state.snapshot();
        assert_eq!(identity_before, identity_after);
        assert_eq!(generation_before, generation_after);
        assert_eq!(snapshot.route_reconcile_calls, 1);
        assert_eq!(
            snapshot.last_route_reconcile_interface_name.as_deref(),
            Some("utun22")
        );
        assert!(snapshot.last_previous_routes.is_empty());
        assert_eq!(snapshot.last_next_routes, vec![mesh_route, exit_default]);
        assert_eq!(
            snapshot.programmed_route_cidrs,
            vec!["100.64.20.0/24".to_owned()]
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_apply_routes_rejects_invalid_cidr_without_mutation() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun23", &private_key_path, 51833);
        backend
            .start(runtime_context("utun23"))
            .expect("backend should start");

        let err = backend
            .apply_routes(vec![route("not-a-cidr", RouteKind::Mesh)])
            .expect_err("invalid route should fail");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.route_reconcile_calls, 0);
        assert!(snapshot.last_next_routes.is_empty());

        let valid_route = route("100.64.30.0/24", RouteKind::Mesh);
        backend
            .apply_routes(vec![valid_route.clone()])
            .expect("valid route after failure should use empty previous state");
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.route_reconcile_calls, 1);
        assert!(snapshot.last_previous_routes.is_empty());
        assert_eq!(snapshot.last_next_routes, vec![valid_route]);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_apply_routes_failure_keeps_previous_successful_state() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun26", &private_key_path, 51836);
        backend
            .start(runtime_context("utun26"))
            .expect("backend should start");
        let stable_route = route("100.64.60.0/24", RouteKind::Mesh);
        let failing_route = route("100.64.70.0/24", RouteKind::Mesh);
        backend
            .apply_routes(vec![stable_route.clone()])
            .expect("initial route should apply");
        tun_state.set_route_behavior(tun::MacosTestRouteBehavior::FailOnAdd {
            cidr: failing_route.destination_cidr.clone(),
            message: "macos route add failure".to_owned(),
        });

        let err = backend
            .apply_routes(vec![failing_route.clone()])
            .expect_err("route failure should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos route add failure"));
        assert_eq!(
            tun_state.snapshot().programmed_route_cidrs,
            vec![stable_route.destination_cidr.clone()]
        );

        tun_state.set_route_behavior(tun::MacosTestRouteBehavior::Succeed);
        backend
            .apply_routes(vec![failing_route.clone()])
            .expect("later valid route apply should use retained successful state");
        assert_eq!(
            tun_state.snapshot().programmed_route_cidrs,
            vec![failing_route.destination_cidr]
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_apply_routes_delete_failure_keeps_stale_route() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun27", &private_key_path, 51837);
        backend
            .start(runtime_context("utun27"))
            .expect("backend should start");
        let stale_route = route("100.64.80.0/24", RouteKind::Mesh);
        let replacement_route = route("100.64.90.0/24", RouteKind::Mesh);
        backend
            .apply_routes(vec![stale_route.clone()])
            .expect("initial route should apply");
        tun_state.set_route_behavior(tun::MacosTestRouteBehavior::FailOnDelete {
            cidr: stale_route.destination_cidr.clone(),
            message: "macos route delete failure".to_owned(),
        });

        let err = backend
            .apply_routes(vec![replacement_route])
            .expect_err("delete failure should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos route delete failure"));
        assert_eq!(
            tun_state.snapshot().programmed_route_cidrs,
            vec![stale_route.destination_cidr]
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_recovers_dead_worker_before_configure_peer() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun29", &private_key_path, 51839);
        backend
            .start(runtime_context("utun29"))
            .expect("backend should start");
        let peer_one = sample_peer("peer-one", SocketAddr::from(([127, 0, 0, 1], 41007)));
        let peer_two = sample_peer("peer-two", SocketAddr::from(([127, 0, 0, 1], 41008)));
        backend
            .configure_peer(peer_one.clone())
            .expect("first peer should configure");
        let initial_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");

        tun_state.set_next_recv_error("macos simulated TUN receive failure");
        wait_for(Duration::from_secs(1), || {
            (backend.worker_exit_count_for_test().unwrap_or_default() > 0).then_some(())
        });

        backend
            .configure_peer(peer_two.clone())
            .expect("backend should recover and configure second peer");

        let recovered_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve after recovery")
            .expect("generation should exist after recovery");
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.prepare_calls, 2);
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(snapshot.live_handles, 1);
        assert_ne!(initial_generation, recovered_generation);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_one.node_id)
                .expect("first peer endpoint should survive replay"),
            Some(peer_one.endpoint)
        );
        assert_eq!(
            backend
                .current_peer_endpoint(&peer_two.node_id)
                .expect("second peer endpoint should exist"),
            Some(peer_two.endpoint)
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_recovers_dead_worker_before_route_apply() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun30", &private_key_path, 51840);
        backend
            .start(runtime_context("utun30"))
            .expect("backend should start");
        let route = route("100.64.130.0/24", RouteKind::Mesh);
        let initial_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");

        tun_state.set_next_recv_error("macos simulated TUN receive failure before route");
        wait_for(Duration::from_secs(1), || {
            (backend.worker_exit_count_for_test().unwrap_or_default() > 0).then_some(())
        });

        backend
            .apply_routes(vec![route.clone()])
            .expect("backend should recover and apply route");

        let recovered_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve after recovery")
            .expect("generation should exist after recovery");
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.prepare_calls, 2);
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(snapshot.live_handles, 1);
        assert_ne!(initial_generation, recovered_generation);
        assert_eq!(
            snapshot.programmed_route_cidrs,
            vec![route.destination_cidr]
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_recovers_dead_worker_before_authoritative_round_trip() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun36", &private_key_path, 51846);
        backend
            .start(runtime_context("utun36"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41012)));
        let route = route("100.64.150.0/24", RouteKind::Mesh);
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");
        backend
            .apply_routes(vec![route.clone()])
            .expect("route should apply");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode should set");
        let initial_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");

        tun_state.set_next_recv_error("macos simulated TUN receive failure before round trip");
        wait_for(Duration::from_secs(1), || {
            (backend.worker_exit_count_for_test().unwrap_or_default() > 0).then_some(())
        });
        assert!(
            backend.authoritative_transport_identity().is_none(),
            "dead worker identity must not be advertised"
        );

        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("remote read timeout");
        let remote_addr = remote.local_addr().expect("remote addr");
        let responder = thread::spawn(move || {
            let mut buffer = [0u8; 128];
            let (len, worker_addr) = remote.recv_from(&mut buffer).expect("round trip request");
            assert_eq!(&buffer[..len], b"stun-after-recovery");
            remote
                .send_to(b"stun-after-recovery-ok", worker_addr)
                .expect("round trip response");
        });

        let response = backend
            .authoritative_transport_round_trip(
                remote_addr,
                b"stun-after-recovery",
                Duration::from_secs(1),
            )
            .expect("authoritative round trip should recover worker");

        responder.join().expect("responder should finish");
        assert_eq!(response.payload, b"stun-after-recovery-ok");
        let recovered_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve after recovery")
            .expect("generation should exist after recovery");
        let snapshot = tun_state.snapshot();
        assert_ne!(initial_generation, recovered_generation);
        assert_eq!(snapshot.prepare_calls, 2);
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(snapshot.live_handles, 1);
        assert_eq!(
            snapshot.programmed_route_cidrs,
            vec![route.destination_cidr]
        );
        assert_eq!(snapshot.current_exit_mode, ExitMode::FullTunnel);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("peer endpoint should survive replay"),
            Some(peer.endpoint)
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_recovers_dead_worker_before_authoritative_send() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun37", &private_key_path, 51847);
        backend
            .start(runtime_context("utun37"))
            .expect("backend should start");
        let initial_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve")
            .expect("generation should exist");

        tun_state.set_next_recv_error("macos simulated TUN receive failure before send");
        wait_for(Duration::from_secs(1), || {
            (backend.worker_exit_count_for_test().unwrap_or_default() > 0).then_some(())
        });
        assert!(
            backend.authoritative_transport_identity().is_none(),
            "dead worker identity must not be advertised"
        );

        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("remote read timeout");
        let remote_addr = remote.local_addr().expect("remote addr");
        let identity = backend
            .authoritative_transport_send(remote_addr, b"relay-after-recovery")
            .expect("authoritative send should recover worker");

        let mut buffer = [0u8; 128];
        let (len, worker_addr) = remote.recv_from(&mut buffer).expect("send datagram");
        assert_eq!(&buffer[..len], b"relay-after-recovery");
        assert_eq!(worker_addr, identity.local_addr);
        let recovered_generation = backend
            .transport_generation_for_test()
            .expect("generation should resolve after recovery")
            .expect("generation should exist after recovery");
        assert_ne!(initial_generation, recovered_generation);
        assert_eq!(tun_state.snapshot().prepare_calls, 2);
        assert_eq!(tun_state.snapshot().cleanup_calls, 1);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_recovery_cleanup_failure_is_retryable() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun34", &private_key_path, 51844);
        backend
            .start(runtime_context("utun34"))
            .expect("backend should start");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state
            .set_next_recv_error("macos simulated TUN receive failure before recovery cleanup");
        wait_for(Duration::from_secs(1), || {
            (backend.worker_exit_count_for_test().unwrap_or_default() > 0).then_some(())
        });
        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Fail {
            message: "macos cleanup failed during recovery".to_owned(),
        });

        let err = backend
            .apply_routes(vec![route("100.64.140.0/24", RouteKind::Mesh)])
            .expect_err("recovery cleanup failure should fail closed");

        assert!(err.message.contains("macos cleanup failed during recovery"));
        assert!(backend.cleanup_pending);
        assert!(backend.runtime.is_none());
        assert_eq!(backend.desired_exit_mode, ExitMode::FullTunnel);
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(snapshot.current_exit_mode, ExitMode::FullTunnel);

        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Succeed);
        backend
            .shutdown()
            .expect("shutdown should retry pending recovery cleanup");

        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.cleanup_calls, 2);
        assert_eq!(snapshot.current_exit_mode, ExitMode::Off);
        assert!(!backend.cleanup_pending);
        assert!(backend.runtime_context.is_none());
        assert!(backend.desired_routes.is_empty());
        assert_eq!(backend.desired_exit_mode, ExitMode::Off);
    }

    #[test]
    fn macos_userspace_shared_backend_exit_mode_tracks_configured_peer_endpoints() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun24", &private_key_path, 51834);
        backend
            .start(runtime_context("utun24"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41005)));
        let peer_node = peer.node_id.clone();
        backend
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");

        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.exit_mode_reconcile_calls, 1);
        assert_eq!(snapshot.last_previous_exit_mode, Some(ExitMode::Off));
        assert_eq!(snapshot.last_next_exit_mode, Some(ExitMode::FullTunnel));
        assert_eq!(snapshot.current_exit_mode, ExitMode::FullTunnel);
        assert_eq!(snapshot.last_exit_mode_peer_endpoints, vec![peer.endpoint]);

        let updated_endpoint = SocketEndpoint {
            addr: "127.0.0.1".parse().expect("valid ip"),
            port: 41006,
        };
        backend
            .update_peer_endpoint(&peer_node, updated_endpoint)
            .expect("endpoint update should refresh exit bypass peers");
        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.exit_mode_reconcile_calls, 2);
        assert_eq!(snapshot.last_previous_exit_mode, Some(ExitMode::FullTunnel));
        assert_eq!(snapshot.last_next_exit_mode, Some(ExitMode::FullTunnel));
        assert_eq!(snapshot.current_exit_mode, ExitMode::FullTunnel);
        assert_eq!(
            snapshot.last_exit_mode_peer_endpoints,
            vec![updated_endpoint]
        );

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_shutdown_clears_exit_mode_state() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun25", &private_key_path, 51835);
        backend
            .start(runtime_context("utun25"))
            .expect("backend should start");

        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        backend.shutdown().expect("shutdown should succeed");

        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.exit_mode_reconcile_calls, 2);
        assert_eq!(snapshot.last_previous_exit_mode, Some(ExitMode::FullTunnel));
        assert_eq!(snapshot.last_next_exit_mode, Some(ExitMode::Off));
        assert_eq!(snapshot.current_exit_mode, ExitMode::Off);
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(
            snapshot.last_cleanup_interface_name.as_deref(),
            Some("utun25")
        );
    }

    #[test]
    fn macos_userspace_shared_backend_shutdown_cleanup_failure_is_retryable() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun33", &private_key_path, 51843);
        backend
            .start(runtime_context("utun33"))
            .expect("backend should start");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Fail {
            message: "macos cleanup failed after shutdown".to_owned(),
        });

        let err = backend
            .shutdown()
            .expect_err("cleanup failure should keep retry state");

        assert!(err.message.contains("macos cleanup failed after shutdown"));
        assert!(backend.cleanup_pending);
        assert!(backend.runtime.is_none());
        assert!(backend.authoritative_transport_identity().is_none());
        assert_eq!(tun_state.snapshot().cleanup_calls, 1);

        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Succeed);
        backend
            .shutdown()
            .expect("second shutdown should retry pending cleanup");

        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.cleanup_calls, 2);
        assert_eq!(snapshot.current_exit_mode, ExitMode::Off);
        assert_eq!(snapshot.live_handles, 0);
        assert!(!backend.cleanup_pending);
        assert!(backend.runtime_context.is_none());
        assert!(backend.desired_peers.is_empty());
        assert!(backend.desired_routes.is_empty());
        assert_eq!(backend.desired_exit_mode, ExitMode::Off);
    }

    #[test]
    fn macos_userspace_shared_backend_start_retries_pending_cleanup_before_restart() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun35", &private_key_path, 51845);
        backend
            .start(runtime_context("utun35"))
            .expect("backend should start");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Fail {
            message: "macos cleanup failed before restart".to_owned(),
        });
        backend
            .shutdown()
            .expect_err("cleanup failure should leave pending cleanup");

        tun_state.set_cleanup_behavior(tun::MacosTestCleanupBehavior::Succeed);
        backend
            .start(runtime_context("utun35"))
            .expect("start should retry pending cleanup before restart");

        let snapshot = tun_state.snapshot();
        assert_eq!(snapshot.cleanup_calls, 2);
        assert_eq!(snapshot.prepare_calls, 2);
        assert_eq!(snapshot.current_exit_mode, ExitMode::Off);
        assert_eq!(snapshot.live_handles, 1);
        assert!(!backend.cleanup_pending);
        assert!(backend.desired_peers.is_empty());
        assert!(backend.desired_routes.is_empty());
        assert_eq!(backend.desired_exit_mode, ExitMode::Off);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_exit_mode_failure_rolls_back_to_previous_state() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun28", &private_key_path, 51838);
        backend
            .start(runtime_context("utun28"))
            .expect("backend should start");
        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnFullTunnel {
            message: "macos exit full tunnel failure".to_owned(),
        });

        let err = backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect_err("full tunnel failure should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos exit full tunnel failure"));
        assert_eq!(tun_state.snapshot().current_exit_mode, ExitMode::Off);

        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should apply after failure clears");
        assert_eq!(tun_state.snapshot().current_exit_mode, ExitMode::FullTunnel);
        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnOff {
            message: "macos exit off failure".to_owned(),
        });

        let err = backend
            .set_exit_mode(ExitMode::Off)
            .expect_err("exit off failure should fail closed");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos exit off failure"));
        assert_eq!(tun_state.snapshot().current_exit_mode, ExitMode::FullTunnel);

        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
        backend
            .set_exit_mode(ExitMode::Off)
            .expect("exit off should apply after failure clears");
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_configure_peer_rolls_back_when_exit_bypass_refresh_fails() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun29", &private_key_path, 51839);
        backend
            .start(runtime_context("utun29"))
            .expect("backend should start");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnFullTunnel {
            message: "macos exit bypass refresh failure".to_owned(),
        });
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41007)));

        let err = backend
            .configure_peer(peer.clone())
            .expect_err("peer configure must fail closed when bypass refresh fails");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos exit bypass refresh failure"));
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint query should resolve"),
            None
        );

        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
        backend
            .configure_peer(peer.clone())
            .expect("peer configure should retry from clean state");
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 1);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint query should resolve"),
            Some(peer.endpoint)
        );
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_update_peer_endpoint_rolls_back_when_exit_bypass_refresh_fails()
     {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun30", &private_key_path, 51840);
        backend
            .start(runtime_context("utun30"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41008)));
        let original_endpoint = peer.endpoint;
        let updated_endpoint = SocketEndpoint {
            addr: "127.0.0.1".parse().expect("valid ip"),
            port: 41009,
        };
        backend
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnFullTunnel {
            message: "macos exit bypass refresh failure".to_owned(),
        });

        let err = backend
            .update_peer_endpoint(&peer.node_id, updated_endpoint)
            .expect_err("endpoint update must fail closed when bypass refresh fails");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos exit bypass refresh failure"));
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint query should resolve"),
            Some(original_endpoint)
        );

        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
        backend
            .update_peer_endpoint(&peer.node_id, updated_endpoint)
            .expect("endpoint update should retry from retained state");
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint query should resolve"),
            Some(updated_endpoint)
        );
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_remove_peer_rolls_back_when_exit_bypass_refresh_fails() {
        let private_key_path = write_private_key([7; 32]);
        let (mut backend, tun_state) =
            backend_with_test_lifecycle("utun31", &private_key_path, 51841);
        backend
            .start(runtime_context("utun31"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 41010)));
        backend
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full tunnel should set");
        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::FailOnFullTunnel {
            message: "macos exit bypass refresh failure".to_owned(),
        });

        let err = backend
            .remove_peer(&peer.node_id)
            .expect_err("peer remove must fail closed when bypass refresh fails");

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("macos exit bypass refresh failure"));
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 1);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint query should resolve"),
            Some(peer.endpoint)
        );

        tun_state.set_exit_mode_behavior(tun::MacosTestExitModeBehavior::Succeed);
        backend
            .remove_peer(&peer.node_id)
            .expect("peer remove should retry from retained state");
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_backend_configures_peer_and_stats() {
        let private_key_path = write_private_key([7; 32]);
        let mut backend = MacosUserspaceSharedBackend::new_for_test(
            "utun11",
            temp_path(&private_key_path),
            51822,
        )
        .expect("construction should succeed");
        backend
            .start(runtime_context("utun11"))
            .expect("backend should start");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 51820)));

        backend
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 1);
        assert_eq!(
            backend
                .current_peer_endpoint(&peer.node_id)
                .expect("endpoint should resolve"),
            Some(peer.endpoint)
        );

        backend
            .remove_peer(&peer.node_id)
            .expect("peer remove should succeed");
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "opens a real macOS utun device but does not alter routes"]
    fn macos_userspace_shared_backend_real_utun_start_shutdown_smoke() {
        let private_key_path = write_private_key([7; 32]);
        let listen_port = free_udp_port().expect("ephemeral UDP port should bind");
        let interface_name = "utun20";
        let mut backend = MacosUserspaceSharedBackend::new(
            interface_name,
            temp_path(&private_key_path),
            listen_port,
        )
        .expect("backend construction should succeed");

        if let Err(err) = backend.start(runtime_context(interface_name)) {
            if err.message.contains("Operation not permitted") {
                eprintln!("skipping real utun smoke: {}", err.message);
                return;
            }
            panic!("real utun backend should start: {err}");
        }
        let identity = backend
            .authoritative_transport_identity()
            .expect("real utun backend should report identity");
        assert_eq!(identity.label, socket::AUTHORITATIVE_TRANSPORT_LABEL);
        assert_ne!(identity.local_addr.port(), 0);

        backend
            .shutdown()
            .expect("real utun shutdown should succeed");
    }

    #[test]
    fn macos_userspace_shared_can_use_shared_boringtun_engine_for_peer_handshake() {
        let private_key_path = write_private_key([7; 32]);
        let mut engine = UserspaceEngine::from_private_key_file(private_key_path.path())
            .expect("engine should load private key");
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 51820)));

        assert_eq!(
            engine
                .configure_peer(&peer)
                .expect("peer configure should succeed"),
            ConfigurePeerDisposition::Added
        );
        let outcome = engine
            .initiate_handshake(&peer.node_id, 42, true)
            .expect("handshake initiation should succeed");
        assert_eq!(outcome.outbound_ciphertext_packets.len(), 1);
        assert_eq!(
            outcome.outbound_ciphertext_packets[0].remote_addr,
            SocketAddr::new(peer.endpoint.addr, peer.endpoint.port)
        );
    }

    #[test]
    fn macos_userspace_shared_can_reuse_shared_handshake_telemetry() {
        let node = NodeId::new("peer-a").expect("valid node id");
        let mut telemetry = HandshakeTelemetry::default();
        assert_eq!(telemetry.latest_handshake(&node), None);
        telemetry.record_authenticated_handshake(&node, 100);
        telemetry.record_authenticated_handshake(&node, 99);
        assert_eq!(telemetry.latest_handshake(&node), Some(100));
        telemetry.record_authenticated_handshake(&node, 101);
        assert_eq!(telemetry.latest_handshake(&node), Some(101));
        telemetry.clear_peer(&node);
        assert_eq!(telemetry.latest_handshake(&node), None);
    }

    fn write_private_key(bytes: [u8; 32]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp key file should be created");
        writeln!(file, "{}", BASE64_STANDARD.encode(bytes)).expect("private key should be written");
        file
    }

    fn backend_with_test_lifecycle(
        interface_name: &str,
        private_key_path: &tempfile::NamedTempFile,
        listen_port: u16,
    ) -> (MacosUserspaceSharedBackend, tun::MacosTunTestState) {
        let lifecycle = tun::TestMacosTunLifecycle::new();
        let state = lifecycle.state();
        let backend = MacosUserspaceSharedBackend::new_with_tun_lifecycle(
            interface_name,
            temp_path(private_key_path),
            listen_port,
            Box::new(lifecycle),
            true,
        )
        .expect("backend construction should succeed");
        (backend, state)
    }

    fn temp_path(file: &tempfile::NamedTempFile) -> String {
        file.path()
            .to_str()
            .expect("temp path should be utf-8")
            .to_owned()
    }

    fn runtime_context(interface_name: &str) -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("mac-node").expect("valid node id"),
            interface_name: interface_name.to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.2/32".to_owned(),
        }
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

    #[cfg(target_os = "macos")]
    fn free_udp_port() -> std::io::Result<u16> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        Ok(socket.local_addr()?.port())
    }

    fn sample_peer(name: &str, endpoint: SocketAddr) -> PeerConfig {
        peer_config_with_key(
            name,
            endpoint,
            peer_public_key([8; 32]),
            vec!["100.64.1.0/24"],
        )
    }

    fn peer_config_with_key(
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
            allowed_ips: allowed_ips.into_iter().map(str::to_owned).collect(),
        }
    }

    fn peer_public_key(private_key: [u8; 32]) -> [u8; 32] {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);
        *public_key.as_bytes()
    }

    fn route(cidr: &str, kind: RouteKind) -> Route {
        Route {
            destination_cidr: cidr.to_owned(),
            via_node: NodeId::new("peer-a").expect("valid node id"),
            kind,
        }
    }
}
