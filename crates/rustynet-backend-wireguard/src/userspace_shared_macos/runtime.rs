#![cfg_attr(test, allow(dead_code))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendError, BackendErrorKind,
    ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint, TunnelStats,
};

use super::socket::{AUTHORITATIVE_TRANSPORT_LABEL, AuthoritativeSocket};
use super::tun::{MacosTunDevice, SharedMacosTunLifecycle};
use crate::userspace_shared::engine::{
    ConfigurePeerDisposition, RecordedPeerCiphertextIngress, RecordedTunnelPlaintextPacket,
    UserspaceEngine,
};
use crate::userspace_shared::handshake::HandshakeTelemetry;

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK: usize = 64;
const MAX_TUN_PACKETS_PER_TICK: usize = 64;

type ReplySender<T> = SyncSender<Result<T, BackendError>>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RecordedAuthoritativeTransportOperationKind {
    RoundTrip,
    Send,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedAuthoritativeTransportOperation {
    pub(crate) kind: RecordedAuthoritativeTransportOperationKind,
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) transport_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedPeerCiphertextEgress {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
    pub(crate) transport_generation: u64,
}

#[derive(Debug)]
pub(crate) struct RunningUserspaceRuntime {
    control: RuntimeControl,
    join_handle: JoinHandle<()>,
}

impl RunningUserspaceRuntime {
    pub(crate) fn start(
        interface_name: &str,
        context: RuntimeContext,
        tun_device: MacosTunDevice,
        authoritative_socket: AuthoritativeSocket,
        engine: UserspaceEngine,
        tun_lifecycle: SharedMacosTunLifecycle,
    ) -> Result<Self, BackendError> {
        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let test_state = RuntimeTestState::default();
        let worker_test_state = test_state.clone();
        let worker_alive = Arc::new(AtomicBool::new(true));
        let worker_alive_for_thread = worker_alive.clone();
        let round_trip_in_flight = Arc::new(AtomicBool::new(false));
        let thread_name = format!("rustynet-wg-macos-userspace-{interface_name}");

        let join_handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                run_worker(WorkerRuntimeParts {
                    context,
                    tun_device,
                    authoritative_socket,
                    engine,
                    tun_lifecycle,
                    command_rx,
                    ready_tx,
                    test_state: worker_test_state,
                    worker_alive: worker_alive_for_thread,
                });
            })
            .map_err(|err| {
                BackendError::internal(format!(
                    "macos userspace-shared runtime worker spawn failed: {err}"
                ))
            })?;

        let authoritative_identity = match ready_rx.recv() {
            Ok(Ok(identity)) => identity,
            Ok(Err(err)) => {
                let _ = join_handle.join();
                return Err(err);
            }
            Err(_) => {
                let _ = join_handle.join();
                return Err(BackendError::internal(
                    "macos userspace-shared runtime worker exited before reporting readiness",
                ));
            }
        };

        Ok(Self {
            control: RuntimeControl {
                command_tx,
                authoritative_identity,
                worker_alive,
                round_trip_in_flight,
                test_state,
            },
            join_handle,
        })
    }

    pub(crate) fn control(&self) -> &RuntimeControl {
        &self.control
    }

    pub(crate) fn shutdown(self) -> Result<(), BackendError> {
        let shutdown_result = self.control.shutdown();
        let join_result = self.join_handle.join().map_err(|_| {
            BackendError::internal("macos userspace-shared runtime worker panicked during shutdown")
        });

        match (shutdown_result, join_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(err)) => Err(err),
            (Err(err), Err(_)) => Err(err),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeControl {
    command_tx: Sender<RuntimeRequest>,
    authoritative_identity: AuthoritativeTransportIdentity,
    worker_alive: Arc<AtomicBool>,
    round_trip_in_flight: Arc<AtomicBool>,
    #[cfg_attr(not(test), allow(dead_code))]
    test_state: RuntimeTestState,
}

impl RuntimeControl {
    pub(crate) fn authoritative_identity(&self) -> AuthoritativeTransportIdentity {
        self.authoritative_identity.clone()
    }

    pub(crate) fn is_worker_alive(&self) -> bool {
        self.worker_alive.load(Ordering::SeqCst)
    }

    pub(crate) fn configure_peer(&self, peer: PeerConfig) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::ConfigurePeer { peer, reply })
    }

    pub(crate) fn update_peer_endpoint(
        &self,
        node_id: NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::UpdatePeerEndpoint {
            node_id,
            endpoint,
            reply,
        })
    }

    pub(crate) fn current_peer_endpoint(
        &self,
        node_id: NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.request(|reply| RuntimeRequest::CurrentPeerEndpoint { node_id, reply })
    }

    pub(crate) fn peer_latest_handshake_unix(
        &self,
        node_id: NodeId,
    ) -> Result<Option<u64>, BackendError> {
        self.request(|reply| RuntimeRequest::PeerLatestHandshake { node_id, reply })
    }

    pub(crate) fn remove_peer(&self, node_id: NodeId) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::RemovePeer { node_id, reply })
    }

    pub(crate) fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.request(|reply| RuntimeRequest::Stats { reply })
    }

    pub(crate) fn initiate_peer_handshake(
        &self,
        node_id: NodeId,
        force_resend: bool,
    ) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::InitiatePeerHandshake {
            node_id,
            force_resend,
            reply,
        })
    }

    pub(crate) fn shutdown(&self) -> Result<(), BackendError> {
        self.round_trip_in_flight.store(false, Ordering::SeqCst);
        self.request(|reply| RuntimeRequest::Shutdown { reply })
    }

    pub(crate) fn apply_routes(&self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::ApplyRoutes { routes, reply })
    }

    pub(crate) fn set_exit_mode(&self, mode: ExitMode) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::SetExitMode { mode, reply })
    }

    pub(crate) fn authoritative_round_trip(
        &self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        self.acquire_round_trip_slot()?;
        let result = self.request(|reply| RuntimeRequest::AuthoritativeRoundTrip {
            remote_addr,
            payload,
            timeout,
            reply,
        });
        self.round_trip_in_flight.store(false, Ordering::SeqCst);
        result
    }

    pub(crate) fn authoritative_send(
        &self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.request(|reply| RuntimeRequest::AuthoritativeSend {
            remote_addr,
            payload,
            reply,
        })
    }

    #[cfg(test)]
    pub(crate) fn worker_local_addr_for_test(&self) -> Result<SocketAddr, BackendError> {
        self.request(|reply| RuntimeRequest::DebugWorkerLocalAddr { reply })
    }

    #[cfg(test)]
    pub(crate) fn transport_generation_for_test(&self) -> Result<u64, BackendError> {
        self.request(|reply| RuntimeRequest::DebugTransportGeneration { reply })
    }

    #[cfg(test)]
    pub(crate) fn recorded_authoritative_operations_for_test(
        &self,
    ) -> Result<Vec<RecordedAuthoritativeTransportOperation>, BackendError> {
        self.request(|reply| RuntimeRequest::DebugRecordedAuthoritativeOperations { reply })
    }

    #[cfg(test)]
    pub(crate) fn recorded_peer_ciphertext_ingress_for_test(
        &self,
    ) -> Result<Vec<RecordedPeerCiphertextIngress>, BackendError> {
        self.request(|reply| RuntimeRequest::DebugRecordedPeerCiphertextIngress { reply })
    }

    #[cfg(test)]
    pub(crate) fn recorded_peer_ciphertext_egress_for_test(
        &self,
    ) -> Result<Vec<RecordedPeerCiphertextEgress>, BackendError> {
        self.request(|reply| RuntimeRequest::DebugRecordedPeerCiphertextEgress { reply })
    }

    #[cfg(test)]
    pub(crate) fn inject_plaintext_packet_for_test(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::DebugInjectPlaintextPacket { packet, reply })
    }

    #[cfg(test)]
    pub(crate) fn recorded_tunnel_plaintext_packets_for_test(
        &self,
    ) -> Result<Vec<RecordedTunnelPlaintextPacket>, BackendError> {
        self.request(|reply| RuntimeRequest::DebugRecordedTunnelPlaintextPackets { reply })
    }

    #[cfg(test)]
    pub(crate) fn queue_tun_plaintext_packet_for_test(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), BackendError> {
        self.request(|reply| RuntimeRequest::DebugQueueTunPlaintextPacket { packet, reply })
    }

    #[cfg(test)]
    pub(crate) fn recorded_tun_outbound_packets_for_test(
        &self,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.request(|reply| RuntimeRequest::DebugRecordedTunOutboundPackets { reply })
    }

    #[cfg(test)]
    pub(crate) fn worker_exit_count_for_test(&self) -> usize {
        self.test_state.worker_exit_count.load(Ordering::SeqCst)
    }

    fn acquire_round_trip_slot(&self) -> Result<(), BackendError> {
        self.round_trip_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| {
                BackendError::internal(
                    "macos userspace-shared authoritative transport round trip rejected because another round trip is already in flight",
                )
            })
    }

    fn request<T>(
        &self,
        make_request: impl FnOnce(ReplySender<T>) -> RuntimeRequest,
    ) -> Result<T, BackendError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.command_tx.send(make_request(reply_tx)).map_err(|_| {
            BackendError::internal("macos userspace-shared runtime worker is unavailable")
        })?;
        reply_rx.recv().map_err(|_| {
            BackendError::internal("macos userspace-shared runtime worker dropped a reply")
        })?
    }
}

#[derive(Debug)]
enum RuntimeRequest {
    ConfigurePeer {
        peer: PeerConfig,
        reply: ReplySender<()>,
    },
    UpdatePeerEndpoint {
        node_id: NodeId,
        endpoint: SocketEndpoint,
        reply: ReplySender<()>,
    },
    CurrentPeerEndpoint {
        node_id: NodeId,
        reply: ReplySender<Option<SocketEndpoint>>,
    },
    PeerLatestHandshake {
        node_id: NodeId,
        reply: ReplySender<Option<u64>>,
    },
    RemovePeer {
        node_id: NodeId,
        reply: ReplySender<()>,
    },
    ApplyRoutes {
        routes: Vec<Route>,
        reply: ReplySender<()>,
    },
    SetExitMode {
        mode: ExitMode,
        reply: ReplySender<()>,
    },
    Stats {
        reply: ReplySender<TunnelStats>,
    },
    InitiatePeerHandshake {
        node_id: NodeId,
        force_resend: bool,
        reply: ReplySender<()>,
    },
    AuthoritativeRoundTrip {
        remote_addr: SocketAddr,
        payload: Vec<u8>,
        timeout: Duration,
        reply: ReplySender<AuthoritativeTransportResponse>,
    },
    AuthoritativeSend {
        remote_addr: SocketAddr,
        payload: Vec<u8>,
        reply: ReplySender<AuthoritativeTransportIdentity>,
    },
    Shutdown {
        reply: ReplySender<()>,
    },
    #[cfg(test)]
    DebugWorkerLocalAddr {
        reply: ReplySender<SocketAddr>,
    },
    #[cfg(test)]
    DebugTransportGeneration {
        reply: ReplySender<u64>,
    },
    #[cfg(test)]
    DebugRecordedAuthoritativeOperations {
        reply: ReplySender<Vec<RecordedAuthoritativeTransportOperation>>,
    },
    #[cfg(test)]
    DebugRecordedPeerCiphertextIngress {
        reply: ReplySender<Vec<RecordedPeerCiphertextIngress>>,
    },
    #[cfg(test)]
    DebugRecordedPeerCiphertextEgress {
        reply: ReplySender<Vec<RecordedPeerCiphertextEgress>>,
    },
    #[cfg(test)]
    DebugInjectPlaintextPacket {
        packet: Vec<u8>,
        reply: ReplySender<()>,
    },
    #[cfg(test)]
    DebugRecordedTunnelPlaintextPackets {
        reply: ReplySender<Vec<RecordedTunnelPlaintextPacket>>,
    },
    #[cfg(test)]
    DebugQueueTunPlaintextPacket {
        packet: Vec<u8>,
        reply: ReplySender<()>,
    },
    #[cfg(test)]
    DebugRecordedTunOutboundPackets {
        reply: ReplySender<Vec<Vec<u8>>>,
    },
}

#[derive(Debug)]
struct RuntimeState {
    context: RuntimeContext,
    tun_device: MacosTunDevice,
    tun_lifecycle: SharedMacosTunLifecycle,
    authoritative_socket: AuthoritativeSocket,
    engine: UserspaceEngine,
    peers: BTreeMap<NodeId, PeerConfig>,
    current_routes: Vec<Route>,
    current_exit_mode: ExitMode,
    outstanding_round_trip: Option<OutstandingRoundTripState>,
    recorded_authoritative_operations: Vec<RecordedAuthoritativeTransportOperation>,
    recorded_peer_ciphertext_egress: Vec<RecordedPeerCiphertextEgress>,
    handshake_telemetry: HandshakeTelemetry,
}

impl RuntimeState {
    fn authoritative_identity(&self) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.authoritative_socket
            .identity(AUTHORITATIVE_TRANSPORT_LABEL)
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        validate_macos_userspace_endpoint(peer.endpoint)?;
        let previous_peer = self.peers.get(&peer.node_id).cloned();
        let disposition = self.engine.configure_peer(&peer)?;
        let node_id = peer.node_id.clone();
        self.peers.insert(node_id.clone(), peer);
        if let Err(err) = self.refresh_exit_mode_bypass_routes_if_needed() {
            let rollback_result = match previous_peer {
                Some(previous_peer) => {
                    self.peers.insert(node_id.clone(), previous_peer.clone());
                    self.engine.configure_peer(&previous_peer).map(|_| ())
                }
                None => {
                    self.peers.remove(&node_id);
                    self.engine.remove_peer(&node_id);
                    self.handshake_telemetry.clear_peer(&node_id);
                    Ok(())
                }
            };
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
            };
        }
        if matches!(disposition, ConfigurePeerDisposition::Replaced) {
            self.handshake_telemetry.clear_peer(&node_id);
        }
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        validate_macos_userspace_endpoint(endpoint)?;
        let Some(peer) = self.peers.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        let previous_endpoint = peer.endpoint;
        peer.endpoint = endpoint;
        self.engine.update_peer_endpoint(node_id, endpoint)?;
        if let Err(err) = self.refresh_exit_mode_bypass_routes_if_needed() {
            if let Some(peer) = self.peers.get_mut(node_id) {
                peer.endpoint = previous_endpoint;
            }
            let rollback_result = self.engine.update_peer_endpoint(node_id, previous_endpoint);
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
            };
        }
        Ok(())
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        Ok(self.engine.current_peer_endpoint(node_id))
    }

    fn peer_latest_handshake_unix(&self, node_id: &NodeId) -> Result<Option<u64>, BackendError> {
        if !self.engine.has_peer(node_id) {
            return Err(BackendError::invalid_input("peer is not configured"));
        }
        Ok(self.handshake_telemetry.latest_handshake(node_id))
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        if let Some(peer) = self.peers.remove(node_id) {
            self.engine.remove_peer(node_id);
            if let Err(err) = self.refresh_exit_mode_bypass_routes_if_needed() {
                self.peers.insert(node_id.clone(), peer.clone());
                let rollback_result = self.engine.configure_peer(&peer).map(|_| ());
                return match rollback_result {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
                };
            }
            self.handshake_telemetry.clear_peer(node_id);
        }
        Ok(())
    }

    fn stats(&self) -> TunnelStats {
        let engine_stats = self.engine.stats();
        TunnelStats {
            peer_count: self.peers.len(),
            bytes_tx: engine_stats.bytes_tx,
            bytes_rx: engine_stats.bytes_rx,
            using_relay_path: false,
        }
    }

    fn initiate_peer_handshake(
        &mut self,
        node_id: &NodeId,
        force_resend: bool,
    ) -> Result<(), BackendError> {
        let outcome = self.engine.initiate_handshake(
            node_id,
            self.authoritative_socket.transport_generation(),
            force_resend,
        )?;
        self.apply_engine_processing_outcome(outcome)
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.tun_lifecycle.reconcile_routes(
            &self.context.interface_name,
            &self.current_routes,
            &routes,
        )?;
        self.current_routes = routes;
        Ok(())
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        let peers = self.configured_peers();
        self.tun_lifecycle.reconcile_exit_mode(
            &self.context.interface_name,
            self.current_exit_mode,
            mode,
            &peers,
        )?;
        self.current_exit_mode = mode;
        Ok(())
    }

    fn refresh_exit_mode_bypass_routes_if_needed(&mut self) -> Result<(), BackendError> {
        if self.current_exit_mode != ExitMode::FullTunnel {
            return Ok(());
        }
        let peers = self.configured_peers();
        self.tun_lifecycle.reconcile_exit_mode(
            &self.context.interface_name,
            ExitMode::FullTunnel,
            ExitMode::FullTunnel,
            &peers,
        )
    }

    fn configured_peers(&self) -> Vec<PeerConfig> {
        self.peers.values().cloned().collect()
    }

    fn start_authoritative_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
        timeout: Duration,
        reply: ReplySender<AuthoritativeTransportResponse>,
    ) {
        let error_reply = reply.clone();
        let result = (|| -> Result<OutstandingRoundTripState, BackendError> {
            if self.outstanding_round_trip.is_some() {
                return Err(BackendError::internal(
                    "macos userspace-shared authoritative transport round trip rejected because another round trip is already in flight",
                ));
            }
            validate_authoritative_remote_addr(remote_addr)?;
            self.reject_control_target(remote_addr)?;

            let local_addr = self.authoritative_socket.local_addr()?;
            let transport_generation = self.authoritative_socket.transport_generation();
            // Unbounded-growth guard: `recorded_authoritative_operations` is only
            // consumed by test fixtures (see `DebugRecordedAuthoritativeOperations`
            // which is itself `#[cfg(test)]`). Pushing on every round-trip in
            // production builds would let any peer that reaches the authoritative
            // socket grow the buffer without bound.
            #[cfg(test)]
            self.recorded_authoritative_operations
                .push(RecordedAuthoritativeTransportOperation {
                    kind: RecordedAuthoritativeTransportOperationKind::RoundTrip,
                    local_addr,
                    remote_addr,
                    payload: payload.clone(),
                    timeout: Some(timeout),
                    transport_generation,
                });
            #[cfg(not(test))]
            {
                let _ = (local_addr, transport_generation, &timeout);
            }
            self.authoritative_socket.send_to(remote_addr, &payload)?;
            Ok(OutstandingRoundTripState {
                remote_addr,
                deadline: Instant::now()
                    .checked_add(timeout)
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(24 * 60 * 60)),
                reply,
                transport_generation,
            })
        })();

        match result {
            Ok(outstanding) => {
                self.outstanding_round_trip = Some(outstanding);
            }
            Err(err) => {
                let _ = error_reply.send(Err(err));
            }
        }
    }

    fn authoritative_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        validate_authoritative_remote_addr(remote_addr)?;
        self.reject_control_target(remote_addr)?;
        let identity = self.authoritative_identity()?;
        // Unbounded-growth guard: see analogous block in
        // `start_authoritative_round_trip`. The send-side recording is only used by
        // test fixtures and must not retain ciphertext payloads in production.
        #[cfg(test)]
        self.recorded_authoritative_operations
            .push(RecordedAuthoritativeTransportOperation {
                kind: RecordedAuthoritativeTransportOperationKind::Send,
                local_addr: identity.local_addr,
                remote_addr,
                payload: payload.clone(),
                timeout: None,
                transport_generation: self.authoritative_socket.transport_generation(),
            });
        self.authoritative_socket.send_to(remote_addr, &payload)?;
        Ok(identity)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn recorded_authoritative_operations(&self) -> Vec<RecordedAuthoritativeTransportOperation> {
        self.recorded_authoritative_operations.clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn recorded_peer_ciphertext_ingress(&self) -> Vec<RecordedPeerCiphertextIngress> {
        self.engine.recorded_peer_ciphertext_ingress().to_vec()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn recorded_peer_ciphertext_egress(&self) -> Vec<RecordedPeerCiphertextEgress> {
        self.recorded_peer_ciphertext_egress.clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn recorded_tunnel_plaintext_packets(&self) -> Vec<RecordedTunnelPlaintextPacket> {
        self.engine.recorded_tunnel_plaintext_packets().to_vec()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn transport_generation(&self) -> u64 {
        self.authoritative_socket.transport_generation()
    }

    fn next_wait_timeout(&self) -> Duration {
        let Some(outstanding) = self.outstanding_round_trip.as_ref() else {
            return WORKER_POLL_INTERVAL;
        };
        let now = Instant::now();
        if outstanding.deadline <= now {
            Duration::ZERO
        } else {
            outstanding
                .deadline
                .saturating_duration_since(now)
                .min(WORKER_POLL_INTERVAL)
        }
    }

    fn poll_authoritative_socket(&mut self) -> Result<(), BackendError> {
        for _ in 0..MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK {
            let Some(datagram) = self.authoritative_socket.try_recv()? else {
                break;
            };
            if self.try_deliver_round_trip_response(&datagram)? {
                continue;
            }

            let local_addr = self.authoritative_socket.local_addr()?;
            let outcome = self.engine.process_inbound_ciphertext(
                datagram.remote_addr,
                local_addr,
                &datagram.payload,
                self.authoritative_socket.transport_generation(),
            )?;
            self.apply_engine_processing_outcome(outcome)?;
        }
        Ok(())
    }

    fn poll_tun_device(&mut self) -> Result<(), BackendError> {
        for _ in 0..MAX_TUN_PACKETS_PER_TICK {
            let Some(packet) = self.tun_device.recv_packet()? else {
                break;
            };
            let outcome = match self
                .engine
                .inject_plaintext_packet(&packet, self.authoritative_socket.transport_generation())
            {
                Ok(outcome) => outcome,
                Err(err) if should_drop_tun_plaintext_packet_error(&err) => continue,
                Err(err) => return Err(err),
            };
            self.apply_engine_processing_outcome(outcome)?;
        }
        Ok(())
    }

    fn expire_timed_out_round_trip(&mut self) {
        let Some(outstanding) = self.outstanding_round_trip.as_ref() else {
            return;
        };
        if Instant::now() < outstanding.deadline {
            return;
        }
        let remote_addr = outstanding.remote_addr;
        self.fail_outstanding_round_trip(BackendError::internal(format!(
            "macos userspace-shared authoritative transport round trip to {remote_addr} timed out"
        )));
    }

    fn fail_outstanding_round_trip(&mut self, err: BackendError) {
        if let Some(outstanding) = self.outstanding_round_trip.take() {
            let _ = outstanding.reply.send(Err(err));
        }
    }

    fn reject_control_target(&self, remote_addr: SocketAddr) -> Result<(), BackendError> {
        let matches_peer_endpoint = self.engine.has_endpoint(remote_addr);
        if matches_peer_endpoint {
            return Err(BackendError::invalid_input(
                "macos userspace-shared authoritative transport target matches a configured peer endpoint",
            ));
        }
        Ok(())
    }

    fn try_deliver_round_trip_response(
        &mut self,
        datagram: &super::socket::ReceivedDatagram,
    ) -> Result<bool, BackendError> {
        let Some(outstanding) = self.outstanding_round_trip.as_ref() else {
            return Ok(false);
        };
        if datagram.remote_addr != outstanding.remote_addr {
            return Ok(false);
        }
        if self.authoritative_socket.transport_generation() != outstanding.transport_generation {
            return Ok(false);
        }

        let local_addr = self.authoritative_socket.local_addr()?;
        let response = AuthoritativeTransportResponse {
            local_addr,
            remote_addr: datagram.remote_addr,
            payload: datagram.payload.clone(),
        };
        let Some(outstanding) = self.outstanding_round_trip.take() else {
            return Ok(false);
        };
        let _ = outstanding.reply.send(Ok(response));
        Ok(true)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn inject_plaintext_packet_for_test(&mut self, packet: Vec<u8>) -> Result<(), BackendError> {
        let outcome = self
            .engine
            .inject_plaintext_packet(&packet, self.authoritative_socket.transport_generation())?;
        self.apply_engine_processing_outcome(outcome)
    }

    #[cfg(test)]
    fn queue_tun_plaintext_packet_for_test(&mut self, packet: Vec<u8>) -> Result<(), BackendError> {
        self.tun_device.queue_inbound_packet_for_test(packet)
    }

    #[cfg(test)]
    fn recorded_tun_outbound_packets(&self) -> Result<Vec<Vec<u8>>, BackendError> {
        self.tun_device.recorded_outbound_packets_for_test()
    }

    fn apply_engine_processing_outcome(
        &mut self,
        outcome: crate::userspace_shared::engine::EngineProcessingOutcome,
    ) -> Result<(), BackendError> {
        let local_addr = self.authoritative_socket.local_addr()?;
        let transport_generation = self.authoritative_socket.transport_generation();
        for packet in outcome.outbound_ciphertext_packets {
            // Unbounded-growth guard: `recorded_peer_ciphertext_egress` is read only
            // by `DebugRecordedPeerCiphertextEgress` (cfg(test)). Persisting every
            // outbound ciphertext frame in production would grow without bound and
            // keep a peer's ciphertext history in memory for the process lifetime.
            #[cfg(test)]
            self.recorded_peer_ciphertext_egress
                .push(RecordedPeerCiphertextEgress {
                    local_addr,
                    remote_addr: packet.remote_addr,
                    payload: packet.payload.clone(),
                    transport_generation,
                });
            self.authoritative_socket
                .send_to(packet.remote_addr, &packet.payload)?;
        }
        #[cfg(not(test))]
        {
            let _ = (local_addr, transport_generation);
        }
        for packet in outcome.tunnel_plaintext_packets {
            self.tun_device.send_packet(&packet)?;
        }
        if let Some((node_id, observed_unix)) = outcome.authenticated_handshake {
            self.handshake_telemetry
                .record_authenticated_handshake(&node_id, observed_unix);
        }
        Ok(())
    }
}

fn combine_peer_mutation_error(primary: BackendError, rollback: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; peer state rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn should_drop_tun_plaintext_packet_error(err: &BackendError) -> bool {
    err.kind == BackendErrorKind::InvalidInput
        && matches!(
            err.message.as_str(),
            "plaintext packet does not contain a valid IPv4/IPv6 destination address"
                | "no configured peer allowed IP matches the plaintext packet destination"
        )
}

fn validate_authoritative_remote_addr(remote_addr: SocketAddr) -> Result<(), BackendError> {
    if remote_addr.port() == 0 {
        return Err(BackendError::invalid_input(
            "macos userspace-shared authoritative transport target port must be non-zero",
        ));
    }
    let addr = remote_addr.ip();
    if addr.is_unspecified() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared authoritative transport target address must not be unspecified",
        ));
    }
    if addr.is_ipv6() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared authoritative transport target currently requires IPv4 because the authoritative socket is IPv4-only",
        ));
    }
    if addr.is_multicast() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared authoritative transport target address must not be multicast",
        ));
    }
    if matches!(addr, std::net::IpAddr::V4(ipv4) if ipv4.is_broadcast()) {
        return Err(BackendError::invalid_input(
            "macos userspace-shared authoritative transport target address must not be broadcast",
        ));
    }
    Ok(())
}

pub(crate) fn validate_macos_userspace_endpoint(
    endpoint: SocketEndpoint,
) -> Result<(), BackendError> {
    if endpoint.port == 0 {
        return Err(BackendError::invalid_input(
            "macos userspace-shared peer endpoint port must be non-zero",
        ));
    }
    if endpoint.addr.is_unspecified() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared peer endpoint address must not be unspecified",
        ));
    }
    if endpoint.addr.is_ipv6() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared peer endpoint currently requires IPv4 because the authoritative socket is IPv4-only",
        ));
    }
    if endpoint.addr.is_multicast() {
        return Err(BackendError::invalid_input(
            "macos userspace-shared peer endpoint address must not be multicast",
        ));
    }
    if matches!(endpoint.addr, std::net::IpAddr::V4(ipv4) if ipv4.is_broadcast()) {
        return Err(BackendError::invalid_input(
            "macos userspace-shared peer endpoint address must not be broadcast",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct OutstandingRoundTripState {
    remote_addr: SocketAddr,
    deadline: Instant,
    reply: ReplySender<AuthoritativeTransportResponse>,
    transport_generation: u64,
}

#[derive(Clone, Debug, Default)]
struct RuntimeTestState {
    worker_exit_count: Arc<AtomicUsize>,
}

struct WorkerRuntimeParts {
    context: RuntimeContext,
    tun_device: MacosTunDevice,
    authoritative_socket: AuthoritativeSocket,
    engine: UserspaceEngine,
    tun_lifecycle: SharedMacosTunLifecycle,
    command_rx: Receiver<RuntimeRequest>,
    ready_tx: ReplySender<AuthoritativeTransportIdentity>,
    test_state: RuntimeTestState,
    worker_alive: Arc<AtomicBool>,
}

fn run_worker(parts: WorkerRuntimeParts) {
    let WorkerRuntimeParts {
        context,
        tun_device,
        authoritative_socket,
        engine,
        tun_lifecycle,
        command_rx,
        ready_tx,
        test_state,
        worker_alive,
    } = parts;
    let mut state = RuntimeState {
        context,
        tun_device,
        tun_lifecycle,
        authoritative_socket,
        engine,
        peers: BTreeMap::new(),
        current_routes: Vec::new(),
        current_exit_mode: ExitMode::Off,
        outstanding_round_trip: None,
        recorded_authoritative_operations: Vec::new(),
        recorded_peer_ciphertext_egress: Vec::new(),
        handshake_telemetry: HandshakeTelemetry::default(),
    };

    match state.authoritative_identity() {
        Ok(identity) => {
            if ready_tx.send(Ok(identity)).is_err() {
                mark_worker_exit(&test_state, &worker_alive);
                return;
            }
        }
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            mark_worker_exit(&test_state, &worker_alive);
            return;
        }
    }

    loop {
        match command_rx.recv_timeout(state.next_wait_timeout()) {
            Ok(request) => {
                if !handle_request(&mut state, request) {
                    break;
                }
                loop {
                    match command_rx.try_recv() {
                        Ok(request) => {
                            if !handle_request(&mut state, request) {
                                mark_worker_exit(&test_state, &worker_alive);
                                return;
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            state.fail_outstanding_round_trip(BackendError::internal(
                                "macos userspace-shared runtime worker command channel disconnected during authoritative transport processing",
                            ));
                            mark_worker_exit(&test_state, &worker_alive);
                            return;
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if let Err(err) = state.poll_authoritative_socket() {
            state.fail_outstanding_round_trip(err);
            break;
        }
        if let Err(err) = state.poll_tun_device() {
            state.fail_outstanding_round_trip(err);
            break;
        }
        state.expire_timed_out_round_trip();
    }

    state.fail_outstanding_round_trip(BackendError::internal(
        "macos userspace-shared runtime worker exited while an authoritative transport round trip was still in flight",
    ));
    mark_worker_exit(&test_state, &worker_alive);
}

fn mark_worker_exit(test_state: &RuntimeTestState, worker_alive: &AtomicBool) {
    worker_alive.store(false, Ordering::SeqCst);
    test_state.worker_exit_count.fetch_add(1, Ordering::SeqCst);
}

fn handle_request(state: &mut RuntimeState, request: RuntimeRequest) -> bool {
    match request {
        RuntimeRequest::ConfigurePeer { peer, reply } => {
            let _ = reply.send(state.configure_peer(peer));
            true
        }
        RuntimeRequest::UpdatePeerEndpoint {
            node_id,
            endpoint,
            reply,
        } => {
            let _ = reply.send(state.update_peer_endpoint(&node_id, endpoint));
            true
        }
        RuntimeRequest::CurrentPeerEndpoint { node_id, reply } => {
            let _ = reply.send(state.current_peer_endpoint(&node_id));
            true
        }
        RuntimeRequest::PeerLatestHandshake { node_id, reply } => {
            let _ = reply.send(state.peer_latest_handshake_unix(&node_id));
            true
        }
        RuntimeRequest::RemovePeer { node_id, reply } => {
            let _ = reply.send(state.remove_peer(&node_id));
            true
        }
        RuntimeRequest::ApplyRoutes { routes, reply } => {
            let _ = reply.send(state.apply_routes(routes));
            true
        }
        RuntimeRequest::SetExitMode { mode, reply } => {
            let _ = reply.send(state.set_exit_mode(mode));
            true
        }
        RuntimeRequest::Stats { reply } => {
            let _ = reply.send(Ok(state.stats()));
            true
        }
        RuntimeRequest::InitiatePeerHandshake {
            node_id,
            force_resend,
            reply,
        } => {
            let _ = reply.send(state.initiate_peer_handshake(&node_id, force_resend));
            true
        }
        RuntimeRequest::AuthoritativeRoundTrip {
            remote_addr,
            payload,
            timeout,
            reply,
        } => {
            state.start_authoritative_round_trip(remote_addr, payload, timeout, reply);
            true
        }
        RuntimeRequest::AuthoritativeSend {
            remote_addr,
            payload,
            reply,
        } => {
            let _ = reply.send(state.authoritative_send(remote_addr, payload));
            true
        }
        RuntimeRequest::Shutdown { reply } => {
            state.fail_outstanding_round_trip(BackendError::internal(
                "macos userspace-shared authoritative transport round trip canceled during backend shutdown",
            ));
            let _ = reply.send(state.set_exit_mode(ExitMode::Off));
            false
        }
        #[cfg(test)]
        RuntimeRequest::DebugWorkerLocalAddr { reply } => {
            let _ = reply.send(state.authoritative_socket.local_addr());
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugTransportGeneration { reply } => {
            let _ = reply.send(Ok(state.transport_generation()));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugRecordedAuthoritativeOperations { reply } => {
            let _ = reply.send(Ok(state.recorded_authoritative_operations()));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugRecordedPeerCiphertextIngress { reply } => {
            let _ = reply.send(Ok(state.recorded_peer_ciphertext_ingress()));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugRecordedPeerCiphertextEgress { reply } => {
            let _ = reply.send(Ok(state.recorded_peer_ciphertext_egress()));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugInjectPlaintextPacket { packet, reply } => {
            let _ = reply.send(state.inject_plaintext_packet_for_test(packet));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugRecordedTunnelPlaintextPackets { reply } => {
            let _ = reply.send(Ok(state.recorded_tunnel_plaintext_packets()));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugQueueTunPlaintextPacket { packet, reply } => {
            let _ = reply.send(state.queue_tun_plaintext_packet_for_test(packet));
            true
        }
        #[cfg(test)]
        RuntimeRequest::DebugRecordedTunOutboundPackets { reply } => {
            let _ = reply.send(state.recorded_tun_outbound_packets());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use base64::prelude::*;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use rustynet_backend_api::{NodeId, RuntimeContext, SocketEndpoint};

    use super::*;
    use crate::userspace_shared::engine::UserspaceEngine;
    use crate::userspace_shared_macos::socket::AuthoritativeSocket;
    use crate::userspace_shared_macos::tun::{
        MacosTunDevice, MacosTunTestState, SharedMacosTunLifecycle, TestMacosTunLifecycle,
    };

    #[test]
    fn macos_runtime_reports_authoritative_identity_and_shutdowns() {
        let runtime = start_test_runtime("utun9");
        let identity = runtime.control().authoritative_identity();

        assert_eq!(identity.label, AUTHORITATIVE_TRANSPORT_LABEL);
        assert_ne!(identity.local_addr.port(), 0);

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_authoritative_round_trip_uses_worker_socket() {
        let runtime = start_test_runtime("utun10");
        let control = runtime.control();
        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("remote read timeout");
        let remote_addr = remote.local_addr().expect("remote addr");
        let responder = thread::spawn(move || {
            let mut buffer = [0u8; 128];
            let (len, worker_addr) = remote.recv_from(&mut buffer).expect("round trip request");
            assert_eq!(&buffer[..len], b"stun-probe");
            remote
                .send_to(b"stun-response", worker_addr)
                .expect("round trip response");
            worker_addr
        });

        let response = control
            .authoritative_round_trip(remote_addr, b"stun-probe".to_vec(), Duration::from_secs(1))
            .expect("round trip should complete");
        let observed_worker_addr = responder.join().expect("responder should finish");

        assert_eq!(response.remote_addr, remote_addr);
        assert_eq!(response.payload, b"stun-response");
        assert_eq!(response.local_addr, observed_worker_addr);

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_authoritative_round_trip_rejects_invalid_remote_before_send_record() {
        let runtime = start_test_runtime("utun13");
        let control = runtime.control();

        for (remote_addr, expected) in [
            (
                SocketAddr::from(([127, 0, 0, 1], 0)),
                "port must be non-zero",
            ),
            (
                SocketAddr::from(([0, 0, 0, 0], 3478)),
                "must not be unspecified",
            ),
            (
                SocketAddr::new("2001:db8::1".parse().expect("valid ip"), 3478),
                "requires IPv4",
            ),
            (
                SocketAddr::from(([224, 0, 0, 1], 3478)),
                "must not be multicast",
            ),
            (
                SocketAddr::from(([255, 255, 255, 255], 3478)),
                "must not be broadcast",
            ),
        ] {
            let err = control
                .authoritative_round_trip(
                    remote_addr,
                    b"stun-probe".to_vec(),
                    Duration::from_millis(10),
                )
                .expect_err("invalid target should fail closed");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
            assert!(err.message.contains(expected));
        }

        assert!(
            control
                .recorded_authoritative_operations_for_test()
                .expect("operation records should resolve")
                .is_empty()
        );
        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_authoritative_send_rejects_invalid_remote_before_send_record() {
        let runtime = start_test_runtime("utun14");
        let control = runtime.control();

        let err = control
            .authoritative_send(
                SocketAddr::new("2001:db8::1".parse().expect("valid ip"), 3478),
                b"relay-keepalive".to_vec(),
            )
            .expect_err("ipv6 relay target should fail closed");

        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert!(err.message.contains("requires IPv4"));
        assert!(
            control
                .recorded_authoritative_operations_for_test()
                .expect("operation records should resolve")
                .is_empty()
        );
        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_authoritative_send_rejects_configured_peer_endpoint_before_send_record() {
        let runtime = start_test_runtime("utun17");
        let control = runtime.control();
        let peer_endpoint = SocketAddr::from(([127, 0, 0, 1], 51820));
        control
            .configure_peer(sample_peer("peer-a", peer_endpoint))
            .expect("peer should configure");

        let err = control
            .authoritative_send(peer_endpoint, b"relay-keepalive".to_vec())
            .expect_err("send to configured peer endpoint should fail closed");

        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert!(err.message.contains("configured peer endpoint"));
        assert!(
            control
                .recorded_authoritative_operations_for_test()
                .expect("operation records should resolve")
                .is_empty()
        );
        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_peer_handshake_uses_authoritative_socket_generation() {
        let runtime = start_test_runtime("utun11");
        let control = runtime.control();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        peer_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let peer_addr = peer_socket.local_addr().expect("peer addr");
        let peer = sample_peer("peer-a", peer_addr);

        control
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");
        control
            .initiate_peer_handshake(peer.node_id.clone(), true)
            .expect("handshake initiation should succeed");

        let mut buffer = [0u8; 512];
        let (len, worker_addr) = peer_socket
            .recv_from(&mut buffer)
            .expect("peer should receive handshake ciphertext");
        assert!(len > 0);
        assert_eq!(
            worker_addr,
            control
                .worker_local_addr_for_test()
                .expect("worker addr should resolve")
        );
        assert_eq!(control.stats().expect("stats should resolve").peer_count, 1);

        let egress = control
            .recorded_peer_ciphertext_egress_for_test()
            .expect("egress records should resolve");
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].remote_addr, peer_addr);
        assert_eq!(
            egress[0].transport_generation,
            control
                .transport_generation_for_test()
                .expect("generation should resolve")
        );

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_configure_peer_rejects_invalid_endpoint_without_state_mutation() {
        let runtime = start_test_runtime("utun15");
        let control = runtime.control();

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
                    port: 51820,
                },
                "must not be unspecified",
            ),
            (
                SocketEndpoint {
                    addr: "2001:db8::1".parse().expect("valid ip"),
                    port: 51820,
                },
                "requires IPv4",
            ),
            (
                SocketEndpoint {
                    addr: "224.0.0.1".parse().expect("valid ip"),
                    port: 51820,
                },
                "must not be multicast",
            ),
            (
                SocketEndpoint {
                    addr: "255.255.255.255".parse().expect("valid ip"),
                    port: 51820,
                },
                "must not be broadcast",
            ),
        ] {
            let mut peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 51820)));
            peer.endpoint = endpoint;
            let err = control
                .configure_peer(peer)
                .expect_err("invalid endpoint should fail closed");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
            assert!(err.message.contains(expected));
            assert_eq!(control.stats().expect("stats should resolve").peer_count, 0);
        }

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_update_peer_endpoint_rejects_invalid_endpoint_without_state_mutation() {
        let runtime = start_test_runtime("utun16");
        let control = runtime.control();
        let peer = sample_peer("peer-a", SocketAddr::from(([127, 0, 0, 1], 51820)));
        let peer_node = peer.node_id.clone();
        let original_endpoint = peer.endpoint;
        control
            .configure_peer(peer)
            .expect("initial peer configure should succeed");

        let err = control
            .update_peer_endpoint(
                peer_node.clone(),
                SocketEndpoint {
                    addr: "2001:db8::1".parse().expect("valid ip"),
                    port: 51820,
                },
            )
            .expect_err("ipv6 endpoint update should fail closed");

        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert!(err.message.contains("requires IPv4"));
        assert_eq!(
            control
                .current_peer_endpoint(peer_node)
                .expect("endpoint should resolve"),
            Some(original_endpoint)
        );
        assert_eq!(control.stats().expect("stats should resolve").peer_count, 1);

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_refreshes_exit_bypass_routes_when_peer_endpoint_changes() {
        let lifecycle = TestMacosTunLifecycle::new();
        let state = lifecycle.state();
        let runtime = start_test_runtime_with_lifecycle("utun12", lifecycle);
        let control = runtime.control();
        let initial_addr = SocketAddr::from(([203, 0, 113, 10], 51820));
        let updated_endpoint = SocketEndpoint {
            addr: "203.0.113.11".parse().expect("valid ip"),
            port: 51820,
        };
        let peer = sample_peer("peer-a", initial_addr);

        control
            .configure_peer(peer.clone())
            .expect("peer configure should succeed");
        control
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode should set");
        assert_eq!(state.snapshot().exit_mode_reconcile_calls, 1);
        assert_eq!(
            state.snapshot().last_exit_mode_peer_endpoints,
            vec![peer.endpoint]
        );

        control
            .update_peer_endpoint(peer.node_id.clone(), updated_endpoint)
            .expect("endpoint update should refresh bypass routes");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.exit_mode_reconcile_calls, 2);
        assert_eq!(
            snapshot.last_exit_mode_peer_endpoints,
            vec![updated_endpoint]
        );

        runtime.shutdown().expect("runtime shutdown should succeed");
    }

    #[test]
    fn macos_runtime_authoritative_socket_poll_is_budgeted_per_tick() {
        let (mut state, _tun_state, _private_key) = test_runtime_state("utun18");
        let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
        let target = loopback_target(
            state
                .authoritative_socket
                .local_addr()
                .expect("worker addr should resolve"),
        );

        for index in 0..(MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK + 3) {
            remote
                .send_to(&[index as u8], target)
                .expect("datagram should send");
        }

        state
            .poll_authoritative_socket()
            .expect("first socket poll should succeed");
        assert_eq!(
            state.recorded_peer_ciphertext_ingress().len(),
            MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK
        );

        state
            .poll_authoritative_socket()
            .expect("second socket poll should drain remaining datagrams");
        assert_eq!(
            state.recorded_peer_ciphertext_ingress().len(),
            MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK + 3
        );
    }

    #[test]
    fn macos_runtime_tun_poll_is_budgeted_per_tick() {
        let (mut state, tun_state, _private_key) = test_runtime_state("utun19");
        let packet_count = MAX_TUN_PACKETS_PER_TICK + 3;
        for index in 0..packet_count {
            state
                .queue_tun_plaintext_packet_for_test(vec![index as u8])
                .expect("test packet should queue");
        }

        state
            .poll_tun_device()
            .expect("first tun poll should drop invalid packets without failing");
        assert_eq!(
            tun_state.snapshot().queued_inbound_packets,
            packet_count - MAX_TUN_PACKETS_PER_TICK
        );

        state
            .poll_tun_device()
            .expect("second tun poll should drain remaining packets");
        assert_eq!(tun_state.snapshot().queued_inbound_packets, 0);
    }

    fn start_test_runtime(interface_name: &str) -> RunningUserspaceRuntime {
        start_test_runtime_with_lifecycle(interface_name, TestMacosTunLifecycle::new())
    }

    fn start_test_runtime_with_lifecycle(
        interface_name: &str,
        lifecycle: TestMacosTunLifecycle,
    ) -> RunningUserspaceRuntime {
        let context = RuntimeContext {
            local_node: NodeId::new("mac-node").expect("valid node id"),
            interface_name: interface_name.to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.2/32".to_owned(),
        };
        let tun_device = MacosTunDevice::test_handle(MacosTunTestState::default());
        let tun_lifecycle = SharedMacosTunLifecycle::new(Box::new(lifecycle));
        let authoritative_socket =
            AuthoritativeSocket::bind_loopback_for_test().expect("authoritative bind");
        let private_key = write_private_key([7; 32]);
        let engine = UserspaceEngine::from_private_key_file(private_key.path())
            .expect("engine should load key");

        RunningUserspaceRuntime::start(
            interface_name,
            context,
            tun_device,
            authoritative_socket,
            engine,
            tun_lifecycle,
        )
        .expect("runtime should start")
    }

    fn test_runtime_state(
        interface_name: &str,
    ) -> (RuntimeState, MacosTunTestState, tempfile::NamedTempFile) {
        let context = RuntimeContext {
            local_node: NodeId::new("mac-node").expect("valid node id"),
            interface_name: interface_name.to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.2/32".to_owned(),
        };
        let tun_state = MacosTunTestState::default();
        let tun_device = MacosTunDevice::test_handle(tun_state.clone());
        let tun_lifecycle = SharedMacosTunLifecycle::new(Box::new(TestMacosTunLifecycle::new()));
        let authoritative_socket =
            AuthoritativeSocket::bind_loopback_for_test().expect("authoritative bind");
        let private_key = write_private_key([7; 32]);
        let engine = UserspaceEngine::from_private_key_file(private_key.path())
            .expect("engine should load key");

        (
            RuntimeState {
                context,
                tun_device,
                tun_lifecycle,
                authoritative_socket,
                engine,
                peers: std::collections::BTreeMap::new(),
                current_routes: Vec::new(),
                current_exit_mode: ExitMode::Off,
                outstanding_round_trip: None,
                recorded_authoritative_operations: Vec::new(),
                recorded_peer_ciphertext_egress: Vec::new(),
                handshake_telemetry: HandshakeTelemetry::default(),
            },
            tun_state,
            private_key,
        )
    }

    fn loopback_target(local_addr: SocketAddr) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], local_addr.port()))
    }

    fn write_private_key(bytes: [u8; 32]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp key file should be created");
        writeln!(file, "{}", BASE64_STANDARD.encode(bytes)).expect("private key should be written");
        file
    }

    fn sample_peer(name: &str, endpoint: SocketAddr) -> PeerConfig {
        let private_key = StaticSecret::from([8; 32]);
        let public_key = PublicKey::from(&private_key);
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: endpoint.ip(),
                port: endpoint.port(),
            },
            public_key: *public_key.as_bytes(),
            allowed_ips: vec!["100.64.1.0/24".to_owned()],
        }
    }
}
