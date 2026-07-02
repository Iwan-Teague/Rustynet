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

use super::engine::{
    ConfigurePeerDisposition, RecordedPeerCiphertextIngress, RecordedTunnelPlaintextPacket,
    UserspaceEngine,
};
use super::handshake::HandshakeTelemetry;
use super::socket::{AUTHORITATIVE_TRANSPORT_LABEL, AuthoritativeSocket};
use super::tun::{SharedTunLifecycle, TunDevice};

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK: usize = 64;
const MAX_TUN_PACKETS_PER_TICK: usize = 64;
/// Size of the long-lived UDP/TUN receive scratch buffers (max
/// datagram / max IP packet).
const RECV_SCRATCH_BYTES: usize = 65_535;

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
        tun_device: TunDevice,
        authoritative_socket: AuthoritativeSocket,
        engine: UserspaceEngine,
        tun_lifecycle: SharedTunLifecycle,
    ) -> Result<Self, BackendError> {
        let (command_tx, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let test_state = RuntimeTestState::default();
        let worker_test_state = test_state.clone();
        let worker_alive = Arc::new(AtomicBool::new(true));
        let worker_alive_for_thread = worker_alive.clone();
        let round_trip_in_flight = Arc::new(AtomicBool::new(false));
        let thread_name = format!("rustynet-wg-userspace-{interface_name}");

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
                    "linux userspace-shared runtime worker spawn failed: {err}"
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
                    "linux userspace-shared runtime worker exited before reporting readiness",
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
            BackendError::internal("linux userspace-shared runtime worker panicked during shutdown")
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

    pub(crate) fn peer_path_quality(
        &self,
        node_id: NodeId,
    ) -> Result<
        Option<(
            rustynet_backend_api::PeerPathSample,
            rustynet_backend_api::PathHealth,
        )>,
        BackendError,
    > {
        self.request(|reply| RuntimeRequest::PeerPathQuality { node_id, reply })
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
                    "linux userspace-shared authoritative transport round trip rejected because another round trip is already in flight",
                )
            })
    }

    fn request<T>(
        &self,
        make_request: impl FnOnce(ReplySender<T>) -> RuntimeRequest,
    ) -> Result<T, BackendError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.command_tx.send(make_request(reply_tx)).map_err(|_| {
            BackendError::internal("linux userspace-shared runtime worker is unavailable")
        })?;
        reply_rx.recv().map_err(|_| {
            BackendError::internal("linux userspace-shared runtime worker dropped a reply")
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
    /// FIS-0004/0013: per-peer path-quality read (raw sample + coarse
    /// health verdict in one round trip).
    PeerPathQuality {
        node_id: NodeId,
        reply: ReplySender<
            Option<(
                rustynet_backend_api::PeerPathSample,
                rustynet_backend_api::PathHealth,
            )>,
        >,
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
    tun_device: TunDevice,
    tun_lifecycle: SharedTunLifecycle,
    authoritative_socket: AuthoritativeSocket,
    engine: UserspaceEngine,
    peers: BTreeMap<NodeId, PeerConfig>,
    current_routes: Vec<Route>,
    current_exit_mode: ExitMode,
    outstanding_round_trip: Option<OutstandingRoundTripState>,
    recorded_authoritative_operations: Vec<RecordedAuthoritativeTransportOperation>,
    recorded_peer_ciphertext_egress: Vec<RecordedPeerCiphertextEgress>,
    handshake_telemetry: HandshakeTelemetry,
    // Long-lived receive scratch buffers (UDP and TUN) reused across every
    // poll pass instead of allocating+zeroing a fresh 64 KiB Vec per packet.
    // Owned by the single worker thread; taken out (mem::take) for the
    // duration of a poll pass so engine calls can borrow `self` mutably.
    udp_recv_scratch: Vec<u8>,
    tun_recv_scratch: Vec<u8>,
    // True when the most recent poll pass consumed its full per-tick budget,
    // i.e. more data is likely still pending. The worker then waits with a
    // zero timeout instead of the 10ms idle interval, removing the
    // ~6.4k pps/direction throughput ceiling while keeping the per-pass
    // budgets (DoS fairness between packet work and control commands) and
    // the commands-first loop structure exactly as before.
    udp_budget_exhausted: bool,
    tun_budget_exhausted: bool,
}

impl RuntimeState {
    fn authoritative_identity(&self) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.authoritative_socket
            .identity(AUTHORITATIVE_TRANSPORT_LABEL)
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        let disposition = self.engine.configure_peer(&peer)?;
        let node_id = peer.node_id.clone();
        self.peers.insert(node_id.clone(), peer);
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
        let Some(peer) = self.peers.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        peer.endpoint = endpoint;
        self.engine.update_peer_endpoint(node_id, endpoint)?;
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

    fn peer_path_quality(
        &mut self,
        node_id: &NodeId,
    ) -> Result<
        Option<(
            rustynet_backend_api::PeerPathSample,
            rustynet_backend_api::PathHealth,
        )>,
        BackendError,
    > {
        if !self.engine.has_peer(node_id) {
            return Err(BackendError::invalid_input("peer is not configured"));
        }
        let latest_handshake = self.handshake_telemetry.latest_handshake(node_id);
        Ok(self.engine.peer_path_quality(node_id, latest_handshake))
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        if self.peers.remove(node_id).is_some() {
            self.engine.remove_peer(node_id);
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
        self.tun_lifecycle
            .reconcile_exit_mode(self.current_exit_mode, mode)?;
        self.current_exit_mode = mode;
        Ok(())
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
                    "linux userspace-shared authoritative transport round trip rejected because another round trip is already in flight",
                ));
            }
            self.reject_round_trip_target(remote_addr)?;

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
        // Data backlog: the last poll pass consumed its full budget, so more
        // packets are likely already queued — re-poll immediately. Commands
        // are still drained first in the worker loop, so the per-pass budgets
        // keep their DoS-fairness role; only the idle sleep is skipped.
        if self.udp_budget_exhausted || self.tun_budget_exhausted {
            return Duration::ZERO;
        }
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
        // Take the scratch out of `self` for the pass so the engine call can
        // borrow `self` mutably while the payload slice stays alive.
        let mut scratch = std::mem::take(&mut self.udp_recv_scratch);
        let result = self.poll_authoritative_socket_with(&mut scratch);
        self.udp_recv_scratch = scratch;
        result
    }

    fn poll_authoritative_socket_with(&mut self, scratch: &mut [u8]) -> Result<(), BackendError> {
        let mut drained = 0usize;
        for _ in 0..MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK {
            let Some((len, remote_addr)) = self.authoritative_socket.try_recv_into(scratch)? else {
                break;
            };
            drained += 1;
            let payload = &scratch[..len];
            if self.try_deliver_round_trip_response(remote_addr, payload)? {
                continue;
            }

            let local_addr = self.authoritative_socket.local_addr()?;
            let outcome = self.engine.process_inbound_ciphertext(
                remote_addr,
                local_addr,
                payload,
                self.authoritative_socket.transport_generation(),
            )?;
            self.apply_engine_processing_outcome(outcome)?;
        }
        self.udp_budget_exhausted = drained == MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK;
        Ok(())
    }

    fn poll_tun_device(&mut self) -> Result<(), BackendError> {
        let mut scratch = std::mem::take(&mut self.tun_recv_scratch);
        let result = self.poll_tun_device_with(&mut scratch);
        self.tun_recv_scratch = scratch;
        result
    }

    fn poll_tun_device_with(&mut self, scratch: &mut [u8]) -> Result<(), BackendError> {
        let mut drained = 0usize;
        for _ in 0..MAX_TUN_PACKETS_PER_TICK {
            let Some(len) = self.tun_device.recv_packet_into(scratch)? else {
                break;
            };
            drained += 1;
            let packet = &scratch[..len];
            let outcome = match self
                .engine
                .inject_plaintext_packet(packet, self.authoritative_socket.transport_generation())
            {
                Ok(outcome) => outcome,
                Err(err) if should_drop_tun_plaintext_packet_error(&err) => continue,
                Err(err) => return Err(err),
            };
            self.apply_engine_processing_outcome(outcome)?;
        }
        self.tun_budget_exhausted = drained == MAX_TUN_PACKETS_PER_TICK;
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
            "linux userspace-shared authoritative transport round trip to {remote_addr} timed out"
        )));
    }

    fn fail_outstanding_round_trip(&mut self, err: BackendError) {
        if let Some(outstanding) = self.outstanding_round_trip.take() {
            let _ = outstanding.reply.send(Err(err));
        }
    }

    fn reject_round_trip_target(&self, remote_addr: SocketAddr) -> Result<(), BackendError> {
        let matches_peer_endpoint = self.engine.has_endpoint(remote_addr);
        if matches_peer_endpoint {
            return Err(BackendError::invalid_input(
                "linux userspace-shared authoritative transport round trip target matches a configured peer endpoint",
            ));
        }
        Ok(())
    }

    fn try_deliver_round_trip_response(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<bool, BackendError> {
        let Some(outstanding) = self.outstanding_round_trip.as_ref() else {
            return Ok(false);
        };
        if remote_addr != outstanding.remote_addr {
            return Ok(false);
        }
        if self.authoritative_socket.transport_generation() != outstanding.transport_generation {
            return Ok(false);
        }

        let local_addr = self.authoritative_socket.local_addr()?;
        let response = AuthoritativeTransportResponse {
            local_addr,
            remote_addr,
            // Owned copy only on the (rare) round-trip match path; data
            // frames stay borrowed from the receive scratch.
            payload: payload.to_vec(),
        };
        let outstanding = self
            .outstanding_round_trip
            .take()
            .expect("outstanding round trip should still exist");
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
        outcome: super::engine::EngineProcessingOutcome,
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

fn should_drop_tun_plaintext_packet_error(err: &BackendError) -> bool {
    err.kind == BackendErrorKind::InvalidInput
        && matches!(
            err.message.as_str(),
            "plaintext packet does not contain a valid IPv4/IPv6 destination address"
                | "no configured peer allowed IP matches the plaintext packet destination"
        )
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
    tun_device: TunDevice,
    authoritative_socket: AuthoritativeSocket,
    engine: UserspaceEngine,
    tun_lifecycle: SharedTunLifecycle,
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
        udp_recv_scratch: vec![0u8; RECV_SCRATCH_BYTES],
        tun_recv_scratch: vec![0u8; RECV_SCRATCH_BYTES],
        udp_budget_exhausted: false,
        tun_budget_exhausted: false,
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
                                "linux userspace-shared runtime worker command channel disconnected during authoritative transport processing",
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
        "linux userspace-shared runtime worker exited while an authoritative transport round trip was still in flight",
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
        RuntimeRequest::PeerPathQuality { node_id, reply } => {
            let _ = reply.send(state.peer_path_quality(&node_id));
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
                "linux userspace-shared authoritative transport round trip canceled during backend shutdown",
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

    use base64::prelude::*;
    use rustynet_backend_api::{NodeId, RuntimeContext};

    use super::*;
    use crate::userspace_shared::engine::UserspaceEngine;
    use crate::userspace_shared::socket::AuthoritativeSocket;
    use crate::userspace_shared::tun::{
        SharedTunLifecycle, TestTunLifecycle, TunDevice, TunTestState,
    };

    #[test]
    fn linux_runtime_authoritative_socket_poll_is_budgeted_per_tick() {
        let (mut state, _tun_state, _private_key) = test_runtime_state("rn-test0");
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
    fn linux_runtime_tun_poll_is_budgeted_per_tick() {
        let (mut state, tun_state, _private_key) = test_runtime_state("rn-test1");
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

    fn test_runtime_state(
        interface_name: &str,
    ) -> (RuntimeState, TunTestState, tempfile::NamedTempFile) {
        let context = RuntimeContext {
            local_node: NodeId::new("linux-node").expect("valid node id"),
            interface_name: interface_name.to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.2/32".to_owned(),
        };
        let tun_state = TunTestState::default();
        let tun_device = TunDevice::test_handle(tun_state.clone());
        let tun_lifecycle = SharedTunLifecycle::new(Box::new(TestTunLifecycle::new()));
        let authoritative_socket = AuthoritativeSocket::bind(0).expect("authoritative bind");
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
                udp_recv_scratch: vec![0u8; RECV_SCRATCH_BYTES],
                tun_recv_scratch: vec![0u8; RECV_SCRATCH_BYTES],
                udp_budget_exhausted: false,
                tun_budget_exhausted: false,
            },
            tun_state,
            private_key,
        )
    }

    fn write_private_key(bytes: [u8; 32]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp key file should be created");
        writeln!(file, "{}", BASE64_STANDARD.encode(bytes)).expect("private key should be written");
        file
    }

    fn loopback_target(local_addr: SocketAddr) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], local_addr.port()))
    }
}
