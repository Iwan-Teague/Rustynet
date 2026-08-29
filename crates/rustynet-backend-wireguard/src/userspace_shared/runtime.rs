use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendError, BackendErrorKind,
    ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint, TunnelStats,
};

use super::engine::{
    ConfigurePeerDisposition, EngineIoSink, RecordedPeerCiphertextIngress,
    RecordedTunnelPlaintextPacket, UserspaceEngine,
};
use super::handshake::HandshakeTelemetry;
use super::socket::{AUTHORITATIVE_TRANSPORT_LABEL, AuthoritativeSocket};
use super::tun::{SharedTunLifecycle, TunDevice};

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Cadence for driving boringtun's periodic timers. WireGuard rounds its own
/// timers to one second (see `Tunn::update_timers`), so ticking faster buys
/// nothing and ticking slower delays keepalives and rekey.
const PEER_TIMER_TICK_INTERVAL: Duration = Duration::from_secs(1);
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

/// Concrete [`EngineIoSink`] wired to the real authoritative UDP socket and
/// TUN device: ciphertext is sent via [`AuthoritativeSocket::send_to`],
/// plaintext is written via [`TunDevice::send_packet`], both immediately and
/// borrowed — no per-frame copy or allocation. `local_addr` /
/// `transport_generation` are captured once per engine call (matching the
/// single snapshot the previous `apply_engine_processing_outcome` took
/// before its two apply loops) rather than re-queried per frame.
struct RuntimeIoSink<'a> {
    authoritative_socket: &'a AuthoritativeSocket,
    tun_device: &'a TunDevice,
    local_addr: SocketAddr,
    transport_generation: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    recorded_peer_ciphertext_egress: &'a mut Vec<RecordedPeerCiphertextEgress>,
}

impl EngineIoSink for RuntimeIoSink<'_> {
    fn send_ciphertext(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), BackendError> {
        // Unbounded-growth guard: `recorded_peer_ciphertext_egress` is read only
        // by `DebugRecordedPeerCiphertextEgress` (cfg(test)). Persisting every
        // outbound ciphertext frame in production would grow without bound and
        // keep a peer's ciphertext history in memory for the process lifetime.
        // Record BEFORE attempting the send (matching the previous
        // `apply_engine_processing_outcome` ordering) so a packet whose send
        // fails is still visible in the test recording.
        #[cfg(test)]
        self.recorded_peer_ciphertext_egress
            .push(RecordedPeerCiphertextEgress {
                local_addr: self.local_addr,
                remote_addr,
                payload: payload.to_vec(),
                transport_generation: self.transport_generation,
            });
        #[cfg(not(test))]
        {
            let _ = (self.local_addr, self.transport_generation);
        }
        // Dataplane egress is loss-tolerant by protocol design: a datagram the
        // OS transiently refuses (host firewall EPERM, link flap, ICMP
        // reflection) is DROPPED here rather than surfaced, because an error on
        // this path exits the worker loop and a 35s firewall block then
        // escalates to a permanently-restricted node (observed live
        // 2026-08-26). Structural socket failures still propagate.
        self.authoritative_socket
            .send_to_dataplane(remote_addr, payload)
            .map(|_delivered| ())
    }

    fn write_plaintext(&mut self, payload: &[u8]) -> Result<(), BackendError> {
        self.tun_device.send_packet(payload)
    }
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
        let worker_exit_cause = Arc::new(Mutex::new(None));
        let worker_exit_cause_for_thread = worker_exit_cause.clone();
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
                    worker_exit_cause: worker_exit_cause_for_thread,
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
                worker_exit_cause,
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
    /// WHY the worker exited, recorded at the exit site (first writer wins).
    /// Before this existed the cause was discarded unless a round trip was in
    /// flight, so a live incident surfaced only as "dropped a reply" with the
    /// actual error (a firewalled send) invisible (2026-08-26).
    worker_exit_cause: Arc<Mutex<Option<String>>>,
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
            self.worker_gone_error("linux userspace-shared runtime worker is unavailable")
        })?;
        reply_rx.recv().map_err(|_| {
            self.worker_gone_error("linux userspace-shared runtime worker dropped a reply")
        })?
    }

    /// Build the worker-gone error, appending the recorded exit cause when one
    /// exists. `is_runtime_worker_unavailable` matches these messages by
    /// PREFIX, so the appended cause keeps the recovery path intact while the
    /// operator finally sees WHY the worker died (on 2026-08-26 the cause — a
    /// firewalled send — was discarded, and root-causing it took a guest
    /// journal excavation).
    fn worker_gone_error(&self, base: &str) -> BackendError {
        let cause = self
            .worker_exit_cause
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        match cause {
            Some(cause) => BackendError::internal(format!("{base}: worker exit cause: {cause}")),
            None => BackendError::internal(base),
        }
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
    // Last time boringtun's periodic timers were driven. WireGuard's timer
    // resolution is one second, so the worker ticks them at that cadence
    // rather than on every poll pass.
    last_peer_timer_tick: Instant,
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
        // Clear the handshake record only when the session was genuinely
        // rebuilt. `Replaced` means a new `Tunn` exists, so any earlier
        // timestamp belongs to a dead session and keeping it would make
        // `handshake_fresh` lie about a peer that has not completed a handshake
        // on its current session.
        //
        // `Unchanged` and `EndpointMoved` are the opposite case and must NOT
        // clear: nothing was rebuilt, the live session is still the one that
        // produced that timestamp, and a peer that merely roamed has not stopped
        // being handshaked. Before `Unchanged` existed, every reconcile of an unchanged
        // peer landed here and wiped the record, which is why liveness read dead
        // on nodes that were passing traffic (QH-51).
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
        let local_addr = self.authoritative_socket.local_addr()?;
        let transport_generation = self.authoritative_socket.transport_generation();
        let Self {
            engine,
            authoritative_socket,
            tun_device,
            recorded_peer_ciphertext_egress,
            handshake_telemetry,
            ..
        } = self;
        let mut sink = RuntimeIoSink {
            authoritative_socket: &*authoritative_socket,
            tun_device: &*tun_device,
            local_addr,
            transport_generation,
            recorded_peer_ciphertext_egress,
        };
        let observed_handshake =
            engine.initiate_handshake(node_id, transport_generation, force_resend, &mut sink)?;
        if let Some((node_id, observed_unix)) = observed_handshake {
            handshake_telemetry.record_authenticated_handshake(&node_id, observed_unix);
        }
        Ok(())
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

    /// Drive boringtun's periodic timers for every peer, at most once per
    /// `PEER_TIMER_TICK_INTERVAL`.
    ///
    /// Nothing drove these before. `Tunn::update_timers` advances boringtun's
    /// internal clock, and because every other timer is stored relative to it,
    /// leaving it frozen made `time_since_last_handshake` grow without bound:
    /// a peer that had just handshaked still reported an ancient handshake and
    /// never counted as live. It also suppressed persistent keepalives (so NAT
    /// bindings were left to expire) and the periodic rekey.
    fn poll_peer_timers(&mut self) -> Result<(), BackendError> {
        if self.last_peer_timer_tick.elapsed() < PEER_TIMER_TICK_INTERVAL {
            return Ok(());
        }
        self.last_peer_timer_tick = Instant::now();

        let local_addr = self.authoritative_socket.local_addr()?;
        let transport_generation = self.authoritative_socket.transport_generation();
        let Self {
            engine,
            authoritative_socket,
            tun_device,
            recorded_peer_ciphertext_egress,
            handshake_telemetry,
            ..
        } = self;
        let mut sink = RuntimeIoSink {
            authoritative_socket: &*authoritative_socket,
            tun_device: &*tun_device,
            local_addr,
            transport_generation,
            recorded_peer_ciphertext_egress,
        };
        for (node_id, observed_unix) in
            engine.update_peer_timers(transport_generation, &mut sink)?
        {
            handshake_telemetry.record_authenticated_handshake(&node_id, observed_unix);
        }
        Ok(())
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
            let transport_generation = self.authoritative_socket.transport_generation();
            let Self {
                engine,
                authoritative_socket,
                tun_device,
                recorded_peer_ciphertext_egress,
                handshake_telemetry,
                ..
            } = &mut *self;
            let mut sink = RuntimeIoSink {
                authoritative_socket: &*authoritative_socket,
                tun_device: &*tun_device,
                local_addr,
                transport_generation,
                recorded_peer_ciphertext_egress,
            };
            let observed_handshake = engine.process_inbound_ciphertext(
                remote_addr,
                local_addr,
                payload,
                transport_generation,
                &mut sink,
            )?;
            if let Some((node_id, observed_unix)) = observed_handshake {
                handshake_telemetry.record_authenticated_handshake(&node_id, observed_unix);
            }
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
            let transport_generation = self.authoritative_socket.transport_generation();
            let Self {
                engine,
                authoritative_socket,
                tun_device,
                recorded_peer_ciphertext_egress,
                handshake_telemetry,
                ..
            } = &mut *self;
            let local_addr = authoritative_socket.local_addr()?;
            let mut sink = RuntimeIoSink {
                authoritative_socket: &*authoritative_socket,
                tun_device: &*tun_device,
                local_addr,
                transport_generation,
                recorded_peer_ciphertext_egress,
            };
            let observed_handshake =
                match engine.inject_plaintext_packet(packet, transport_generation, &mut sink) {
                    Ok(observed) => observed,
                    Err(err) if should_drop_tun_plaintext_packet_error(&err) => continue,
                    Err(err) => return Err(err),
                };
            if let Some((node_id, observed_unix)) = observed_handshake {
                handshake_telemetry.record_authenticated_handshake(&node_id, observed_unix);
            }
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
        let local_addr = self.authoritative_socket.local_addr()?;
        let transport_generation = self.authoritative_socket.transport_generation();
        let Self {
            engine,
            authoritative_socket,
            tun_device,
            recorded_peer_ciphertext_egress,
            handshake_telemetry,
            ..
        } = self;
        let mut sink = RuntimeIoSink {
            authoritative_socket: &*authoritative_socket,
            tun_device: &*tun_device,
            local_addr,
            transport_generation,
            recorded_peer_ciphertext_egress,
        };
        let observed_handshake =
            engine.inject_plaintext_packet(&packet, transport_generation, &mut sink)?;
        if let Some((node_id, observed_unix)) = observed_handshake {
            handshake_telemetry.record_authenticated_handshake(&node_id, observed_unix);
        }
        Ok(())
    }

    #[cfg(test)]
    fn queue_tun_plaintext_packet_for_test(&mut self, packet: Vec<u8>) -> Result<(), BackendError> {
        self.tun_device.queue_inbound_packet_for_test(packet)
    }

    #[cfg(test)]
    fn recorded_tun_outbound_packets(&self) -> Result<Vec<Vec<u8>>, BackendError> {
        self.tun_device.recorded_outbound_packets_for_test()
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
    worker_exit_cause: Arc<Mutex<Option<String>>>,
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
        worker_exit_cause,
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
        last_peer_timer_tick: Instant::now(),
    };

    match state.authoritative_identity() {
        Ok(identity) => {
            if ready_tx.send(Ok(identity)).is_err() {
                record_worker_exit_cause(
                    &worker_exit_cause,
                    "runtime control dropped the readiness channel before the worker reported ready",
                );
                mark_worker_exit(&test_state, &worker_alive);
                return;
            }
        }
        Err(err) => {
            record_worker_exit_cause(
                &worker_exit_cause,
                format!(
                    "startup failed resolving authoritative identity: {}",
                    err.message
                ),
            );
            let _ = ready_tx.send(Err(err));
            mark_worker_exit(&test_state, &worker_alive);
            return;
        }
    }

    loop {
        match command_rx.recv_timeout(state.next_wait_timeout()) {
            Ok(request) => {
                if !handle_request(&mut state, request) {
                    record_worker_exit_cause(&worker_exit_cause, "shutdown requested");
                    break;
                }
                loop {
                    match command_rx.try_recv() {
                        Ok(request) => {
                            if !handle_request(&mut state, request) {
                                record_worker_exit_cause(&worker_exit_cause, "shutdown requested");
                                mark_worker_exit(&test_state, &worker_alive);
                                return;
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            record_worker_exit_cause(
                                &worker_exit_cause,
                                "command channel disconnected during authoritative transport processing",
                            );
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
            Err(RecvTimeoutError::Disconnected) => {
                record_worker_exit_cause(&worker_exit_cause, "command channel disconnected");
                break;
            }
        }

        if let Err(err) = state.poll_peer_timers() {
            record_worker_exit_cause(
                &worker_exit_cause,
                format!("peer timer tick failed: {}", err.message),
            );
            state.fail_outstanding_round_trip(err);
            mark_worker_exit(&test_state, &worker_alive);
            return;
        }

        if let Err(err) = state.poll_authoritative_socket() {
            record_worker_exit_cause(
                &worker_exit_cause,
                format!("authoritative socket poll failed: {}", err.message),
            );
            state.fail_outstanding_round_trip(err);
            break;
        }
        if let Err(err) = state.poll_tun_device() {
            record_worker_exit_cause(
                &worker_exit_cause,
                format!("tun device poll failed: {}", err.message),
            );
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

/// Record WHY the worker exited. First writer wins: the first error is the one
/// that initiated the exit; later fallthrough sites must not overwrite it. A
/// poisoned lock is skipped — this is diagnostics, never worth a panic.
fn record_worker_exit_cause(slot: &Mutex<Option<String>>, cause: impl Into<String>) {
    if let Ok(mut guard) = slot.lock() {
        guard.get_or_insert_with(|| cause.into());
    }
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

    #[test]
    fn worker_loop_drives_boringtun_peer_timers() {
        // Regression pin: nothing in this workspace ever called
        // `Tunn::update_timers`. That is boringtun's clock driver, and because
        // every other timer is stored relative to it, leaving it frozen made
        // `time_since_last_handshake` grow without bound -- a peer that had
        // just completed a handshake still reported an ancient handshake, so
        // `path_live_peer_count` stayed 0 while traffic flowed cleanly at
        // 6.94 Mbit/s on a real cross-network path. It also suppressed
        // persistent keepalives (leaving NAT bindings to expire) and the
        // periodic rekey.
        let source = include_str!("runtime.rs");
        assert!(
            source.contains("fn poll_peer_timers(&mut self)"),
            "linux userspace-shared runtime must define the peer timer tick"
        );
        assert!(
            source.contains("state.poll_peer_timers()"),
            "linux userspace-shared worker loop must DRIVE the peer timer tick; \
             defining it without calling it leaves boringtun's clock frozen"
        );
        assert!(
            source.contains("engine.update_peer_timers(transport_generation, &mut sink)"),
            "linux peer timer tick must call through to the engine's update_peer_timers"
        );
        assert!(
            source.contains("PEER_TIMER_TICK_INTERVAL"),
            "linux peer timer tick must be paced by an explicit interval"
        );
    }
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

        // The datagrams cross a real loopback socket, so arrival is not
        // synchronous with send_to: asserting the FIRST poll ingests exactly
        // the budget raced the kernel and flaked on loaded CI runners. The
        // budget property is that no single poll may ingest more than
        // MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK; poll until everything has
        // drained (bounded), asserting the per-poll cap on every iteration.
        let expected_total = MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK + 3;
        let mut seen = 0usize;
        let mut capped_polls = 0usize;
        for _ in 0..200 {
            state
                .poll_authoritative_socket()
                .expect("socket poll should succeed");
            let now = state.recorded_peer_ciphertext_ingress().len();
            let delta = now - seen;
            assert!(
                delta <= MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK,
                "a single poll ingested {delta} datagrams, exceeding the                  per-tick budget of {MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK}"
            );
            if delta == MAX_AUTHORITATIVE_DATAGRAMS_PER_TICK {
                capped_polls += 1;
            }
            seen = now;
            if seen == expected_total {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            seen, expected_total,
            "all datagrams must eventually drain within the poll budget"
        );
        assert!(
            capped_polls >= 1,
            "with budget+3 datagrams in flight at least one poll must hit              the cap, proving the budget actually split the drain"
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
    // ---- QH-51: network-flap recovery — reconcile must not churn sessions ----
    //
    // After a network flap the reconcile pass re-applies every peer config.
    // While ANY re-configure of an existing peer reported `Replaced`, each pass
    // tore down the live session and, seeing `Replaced`, cleared that peer's
    // recorded handshake — so liveness read permanently dead on nodes that were
    // passing traffic (QH-51). These pin the RUNTIME half of the contract (the
    // engine's disposition/session pins live in engine.rs): the recorded
    // handshake SURVIVES an unchanged or roaming re-apply, and is CLEARED only
    // when the peer's material genuinely changed, so a stale timestamp can
    // never be carried onto a new session and make `handshake_fresh` lie.

    #[test]
    fn linux_runtime_peer_timer_tick_survives_firewalled_egress() {
        // Live incident 2026-08-26 (live_network_flap_validation): an nft
        // REJECT on the WG port made the keepalive send fail with EPERM, the
        // error escaped poll_peer_timers, the worker loop exited (silently),
        // the replacement worker died the same way during recovery replay, and
        // five failed reconciles latched the node PERMANENTLY restricted — a
        // 35-second firewall block became an unrecoverable dataplane.
        //
        // A broadcast endpoint without SO_BROADCAST is refused with EACCES ->
        // PermissionDenied, the same classifier bucket as EPERM: every send
        // the timer tick emits toward this peer is refused, exactly like a
        // firewalled egress. The tick must ride it out.
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let (mut state, _tun_state, _private_key) = test_runtime_state("rn-test-flap");
        // Loopback-bound: a broadcast send from a wildcard-bound socket is not
        // refused on macOS, and this module's tests also run on the macOS CI
        // leg. From loopback, 255.255.255.255 without SO_BROADCAST is refused
        // with EACCES on both OSes, so the refusal is deterministic.
        state.authoritative_socket = AuthoritativeSocket::from_bound_socket(
            UdpSocket::bind("127.0.0.1:0").expect("loopback bind"),
        )
        .expect("adopt loopback socket");
        let node_id = NodeId::new("peer-firewalled").expect("valid node id");
        state
            .configure_peer(PeerConfig {
                node_id: node_id.clone(),
                endpoint: SocketEndpoint {
                    addr: "255.255.255.255".parse().expect("valid ip"),
                    port: 51820,
                },
                public_key: [22u8; 32],
                allowed_ips: vec!["100.64.0.22/32".to_owned()],
                persistent_keepalive_secs: Some(1),
            })
            .expect("configure should succeed even when egress is refused");

        // Queue plaintext routed to that peer: encapsulation has no session,
        // so the engine emits a handshake initiation through the sink — a real
        // refused send on the exact seam that killed the worker.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[3] = 20; // total length
        packet[8] = 64; // TTL
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]); // src: local
        packet[16..20].copy_from_slice(&[100, 64, 0, 22]); // dst: the peer
        state
            .queue_tun_plaintext_packet_for_test(packet)
            .expect("test packet should queue");
        state
            .poll_tun_device()
            .expect("a refused handshake-initiation send must not kill the tun poll");
        assert!(
            !state.recorded_peer_ciphertext_egress.is_empty(),
            "the queued plaintext must have provoked an egress send attempt — \
             without one this test proves nothing"
        );

        // Drive several timer ticks past the pacing interval so handshake
        // initiations / keepalives are actually attempted (and refused).
        for _ in 0..3 {
            state.last_peer_timer_tick = Instant::now()
                .checked_sub(PEER_TIMER_TICK_INTERVAL * 2)
                .expect("clock arithmetic");
            state
                .poll_peer_timers()
                .expect("a refused egress send must not kill the timer tick");
        }
    }

    #[test]
    fn linux_runtime_worker_exit_cause_surfaces_in_control_errors() {
        // 2026-08-26: the worker died on a firewalled send and the CAUSE was
        // discarded — `fail_outstanding_round_trip` only forwards the error
        // when a round trip is in flight — so the daemon journal showed hours
        // of bare "dropped a reply" and root-causing took a guest journal
        // excavation. Pin: the recorded exit cause must surface in the
        // control's worker-gone errors, as a SUFFIX (the recovery matcher
        // `is_runtime_worker_unavailable` matches these messages by prefix).
        let context = RuntimeContext {
            local_node: NodeId::new("linux-diag-node").expect("valid node id"),
            interface_name: "rn-test-diag".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.9/32".to_owned(),
        };
        let tun_state = TunTestState::default();
        let tun_device = TunDevice::test_handle(tun_state.clone());
        let tun_lifecycle = SharedTunLifecycle::new(Box::new(TestTunLifecycle::new()));
        let authoritative_socket = AuthoritativeSocket::bind(0).expect("authoritative bind");
        let private_key = write_private_key([9; 32]);
        let engine = UserspaceEngine::from_private_key_file(private_key.path())
            .expect("engine should load key");
        let runtime = RunningUserspaceRuntime::start(
            "rn-test-diag",
            context,
            tun_device,
            authoritative_socket,
            engine,
            tun_lifecycle,
        )
        .expect("runtime should start");

        tun_state.set_next_recv_error("injected tun failure for the diagnosability pin");
        let control = runtime.control().clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        while control.is_worker_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !control.is_worker_alive(),
            "the injected tun recv error must kill the worker"
        );

        let err = control
            .current_peer_endpoint(NodeId::new("any-peer").expect("valid node id"))
            .expect_err("a request against a dead worker must error");
        assert!(
            err.message
                .starts_with("linux userspace-shared runtime worker"),
            "prefix must stay matchable by is_runtime_worker_unavailable: {}",
            err.message
        );
        assert!(
            err.message.contains("worker exit cause:")
                && err
                    .message
                    .contains("injected tun failure for the diagnosability pin"),
            "the recorded exit cause must surface in the control error: {}",
            err.message
        );
    }

    #[test]
    fn linux_runtime_identical_reconfigure_keeps_recorded_handshake() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let (mut state, _tun_state, _private_key) = test_runtime_state("rn-test3");
        let node_id = NodeId::new("peer-flap").expect("valid node id");
        let config = PeerConfig {
            node_id: node_id.clone(),
            endpoint: SocketEndpoint {
                addr: "203.0.113.20".parse().expect("valid ip"),
                port: 51820,
            },
            public_key: [21u8; 32],
            allowed_ips: vec!["100.64.0.20/32".to_owned()],
            persistent_keepalive_secs: Some(25),
        };

        state
            .configure_peer(config.clone())
            .expect("first configure");
        let handshake_unix = 1_700_000_000;
        state
            .handshake_telemetry
            .record_authenticated_handshake(&node_id, handshake_unix);

        // The flap lifts; the reconcile pass re-applies the SAME material.
        state.configure_peer(config).expect("identical re-apply");

        assert_eq!(
            state.handshake_telemetry.latest_handshake(&node_id),
            Some(handshake_unix),
            "an unchanged re-apply must not wipe the recorded handshake"
        );
    }

    #[test]
    fn linux_runtime_endpoint_only_reconfigure_keeps_recorded_handshake_and_moves_the_peer() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let (mut state, _tun_state, _private_key) = test_runtime_state("rn-test4");
        let node_id = NodeId::new("peer-roam").expect("valid node id");
        let at = |port: u16| PeerConfig {
            node_id: node_id.clone(),
            endpoint: SocketEndpoint {
                addr: "203.0.113.21".parse().expect("valid ip"),
                port,
            },
            public_key: [22u8; 32],
            allowed_ips: vec!["100.64.0.21/32".to_owned()],
            persistent_keepalive_secs: None,
        };

        state.configure_peer(at(51820)).expect("first configure");
        let handshake_unix = 1_700_000_100;
        state
            .handshake_telemetry
            .record_authenticated_handshake(&node_id, handshake_unix);

        // Roaming is an endpoint-only change: the session is keyed by the
        // static keys, so the peer moves in place and its record stays.
        state.configure_peer(at(51999)).expect("roaming re-apply");

        assert_eq!(
            state.handshake_telemetry.latest_handshake(&node_id),
            Some(handshake_unix),
            "a roaming re-apply must not wipe the recorded handshake"
        );
        assert_eq!(
            state
                .current_peer_endpoint(&node_id)
                .expect("peer configured"),
            Some(SocketEndpoint {
                addr: "203.0.113.21".parse().expect("valid ip"),
                port: 51999,
            }),
            "the peer must actually move to the new endpoint"
        );
    }

    #[test]
    fn linux_runtime_replaced_peer_material_clears_recorded_handshake() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let base = |pubkey: u8, cidr: &str| PeerConfig {
            node_id: NodeId::new("peer-rekey").expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.22".parse().expect("valid ip"),
                port: 51820,
            },
            public_key: [pubkey; 32],
            allowed_ips: vec![cidr.to_owned()],
            persistent_keepalive_secs: None,
        };
        let record_handshake = |state: &mut RuntimeState, node_id: &NodeId| {
            state
                .handshake_telemetry
                .record_authenticated_handshake(node_id, 1_700_000_200);
        };

        for (label, changed) in [
            ("public key", base(9, "100.64.0.22/32")),
            ("allowed ips", base(4, "100.64.0.23/32")),
        ] {
            let (mut state, _tun_state, _private_key) = test_runtime_state("rn-test5");
            let node_id = NodeId::new("peer-rekey").expect("valid node id");
            state
                .configure_peer(base(4, "100.64.0.22/32"))
                .expect("first configure");
            record_handshake(&mut state, &node_id);

            // Material that ACTUALLY changed rebuilds the session; keeping the
            // old timestamp would attach it to a session that never produced
            // it and make `handshake_fresh` lie.
            state.configure_peer(changed).expect("changed re-apply");

            assert_eq!(
                state.handshake_telemetry.latest_handshake(&node_id),
                None,
                "a changed {label} must clear the stale handshake record"
            );
        }
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
                last_peer_timer_tick: Instant::now(),
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

    // Fail-closed pin for `reject_round_trip_target`: an authoritative
    // transport round trip aimed at a CONFIGURED peer's endpoint must be
    // refused — that check is exactly `engine.has_endpoint`, which since the
    // P4 endpoint reverse index is a `contains_key` on the index rather than
    // the old linear `peer_states` scan. This test pins that the fail-closed
    // behavior survived the index swap, and that removing the peer retires
    // the indexed answer in lockstep (the check must stop firing).
    #[test]
    fn authoritative_round_trip_rejects_a_configured_peer_endpoint_fail_closed() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};

        let (mut state, _tun_state, _key) = test_runtime_state("utun-reject-rt");
        let peer_endpoint: SocketAddr = "203.0.113.77:51820".parse().expect("addr");
        let node_id = NodeId::new("peer-target").expect("node id");
        state
            .engine
            .configure_peer(&PeerConfig {
                node_id: node_id.clone(),
                endpoint: SocketEndpoint {
                    addr: peer_endpoint.ip(),
                    port: peer_endpoint.port(),
                },
                public_key: [0x33; 32],
                allowed_ips: vec!["100.64.11.0/24".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("peer configures");

        // With the peer configured, a round trip at its endpoint must be
        // rejected by the endpoint-match check specifically.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        state.start_authoritative_round_trip(
            peer_endpoint,
            b"probe".to_vec(),
            std::time::Duration::from_millis(100),
            tx,
        );
        let err = rx
            .recv()
            .expect("reply delivered")
            .expect_err("round trip at a peer endpoint must be rejected");
        assert!(
            err.to_string()
                .contains("matches a configured peer endpoint"),
            "unexpected rejection reason: {err}"
        );

        // After the peer is removed, the same target must no longer be
        // rejected by THIS check — the index entry is retired in lockstep
        // with `peer_states`. The round trip may then proceed (no worker is
        // running to deliver a response) or fail on the socket; both are
        // fine, only the endpoint-match rejection would be wrong. A
        // recv_timeout bounds the wait because with no worker loop nothing
        // answers the timeout expiry either.
        assert!(state.engine.remove_peer(&node_id));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        state.start_authoritative_round_trip(
            peer_endpoint,
            b"probe".to_vec(),
            std::time::Duration::from_millis(100),
            tx,
        );
        match rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(err)) => assert!(
                !err.to_string()
                    .contains("matches a configured peer endpoint"),
                "endpoint-match rejection must not fire after the peer was removed: {err}"
            ),
        }
    }
}
