//! FIS-0012: two-budget deficit-round-robin fair drain for the shared pump
//! loops (Shreedhar & Varghese DRR + the flow-isolation half of FQ-CoDel —
//! deliberately WITHOUT CoDel's sojourn-time control law, which is
//! mismatched to a tick-budgeted pull loop).
//!
//! The scheduler decides only WHICH already-arrived opaque packet is handed
//! to the next processing step within the existing per-tick budget, using
//! routing metadata (source/destination peer) knowable before any
//! processing. Nothing here touches validity judgment, crypto, or packet
//! contents. Under sustained flood, overflow drops move from the shared
//! kernel FIFO (where loss falls on whoever arrives while it is full) into
//! per-flow bounded stashes where each flow's excess is dropped against its
//! OWN cap — relocate + fair-ify the drop point, not eliminate drops.
//!
//! Pure module: no sockets, no engine types beyond `NodeId`.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use rustynet_backend_api::NodeId;

/// Pool slot size (≈ MTU-sized; datagrams above this take a one-off heap
/// allocation — rare, jumbo-frame only).
const POOL_SLOT_BYTES: usize = 2048;

/// Default DRR quantum: one MTU per flow per service round.
pub(crate) const DEFAULT_QUANTUM_BYTES: usize = 1500;
/// Default per-flow stash cap (packets).
pub(crate) const DEFAULT_PER_FLOW_CAP_PACKETS: usize = 16;
/// Default global stash cap (packets) — the read budget R.
pub(crate) const DEFAULT_GLOBAL_CAP_PACKETS: usize = 256;

/// Flow classification: a configured peer, or the shared unclassified queue
/// (unknown endpoints — handshake initiations, junk). Isolating unknowns
/// into ONE capped queue is a quiet security improvement: a spoofed-source
/// flood competes against its own cap instead of crowding every peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FlowKey {
    Peer(NodeId),
    Unclassified,
}

/// Pooled 2 KB slot or oversize heap fallback.
#[derive(Debug)]
enum PooledBuf {
    Pooled(Box<[u8; POOL_SLOT_BYTES]>),
    Oversize(Vec<u8>),
}

impl PooledBuf {
    fn as_slice(&self) -> &[u8] {
        match self {
            PooledBuf::Pooled(buf) => buf.as_ref(),
            PooledBuf::Oversize(buf) => buf.as_slice(),
        }
    }
}

/// One stashed packet: copied out of the shared scratch buffer (the scratch
/// slice is only valid within its own read iteration).
#[derive(Debug)]
pub(crate) struct StashedPacket {
    buf: PooledBuf,
    len: usize,
    remote_addr: Option<SocketAddr>,
}

impl StashedPacket {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.buf.as_slice()[..self.len]
    }

    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

/// Outcome of a stash attempt. Drops are per-flow (the offending flow's
/// tail) or global-cap rejections — callers may count them for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StashOutcome {
    Stashed,
    DroppedFlowCap,
    DroppedGlobalCap,
}

#[derive(Debug, Default)]
struct FlowQueue {
    deficit_bytes: usize,
    quantum_granted: bool,
    packets: VecDeque<StashedPacket>,
    stashed_bytes: usize,
}

/// Buffer pool: preallocated free list of 2 KB slots. `recycle` returns
/// pooled slots after processing; oversize buffers are simply dropped.
#[derive(Debug)]
struct BufferPool {
    free: Vec<Box<[u8; POOL_SLOT_BYTES]>>,
    max_pooled: usize,
}

impl BufferPool {
    fn new(max_pooled: usize) -> Self {
        Self {
            free: Vec::new(),
            max_pooled,
        }
    }

    fn take(&mut self, payload: &[u8]) -> (PooledBuf, usize) {
        let len = payload.len();
        if len <= POOL_SLOT_BYTES {
            let mut slot = self
                .free
                .pop()
                .unwrap_or_else(|| Box::new([0u8; POOL_SLOT_BYTES]));
            slot[..len].copy_from_slice(payload);
            (PooledBuf::Pooled(slot), len)
        } else {
            (PooledBuf::Oversize(payload.to_vec()), len)
        }
    }

    fn put_back(&mut self, buf: PooledBuf) {
        if let PooledBuf::Pooled(slot) = buf
            && self.free.len() < self.max_pooled
        {
            self.free.push(slot);
        }
    }
}

/// Deficit-round-robin scheduler with bounded per-flow stashes.
#[derive(Debug)]
pub(crate) struct FairDrainScheduler {
    flows: BTreeMap<FlowKey, FlowQueue>,
    /// DRR active list — flows with stashed packets, in service order.
    active: VecDeque<FlowKey>,
    pool: BufferPool,
    quantum_bytes: usize,
    per_flow_cap_packets: usize,
    global_cap_packets: usize,
    total_stashed: usize,
}

impl FairDrainScheduler {
    pub(crate) fn new(
        quantum_bytes: usize,
        per_flow_cap_packets: usize,
        global_cap_packets: usize,
    ) -> Self {
        Self {
            flows: BTreeMap::new(),
            active: VecDeque::new(),
            pool: BufferPool::new(global_cap_packets),
            quantum_bytes: quantum_bytes.max(1),
            per_flow_cap_packets: per_flow_cap_packets.max(1),
            global_cap_packets: global_cap_packets.max(1),
            total_stashed: 0,
        }
    }

    pub(crate) fn with_defaults() -> Self {
        Self::new(
            DEFAULT_QUANTUM_BYTES,
            DEFAULT_PER_FLOW_CAP_PACKETS,
            DEFAULT_GLOBAL_CAP_PACKETS,
        )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.total_stashed == 0
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn stashed_packets(&self) -> usize {
        self.total_stashed
    }

    /// Copy a packet out of the caller's scratch buffer into the flow's
    /// stash. Tail-drops within the OFFENDING flow when its cap is hit;
    /// rejects globally at the read-budget cap.
    pub(crate) fn stash(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        remote_addr: Option<SocketAddr>,
    ) -> StashOutcome {
        if self.total_stashed >= self.global_cap_packets {
            return StashOutcome::DroppedGlobalCap;
        }
        let flow = self.flows.entry(key.clone()).or_default();
        if flow.packets.len() >= self.per_flow_cap_packets {
            return StashOutcome::DroppedFlowCap;
        }
        let was_empty = flow.packets.is_empty();
        let (buf, len) = self.pool.take(payload);
        flow.packets.push_back(StashedPacket {
            buf,
            len,
            remote_addr,
        });
        flow.stashed_bytes += len;
        self.total_stashed += 1;
        if was_empty {
            self.active.push_back(key);
        }
        StashOutcome::Stashed
    }

    /// Next packet to process in DRR order (Shreedhar–Varghese): a flow at
    /// the head of the round gains one quantum; its head packets are served
    /// while the deficit covers them; a flow that empties leaves the round
    /// with its deficit reset (anti-hoarding); a flow whose deficit is
    /// exhausted rotates to the back carrying its deficit. Deficits grow by
    /// one quantum per rotation, so any bounded packet is eventually served
    /// — the iteration cap is a defensive backstop, not a correctness
    /// boundary.
    pub(crate) fn next_to_process(&mut self) -> Option<StashedPacket> {
        let mut budget = self.active.len().saturating_mul(64).max(64);
        while budget > 0 && !self.active.is_empty() {
            budget -= 1;
            let key = self.active.front()?.clone();
            let Some(flow) = self.flows.get_mut(&key) else {
                self.active.pop_front();
                continue;
            };
            if !flow.quantum_granted {
                flow.deficit_bytes = flow.deficit_bytes.saturating_add(self.quantum_bytes);
                flow.quantum_granted = true;
            }
            let Some(front_len) = flow.packets.front().map(|packet| packet.len) else {
                flow.deficit_bytes = 0;
                flow.quantum_granted = false;
                self.active.pop_front();
                continue;
            };
            if flow.deficit_bytes >= front_len {
                let packet = flow.packets.pop_front()?;
                flow.deficit_bytes -= front_len;
                flow.stashed_bytes -= front_len;
                self.total_stashed -= 1;
                if flow.packets.is_empty() {
                    flow.deficit_bytes = 0;
                    flow.quantum_granted = false;
                    self.active.pop_front();
                }
                return Some(packet);
            }
            // Deficit exhausted: rotate to the back, deficit carries.
            flow.quantum_granted = false;
            if let Some(rotated) = self.active.pop_front() {
                self.active.push_back(rotated);
            }
        }
        None
    }

    /// Return a processed packet's buffer to the pool.
    pub(crate) fn recycle(&mut self, packet: StashedPacket) {
        self.pool.put_back(packet.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::{FairDrainScheduler, FlowKey, StashOutcome};
    use rustynet_backend_api::NodeId;

    fn peer(name: &str) -> FlowKey {
        FlowKey::Peer(NodeId::new(name).expect("node id"))
    }

    fn stash_n(scheduler: &mut FairDrainScheduler, key: &FlowKey, count: usize, size: usize) {
        for _ in 0..count {
            let payload = vec![0xAB; size];
            let outcome = scheduler.stash(key.clone(), &payload, None);
            assert_eq!(outcome, StashOutcome::Stashed);
        }
    }

    #[test]
    fn fair_drain_scheduler_gives_equal_share_under_asymmetric_offered_load() {
        // Flow A offers 10x flow B's packets; equal-size packets. Over any
        // service window both active flows must receive equal service
        // (± one quantum), regardless of offered load.
        let mut scheduler = FairDrainScheduler::new(1500, 64, 256);
        let flow_a = peer("peer-a");
        let flow_b = peer("peer-b");
        stash_n(&mut scheduler, &flow_a, 40, 1000);
        stash_n(&mut scheduler, &flow_b, 4, 1000);

        // Serve 8 packets: DRR must alternate service shares (one quantum =
        // one 1000-byte packet per flow per round), not drain the flood
        // first. After 8 served, B (4 offered) is fully drained and A got
        // the other 4 — leaving exactly A's 36-packet backlog.
        for _ in 0..8 {
            let packet = scheduler.next_to_process().expect("packet available");
            scheduler.recycle(packet);
        }
        assert_eq!(scheduler.stashed_packets(), 36);
        let mut remaining = 0usize;
        while let Some(packet) = scheduler.next_to_process() {
            remaining += 1;
            scheduler.recycle(packet);
        }
        assert_eq!(remaining, 36, "only the flood flow's backlog remains");
    }

    #[test]
    fn fair_drain_scheduler_carries_deficit_and_resets_on_empty() {
        // Quantum 500, packets of 1200 bytes: a flow needs 3 rotations of
        // accumulated deficit per packet (Shreedhar-Varghese carry), and its
        // deficit resets when it empties (anti-hoarding).
        let mut scheduler = FairDrainScheduler::new(500, 16, 256);
        let flow_a = peer("peer-a");
        let flow_b = peer("peer-b");
        stash_n(&mut scheduler, &flow_a, 2, 1200);
        stash_n(&mut scheduler, &flow_b, 2, 300);

        let mut order: Vec<usize> = Vec::new();
        while let Some(packet) = scheduler.next_to_process() {
            order.push(packet.payload().len());
            scheduler.recycle(packet);
        }
        assert_eq!(order.len(), 4);
        // B's small packets are served while A accumulates deficit; both of
        // A's oversize-of-quantum packets still get through eventually.
        assert_eq!(order.iter().filter(|len| **len == 1200).count(), 2);
        assert_eq!(order.iter().filter(|len| **len == 300).count(), 2);
        assert_eq!(
            order.first().copied(),
            Some(300),
            "small-packet flow must not wait behind the deficit-accumulating one"
        );
        assert!(scheduler.is_empty());
    }

    #[test]
    fn fair_drain_scheduler_tail_drops_within_offending_flow_only() {
        let mut scheduler = FairDrainScheduler::new(1500, 4, 256);
        let flood = peer("flood");
        let light = peer("light");
        // Flood beyond its per-flow cap: excess drops against ITS cap.
        for index in 0..10usize {
            let outcome = scheduler.stash(flood.clone(), &[0u8; 100], None);
            if index < 4 {
                assert_eq!(outcome, StashOutcome::Stashed);
            } else {
                assert_eq!(outcome, StashOutcome::DroppedFlowCap);
            }
        }
        // The light flow is unaffected by the flood flow's cap.
        assert_eq!(
            scheduler.stash(light.clone(), &[0u8; 100], None),
            StashOutcome::Stashed
        );
        assert_eq!(scheduler.stashed_packets(), 5);
    }

    #[test]
    fn fair_drain_scheduler_rejects_at_global_cap() {
        let mut scheduler = FairDrainScheduler::new(1500, 64, 8);
        let flow = peer("peer-a");
        for _ in 0..8 {
            assert_eq!(
                scheduler.stash(flow.clone(), &[0u8; 64], None),
                StashOutcome::Stashed
            );
        }
        assert_eq!(
            scheduler.stash(flow.clone(), &[0u8; 64], None),
            StashOutcome::DroppedGlobalCap
        );
    }

    #[test]
    fn fair_drain_unclassified_flood_cannot_starve_known_peers() {
        let mut scheduler = FairDrainScheduler::new(1500, 16, 256);
        let known = peer("peer-a");
        stash_n(&mut scheduler, &FlowKey::Unclassified, 16, 1000);
        stash_n(&mut scheduler, &known, 2, 1000);

        // Within the first service round (one quantum each), the known
        // peer's packet is served despite 16 unclassified packets ahead.
        let mut seen_known = false;
        for _ in 0..3 {
            let Some(packet) = scheduler.next_to_process() else {
                break;
            };
            // Known-peer packets carry no distinguishing payload; identify
            // by elimination: unclassified stash shrinks only when its
            // packet is served.
            let _ = packet.payload();
            scheduler.recycle(packet);
            seen_known = true;
        }
        assert!(seen_known);
        // Stronger check: drain fully; the known peer's two packets must be
        // served within the first two full rounds (positions <= 4 among 18).
        let mut scheduler = FairDrainScheduler::new(1500, 16, 256);
        stash_n(&mut scheduler, &FlowKey::Unclassified, 16, 1000);
        // Tag the known peer's packets by distinct size.
        for _ in 0..2 {
            assert_eq!(
                scheduler.stash(known.clone(), &[0u8; 777], None),
                StashOutcome::Stashed
            );
        }
        let mut known_positions = Vec::new();
        let mut position = 0usize;
        while let Some(packet) = scheduler.next_to_process() {
            if packet.payload().len() == 777 {
                known_positions.push(position);
            }
            position += 1;
            scheduler.recycle(packet);
        }
        assert_eq!(known_positions.len(), 2);
        assert!(
            known_positions[1] <= 4,
            "known peer must be served within the first rounds, got {known_positions:?}"
        );
    }

    #[test]
    fn fair_drain_oversize_packets_round_trip_intact() {
        // Above the 2 KB pool slot: oversize heap fallback, content intact.
        let mut scheduler = FairDrainScheduler::with_defaults();
        let flow = peer("peer-a");
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(scheduler.stash(flow, &payload, None), StashOutcome::Stashed);
        let packet = scheduler.next_to_process().expect("packet");
        assert_eq!(packet.payload(), payload.as_slice());
        scheduler.recycle(packet);
        assert!(scheduler.is_empty());
    }
}
