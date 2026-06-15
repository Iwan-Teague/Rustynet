//! Fixed-work measurement probe for the control-plane reconcile hot
//! path: building the canonical signed payload of mesh state, hashing
//! it to a state root, and parsing it back. These run on the daemon's
//! 1 Hz reconcile tick (and on every membership apply), so the hex
//! encoder (#1), canonical-payload builder (#2), and key=value parser
//! (#4) are the targets the Tier-1 perf changes address.
//!
//! Prints wall/op + allocs/op + bytes/op (dev-only counting
//! allocator). Run under `/usr/bin/time -l` for instructions/cycles/
//! CPU-time/peak RSS:
//!
//! ```sh
//! cargo build --release -p rustynet-control --example perfprobe_membership
//! /usr/bin/time -l target/release/examples/perfprobe_membership
//! ```

use std::hint::black_box;
use std::time::Instant;

use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
    decode_membership_state,
};
use rustynet_control::roles::RoleCapability;

#[global_allocator]
static ALLOC_METER: rustynet_alloc_meter::CountingAllocator =
    rustynet_alloc_meter::CountingAllocator;

const NODES: usize = 50;
const WARMUP_OPS: u64 = 2_000;
const MEASURED_OPS: u64 = 50_000;

fn pubkey_hex(seed: u8) -> String {
    // 32 bytes -> 64 lowercase hex chars (valid for decode_hex_to_fixed::<32>).
    (0..32).map(|i| format!("{:02x}", seed ^ i as u8)).collect()
}

fn sample_state() -> MembershipState {
    let nodes = (0..NODES)
        .map(|i| MembershipNode {
            node_id: format!("node-{i:03}"),
            node_pubkey_hex: pubkey_hex(i as u8),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:members".to_owned()],
            capabilities: vec![RoleCapability::Client],
            joined_at_unix: 1_000 + i as u64,
            updated_at_unix: 2_000 + i as u64,
        })
        .collect();
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: "perfprobe-net".to_owned(),
        epoch: 7,
        nodes,
        approver_set: vec![MembershipApprover {
            approver_id: "owner-1".to_owned(),
            approver_pubkey_hex: pubkey_hex(0xAA),
            role: MembershipApproverRole::Owner,
            status: MembershipApproverStatus::Active,
            created_at_unix: 500,
        }],
        quorum_threshold: 1,
        metadata_hash: None,
    }
}

fn one_op(state: &MembershipState) -> usize {
    // The reconcile-tick shape: canonical payload (#2 builder + #1 hex via
    // validate) -> state root (#1 sha256_hex) -> decode round trip (#4 parser).
    let payload = state.canonical_payload().expect("canonical payload");
    let root = state.state_root_hex().expect("state root");
    let decoded = decode_membership_state(&payload).expect("decode round trip");
    payload.len() + root.len() + decoded.nodes.len()
}

fn main() {
    let state = sample_state();
    for _ in 0..WARMUP_OPS {
        black_box(one_op(&state));
    }

    let alloc_before = rustynet_alloc_meter::snapshot();
    let started = Instant::now();
    let mut acc = 0usize;
    for _ in 0..MEASURED_OPS {
        acc = acc.wrapping_add(one_op(&state));
    }
    let elapsed = started.elapsed();
    let (alloc_calls, alloc_bytes) =
        rustynet_alloc_meter::delta(alloc_before, rustynet_alloc_meter::snapshot());
    black_box(acc);

    println!("probe=membership_canonical_roundtrip nodes={NODES} ops={MEASURED_OPS}");
    println!(
        "wall_s={:.3} ns_per_op={:.0}",
        elapsed.as_secs_f64(),
        elapsed.as_nanos() as f64 / MEASURED_OPS as f64
    );
    println!(
        "allocs_per_op={:.1} alloc_bytes_per_op={:.0}",
        alloc_calls as f64 / MEASURED_OPS as f64,
        alloc_bytes as f64 / MEASURED_OPS as f64
    );
}
