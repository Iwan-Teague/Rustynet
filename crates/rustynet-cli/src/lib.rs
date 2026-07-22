#![forbid(unsafe_code)]

//! Library surface for the `rustynet-cli` package.
//!
//! `src/main.rs` remains the primary Unix-oriented `rustynet` operator
//! binary. This crate exists so sibling binaries under `src/bin/` —
//! notably the Windows daemon-control CLI
//! (`src/bin/rustynet-windows-trust-cli.rs`) — can reuse the pure,
//! platform-neutral role-transition planner instead of forking a second
//! copy of it (CLAUDE.md §3: one hardened execution path per
//! security-sensitive workflow).

#[path = "role_cli.rs"]
pub mod role_cli;

// ── vm-lab (RNQ-17) ─────────────────────────────────────────────────────────
//
// Under the default-off `vm-lab` feature the library also compiles the lab
// orchestrator tree so integration tests (RNQ-09) can drive the state-machine
// runner without going through the shipped binary. The binary keeps its own
// independent `mod vm_lab;` — this block is additive and changes nothing in
// the default-feature library surface.
//
// The support modules below are the `crate::`-closure the vm_lab tree needs
// (`vm_lab` → `anchor_init`/`env_file`/`live_lab_*`/`ops_e2e`/
// `ops_live_lab_orchestrator`; `ops_e2e` → `secret_material`/`role_cli`).
// They are private and `allow(dead_code)`: the full ops command surface that
// makes every item live exists only in the binary; the library compiles them
// solely so the orchestrator re-exports resolve.

#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod anchor_init;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod env_file;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_results;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_run_matrix;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_stage_manifest;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_stage_recorder;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_stage_registry;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod live_lab_stage_triage;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod ops_e2e;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod ops_live_lab_orchestrator;
#[cfg(feature = "vm-lab")]
#[allow(dead_code)]
mod secret_material;
// `unused_imports` additionally allowed: the tree's convenience `pub use`
// re-exports are consumed by the binary's ops dispatch, which this library
// compile does not include. The binary target keeps full lint strength.
#[cfg(feature = "vm-lab")]
#[allow(dead_code, unused_imports)]
mod vm_lab;

/// Orchestrator surface for integration tests (RNQ-09). Everything here is
/// already `pub` inside the vm_lab tree; this only makes it reachable from
/// a `tests/` target when the crate is built with `--features vm-lab`.
///
/// `OrchestrationStage` + `StageFanout` are included alongside `StageId` so a
/// `tests/` target or `src/bin/` harness can define its OWN synthetic stages
/// (e.g. the RNQ-09 real-subprocess signal-cleanup harness) and hand them to
/// `StateMachineRunner::new` without reimplementing the trait or reaching
/// into a private module path.
#[cfg(feature = "vm-lab")]
pub mod orchestrator_test_surface {
    pub use crate::ops_live_lab_orchestrator::{
        ExtractManagedDnsExpectedIpConfig, execute_ops_extract_managed_dns_expected_ip,
    };
    pub use crate::vm_lab::orchestrator::context::OrchestrationContext;
    pub use crate::vm_lab::orchestrator::diagnostics::{
        register_shutdown_handlers, register_shutdown_handlers_with,
    };
    pub use crate::vm_lab::orchestrator::error::StageOutcome;
    pub use crate::vm_lab::orchestrator::role::NodeRole;
    pub use crate::vm_lab::orchestrator::runner::{StageObserver, StateMachineRunner};
    pub use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
}
