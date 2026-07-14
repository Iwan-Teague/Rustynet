#![forbid(unsafe_code)]
#![cfg(feature = "vm-lab")]
//! RNQ-09 subprocess signal-cleanup test harness.
//!
//! Test-only, never shipped: this binary exists solely so
//! `tests/rnq09_signal_cleanup.rs` can drive the REAL orchestrator
//! shutdown-handler + `StateMachineRunner` seam
//! (`rustynet_cli::orchestrator_test_surface`, RNQ-17) inside a real OS
//! process and deliver it a real SIGTERM/SIGINT — the one thing an
//! in-process unit test cannot prove. Gated behind the default-off `vm-lab`
//! cargo feature both here (`#![cfg(feature = "vm-lab")]`, whole file) and in
//! `Cargo.toml` (`required-features = ["vm-lab"]` on its `[[bin]]` entry, the
//! mechanism that actually keeps `cargo check -p rustynet-cli` (no features)
//! from attempting to build it at all — a whole-file `cfg` alone is not
//! sufficient for a binary target, since a crate with zero items still needs
//! a `fn main`).
//!
//! Contract with the driving test (`tests/rnq09_signal_cleanup.rs`):
//!   - env var `RNQ09_MARKER_DIR` names a directory the test owns; it must
//!     already exist.
//!   - stdout line 1 is `READY` (flushed) — the handshake. The test blocks on
//!     it (a real blocking read, not a sleep) before delivering a signal, so
//!     the signal is guaranteed to land while stage A is actively polling
//!     the shutdown flag, not before the handler is installed and not after
//!     the run has already finished.
//!   - stage A (`Preflight`) has no dependencies, is NOT `always_run`, and
//!     polls the SAME `Arc<AtomicBool>` `register_shutdown_handlers` returns
//!     — proving the flag a real OS signal sets is visible to a stage that
//!     is already mid-flight, not just to the runner's between-stage check.
//!   - stage B (`PrepareSourceArchive`) depends on stage A, is NOT
//!     `always_run`, and MUST be skipped once the shutdown flag is observed:
//!     if it ever executes, it writes `<marker dir>/STAGE_B_RAN` — a
//!     regression signal the driving test asserts must never exist.
//!   - stage C (`Cleanup`) is `always_run = true`: it MUST execute
//!     regardless of the shutdown flag (this is the actual behavior RNQ-09
//!     protects — a SIGTERM/SIGINT mid-run must still tear down guest
//!     killswitch/exit-NAT residue) and writes `<marker dir>/CLEANUP_RAN`.
//!   - once the run finishes, if the shutdown flag was observed the harness
//!     prints `SHUTDOWN_ACK` (flushed) and exits non-zero. A signal-cleanup
//!     harness has no success outcome to report, so no code path here ever
//!     writes a `PASSED` marker.

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustynet_cli::orchestrator_test_surface::{
    NodeRole, OrchestrationContext, OrchestrationStage, StageFanout, StageId, StageOutcome,
    StateMachineRunner, register_shutdown_handlers,
};

/// Directory the driving test owns; every marker below is written inside it.
const MARKER_DIR_ENV: &str = "RNQ09_MARKER_DIR";
/// Handshake line: proves signal handlers are installed and stage A is
/// actively polling before the test delivers anything.
const READY_LINE: &str = "READY";
/// Printed once the post-run `shutdown_flag.load()` check (mirroring
/// `orchestrator/native.rs`'s own post-run check) observes the signal.
const SHUTDOWN_ACK_LINE: &str = "SHUTDOWN_ACK";
/// Written by the `always_run` cleanup stage. Must exist after every exit
/// path once a signal has been delivered.
const CLEANUP_MARKER_NAME: &str = "CLEANUP_RAN";
/// Written ONLY if the must-be-skipped stage regresses into executing.
const UNEXPECTED_STAGE_MARKER_NAME: &str = "STAGE_B_RAN";

/// Bounded wait for the shutdown flag inside a running stage: long enough to
/// never flake under CI load (the driving test delivers the signal within
/// milliseconds of reading `READY`), but bounded so a harness invoked by hand
/// without ever being signalled terminates instead of hanging forever.
const FLAG_POLL_BOUND: Duration = Duration::from_secs(20);
const FLAG_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn print_flushed(line: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{line}").map_err(|err| format!("write '{line}' to stdout: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush stdout after '{line}': {err}"))
}

fn write_marker(marker_dir: &Path, name: &str) -> Result<(), String> {
    std::fs::write(marker_dir.join(name), b"").map_err(|err| {
        format!(
            "write marker '{name}' into '{}': {err}",
            marker_dir.display()
        )
    })
}

/// Stage A: no dependencies, not `always_run`. Prints the READY handshake,
/// then cooperatively polls the SAME shutdown flag `register_shutdown_handlers`
/// returned so it stops promptly once a real SIGTERM/SIGINT lands, rather
/// than relying solely on the runner's own between-stage shutdown check
/// (which only short-circuits stages that have not started yet) — this stage
/// proves the signal reaches a stage that is already mid-flight.
struct ReadyThenPollStage {
    flag: Arc<AtomicBool>,
}

impl OrchestrationStage for ReadyThenPollStage {
    fn id(&self) -> StageId {
        StageId::Preflight
    }
    fn name(&self) -> &str {
        "rnq09-ready-then-poll"
    }
    fn dependencies(&self) -> &[StageId] {
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn always_run(&self) -> bool {
        false
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        if let Err(err) = print_flushed(READY_LINE) {
            return StageOutcome::Failed(err);
        }
        let started = Instant::now();
        while !self.flag.load(Ordering::Acquire) {
            if started.elapsed() >= FLAG_POLL_BOUND {
                break;
            }
            std::thread::sleep(FLAG_POLL_INTERVAL);
        }
        StageOutcome::Passed
    }
}

/// Stage B: depends on stage A, not `always_run`. Must NEVER execute once the
/// shutdown flag is observed — the runner's shutdown-skip branch must skip it
/// before `execute` is ever called. If it DOES run, that is itself the
/// regression under test; it leaves a marker the driving test asserts must
/// never exist.
struct MustSkipStage {
    marker_dir: PathBuf,
}

impl OrchestrationStage for MustSkipStage {
    fn id(&self) -> StageId {
        StageId::PrepareSourceArchive
    }
    fn name(&self) -> &str {
        "rnq09-must-skip"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::Preflight]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn always_run(&self) -> bool {
        false
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        // Reaching this line is itself the failure condition under test; the
        // marker lets the driving test detect it without parsing stdout.
        match write_marker(&self.marker_dir, UNEXPECTED_STAGE_MARKER_NAME) {
            Ok(()) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(err),
        }
    }
}

/// Stage C: `always_run = true`. Must execute regardless of the shutdown
/// flag — the entire point of RNQ-09 is that a SIGTERM/SIGINT mid-run must
/// still tear down guest killswitch/exit-NAT residue rather than leaving it
/// behind.
struct CleanupStage {
    marker_dir: PathBuf,
}

impl OrchestrationStage for CleanupStage {
    fn id(&self) -> StageId {
        StageId::Cleanup
    }
    fn name(&self) -> &str {
        "rnq09-cleanup"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::PrepareSourceArchive]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn always_run(&self) -> bool {
        true
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        match write_marker(&self.marker_dir, CLEANUP_MARKER_NAME) {
            Ok(()) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(err),
        }
    }
}

/// Returns `Ok(true)` iff the shutdown flag was observed by the time the run
/// finished (mirrors `orchestrator/native.rs`'s own post-run
/// `shutdown_flag.load(Ordering::Acquire)` check).
fn run() -> Result<bool, String> {
    // 1) Register REAL OS signal handlers FIRST — mirrors the production
    //    ordering in `orchestrator/native.rs` (shutdown handling must precede
    //    any mutation), and is the exact function under test.
    let shutdown_flag = register_shutdown_handlers()?;

    let marker_dir = PathBuf::from(
        env::var(MARKER_DIR_ENV)
            .map_err(|_| format!("{MARKER_DIR_ENV} env var must be set by the driving test"))?,
    );
    std::fs::create_dir_all(&marker_dir)
        .map_err(|err| format!("create marker directory '{}': {err}", marker_dir.display()))?;

    let stages: Vec<Box<dyn OrchestrationStage>> = vec![
        Box::new(ReadyThenPollStage {
            flag: Arc::clone(&shutdown_flag),
        }),
        Box::new(MustSkipStage {
            marker_dir: marker_dir.clone(),
        }),
        Box::new(CleanupStage {
            marker_dir: marker_dir.clone(),
        }),
    ];

    let runner = StateMachineRunner::new(stages)?.with_shutdown_flag(Arc::clone(&shutdown_flag));
    let mut ctx = OrchestrationContext::new(
        Vec::new(),
        marker_dir.join("report"),
        "rnq09-signal-harness".to_owned(),
    );
    runner.run(&mut ctx)?;

    Ok(shutdown_flag.load(Ordering::Acquire))
}

fn main() {
    match run() {
        Ok(true) => {
            // The scenario under test: a real signal reached the runner and
            // was observed once the run completed. There is no "success"
            // outcome for a signal-cleanup harness to report — only "cleanup
            // ran", which the caller verifies via the marker file — so this
            // path deliberately never writes a PASSED marker and always
            // exits non-zero.
            if print_flushed(SHUTDOWN_ACK_LINE).is_err() {
                process::exit(3);
            }
            process::exit(1);
        }
        Ok(false) => {
            eprintln!(
                "rnq09_signal_harness: the run completed WITHOUT ever observing the shutdown \
                 flag; the driving test must deliver SIGTERM/SIGINT after reading the \
                 '{READY_LINE}' stdout line"
            );
            process::exit(2);
        }
        Err(err) => {
            eprintln!("rnq09_signal_harness: fatal setup error: {err}");
            process::exit(4);
        }
    }
}
