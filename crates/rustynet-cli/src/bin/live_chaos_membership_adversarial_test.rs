#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_concurrent_role_transitions",
            fault: "request mutually conflicting role transitions concurrently",
            pass_criterion: "only one role outcome wins, conflicts fail closed, audit log records resolution",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_owner_key_compromise_simulation",
            fault: "rotate owner key while submitting updates from old key",
            pass_criterion: "post-rotation old-key updates are rejected while valid in-flight updates complete",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_revoked_node_persistence",
            fault: "attempt mesh rejoin with stale assignment after revocation",
            pass_criterion: "revoked node fails closed and peers drop traversal targets",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_membership_log_tamper",
            fault: "bit-flip membership log after write",
            pass_criterion: "digest mismatch is detected and derived state is refused",
            recovery_deadline_secs: 120,
        },
    ];
    if let Err(err) = parse_config(
        "chaos_membership_adversarial",
        stages,
        std::env::args().skip(1),
    )
    .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
