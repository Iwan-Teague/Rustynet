#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_crash_during_membership_apply",
            fault: "crash daemon between verified update and membership apply",
            pass_criterion: "snapshot rolls back to prior valid state or completes atomically",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_crash_during_tunnel_setup",
            fault: "crash after tunnel interface creation before route install",
            pass_criterion: "next reconcile cleans partial interface and killswitch holds during gap",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_crash_during_bundle_write",
            fault: "crash during signed bundle atomic publish",
            pass_criterion: "atomic rename leaves pre-write or post-write state only",
            recovery_deadline_secs: 120,
        },
    ];
    if let Err(err) = parse_config("chaos_crash_recovery", stages, std::env::args().skip(1))
        .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
