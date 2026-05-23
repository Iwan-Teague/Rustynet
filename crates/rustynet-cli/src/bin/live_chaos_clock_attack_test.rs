#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_clock_jump_forward_past_max_age",
            fault: "jump host clock beyond signed-state max age",
            pass_criterion: "future-dated bundles are rejected and recovery occurs after clock resync",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_clock_jump_backward_past_replay_window",
            fault: "jump clock backward beyond replay watermark window",
            pass_criterion: "replay watermark is not regressed and stale state is rejected",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_clock_skew_slow_drift",
            fault: "slowly drift clock past accepted skew",
            pass_criterion: "within-window drift is tolerated; out-of-window drift fails closed",
            recovery_deadline_secs: 900,
        },
    ];
    if let Err(err) =
        parse_config("chaos_clock_attack", stages, std::env::args().skip(1)).and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
