#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_privileged_helper_malformed_argv",
            fault: "send helper arg lists with metacharacters, nulls, and oversize args",
            pass_criterion: "helper rejects malformed argv without shell construction or panic",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_privileged_helper_socket_race",
            fault: "rapidly open and close helper socket during daemon startup",
            pass_criterion: "mid-create connections are rejected cleanly",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_setuid_binary_inspection",
            fault: "inspect privileged binary mode bits and privilege-dropping posture",
            pass_criterion: "no unexpected setuid surface exists",
            recovery_deadline_secs: 60,
        },
    ];
    if let Err(err) = parse_config(
        "chaos_privileged_boundary",
        stages,
        std::env::args().skip(1),
    )
    .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
