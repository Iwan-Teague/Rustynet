#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_daemon_kill_during_reconcile",
            fault: "kill rustynetd while baseline traffic is in flight",
            pass_criterion: "daemon restarts, killswitch holds, zero plaintext egress during fault window",
            recovery_deadline_secs: 90,
        },
        ChaosStage {
            name: "chaos_daemon_oom_during_bundle_write",
            fault: "clip daemon address space during assignment refresh",
            pass_criterion: "signed-state file is valid or absent, never partial; next reconcile recovers",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_daemon_sigstop_sigcont",
            fault: "SIGSTOP daemon beyond reconcile interval, then SIGCONT",
            pass_criterion: "peers fail closed during stop window and recover after daemon resumes",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_helper_socket_race",
            fault: "race privileged-helper socket with malformed argv frames",
            pass_criterion: "argv-only boundary rejects malformed input without panic or shell construction",
            recovery_deadline_secs: 60,
        },
    ];
    if let Err(err) =
        parse_config("chaos_daemon_fault", stages, std::env::args().skip(1)).and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
