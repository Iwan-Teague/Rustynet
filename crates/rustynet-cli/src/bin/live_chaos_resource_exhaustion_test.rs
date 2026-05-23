#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_disk_full_signed_state_write",
            fault: "fill signed-state filesystem during bundle write",
            pass_criterion: "write fails cleanly, previous valid bundle remains intact",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_readonly_filesystem_state",
            fault: "remount signed-state path read-only mid-run",
            pass_criterion: "reconcile reports I/O failure cleanly without panic",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_inotify_watch_exhaustion",
            fault: "exhaust inotify watcher budget before daemon startup",
            pass_criterion: "startup fails closed or degrades explicitly with no half-armed state",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_file_descriptor_exhaustion",
            fault: "start daemon with constrained file descriptor limit",
            pass_criterion: "startup fails closed with no partial WireGuard state",
            recovery_deadline_secs: 120,
        },
    ];
    if let Err(err) = parse_config(
        "chaos_resource_exhaustion",
        stages,
        std::env::args().skip(1),
    )
    .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
