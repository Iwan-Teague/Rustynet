#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_replay_old_membership",
            fault: "inject older validly-signed membership update with stale watermark",
            pass_criterion: "replay rejected and daemon stays on current snapshot",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_future_dated_assignment",
            fault: "inject assignment bundle generated beyond allowed clock skew",
            pass_criterion: "future bundle rejected and existing assignment remains active",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_malformed_bundle_truncation",
            fault: "submit truncated signed-state bundle variants",
            pass_criterion: "all malformed variants fail closed with structured errors and no panic",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_forged_signature_attempt",
            fault: "submit bundle signed by unauthorised key material",
            pass_criterion: "signature verification fails and no state mutation occurs",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_quorum_starvation_propose",
            fault: "submit quorum-governed update without enough approvals",
            pass_criterion: "record stays pending and no partial-quorum mutation is accepted",
            recovery_deadline_secs: 60,
        },
    ];
    if let Err(err) = parse_config(
        "chaos_signed_state_adversarial",
        stages,
        std::env::args().skip(1),
    )
    .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
