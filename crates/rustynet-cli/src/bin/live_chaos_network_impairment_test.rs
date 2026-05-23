#![forbid(unsafe_code)]

mod live_chaos_support;

use live_chaos_support::{ChaosStage, parse_config, run_category};

fn main() {
    let stages = vec![
        ChaosStage {
            name: "chaos_heavy_packet_loss",
            fault: "apply 60 percent packet loss to the tunnel path",
            pass_criterion: "mesh survives via retries or relay activates after direct-loss threshold",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_jitter_with_reorder",
            fault: "apply delay, jitter, and packet reordering",
            pass_criterion: "handshake completes within budget or controlled relay failover occurs",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_asymmetric_route_break",
            fault: "block one direction of WireGuard UDP",
            pass_criterion: "handshake fails closed within keepalive window and recovers on rule removal",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_mtu_blackhole",
            fault: "drop fragmentation-needed path feedback with mismatched MTU",
            pass_criterion: "path-MTU recovery or controlled fail-closed state, no plaintext leak",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_dns_poisoning_attempt",
            fault: "return unsigned wrong IP for mesh hostnames",
            pass_criterion: "signed DNS zone verification rejects unsigned answers and resolver fails closed",
            recovery_deadline_secs: 120,
        },
    ];
    if let Err(err) = parse_config("chaos_network_impairment", stages, std::env::args().skip(1))
        .and_then(run_category)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
