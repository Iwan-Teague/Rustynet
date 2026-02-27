#![forbid(unsafe_code)]

use rustynet_relay::{RelayFleet, RelayNode};

fn main() {
    let fleet = RelayFleet {
        nodes: vec![
            RelayNode {
                id: "relay-us-east".to_string(),
                region: "us-east".to_string(),
                healthy: true,
                latency_ms: 20,
            },
            RelayNode {
                id: "relay-us-west".to_string(),
                region: "us-west".to_string(),
                healthy: true,
                latency_ms: 28,
            },
        ],
    };

    match fleet.select_best(Some("us-east")) {
        Some(relay) => println!(
            "rustynet-relay ready: selected={} region={} latency_ms={}",
            relay.id, relay.region, relay.latency_ms
        ),
        None => {
            eprintln!("rustynet-relay startup failed: no healthy relays available");
            std::process::exit(1);
        }
    }
}
