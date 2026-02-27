#![forbid(unsafe_code)]

use rustynet_crypto::NodeKeyPair;
use rustynet_policy::{AccessRequest, PolicyRule, PolicySet, Protocol, RuleAction};

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynet-control startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let policy = PolicySet {
        rules: vec![PolicyRule {
            src: "group:family".to_string(),
            dst: "tag:servers".to_string(),
            protocol: Protocol::Any,
            action: RuleAction::Allow,
        }],
    };

    let decision = policy.evaluate(&AccessRequest {
        src: "group:family".to_string(),
        dst: "tag:servers".to_string(),
        protocol: Protocol::Udp,
    });

    let keypair = NodeKeyPair::from_raw([11; 32], [13; 32]).map_err(|err| err.to_string())?;

    println!(
        "rustynet-control scaffold ready: decision={decision:?}, signing_pubkey_prefix={}",
        keypair.public_key.as_bytes()[0]
    );

    Ok(())
}
