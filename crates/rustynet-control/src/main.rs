#![forbid(unsafe_code)]

use ed25519_dalek::SigningKey;
use rustynet_crypto::NodeKeyPair;
use rustynet_policy::{AccessRequest, PolicyRule, PolicySet, Protocol, RuleAction};

fn main() {
    if let Err(err) = run() {
        eprintln!("rustynet-control startup failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => print_scaffold_ready(),
        _ => Err(help_text()),
    }
}

fn print_scaffold_ready() -> Result<(), String> {
    let policy = PolicySet {
        rules: vec![PolicyRule {
            src: "group:family".to_owned(),
            dst: "tag:servers".to_owned(),
            protocol: Protocol::Any,
            action: RuleAction::Allow,
        }],
    };

    let decision = policy.evaluate(&AccessRequest {
        src: "group:family".to_owned(),
        dst: "tag:servers".to_owned(),
        protocol: Protocol::Udp,
    });

    // CRY-06: `from_raw` now verifies the public half actually belongs to the
    // private half, so the demo pair must be a real one. This previously passed
    // `([11; 32], [13; 32])`, which is not a corresponding pair — it was accepted
    // only because nothing checked, and it made this binary fail at startup once
    // the check landed. Derive the public key from the seed instead.
    let seed = [13u8; 32];
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let keypair = NodeKeyPair::from_raw(public_key, seed).map_err(|err| err.to_string())?;

    println!(
        "rustynet-control scaffold ready: decision={decision:?}, signing_pubkey_prefix={}",
        keypair.public_key.as_bytes()[0]
    );

    Ok(())
}

fn help_text() -> String {
    ["rustynet-control usage:", "  rustynet-control"].join("\n")
}
