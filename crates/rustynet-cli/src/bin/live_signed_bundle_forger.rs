#![forbid(unsafe_code)]

mod live_chaos_support;

use std::fs;
use std::path::PathBuf;

use live_chaos_support::{repo_root, unix_now};
use serde_json::json;

const SCENARIOS: &[&str] = &[
    "truncated_one_byte",
    "truncated_half_length",
    "future_dated_assignment",
    "forged_signature_attempt",
    "replay_watermarked_membership",
    "quorum_starved_update",
];

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = repo_root()?;
    let mut output_dir = root.join("artifacts/phase10/chaos_forger");
    let mut scenario = "all".to_owned();
    let mut idx = 1usize;
    let args = std::env::args().collect::<Vec<_>>();
    while idx < args.len() {
        match args[idx].as_str() {
            "--output-dir" => {
                idx += 1;
                output_dir = PathBuf::from(required_value(&args, idx, "--output-dir")?);
            }
            "--scenario" => {
                idx += 1;
                scenario = required_value(&args, idx, "--scenario")?;
            }
            "--list-scenarios" => {
                for name in SCENARIOS {
                    println!("{name}");
                }
                return Ok(());
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                print_usage();
                return Err(format!("unknown argument: {other}"));
            }
        }
        idx += 1;
    }

    let selected = selected_scenarios(&scenario)?;
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("create {} failed: {err}", output_dir.display()))?;
    let generated_at = unix_now();
    let mut artifacts = Vec::new();
    for name in selected {
        let bytes = fixture_bytes(name, generated_at);
        let path = output_dir.join(format!("{name}.fixture"));
        fs::write(&path, &bytes)
            .map_err(|err| format!("write {} failed: {err}", path.display()))?;
        artifacts.push(json!({
            "scenario": name,
            "path": path,
            "bytes": bytes.len(),
            "expected_result": "reject_fail_closed",
        }));
    }
    let manifest = json!({
        "schema_version": 1,
        "tool": "live_signed_bundle_forger",
        "production_accepted": false,
        "generated_at_unix": generated_at,
        "scenarios": artifacts,
    });
    let manifest_path = output_dir.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest)
            .map_err(|err| format!("serialise manifest failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", manifest_path.display()))?;
    println!("{}", manifest_path.display());
    Ok(())
}

fn selected_scenarios(name: &str) -> Result<Vec<&'static str>, String> {
    if name == "all" {
        return Ok(SCENARIOS.to_vec());
    }
    SCENARIOS
        .iter()
        .copied()
        .find(|candidate| *candidate == name)
        .map(|scenario| vec![scenario])
        .ok_or_else(|| format!("unsupported scenario: {name}"))
}

fn fixture_bytes(name: &str, generated_at: u64) -> Vec<u8> {
    match name {
        "truncated_one_byte" => vec![b'{'],
        "truncated_half_length" => br#"{"schema_version":1,"payload":"half"#.to_vec(),
        "future_dated_assignment" => json!({
            "schema_version": 1,
            "bundle_type": "assignment",
            "generated_at_unix": generated_at + 86_400,
            "signature": "invalid-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "forged_signature_attempt" => json!({
            "schema_version": 1,
            "bundle_type": "membership",
            "signer": "unauthorised-test-key",
            "signature": "forged-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "replay_watermarked_membership" => json!({
            "schema_version": 1,
            "bundle_type": "membership",
            "watermark": 1,
            "epoch": 1,
            "signature": "stale-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "quorum_starved_update" => json!({
            "schema_version": 1,
            "bundle_type": "membership_update_proposal",
            "required_quorum": 3,
            "present_signatures": 1,
            "signature": "partial-quorum-test-fixture",
        })
        .to_string()
        .into_bytes(),
        _ => Vec::new(),
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: live_signed_bundle_forger --output-dir <path> [--scenario all|{}]",
        SCENARIOS.join("|")
    );
}
