#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn create() -> Result<Self, String> {
        let base_dir = env::temp_dir();
        let pid = std::process::id();
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure while creating temp dir: {err}"))?
            .as_nanos();

        for attempt in 0..100u64 {
            let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = base_dir.join(format!(
                "rustynet-test-validate-network-discovery-bundle-{pid}-{now_nanos}-{counter}-{attempt}"
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "create temp dir failed ({}): {err}",
                        candidate.display()
                    ));
                }
            }
        }

        Err("create temp dir failed: exhausted unique path attempts".to_string())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("clock failure: {err}"))
}

fn write_auto_bundle(
    output_path: &Path,
    collected_at_unix: u64,
    assignment_key_b64: &str,
    host_endpoint: &str,
    add_secret_like: bool,
) -> Result<(), String> {
    let extra_field_line = if add_secret_like {
        "  \"leaked_private_key\": \"abc\",\n"
    } else {
        ""
    };

    let body = format!(
        "{{\n  \"schema_version\": 1,\n  \"collected_at_unix\": {collected_at_unix},\n  \"collected_at_iso\": \"2026-03-19T00:00:00Z\",\n  \"purpose\": \"cross_network_discovery_bundle\",\n  \"note\": \"test bundle\",\n  \"node_identity\": {{\n    \"node_id\": \"client-1\",\n    \"hostname\": \"client-1.local\",\n    \"os\": \"Linux Debian\",\n    \"kernel\": \"6.8.0\",\n    \"arch\": \"x86_64\"\n  }},\n  \"wireguard\": {{\n    \"interface\": \"rustynet0\",\n    \"public_key\": \"{default_key_b64}\",\n    \"listen_port\": 51820,\n    \"interface_addresses\": \"100.64.0.2/32\",\n    \"peer_stanza_template\": \"[Peer]\\\\nPublicKey = {default_key_b64}\\\\n\"\n  }},\n  \"endpoint_candidates\": [\n    {{\n      \"type\": \"host\",\n      \"endpoint\": \"{host_endpoint}\",\n      \"address\": \"192.168.1.10\",\n      \"prefix_len\": \"24\",\n      \"priority\": 120\n    }},\n    {{\n      \"type\": \"server_reflexive\",\n      \"endpoint\": \"203.0.113.10:51820\",\n      \"address\": \"203.0.113.10\",\n      \"priority\": 200\n    }},\n    {{\n      \"type\": \"relay\",\n      \"endpoint\": \"\",\n      \"priority\": 50,\n      \"note\": \"relay assigned by control plane\"\n    }}\n  ],\n  \"nat_profile\": {{\n    \"behind_nat\": true,\n    \"first_lan_ip\": \"192.168.1.10\",\n    \"detected_public_ip\": \"203.0.113.10\",\n    \"port_forwarded_hint\": \"assumed_no\",\n    \"recommended_traversal_strategy\": \"hole_punch_or_relay\"\n  }},\n  \"verifier_keys\": {{\n    \"note\": \"verifier keys\",\n    \"assignment_verifier_key_b64\": \"{assignment_key_b64}\",\n    \"traversal_verifier_key_b64\": \"{default_key_b64}\",\n    \"dns_zone_verifier_key_b64\": \"{default_key_b64}\",\n    \"trust_evidence_verifier_key_b64\": \"{default_key_b64}\"\n  }},\n  \"rustynet_artifacts\": {{\n    \"assignment_bundle\": {{\n      \"path\": \"/var/lib/rustynet/rustynetd.assignment\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {assignment_mtime}\n    }},\n    \"traversal_bundle\": {{\n      \"path\": \"/var/lib/rustynet/rustynetd.traversal\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {artifact_mtime}\n    }},\n    \"membership_snapshot\": {{\n      \"path\": \"/var/lib/rustynet/membership.snapshot\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {artifact_mtime}\n    }},\n    \"membership_log\": {{\n      \"path\": \"/var/lib/rustynet/membership.log\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {artifact_mtime}\n    }},\n    \"dns_zone_bundle\": {{\n      \"path\": \"/var/lib/rustynet/rustynetd.dns-zone\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {artifact_mtime}\n    }},\n    \"trust_evidence\": {{\n      \"path\": \"/var/lib/rustynet/rustynetd.trust\",\n      \"exists\": true,\n      \"size_bytes\": 100,\n      \"mtime_unix\": {artifact_mtime}\n    }}\n  }},\n  \"daemon_status\": {{\n    \"active\": \"active\",\n    \"pid\": \"1234\",\n    \"socket_path\": \"/run/rustynet/rustynetd.sock\",\n    \"socket_present\": true\n  }},\n  \"known_peers\": [\n    {{\n      \"public_key\": \"{default_key_b64}\",\n      \"endpoint\": \"198.51.100.20:51820\",\n      \"allowed_ips\": \"100.64.0.3/32\",\n      \"latest_handshake_unix\": {handshake_unix},\n      \"rx_bytes\": 10,\n      \"tx_bytes\": 20\n    }}\n  ],\n{extra_field_line}  \"remote_network_checklist\": [\n    \"1. add node\",\n    \"2. issue bundles\"\n  ]\n}}\n",
        assignment_mtime = collected_at_unix.saturating_sub(10),
        artifact_mtime = collected_at_unix.saturating_sub(10),
        handshake_unix = collected_at_unix.saturating_sub(5),
        default_key_b64 = DEFAULT_KEY_B64,
    );

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output parent directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(output_path, body)
        .map_err(|err| format!("write output failed ({}): {err}", output_path.display()))
}

fn run_validation(args: &[&str]) -> Result<std::process::ExitStatus, String> {
    Command::new("cargo")
        .args(args)
        .status()
        .map_err(|err| format!("failed to run cargo: {err}"))
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let temp_dir = TempDirGuard::create().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let now_unix = match now_unix() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            return Err(1);
        }
    };
    let stale_unix = now_unix.saturating_sub(99_999);

    let valid_bundle = temp_dir.path().join("valid.json");
    let invalid_stale = temp_dir.path().join("invalid_stale.json");
    let invalid_missing_verifier_key = temp_dir.path().join("invalid_missing_verifier_key.json");
    let invalid_endpoint = temp_dir.path().join("invalid_endpoint.json");
    let invalid_secret_like = temp_dir.path().join("invalid_secret_like.json");
    let valid_output = temp_dir.path().join("valid.md");

    write_auto_bundle(
        valid_bundle.as_path(),
        now_unix,
        DEFAULT_KEY_B64,
        "192.168.1.10:51820",
        false,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_auto_bundle(
        invalid_stale.as_path(),
        stale_unix,
        DEFAULT_KEY_B64,
        "192.168.1.10:51820",
        false,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_auto_bundle(
        invalid_missing_verifier_key.as_path(),
        now_unix,
        "",
        "192.168.1.10:51820",
        false,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_auto_bundle(
        invalid_endpoint.as_path(),
        now_unix,
        DEFAULT_KEY_B64,
        "not-an-endpoint",
        false,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    write_auto_bundle(
        invalid_secret_like.as_path(),
        now_unix,
        DEFAULT_KEY_B64,
        "192.168.1.10:51820",
        true,
    )
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let valid_status = run_validation(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "validate-network-discovery-bundle",
        "--bundle",
        valid_bundle.to_str().expect("temp paths are valid utf-8"),
        "--max-age-seconds",
        "900",
        "--require-verifier-keys",
        "--require-daemon-active",
        "--require-socket-present",
        "--output",
        valid_output.to_str().expect("temp paths are valid utf-8"),
    ])
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if !valid_status.success() {
        return Err(valid_status.code().unwrap_or(1));
    }

    let stale_status = run_validation(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "validate-network-discovery-bundle",
        "--bundle",
        invalid_stale.to_str().expect("temp paths are valid utf-8"),
        "--max-age-seconds",
        "900",
    ])
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if stale_status.success() {
        eprintln!("expected invalid_stale.json to fail validation");
        return Err(1);
    }

    let missing_key_status = run_validation(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "validate-network-discovery-bundle",
        "--bundle",
        invalid_missing_verifier_key
            .to_str()
            .expect("temp paths are valid utf-8"),
        "--max-age-seconds",
        "900",
        "--require-verifier-keys",
    ])
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if missing_key_status.success() {
        eprintln!("expected invalid_missing_verifier_key.json to fail validation");
        return Err(1);
    }

    let endpoint_status = run_validation(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "validate-network-discovery-bundle",
        "--bundle",
        invalid_endpoint
            .to_str()
            .expect("temp paths are valid utf-8"),
        "--max-age-seconds",
        "900",
        "--require-verifier-keys",
    ])
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if endpoint_status.success() {
        eprintln!("expected invalid_endpoint.json to fail validation");
        return Err(1);
    }

    let secret_like_status = run_validation(&[
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        "validate-network-discovery-bundle",
        "--bundle",
        invalid_secret_like
            .to_str()
            .expect("temp paths are valid utf-8"),
        "--max-age-seconds",
        "900",
        "--require-verifier-keys",
    ])
    .map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if secret_like_status.success() {
        eprintln!("expected invalid_secret_like.json to fail validation");
        return Err(1);
    }

    println!("Network discovery bundle validation tests: PASS");
    Ok(())
}
