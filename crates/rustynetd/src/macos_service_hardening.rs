#![allow(clippy::result_large_err)]

//! macOS service-hardening verifier.
//!
//! macOS parity for `linux_service_hardening`. Confirms the live
//! launchd service registration for `com.rustynet.daemon` matches the
//! reviewed hardening in `scripts/launchd/com.rustynet.daemon.plist`.
//!
//! The collector reads the on-disk plist at
//! `/Library/LaunchDaemons/com.rustynet.daemon.plist` and checks that
//! the reviewed keys are present with the reviewed values. Unlike
//! `systemctl show`, `launchctl print` output is not key=value, so we
//! parse the plist file directly.
//!
//! Reviewed hardening keys (from the reviewed plist):
//!   `UserName`        = rustynetd
//!   `GroupName`       = rustynetd
//!   `RunAtLoad`       = true
//!   `KeepAlive`       = true
//!   `ProcessType`     = Background
//!   `AbandonProcessGroup` = false
//!
//! Wired through the CLI as `rustynetd macos-service-hardening-check`.
//! The orchestrator's `MacosDaemonProbe` dispatches `ServiceHardening` here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REVIEWED_LAUNCHDAEMON_PLIST: &str = "/Library/LaunchDaemons/com.rustynet.daemon.plist";
pub const REVIEWED_SERVICE_LABEL: &str = "com.rustynet.daemon";

/// Reviewed plist key=value pairs.
const REVIEWED_PLIST_DIRECTIVES: &[(&str, &str)] = &[
    ("UserName", "rustynetd"),
    ("GroupName", "rustynetd"),
    ("RunAtLoad", "true"),
    ("KeepAlive", "true"),
    ("ProcessType", "Background"),
    ("AbandonProcessGroup", "false"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosServiceHardeningReport {
    pub schema_version: u32,
    pub service_label: String,
    pub plist_path: String,
    pub overall_ok: bool,
    pub probed: bool,
    pub probe_reason: Option<String>,
    pub drift_reasons: Vec<String>,
    pub observed: BTreeMap<String, String>,
    pub program_arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

/// Pure evaluator: walks the reviewed-property table against a parsed
/// property map. Returns every drift reason in one pass.
pub fn evaluate_macos_service_hardening(observed: &BTreeMap<String, String>) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    if observed.is_empty() {
        reasons.push("plist contained no parseable key=value properties".to_owned());
        return reasons;
    }
    for (key, expected) in REVIEWED_PLIST_DIRECTIVES {
        match observed.get(*key) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                reasons.push(format!(
                    "{key} drifted: expected {expected:?}, observed {actual:?}"
                ));
            }
            None => {
                reasons.push(format!("{key} missing from plist (expected {expected:?})"));
            }
        }
    }
    reasons
}

/// Parse a minimal subset of plist XML: extract scalar string and bool
/// values for the reviewed keys. Only handles the simple flat key/value
/// structure used by the reviewed plist (not nested dicts or arrays).
pub fn parse_plist_scalars(xml: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    for line in xml.lines() {
        let line = line.trim();
        if let Some(inner) = line
            .strip_prefix("<key>")
            .and_then(|s| s.strip_suffix("</key>"))
        {
            last_key = Some(inner.to_owned());
        } else if let Some(key) = last_key.take() {
            if let Some(inner) = line
                .strip_prefix("<string>")
                .and_then(|s| s.strip_suffix("</string>"))
            {
                map.insert(key, inner.to_owned());
            } else if line == "<true/>" {
                map.insert(key, "true".to_owned());
            } else if line == "<false/>" {
                map.insert(key, "false".to_owned());
            } else {
                // dict, array, or other complex type — skip value, leave key consumed
            }
        }
    }
    map
}

pub fn parse_plist_string_array(xml: &str, key_name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut pending_key = false;
    let mut in_target_array = false;
    for line in xml.lines() {
        let line = line.trim();
        if in_target_array {
            if line == "</array>" {
                break;
            }
            if let Some(inner) = line
                .strip_prefix("<string>")
                .and_then(|s| s.strip_suffix("</string>"))
            {
                values.push(inner.to_owned());
            }
            continue;
        }
        if pending_key {
            if line == "<array>" {
                in_target_array = true;
            }
            pending_key = false;
            continue;
        }
        if let Some(inner) = line
            .strip_prefix("<key>")
            .and_then(|s| s.strip_suffix("</key>"))
        {
            pending_key = inner == key_name;
        }
    }
    values
}

pub fn parse_plist_string_dict(xml: &str, key_name: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut pending_outer_key = false;
    let mut in_target_dict = false;
    let mut last_key: Option<String> = None;
    for line in xml.lines() {
        let line = line.trim();
        if in_target_dict {
            if line == "</dict>" {
                break;
            }
            if let Some(inner) = line
                .strip_prefix("<key>")
                .and_then(|s| s.strip_suffix("</key>"))
            {
                last_key = Some(inner.to_owned());
                continue;
            }
            if let Some(key) = last_key.take()
                && let Some(inner) = line
                    .strip_prefix("<string>")
                    .and_then(|s| s.strip_suffix("</string>"))
            {
                values.insert(key, inner.to_owned());
            }
            continue;
        }
        if pending_outer_key {
            if line == "<dict>" {
                in_target_dict = true;
            }
            pending_outer_key = false;
            continue;
        }
        if let Some(inner) = line
            .strip_prefix("<key>")
            .and_then(|s| s.strip_suffix("</key>"))
        {
            pending_outer_key = inner == key_name;
        }
    }
    values
}

pub fn evaluate_macos_program_arguments(program_arguments: &[String]) -> Vec<String> {
    let mut reasons = Vec::new();
    if program_arguments.is_empty() {
        reasons.push("ProgramArguments array is missing or empty".to_owned());
        return reasons;
    }
    if !program_arguments.iter().any(|arg| arg == "daemon") {
        reasons.push("ProgramArguments missing daemon subcommand".to_owned());
    }
    match program_arguments.iter().position(|arg| arg == "--backend") {
        Some(index) => match program_arguments.get(index + 1) {
            Some(value) if value == "macos-wireguard-userspace-shared" => {}
            Some(value) => reasons.push(format!(
                "ProgramArguments --backend drifted: expected \"macos-wireguard-userspace-shared\", observed {value:?}"
            )),
            None => reasons.push("ProgramArguments --backend missing value".to_owned()),
        },
        None => reasons.push("ProgramArguments missing --backend".to_owned()),
    }
    for flag in [
        "--wg-private-key",
        "--wg-encrypted-private-key",
        "--wg-key-passphrase",
        "--wg-public-key",
    ] {
        if !program_arguments.iter().any(|arg| arg == flag) {
            reasons.push(format!("ProgramArguments missing {flag}"));
        }
    }
    reasons
}

pub fn evaluate_macos_launchd_environment(environment: &BTreeMap<String, String>) -> Vec<String> {
    let mut reasons = Vec::new();
    if environment.is_empty() {
        reasons.push("EnvironmentVariables dict is missing or empty".to_owned());
        return reasons;
    }
    match environment.get("RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT") {
        Some(account) if is_safe_macos_keychain_account(account) => {}
        Some(account) => reasons.push(format!(
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT invalid or unsafe: {account:?}"
        )),
        None => reasons.push(
            "EnvironmentVariables missing RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT".to_owned(),
        ),
    }
    match environment.get("RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE") {
        Some(service) if service == "net.rustynet.wg-key-passphrase" => {}
        Some(service) => reasons.push(format!(
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE drifted: expected \"net.rustynet.wg-key-passphrase\", observed {service:?}"
        )),
        None => reasons.push(
            "EnvironmentVariables missing RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE"
                .to_owned(),
        ),
    }
    match environment.get("RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH") {
        Some(path) if path == "/usr/local/var/rustynet/keys/wireguard.passphrase" => {}
        Some(path) => reasons.push(format!(
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH drifted: expected \"/usr/local/var/rustynet/keys/wireguard.passphrase\", observed {path:?}"
        )),
        None => reasons.push(
            "EnvironmentVariables missing RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH".to_owned(),
        ),
    }
    reasons
}

fn is_safe_macos_keychain_account(account: &str) -> bool {
    let trimmed = account.trim();
    !trimmed.is_empty()
        && trimmed == account
        && trimmed.len() <= 128
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

pub fn build_macos_service_hardening_report(
    probed: bool,
    probe_reason: Option<String>,
    observed: BTreeMap<String, String>,
) -> MacosServiceHardeningReport {
    build_macos_service_hardening_report_with_program_arguments_and_environment(
        probed,
        probe_reason,
        observed,
        reviewed_program_arguments_fixture(),
        reviewed_environment_fixture(),
    )
}

pub fn build_macos_service_hardening_report_with_program_arguments(
    probed: bool,
    probe_reason: Option<String>,
    observed: BTreeMap<String, String>,
    program_arguments: Vec<String>,
) -> MacosServiceHardeningReport {
    build_macos_service_hardening_report_with_program_arguments_and_environment(
        probed,
        probe_reason,
        observed,
        program_arguments,
        reviewed_environment_fixture(),
    )
}

pub fn build_macos_service_hardening_report_with_program_arguments_and_environment(
    probed: bool,
    probe_reason: Option<String>,
    observed: BTreeMap<String, String>,
    program_arguments: Vec<String>,
    environment: BTreeMap<String, String>,
) -> MacosServiceHardeningReport {
    let drift_reasons =
        if probed {
            let mut reasons = evaluate_macos_service_hardening(&observed);
            reasons.extend(evaluate_macos_program_arguments(&program_arguments));
            reasons.extend(evaluate_macos_launchd_environment(&environment));
            reasons
        } else {
            vec![probe_reason.clone().unwrap_or_else(|| {
                "plist was not read; service hardening posture unknown".to_owned()
            })]
        };
    let overall_ok = probed && drift_reasons.is_empty();
    MacosServiceHardeningReport {
        schema_version: 1,
        service_label: REVIEWED_SERVICE_LABEL.to_owned(),
        plist_path: REVIEWED_LAUNCHDAEMON_PLIST.to_owned(),
        overall_ok,
        probed,
        probe_reason,
        drift_reasons,
        observed,
        program_arguments,
        environment,
    }
}

pub fn collect_macos_service_hardening_report() -> MacosServiceHardeningReport {
    match std::fs::read_to_string(REVIEWED_LAUNCHDAEMON_PLIST) {
        Ok(xml) => {
            let observed = parse_plist_scalars(&xml);
            let program_arguments = parse_plist_string_array(&xml, "ProgramArguments");
            let environment = parse_plist_string_dict(&xml, "EnvironmentVariables");
            build_macos_service_hardening_report_with_program_arguments_and_environment(
                true,
                None,
                observed,
                program_arguments,
                environment,
            )
        }
        Err(err) => build_macos_service_hardening_report(
            false,
            Some(format!(
                "could not read {REVIEWED_LAUNCHDAEMON_PLIST}: {err}"
            )),
            BTreeMap::new(),
        ),
    }
}

fn reviewed_program_arguments_fixture() -> Vec<String> {
    [
        "/usr/local/bin/rustynetd",
        "daemon",
        "--wg-private-key",
        "/usr/local/var/rustynet/keys/wireguard.key",
        "--wg-encrypted-private-key",
        "/usr/local/var/rustynet/keys/wireguard.key.enc",
        "--wg-key-passphrase",
        "/usr/local/var/rustynet/keys/wireguard.passphrase",
        "--wg-public-key",
        "/usr/local/var/rustynet/keys/wireguard.pub",
        "--backend",
        "macos-wireguard-userspace-shared",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect()
}

fn reviewed_environment_fixture() -> BTreeMap<String, String> {
    [
        (
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
            "wg-passphrase-daemon-local",
        ),
        (
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE",
            "net.rustynet.wg-key-passphrase",
        ),
        (
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH",
            "/usr/local/var/rustynet/keys/wireguard.passphrase",
        ),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_property_map() -> BTreeMap<String, String> {
        REVIEWED_PLIST_DIRECTIVES
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    const SAMPLE_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rustynet.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rustynetd</string>
        <string>daemon</string>
        <string>--wg-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key</string>
        <string>--wg-encrypted-private-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.key.enc</string>
        <string>--wg-key-passphrase</string>
        <string>/usr/local/var/rustynet/keys/wireguard.passphrase</string>
        <string>--wg-public-key</string>
        <string>/usr/local/var/rustynet/keys/wireguard.pub</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
    </array>
    <key>UserName</key>
    <string>rustynetd</string>
    <key>GroupName</key>
    <string>rustynetd</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>AbandonProcessGroup</key>
    <false/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT</key>
        <string>wg-passphrase-daemon-local</string>
        <key>RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE</key>
        <string>net.rustynet.wg-key-passphrase</string>
        <key>RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH</key>
        <string>/usr/local/var/rustynet/keys/wireguard.passphrase</string>
    </dict>
</dict>
</plist>"#;

    #[test]
    fn parser_extracts_reviewed_keys() {
        let map = parse_plist_scalars(SAMPLE_PLIST);
        assert_eq!(map.get("UserName").map(String::as_str), Some("rustynetd"));
        assert_eq!(map.get("GroupName").map(String::as_str), Some("rustynetd"));
        assert_eq!(map.get("RunAtLoad").map(String::as_str), Some("true"));
        assert_eq!(map.get("KeepAlive").map(String::as_str), Some("true"));
        assert_eq!(
            map.get("ProcessType").map(String::as_str),
            Some("Background")
        );
        assert_eq!(
            map.get("AbandonProcessGroup").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn parser_extracts_program_arguments_array() {
        let args = parse_plist_string_array(SAMPLE_PLIST, "ProgramArguments");
        assert_eq!(
            args.first().map(String::as_str),
            Some("/usr/local/bin/rustynetd")
        );
        assert!(args.iter().any(|arg| arg == "daemon"));
        assert!(args.iter().any(|arg| arg == "--backend"));
    }

    #[test]
    fn parser_extracts_environment_variables_dict() {
        let environment = parse_plist_string_dict(SAMPLE_PLIST, "EnvironmentVariables");
        assert_eq!(
            environment
                .get("RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE")
                .map(String::as_str),
            Some("net.rustynet.wg-key-passphrase")
        );
        assert_eq!(
            environment
                .get("RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH")
                .map(String::as_str),
            Some("/usr/local/var/rustynet/keys/wireguard.passphrase")
        );
    }

    #[test]
    fn evaluator_accepts_reviewed_property_map() {
        let reasons = evaluate_macos_service_hardening(&reviewed_property_map());
        assert!(
            reasons.is_empty(),
            "reviewed posture must pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_empty_map() {
        let reasons = evaluate_macos_service_hardening(&BTreeMap::new());
        assert!(
            reasons.iter().any(|r| r.contains("no parseable")),
            "empty map must surface no-output: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_username_drift() {
        let mut map = reviewed_property_map();
        map.insert("UserName".to_owned(), "root".to_owned());
        let reasons = evaluate_macos_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("UserName drifted")),
            "UserName drift must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_missing_directive() {
        let mut map = reviewed_property_map();
        map.remove("KeepAlive");
        let reasons = evaluate_macos_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("KeepAlive missing")),
            "missing key must surface: {reasons:?}"
        );
    }

    #[test]
    fn program_arguments_accepts_reviewed_userspace_shared_backend() {
        let reasons = evaluate_macos_program_arguments(&reviewed_program_arguments_fixture());
        assert!(
            reasons.is_empty(),
            "reviewed ProgramArguments must pass: {reasons:?}"
        );
    }

    #[test]
    fn program_arguments_rejects_legacy_macos_wireguard_backend() {
        let mut args = reviewed_program_arguments_fixture();
        let backend_index = args
            .iter()
            .position(|arg| arg == "--backend")
            .expect("backend flag exists")
            + 1;
        args[backend_index] = "macos-wireguard".to_owned();
        let reasons = evaluate_macos_program_arguments(&args);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("--backend drifted")),
            "legacy backend must drift: {reasons:?}"
        );
    }

    #[test]
    fn program_arguments_rejects_missing_passphrase_arg() {
        let args = reviewed_program_arguments_fixture()
            .into_iter()
            .filter(|arg| arg != "--wg-key-passphrase")
            .collect::<Vec<_>>();
        let reasons = evaluate_macos_program_arguments(&args);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("--wg-key-passphrase")),
            "missing passphrase arg must drift: {reasons:?}"
        );
    }

    #[test]
    fn launchd_environment_accepts_reviewed_keychain_custody_env() {
        let reasons = evaluate_macos_launchd_environment(&reviewed_environment_fixture());
        assert!(
            reasons.is_empty(),
            "reviewed launchd environment must pass: {reasons:?}"
        );
    }

    #[test]
    fn launchd_environment_rejects_missing_keychain_account() {
        let mut environment = reviewed_environment_fixture();
        environment.remove("RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT");
        let reasons = evaluate_macos_launchd_environment(&environment);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("KEYCHAIN_ACCOUNT")),
            "missing keychain account must drift: {reasons:?}"
        );
    }

    #[test]
    fn launchd_environment_rejects_unsafe_keychain_account() {
        let mut environment = reviewed_environment_fixture();
        environment.insert(
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT".to_owned(),
            "wg passphrase<script>".to_owned(),
        );
        let reasons = evaluate_macos_launchd_environment(&environment);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("invalid or unsafe")),
            "unsafe keychain account must drift: {reasons:?}"
        );
    }

    #[test]
    fn launchd_environment_rejects_wrong_keychain_service() {
        let mut environment = reviewed_environment_fixture();
        environment.insert(
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE".to_owned(),
            "rustynet.wg_passphrase".to_owned(),
        );
        let reasons = evaluate_macos_launchd_environment(&environment);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("KEYCHAIN_SERVICE drifted")),
            "wrong keychain service must drift: {reasons:?}"
        );
    }

    #[test]
    fn build_report_includes_environment_drift() {
        let mut environment = reviewed_environment_fixture();
        environment.insert(
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH".to_owned(),
            "/tmp/wireguard.passphrase".to_owned(),
        );
        let report = build_macos_service_hardening_report_with_program_arguments_and_environment(
            true,
            None,
            reviewed_property_map(),
            reviewed_program_arguments_fixture(),
            environment,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("CREDENTIAL_PATH drifted")),
            "credential path drift must be present: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn build_report_includes_program_argument_drift() {
        let mut args = reviewed_program_arguments_fixture();
        let backend_index = args
            .iter()
            .position(|arg| arg == "--backend")
            .expect("backend flag exists")
            + 1;
        args[backend_index] = "macos-wireguard".to_owned();
        let report = build_macos_service_hardening_report_with_program_arguments(
            true,
            None,
            reviewed_property_map(),
            args,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("--backend drifted")),
            "backend drift must be present: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn build_report_clean_plist_is_ok() {
        let report = build_macos_service_hardening_report(true, None, reviewed_property_map());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert!(report.probed);
    }

    #[test]
    fn build_report_unprobed_marks_overall_fail() {
        let report = build_macos_service_hardening_report(
            false,
            Some("plist unreadable".to_owned()),
            BTreeMap::new(),
        );
        assert!(!report.overall_ok);
        assert!(!report.probed);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_macos_service_hardening_report(true, None, reviewed_property_map());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosServiceHardeningReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn full_sample_plist_passes_evaluator() {
        let map = parse_plist_scalars(SAMPLE_PLIST);
        let reasons = evaluate_macos_service_hardening(&map);
        assert!(
            reasons.is_empty(),
            "full sample plist must pass evaluator: {reasons:?}"
        );
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn reviewed_directives_snapshot_pins_six_entries_with_exact_values() {
        // Pin REVIEWED_PLIST_DIRECTIVES: the canonical 6-entry shape.
        // Any silent edit (e.g. swap RunAtLoad=true to false) has to
        // update this snapshot alongside the constant.
        let canonical = [
            ("UserName", "rustynetd"),
            ("GroupName", "rustynetd"),
            ("RunAtLoad", "true"),
            ("KeepAlive", "true"),
            ("ProcessType", "Background"),
            ("AbandonProcessGroup", "false"),
        ];
        assert_eq!(REVIEWED_PLIST_DIRECTIVES.len(), canonical.len());
        for ((key, value), expected) in REVIEWED_PLIST_DIRECTIVES.iter().zip(canonical.iter()) {
            assert_eq!(*key, expected.0);
            assert_eq!(*value, expected.1);
        }
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = build_macos_service_hardening_report(true, None, reviewed_property_map());
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape: {body}"
        );
    }

    #[test]
    fn evaluator_aggregates_drift_across_every_reviewed_directive() {
        // Pin the no-short-circuit contract: if every reviewed
        // directive drifts, the evaluator surfaces 6 reasons (one
        // per directive), NOT bail at the first miss.
        let mut map = reviewed_property_map();
        map.insert("UserName".to_owned(), "root".to_owned());
        map.insert("GroupName".to_owned(), "root".to_owned());
        map.insert("RunAtLoad".to_owned(), "false".to_owned());
        map.insert("KeepAlive".to_owned(), "false".to_owned());
        map.insert("ProcessType".to_owned(), "Interactive".to_owned());
        map.insert("AbandonProcessGroup".to_owned(), "true".to_owned());
        let reasons = evaluate_macos_service_hardening(&map);
        assert_eq!(
            reasons.len(),
            REVIEWED_PLIST_DIRECTIVES.len(),
            "all 6 directives must surface independently: {reasons:?}"
        );
    }

    #[test]
    fn parser_ignores_dict_or_array_value_after_key() {
        // The parser handles flat key/scalar shapes only; a key
        // followed by a <dict> or <array> opener must leave the
        // key consumed but no value inserted. Pin so a future
        // refactor that starts inserting placeholder values trips.
        let xml = r#"<key>WatchPaths</key>
<array>
    <string>/var/whatever</string>
</array>
<key>UserName</key>
<string>rustynetd</string>"#;
        let map = parse_plist_scalars(xml);
        assert!(
            !map.contains_key("WatchPaths"),
            "dict/array-shaped value must NOT be captured: {map:?}"
        );
        // The next valid scalar key must still land.
        assert_eq!(map.get("UserName").map(String::as_str), Some("rustynetd"));
    }

    #[test]
    fn parser_ignores_inline_comment_lines_between_pairs() {
        // The parser splits on lines and only looks for <key> /
        // <string> / <true|false/> shapes. Pin tolerance of XML
        // comments and other unrelated tags between reviewed pairs.
        let xml = r#"<!-- intro comment -->
<key>UserName</key>
<string>rustynetd</string>
<!-- mid comment -->
<key>RunAtLoad</key>
<true/>"#;
        let map = parse_plist_scalars(xml);
        assert_eq!(map.get("UserName").map(String::as_str), Some("rustynetd"));
        assert_eq!(map.get("RunAtLoad").map(String::as_str), Some("true"));
    }

    #[test]
    fn build_report_unprobed_with_no_reason_uses_default_message() {
        // build_macos_service_hardening_report(false, None, _)
        // falls back to a hardcoded "plist was not read" reason.
        // Pin the fallback so a future None-handling refactor trips.
        let report = build_macos_service_hardening_report(false, None, BTreeMap::new());
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("plist was not read")),
            "default fallback reason must surface: {:?}",
            report.drift_reasons
        );
    }
}
