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

pub fn build_macos_service_hardening_report(
    probed: bool,
    probe_reason: Option<String>,
    observed: BTreeMap<String, String>,
) -> MacosServiceHardeningReport {
    let drift_reasons =
        if probed {
            evaluate_macos_service_hardening(&observed)
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
    }
}

pub fn collect_macos_service_hardening_report() -> MacosServiceHardeningReport {
    match std::fs::read_to_string(REVIEWED_LAUNCHDAEMON_PLIST) {
        Ok(xml) => {
            let observed = parse_plist_scalars(&xml);
            build_macos_service_hardening_report(true, None, observed)
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
