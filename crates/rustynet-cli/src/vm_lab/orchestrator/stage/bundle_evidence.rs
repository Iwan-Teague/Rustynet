//! QH-83 F1b (NodeEngineSetupProvenanceAudit_2026-09-09.md): the
//! bundle-distribution witness. Every stage that installs signed bundles —
//! `distribute_assignments`, `distribute_traversal`, `distribute_dns_zone`,
//! `distribute_membership`, `refresh_signed_bundles` — must write
//! `logs/distribute_<kind>.bundle_evidence.json` (one record per receiving
//! alias: `{alias, node_id, file, sha256, install_dst}`) BEFORE returning
//! `Passed`, and the catalog rows declare
//! `StageEvidence::File("logs/distribute_<kind>.bundle_evidence.json")` so
//! the runner demotes any unwitnessed pass to `NotProven`.
//!
//! Fail-closed: a write that cannot land is an error the calling stage turns
//! into a failure — a pass whose distribution left no durable record must
//! never stand.
//!
//! The `install_dst` half is resolved from the guest PLATFORM through the
//! per-adapter `remote_bundle_paths` tables (the same tables the adapters'
//! own digest-verified install scripts use — provenance audit F1a), so the
//! witness names exactly where the bundle was installed without widening
//! the `NodeAdapter` trait and its many test doubles.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::error::BundleKind;

/// One per-alias bundle-install record for the witness artifact.
#[derive(Debug, Clone)]
pub(crate) struct BundleWitnessEntry {
    pub alias: String,
    pub node_id: String,
    /// Bundle file name as minted (`<prefix>-<node_id>.<ext>`, or the
    /// membership snapshot file name).
    pub file: String,
    /// Host-side sha256 of the exact distributed bytes (the same digest the
    /// adapter's install script re-verifies on the guest).
    pub sha256: String,
    /// Remote path the adapter installed the bundle to.
    pub install_dst: String,
}

/// The report-dir-relative witness path for a bundle kind — the single
/// spelling shared by the writer and the catalog's `StageEvidence::File`
/// declarations.
pub(crate) fn bundle_evidence_relative_path(kind: &BundleKind) -> String {
    format!("logs/distribute_{kind}.bundle_evidence.json")
}

/// Write the per-kind bundle-distribution witness to the report directory.
/// `Ok` only when the file exists on disk with the full per-alias record.
pub(crate) fn write_bundle_evidence(
    report_dir: &std::path::Path,
    kind: &BundleKind,
    entries: &[BundleWitnessEntry],
) -> Result<(), String> {
    let body = serde_json::json!({
        "kind": kind.to_string(),
        "bundles": entries
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "alias": entry.alias,
                    "node_id": entry.node_id,
                    "file": entry.file,
                    "sha256": entry.sha256,
                    "install_dst": entry.install_dst,
                })
            })
            .collect::<Vec<_>>(),
    });
    let text = serde_json::to_vec_pretty(&body)
        .map_err(|err| format!("serialize {kind} bundle evidence: {err}"))?;
    let path = report_dir.join(bundle_evidence_relative_path(kind));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create bundle evidence dir {}: {err}", parent.display()))?;
    }
    std::fs::write(&path, text)
        .map_err(|err| format!("write bundle evidence {}: {err}", path.display()))
}

/// The remote install destination for a signed bundle kind on a guest of
/// `platform` — read from the same per-adapter table the digest-verified
/// install script uses, so the witness cannot name a path the adapter did
/// not install to. A platform with no bundle-install path (iOS/Android
/// adapters do not distribute bundles) is an error, never a placeholder.
pub(crate) fn bundle_install_dst_for_platform(
    platform: VmGuestPlatform,
    kind: &BundleKind,
) -> Result<String, String> {
    match platform {
        VmGuestPlatform::Linux => {
            Ok(crate::vm_lab::orchestrator::adapter::linux_membership::remote_bundle_paths(kind).1)
        }
        VmGuestPlatform::Macos => {
            Ok(crate::vm_lab::orchestrator::adapter::macos_membership::remote_bundle_paths(kind).1)
        }
        VmGuestPlatform::Windows => Ok(
            crate::vm_lab::orchestrator::adapter::windows_membership::remote_bundle_paths(kind).1,
        ),
        other => Err(format!(
            "no bundle install path for platform {other:?} (bundle distribution does not reach it)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(alias: &str, node_id: &str, file: &str) -> BundleWitnessEntry {
        BundleWitnessEntry {
            alias: alias.to_owned(),
            node_id: node_id.to_owned(),
            file: file.to_owned(),
            sha256: "a".repeat(64),
            install_dst: "/var/lib/rustynet/rustynetd.traversal".to_owned(),
        }
    }

    /// Mutation caught: dropping the write (or demoting it back to
    /// best-effort) would leave the File-declared catalog rows with no
    /// artifact on a pass path, and the runner would demote every real
    /// bundle distribution to NotProven.
    #[test]
    fn bundle_evidence_write_lands_per_alias_record() {
        let dir = std::env::temp_dir().join(format!(
            "bundle_evidence_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        write_bundle_evidence(
            &dir,
            &BundleKind::Traversal,
            &[entry(
                "client-1",
                "node-abc",
                "rn-traversal-node-abc.traversal",
            )],
        )
        .expect("witness write");

        let path = dir.join(bundle_evidence_relative_path(&BundleKind::Traversal));
        let text = std::fs::read_to_string(&path).expect("witness readable");
        assert!(text.contains("\"kind\": \"traversal\""), "{text}");
        assert!(text.contains("\"alias\": \"client-1\""), "{text}");
        assert!(text.contains("\"node_id\": \"node-abc\""), "{text}");
        assert!(
            text.contains("rn-traversal-node-abc.traversal"),
            "the minted bundle file name must be recorded: {text}"
        );
        assert!(
            text.contains("\"install_dst\": \"/var/lib/rustynet/rustynetd.traversal\""),
            "{text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as
    /// an error the stage turns into a failure (never a silent pass).
    #[test]
    fn bundle_evidence_write_failure_is_propagated() {
        let blocker =
            std::env::temp_dir().join(format!("bundle_evidence_blocker_{}", std::process::id()));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let err = write_bundle_evidence(
            &blocker,
            &BundleKind::Assignment,
            &[entry(
                "client-1",
                "node-abc",
                "rn-assignment-node-abc.assignment",
            )],
        )
        .expect_err("write into a regular file path must fail");
        assert!(!err.is_empty());

        let _ = std::fs::remove_file(&blocker);
    }

    /// The witness path is derived from the kind's wire spelling, so the
    /// catalog's `StageEvidence::File` declarations and the writer can never
    /// disagree (the `dns-zone` vs `dns_zone` divergence class).
    #[test]
    fn evidence_path_follows_the_kind_wire_spelling() {
        assert_eq!(
            bundle_evidence_relative_path(&BundleKind::Membership),
            "logs/distribute_membership.bundle_evidence.json"
        );
        assert_eq!(
            bundle_evidence_relative_path(&BundleKind::Assignment),
            "logs/distribute_assignment.bundle_evidence.json"
        );
        assert_eq!(
            bundle_evidence_relative_path(&BundleKind::Traversal),
            "logs/distribute_traversal.bundle_evidence.json"
        );
        assert_eq!(
            bundle_evidence_relative_path(&BundleKind::DnsZone),
            "logs/distribute_dns-zone.bundle_evidence.json"
        );
    }

    /// The install destination comes from the same table the adapter's
    /// digest-verified install script uses; a platform that cannot receive
    /// bundles is an error, never a guessed path.
    #[test]
    fn install_dst_matches_the_adapter_tables_and_unknown_platforms_error() {
        assert_eq!(
            bundle_install_dst_for_platform(VmGuestPlatform::Linux, &BundleKind::Membership)
                .expect("linux membership dst"),
            "/var/lib/rustynet/membership.snapshot"
        );
        assert!(
            bundle_install_dst_for_platform(VmGuestPlatform::Ios, &BundleKind::Traversal).is_err()
        );
    }
}
