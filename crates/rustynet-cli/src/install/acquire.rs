//! Binary acquisition: get the shipping binaries into a fresh, verified staging
//! directory. The first live install step and the one most tied to Phase 1 —
//! `FromDir` reuses the signed release manifest (`crate::release_manifest`) for
//! integrity. Nothing here mutates system state beyond a staging dir, so it needs
//! no elevation; the OS mutation happens in later steps that consume the result.

use super::AcquisitionMode;
use crate::release_manifest::ReleaseManifest;
use std::path::{Path, PathBuf};

/// Logical shipping-binary names. The CLI (`rustynet-cli`) ships as `rustynet`.
pub(super) const SHIPPING: &[&str] = &["rustynetd", "rustynet", "rustynet-relay"];

/// The result of acquisition: a staging dir holding each shipping binary under
/// its plain install name (`rustynetd`, `rustynet`, `rustynet-relay`, `.exe` on
/// Windows), plus human-readable notes for the install report.
#[derive(Debug)]
pub(super) struct Acquired {
    pub staging_dir: PathBuf,
    pub notes: Vec<String>,
}

/// Acquire + verify the shipping binaries for `triple` (file `ext` = "" or
/// ".exe") into `staging`. Fail-closed on any missing or mismatched binary.
pub(super) fn acquire(
    mode: &AcquisitionMode,
    triple: &str,
    ext: &str,
    staging: &Path,
) -> Result<Acquired, String> {
    std::fs::create_dir_all(staging)
        .map_err(|err| format!("cannot create staging dir {}: {err}", staging.display()))?;
    match mode {
        AcquisitionMode::FromDir(dir) => from_dir(dir, triple, ext, staging),
        AcquisitionMode::BuildFromSource => build_from_source(ext, staging),
        AcquisitionMode::VerifiedDownload => Err(
            "verified-download acquisition is not available until a signed release + a pinned \
             verifier key exist; use --from-dir <dir> (optionally with a release-manifest.json) \
             or --build-from-source"
                .to_owned(),
        ),
    }
}

/// Copy the shipping binaries out of a local directory (prebuilt release assets
/// or a `target/release` build) into staging. If a `release-manifest.json` is
/// co-located, every binary's sha256+size is verified against it.
///
/// NOTE: a co-located manifest gives INTEGRITY (the bytes match a manifest that
/// self-verifies), not AUTHENTICITY (the manifest key is not pinned). True
/// pinned-key authenticity is the `VerifiedDownload` path, which lands once a
/// signed release + pinned key exist.
fn from_dir(dir: &Path, triple: &str, ext: &str, staging: &Path) -> Result<Acquired, String> {
    let manifest = load_and_self_verify_manifest(dir)?;
    for name in SHIPPING {
        let src = locate_binary(dir, name, triple, ext).ok_or_else(|| {
            format!(
                "binary '{name}' not found in {} (looked for {name}-{triple}{ext} and {name}{ext})",
                dir.display()
            )
        })?;
        let bytes =
            std::fs::read(&src).map_err(|err| format!("cannot read {}: {err}", src.display()))?;
        if let Some(m) = &manifest {
            m.verify_artifact(name, triple, &bytes)
                .map_err(|err| format!("integrity check failed for {name} ({triple}): {err}"))?;
        }
        stage_binary(name, ext, &bytes, staging)?;
    }
    let note = match &manifest {
        Some(_) => {
            "verified each binary's sha256 against the co-located release-manifest.json (integrity; \
             not a pinned-key authenticity check)"
                .to_owned()
        }
        None => {
            "no release-manifest.json in the source dir — staged without integrity verification \
             (dev convenience)"
                .to_owned()
        }
    };
    Ok(Acquired {
        staging_dir: staging.to_path_buf(),
        notes: vec![note],
    })
}

/// Build the shipping binaries from the current source checkout (dev/fallback).
/// Requires the toolchain + being run from a rustynet checkout.
fn build_from_source(ext: &str, staging: &Path) -> Result<Acquired, String> {
    let builds: &[(&str, &[&str])] = &[
        (
            "rustynetd",
            &["build", "--release", "--locked", "-p", "rustynetd"],
        ),
        (
            "rustynet",
            &[
                "build",
                "--release",
                "--locked",
                "-p",
                "rustynet-cli",
                "--bin",
                "rustynet-cli",
            ],
        ),
        (
            "rustynet-relay",
            &[
                "build",
                "--release",
                "--locked",
                "-p",
                "rustynet-relay",
                "--features",
                "daemon",
            ],
        ),
    ];
    for (_, args) in builds {
        let status = std::process::Command::new("cargo")
            .args(*args)
            .status()
            .map_err(|err| format!("failed to run cargo build: {err}"))?;
        if !status.success() {
            return Err(format!(
                "cargo {} failed (build-from-source requires a rustynet source checkout + toolchain)",
                args.join(" ")
            ));
        }
    }
    // Built binaries land in target/release under their crate binary names.
    let release = Path::new("target").join("release");
    let sources = [
        ("rustynetd", "rustynetd"),
        ("rustynet", "rustynet-cli"),
        ("rustynet-relay", "rustynet-relay"),
    ];
    for (name, built_name) in sources {
        let src = release.join(format!("{built_name}{ext}"));
        let bytes = std::fs::read(&src)
            .map_err(|err| format!("built binary missing {}: {err}", src.display()))?;
        stage_binary(name, ext, &bytes, staging)?;
    }
    Ok(Acquired {
        staging_dir: staging.to_path_buf(),
        notes: vec!["built from source (dev/fallback; no manifest verification)".to_owned()],
    })
}

/// Look for `<name>-<triple><ext>` (release asset naming) first, then `<name><ext>`
/// (a plain build dir).
fn locate_binary(dir: &Path, name: &str, triple: &str, ext: &str) -> Option<PathBuf> {
    let release_named = dir.join(format!("{name}-{triple}{ext}"));
    if release_named.is_file() {
        return Some(release_named);
    }
    let plain = dir.join(format!("{name}{ext}"));
    if plain.is_file() {
        return Some(plain);
    }
    None
}

fn stage_binary(name: &str, ext: &str, bytes: &[u8], staging: &Path) -> Result<(), String> {
    let dst = staging.join(format!("{name}{ext}"));
    std::fs::write(&dst, bytes).map_err(|err| format!("cannot stage {}: {err}", dst.display()))?;
    set_executable(&dst);
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

/// Load a co-located `release-manifest.json` if present, and self-verify it (the
/// signature must validate against its own embedded key, and the schema must be
/// understood). A present-but-invalid manifest is a hard error (fail-closed): we
/// do not silently ignore a corrupt manifest.
fn load_and_self_verify_manifest(dir: &Path) -> Result<Option<ReleaseManifest>, String> {
    let path = dir.join("release-manifest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let manifest: ReleaseManifest = serde_json::from_str(&json)
        .map_err(|err| format!("cannot parse release-manifest.json: {err}"))?;
    // Self-verify against the manifest's own key: proves internal consistency
    // (integrity). Authenticity would require a PINNED key (VerifiedDownload).
    manifest
        .verify_signed_with_pinned_key(&manifest.verifier_key_hex)
        .map_err(|err| {
            format!("co-located release-manifest.json failed self-verification: {err}")
        })?;
    Ok(Some(manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_manifest::{ManifestArtifact, build_signed_manifest, sha256_hex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rn-acquire-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    const TRIPLE: &str = "x86_64-unknown-linux-gnu";

    fn write_fake_binaries(dir: &Path) -> std::collections::BTreeMap<&'static str, Vec<u8>> {
        std::fs::create_dir_all(dir).unwrap();
        let mut map = std::collections::BTreeMap::new();
        for name in SHIPPING {
            let bytes = format!("fake-{name}-bytes").into_bytes();
            std::fs::write(dir.join(format!("{name}-{TRIPLE}")), &bytes).unwrap();
            map.insert(*name, bytes);
        }
        map
    }

    fn signed_manifest_for(bytes: &std::collections::BTreeMap<&'static str, Vec<u8>>) -> String {
        let seed = [7u8; 32];
        let artifacts = bytes
            .iter()
            .map(|(name, b)| ManifestArtifact {
                name: (*name).to_owned(),
                target: TRIPLE.to_owned(),
                filename: format!("{name}-{TRIPLE}"),
                sha256: sha256_hex(b),
                size_bytes: b.len() as u64,
            })
            .collect();
        let m = build_signed_manifest("beta", 1_700_000_000, "ed25519:test", seed, artifacts);
        serde_json::to_string(&m).unwrap()
    }

    #[test]
    fn from_dir_stages_all_binaries_without_manifest() {
        let src = tmp("nomani-src");
        write_fake_binaries(&src);
        let staging = tmp("nomani-stg");
        let out = acquire(&AcquisitionMode::FromDir(src.clone()), TRIPLE, "", &staging).unwrap();
        for name in SHIPPING {
            assert!(out.staging_dir.join(name).is_file(), "{name} staged");
        }
        assert!(out.notes[0].contains("without integrity verification"));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn from_dir_verifies_against_co_located_manifest() {
        let src = tmp("mani-src");
        let bytes = write_fake_binaries(&src);
        std::fs::write(
            src.join("release-manifest.json"),
            signed_manifest_for(&bytes),
        )
        .unwrap();
        let staging = tmp("mani-stg");
        let out = acquire(&AcquisitionMode::FromDir(src.clone()), TRIPLE, "", &staging).unwrap();
        assert!(out.notes[0].contains("integrity"));
        for name in SHIPPING {
            assert!(out.staging_dir.join(name).is_file());
        }
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn from_dir_fails_closed_on_tampered_binary_vs_manifest() {
        let src = tmp("tamper-src");
        let bytes = write_fake_binaries(&src);
        std::fs::write(
            src.join("release-manifest.json"),
            signed_manifest_for(&bytes),
        )
        .unwrap();
        // Tamper one binary AFTER the manifest was computed.
        std::fs::write(
            src.join(format!("rustynetd-{TRIPLE}")),
            b"TAMPERED-different",
        )
        .unwrap();
        let staging = tmp("tamper-stg");
        let err = acquire(&AcquisitionMode::FromDir(src.clone()), TRIPLE, "", &staging)
            .expect_err("tampered binary must fail closed");
        assert!(err.contains("integrity check failed"), "{err}");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn from_dir_fails_closed_on_missing_binary() {
        let src = tmp("missing-src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join(format!("rustynetd-{TRIPLE}")), b"only-one").unwrap();
        let staging = tmp("missing-stg");
        let err = acquire(&AcquisitionMode::FromDir(src.clone()), TRIPLE, "", &staging)
            .expect_err("missing binary must fail closed");
        assert!(err.contains("not found"), "{err}");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn corrupt_co_located_manifest_is_a_hard_error() {
        let src = tmp("badmani-src");
        write_fake_binaries(&src);
        std::fs::write(src.join("release-manifest.json"), b"{not valid json").unwrap();
        let staging = tmp("badmani-stg");
        let err = acquire(&AcquisitionMode::FromDir(src.clone()), TRIPLE, "", &staging)
            .expect_err("corrupt manifest must fail closed");
        assert!(err.contains("release-manifest.json"), "{err}");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn verified_download_is_deferred_fail_closed() {
        let staging = tmp("vd-stg");
        let err = acquire(&AcquisitionMode::VerifiedDownload, TRIPLE, "", &staging)
            .expect_err("verified-download not yet available");
        assert!(err.contains("verified-download"), "{err}");
        let _ = std::fs::remove_dir_all(&staging);
    }
}
