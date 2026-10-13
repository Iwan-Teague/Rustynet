//! LAB-ONLY release-manifest seam for macOS live-lab installs.
//!
//! This module exists so that a live-lab macOS guest can pass the daemon's
//! signed-release provenance gate without weakening any security posture in
//! production builds. It mints a **throwaway, per-run Ed25519 signing seed**
//! under the orchestrator's report directory, signs release manifest(s) for
//! the exact artifacts about to be shipped — always the source archive, plus
//! a second manifest when host-cross-built prebuilt binaries ship (the
//! bootstrap verifies each against a staging dir holding only that
//! manifest's artifacts) — transfers the manifest(s) to the guest, and
//! injects the environment variables the bootstrap script already honours
//! (`RUSTYNET_RELEASE_MANIFEST`, `RN_PREBUILT_RELEASE_MANIFEST`,
//! `RUSTYNET_RELEASE_PINNED_KEY_HEX`). The guest verifies with the pinned
//! key exactly as it would for an official release; nothing about the
//! verification logic is bypassed.
//!
//! Threat-model notes:
//! - The seed is created with `O_EXCL` semantics (`create_new`) and mode
//!   `0600`, inside a `0700` directory (mode re-asserted even on a
//!   pre-existing dir), and is deleted when the `ThrowawaySeedGuard` drops
//!   (every install exit path). A seed left by a SIGKILLed run is swept at
//!   the next mint (age-threshold, far above any install's lifetime).
//! - The signed manifests cover the artifacts by *basename*, so a stale or
//!   substituted artifact cannot satisfy `--require-artifact`. The staging
//!   dir is unique per seam run (pid+nanos) so parallel node installs
//!   cannot overwrite each other's signed manifest.
//! - This entire module lives behind the `vm-lab` cargo feature and the
//!   explicit `--lab-throwaway-release-manifest` CLI flag (default OFF).
//!   Release builds never enable `vm-lab`, so none of this code — nor the
//!   pinned-key env var name — appears in release binaries. The
//!   `vm_lab_seam_release_hygiene_gate.sh` CI gate enforces that invariant.
//!
//! Owner approval: lab-only weakening for the macOS live lab (2026-10-06),
//! with the requirement that production strength is unchanged.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRngCore;

use crate::vm_lab::orchestrator::error::AdapterError;

/// Guest-side destination for the signed release manifest covering the
/// source archive (the manifest `RUSTYNET_RELEASE_MANIFEST` points at).
pub(crate) const LAB_MANIFEST_GUEST_PATH: &str = "/tmp/rn_release_manifest.json";

/// Guest-side destination for the signed release manifest covering the
/// host-cross prebuilt binaries (the manifest `RN_PREBUILT_RELEASE_MANIFEST`
/// points at). A separate file from [`LAB_MANIFEST_GUEST_PATH`] because the
/// bootstrap verifies each manifest against an artifacts dir that contains
/// ONLY that manifest's artifacts: the source-verify staging dir holds just
/// the archive copy, the prebuilt staging dir just the three binaries
/// (Bootstrap-RustyNetMacos.sh: verify_downloaded_payload reads every listed
/// artifact from its `--artifacts-dir`, so one combined manifest would fail
/// both verifications).
pub(crate) const LAB_PREBUILT_MANIFEST_GUEST_PATH: &str = "/tmp/rn_prebuilt_release_manifest.json";

/// Bootstrap-side env var carrying the manifest path. Must match
/// scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh exactly.
const ENV_MANIFEST_PATH: &str = "RUSTYNET_RELEASE_MANIFEST";
/// Bootstrap-side env var carrying the pinned verifier key (hex). Must match
/// the bootstrap script and Verify-RustyNetRelease.sh exactly.
const ENV_PINNED_KEY: &str = "RUSTYNET_RELEASE_PINNED_KEY_HEX";
/// Bootstrap-side env var overriding the prebuilt manifest location
/// (default `${RN_PREBUILT_DIR}/release-manifest.json`, which the seam does
/// not write). Must match Bootstrap-RustyNetMacos.sh exactly.
const ENV_PREBUILT_MANIFEST_PATH: &str = "RN_PREBUILT_RELEASE_MANIFEST";

/// Filenames the guest bootstrap verifies BY NAME when prebuilt binaries
/// are shipped. Anything else is refused here rather than failing later on
/// the guest; a set missing any of the three is refused too, because the
/// bootstrap hard-fails on every one of these names in RN_PREBUILT_DIR.
const PREBUILT_ARTIFACT_NAMES: [&str; 3] = ["rustynetd", "rustynet-cli", "rustynet-relay"];

/// D5 (review macos-harness-b): the artifact triple every lab manifest line
/// carries. The lab fleet is aarch64-macOS-only, and the manifest triple
/// must label the artifacts honestly — signing an x86_64 build under an
/// `aarch64-apple-darwin` triple would mislabel what the guest verifies.
/// [`seam_target_triple_for_arch`] refuses any other host arch instead.
pub(crate) const LAB_SEAM_TARGET_TRIPLE: &str = "aarch64-apple-darwin";

/// D5: resolve the manifest triple for the seam's host arch, refusing (named
/// error) when the arch is not aarch64. Pure in the host arch, so the guard
/// is unit-testable on any host; the production entry point
/// ([`LabManifestSeam::run`]) threads `std::env::consts::ARCH` through
/// [`LabManifestSeam::run_with_arch`] into this guard, so a non-aarch64
/// build host still refuses to sign lab manifests.
fn seam_target_triple_for_arch(host_arch: &str) -> Result<&'static str, AdapterError> {
    if host_arch == "aarch64" {
        Ok(LAB_SEAM_TARGET_TRIPLE)
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "lab manifest seam: this host is '{host_arch}' but every lab manifest triple \
                 is pinned to '{LAB_SEAM_TARGET_TRIPLE}' (the lab fleet is aarch64-macOS-only); \
                 signing here would mislabel the artifacts — refuse instead (fail closed; D5)"
            ),
        })
    }
}

/// Seeds older than this are leftovers from a SIGKILLed/`process::exit`ed
/// run (the Drop guard only covers unwinding). Swept at the next mint; the
/// threshold is far above any single install's lifetime, so a concurrent
/// live seed is never collected.
const STALE_SEED_MAX_AGE_SECS: u64 = 3600;

/// Validate a pinned-verifier-key hex string: exactly 64 lowercase hex
/// characters (an Ed25519 public key). This is the value that will travel to
/// the guest, so it is validated strictly at the seam.
pub(crate) fn validate_verifier_key_hex(key: &str) -> Result<(), AdapterError> {
    let reject = |why: &str| AdapterError::Protocol {
        message: format!("lab manifest seam: invalid verifier key hex: {why}"),
    };
    if key.len() != 64 {
        return Err(reject(
            "expected exactly 64 hex characters (Ed25519 public key)",
        ));
    }
    if !key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(reject("must be lowercase hex only"));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Read the `verifier_key_hex` field out of a signed manifest and validate it.
pub(crate) fn verifier_key_from_manifest(manifest_path: &Path) -> Result<String, AdapterError> {
    let raw = std::fs::read_to_string(manifest_path).map_err(|e| AdapterError::Io {
        message: format!(
            "lab manifest seam: cannot read manifest {}: {e}",
            manifest_path.display()
        ),
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AdapterError::Protocol {
            message: format!("lab manifest seam: manifest is not valid JSON: {e}"),
        })?;
    let key = value
        .get("verifier_key_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AdapterError::Protocol {
            message: "lab manifest seam: manifest lacks verifier_key_hex".to_owned(),
        })?;
    validate_verifier_key_hex(key)?;
    Ok(key.to_owned())
}

/// Drops → deletes the throwaway seed file. Held by [`LabManifestSeam`] so
/// every install exit path (success, scp failure, guest failure) removes the
/// signing material from the host.
struct ThrowawaySeedGuard {
    seed_path: PathBuf,
}

impl Drop for ThrowawaySeedGuard {
    fn drop(&mut self) {
        // Best effort: the seed dir is 0700 under the report dir, so a
        // failure to unlink is not a directory-traversal hazard. Tests pin
        // the deletion behaviour.
        let _ = std::fs::remove_file(&self.seed_path);
    }
}

/// Mint a fresh 32-byte OsRng seed, write it as a hex text file (the format
/// `ops create-release-manifest --signing-seed-file` consumes) under
/// `<report_dir>/lab-release-seed/`, created `0700`; the file itself is
/// `0600` and created with `create_new` (O_EXCL) so a colliding name fails
/// instead of overwriting. Before minting: the directory mode is re-asserted
/// `0700` even if the directory already existed with a weaker mode, and seed
/// files older than [`STALE_SEED_MAX_AGE_SECS`] (left by a SIGKILLed /
/// `process::exit`ed run the Drop guard could not cover) are swept.
fn mint_throwaway_seed(report_dir: &Path) -> Result<(PathBuf, String), AdapterError> {
    let dir = report_dir.join("lab-release-seed");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot create seed dir {}: {e}",
                dir.display()
            ),
        })?;
    // DirBuilder::create is a no-op on an existing directory: re-assert the
    // mode so a pre-existing weaker dir cannot downgrade the seed's
    // containment.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot enforce 0700 on seed dir {}: {e}",
                dir.display()
            ),
        }
    })?;
    sweep_stale_seeds(&dir)?;

    let mut seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| AdapterError::Protocol {
            message: format!("lab manifest seam: OsRng failure: {e}"),
        })?;
    let hex = hex_encode(&seed);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("seed-{}-{}.hex", std::process::id(), nanos));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot create seed file {}: {e}",
                path.display()
            ),
        })?;
    f.write_all(hex.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot write seed file {}: {e}",
                path.display()
            ),
        })?;
    Ok((path, hex))
}

/// Best-effort sweep of seed files left behind by a run that died without
/// unwinding (SIGKILL / `process::exit` bypass the Drop guard). Only files
/// named `seed-*.hex` older than [`STALE_SEED_MAX_AGE_SECS`] are removed —
/// a threshold far above any single install's lifetime, so seeds of
/// concurrent live installs (minutes old at most) are never collected.
fn sweep_stale_seeds(dir: &Path) -> Result<(), AdapterError> {
    let entries = std::fs::read_dir(dir).map_err(|e| AdapterError::Io {
        message: format!(
            "lab manifest seam: cannot read seed dir {}: {e}",
            dir.display()
        ),
    })?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("seed-") || !name.ends_with(".hex") {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.elapsed().ok())
            .map(|age| age.as_secs() > STALE_SEED_MAX_AGE_SECS)
            .unwrap_or(false);
        if stale {
            // Best effort: the sweep is hygiene, not a security boundary
            // (the dir is 0700 and the files 0600).
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// The exact env-file lines the seam appends. The key is validated before
/// this is ever called; the extra validation here is defence in depth.
/// `prebuilt` adds the `RN_PREBUILT_RELEASE_MANIFEST` override pointing the
/// bootstrap's prebuilt branch at the seam's binaries manifest (its default
/// location `${RN_PREBUILT_DIR}/release-manifest.json` is never written by
/// the seam).
pub(crate) fn lab_manifest_env_lines(
    verifier_key_hex: &str,
    prebuilt: bool,
) -> Result<String, AdapterError> {
    validate_verifier_key_hex(verifier_key_hex)?;
    let mut out = format!(
        "{ENV_MANIFEST_PATH}={LAB_MANIFEST_GUEST_PATH}\n{ENV_PINNED_KEY}={verifier_key_hex}\n"
    );
    if prebuilt {
        out.push_str(&format!(
            "{ENV_PREBUILT_MANIFEST_PATH}={LAB_PREBUILT_MANIFEST_GUEST_PATH}\n"
        ));
    }
    Ok(out)
}

/// Read the signing seed back in the strict format the ops layer expects
/// (hex text → `[u8; 32]`).
fn read_seed_bytes(seed_path: &Path) -> Result<Vec<u8>, AdapterError> {
    let text = std::fs::read_to_string(seed_path).map_err(|e| AdapterError::Io {
        message: format!(
            "lab manifest seam: cannot read seed {}: {e}",
            seed_path.display()
        ),
    })?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(AdapterError::Protocol {
            message: "lab manifest seam: seed hex must be 64 chars".to_owned(),
        });
    }
    let mut out = Vec::with_capacity(32);
    let nibble = |b: u8| -> Result<u8, AdapterError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(AdapterError::Protocol {
                message: "lab manifest seam: seed hex invalid".to_owned(),
            }),
        }
    };
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

/// A live-lab manifest seam run: owns the throwaway seed (deleted on drop),
/// the host-side signed manifests, and the verifier key they advertise.
pub(crate) struct LabManifestSeam {
    _seed_guard: ThrowawaySeedGuard,
    /// Per-run staging dir `<report_dir>/lab-release-manifest/run-<pid>-<nanos>/`
    /// (0700). Unique per seam run so parallel node installs sharing a
    /// report dir cannot overwrite each other's signed manifest between
    /// signing and scp.
    run_dir: PathBuf,
    /// Manifest covering the staged source archive; always present, because
    /// the bootstrap verifies the archive before every build path.
    source_manifest_path: PathBuf,
    /// Manifest covering the host-cross prebuilt binaries; present only when
    /// prebuilt binaries are actually shipped.
    prebuilt_manifest_path: Option<PathBuf>,
    verifier_key_hex: String,
}

impl LabManifestSeam {
    /// Create the seed and sign the manifest(s) for exactly the artifacts
    /// about to be shipped, keying the D5 arch guard on THIS host
    /// (`std::env::consts::ARCH`). The source archive is ALWAYS signed (staged as
    /// `rn_source.tar.gz`, the name `install_daemon` transfers and the
    /// bootstrap verifies by) — the guest bootstrap verifies the archive
    /// before every build path, prebuilt or not. When `prebuilt_binaries`
    /// is non-empty, a SECOND manifest covering those binaries by basename
    /// is signed: the bootstrap's prebuilt branch verifies its own manifest
    /// against a staging dir holding only the binaries, so the two
    /// verifications cannot share one manifest.
    pub(crate) fn run(
        report_dir: &Path,
        source_archive: &Path,
        prebuilt_binaries: &[PathBuf],
    ) -> Result<Self, AdapterError> {
        Self::run_with_arch(
            report_dir,
            source_archive,
            prebuilt_binaries,
            std::env::consts::ARCH,
        )
    }

    /// [`Self::run`] with the build-host arch injected. Production callers
    /// must go through [`Self::run`] (which keys on `std::env::consts::ARCH`);
    /// tests pass the pinned lab arch explicitly so both the signing path
    /// and the D5 refusal are exercised on every host arch, Linux CI
    /// included.
    fn run_with_arch(
        report_dir: &Path,
        source_archive: &Path,
        prebuilt_binaries: &[PathBuf],
        host_arch: &str,
    ) -> Result<Self, AdapterError> {
        // Resolve the D5 guard FIRST: a non-aarch64 build host is refused
        // before any signing material is minted or the archive is staged.
        let triple = seam_target_triple_for_arch(host_arch)?;
        let (seed_path, _seed_hex) = mint_throwaway_seed(report_dir)?;
        let seed_guard = ThrowawaySeedGuard {
            seed_path: seed_path.clone(),
        };

        let run_dir = seam_run_dir(report_dir)?;
        let staged = stage_source_archive(&run_dir, source_archive)?;
        let source_manifest_path = create_lab_manifest(
            &[format!("rn_source.tar.gz:{}:{}", triple, staged.display())],
            &seed_path,
            run_dir.join("release-manifest.json"),
        )?;
        let prebuilt_manifest_path = if prebuilt_binaries.is_empty() {
            None
        } else {
            Some(create_lab_manifest(
                &prebuilt_artifact_specs(prebuilt_binaries, triple)?,
                &seed_path,
                run_dir.join("prebuilt-release-manifest.json"),
            )?)
        };

        let verifier_key_hex = verifier_key_from_manifest(&source_manifest_path)?;
        Ok(LabManifestSeam {
            _seed_guard: seed_guard,
            run_dir,
            source_manifest_path,
            prebuilt_manifest_path,
            verifier_key_hex,
        })
    }

    /// Host-side path of the source-archive manifest to scp to
    /// [`LAB_MANIFEST_GUEST_PATH`].
    pub(crate) fn manifest_host_path(&self) -> &Path {
        &self.source_manifest_path
    }

    /// Host-side path of the prebuilt-binaries manifest to scp to
    /// [`LAB_PREBUILT_MANIFEST_GUEST_PATH`], when prebuilt binaries are
    /// shipped.
    pub(crate) fn prebuilt_manifest_host_path(&self) -> Option<&Path> {
        self.prebuilt_manifest_path.as_deref()
    }

    /// Env-file lines pointing the guest bootstrap at the manifest(s) and
    /// the pinned verifier key.
    pub(crate) fn env_lines(&self) -> Result<String, AdapterError> {
        lab_manifest_env_lines(
            &self.verifier_key_hex,
            self.prebuilt_manifest_path.is_some(),
        )
    }
}

/// Stage the source archive into the per-run dir under the exact basename
/// the guest requires (`rn_source.tar.gz` — the manifest binds artifacts by
/// the staged file's basename).
fn stage_source_archive(run_dir: &Path, source_archive: &Path) -> Result<PathBuf, AdapterError> {
    if !source_archive.exists() {
        return Err(AdapterError::InvalidPath {
            path: source_archive.to_path_buf(),
            reason: "lab manifest seam: source archive does not exist".to_owned(),
        });
    }
    let staged = run_dir.join("rn_source.tar.gz");
    std::fs::copy(source_archive, &staged).map_err(|e| AdapterError::Io {
        message: format!(
            "lab manifest seam: cannot stage archive {} → {}: {e}",
            source_archive.display(),
            staged.display()
        ),
    })?;
    Ok(staged)
}

/// Build the artifact specs for the host-cross prebuilt binaries. Every
/// file must be named exactly `rustynetd`, `rustynet-cli`, or
/// `rustynet-relay`, and all three must be present — the guest bootstrap
/// hard-fails if any of the three is missing from RN_PREBUILT_DIR, so a
/// subset would only move the failure to the guest. `triple` is the
/// D5-resolved manifest triple (see [`seam_target_triple_for_arch`]).
fn prebuilt_artifact_specs(
    binaries: &[PathBuf],
    triple: &str,
) -> Result<Vec<String>, AdapterError> {
    let mut specs = Vec::with_capacity(binaries.len());
    for bin in binaries {
        let name =
            bin.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| AdapterError::InvalidPath {
                    path: bin.clone(),
                    reason: "lab manifest seam: binary has no usable filename".to_owned(),
                })?;
        if !PREBUILT_ARTIFACT_NAMES.contains(&name) {
            return Err(AdapterError::Protocol {
                message: format!(
                    "lab manifest seam: prebuilt binary '{name}' is not one of {}",
                    PREBUILT_ARTIFACT_NAMES.join(", ")
                ),
            });
        }
        specs.push(format!("{name}:{triple}:{}", bin.display()));
    }
    let mut names: Vec<&str> = specs
        .iter()
        .map(|s| s.split(':').next().unwrap_or(""))
        .collect();
    names.sort_unstable();
    let mut expected = PREBUILT_ARTIFACT_NAMES.to_vec();
    expected.sort_unstable();
    if names != expected {
        return Err(AdapterError::Protocol {
            message: format!(
                "lab manifest seam: prebuilt flavour needs exactly {}, got: {}",
                PREBUILT_ARTIFACT_NAMES.join(", "),
                names.join(", ")
            ),
        });
    }
    Ok(specs)
}

/// Per-run staging dir: `<report_dir>/lab-release-manifest/run-<pid>-<nanos>/`,
/// created (and re-asserted) `0700`. The pid+nanos suffix keeps concurrent
/// node installs — the orchestrator supports `--max-parallel-node-workers > 1`
/// — from overwriting each other's staged archive or signed manifest.
fn seam_run_dir(report_dir: &Path) -> Result<PathBuf, AdapterError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = report_dir.join("lab-release-manifest").join(format!(
        "run-{}-{}",
        std::process::id(),
        nanos
    ));
    create_dir_0700(&dir)?;
    Ok(dir)
}

/// Create `dir` (recursively) and re-assert `0700` even if it already
/// existed with a weaker mode (`DirBuilder::create` no-ops on existing
/// directories).
fn create_dir_0700(dir: &Path) -> Result<(), AdapterError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot create dir {}: {e}",
                dir.display()
            ),
        })?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        AdapterError::Io {
            message: format!(
                "lab manifest seam: cannot enforce 0700 on {}: {e}",
                dir.display()
            ),
        }
    })
}

/// Call the ops layer in-process to build and sign the manifest at `output`.
/// Returns the manifest path.
fn create_lab_manifest(
    artifacts: &[String],
    seed_path: &Path,
    output: PathBuf,
) -> Result<PathBuf, AdapterError> {
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::ops_release_manifest::execute_ops_create_release_manifest(
        artifacts.to_vec(),
        "lab-throwaway".to_owned(),
        seed_path.to_path_buf(),
        "lab-throwaway-seed".to_owned(),
        output.clone(),
        generated_at,
    )
    .map_err(|e| AdapterError::Protocol { message: e })?;
    Ok(output)
}

/// Append the seam env lines to a bootstrap env file.
///
/// `None` → byte-identical passthrough (the OFF path must not change a
/// single byte of existing behaviour). `Some` → a blank line, then the
/// `RUSTYNET_RELEASE_MANIFEST` / `RUSTYNET_RELEASE_PINNED_KEY_HEX` lines,
/// then — for build-from-source runs — the `SOURCE_ARCHIVE` pin that the
/// bootstrap's `set -u` requires and that the from-workdir path normally
/// provides via a remote echo.
pub(crate) fn append_lab_manifest_env(
    env_content: String,
    seam: Option<&LabManifestSeam>,
) -> Result<String, AdapterError> {
    let Some(seam) = seam else {
        return Ok(env_content);
    };
    let mut out = env_content;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&seam.env_lines()?);
    out.push_str("SOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rn-seam-test-{}-{}",
            tag,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn validate_verifier_key_hex_accepts_64_lowercase() {
        assert!(validate_verifier_key_hex(VALID_KEY).is_ok());
    }

    #[test]
    fn validate_verifier_key_hex_rejects_wrong_length() {
        assert!(validate_verifier_key_hex("00ff").is_err());
        assert!(validate_verifier_key_hex(&"a".repeat(63)).is_err());
        assert!(validate_verifier_key_hex(&"a".repeat(65)).is_err());
        assert!(validate_verifier_key_hex("").is_err());
    }

    #[test]
    fn validate_verifier_key_hex_rejects_uppercase_and_metachars() {
        assert!(validate_verifier_key_hex(&VALID_KEY.to_uppercase()).is_err());
        let mut evil = VALID_KEY.as_bytes().to_vec();
        evil[0] = b'g';
        assert!(validate_verifier_key_hex(std::str::from_utf8(&evil).unwrap()).is_err());
        let mut inject = VALID_KEY.as_bytes().to_vec();
        inject[10] = b'\n';
        assert!(validate_verifier_key_hex(std::str::from_utf8(&inject).unwrap()).is_err());
        let mut space = VALID_KEY.as_bytes().to_vec();
        space[30] = b' ';
        assert!(validate_verifier_key_hex(std::str::from_utf8(&space).unwrap()).is_err());
    }

    #[test]
    fn env_lines_are_exact() {
        let lines = lab_manifest_env_lines(VALID_KEY, false).unwrap();
        assert_eq!(
            lines,
            format!(
                "RUSTYNET_RELEASE_MANIFEST={LAB_MANIFEST_GUEST_PATH}\nRUSTYNET_RELEASE_PINNED_KEY_HEX={VALID_KEY}\n"
            )
        );
        // Prebuilt mode adds exactly one more line, pointing the bootstrap's
        // prebuilt branch at the seam's binaries manifest.
        let prebuilt_lines = lab_manifest_env_lines(VALID_KEY, true).unwrap();
        assert_eq!(
            prebuilt_lines,
            format!(
                "RUSTYNET_RELEASE_MANIFEST={LAB_MANIFEST_GUEST_PATH}\nRUSTYNET_RELEASE_PINNED_KEY_HEX={VALID_KEY}\nRN_PREBUILT_RELEASE_MANIFEST={LAB_PREBUILT_MANIFEST_GUEST_PATH}\n"
            )
        );
        // and refuse an unvalidated key
        assert!(lab_manifest_env_lines("short", false).is_err());
    }

    #[test]
    fn minted_seed_is_0600_in_0700_dir_and_hex64() {
        let report = tmpdir("mint");
        let (path, hex) = mint_throwaway_seed(&report).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "seed file must be 0600");
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "seed dir must be 0700");
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn seed_is_deleted_after_drop() {
        let report = tmpdir("guard");
        // create a tiny fake archive
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"pretend-archive").unwrap();
        let seam = LabManifestSeam::run_with_arch(&report, &arch, &[], "aarch64").unwrap();
        let seed_dir = report.join("lab-release-seed");
        let seeds_before: Vec<_> = std::fs::read_dir(&seed_dir).unwrap().collect();
        assert_eq!(seeds_before.len(), 1, "exactly one throwaway seed exists");
        let manifest_path = seam.manifest_host_path().to_path_buf();
        assert!(manifest_path.exists());
        drop(seam);
        assert!(
            std::fs::read_dir(&seed_dir).unwrap().next().is_none(),
            "seed must be deleted when the seam drops"
        );
        // manifest itself survives (evidence for the run report)
        assert!(manifest_path.exists());
        std::fs::remove_dir_all(&report).unwrap();
    }

    /// D5 (review macos-harness-b): the manifest triple is pinned to
    /// aarch64 macOS; a host that is not aarch64 must be REFUSED with a
    /// named error instead of receiving mislabelled artifact specs.
    #[test]
    fn seam_triple_refuses_a_non_aarch64_host_arch() {
        assert_eq!(
            seam_target_triple_for_arch("aarch64").expect("aarch64 is the pinned lab host"),
            LAB_SEAM_TARGET_TRIPLE,
        );
        let err = seam_target_triple_for_arch("x86_64").expect_err("must refuse");
        match err {
            AdapterError::Protocol { message } => {
                assert!(
                    message.contains("x86_64"),
                    "the refusal must name the offending arch: {message}"
                );
                assert!(
                    message.contains(LAB_SEAM_TARGET_TRIPLE),
                    "the refusal must name the pinned triple: {message}"
                );
                assert!(
                    message.contains("mislabel"),
                    "the refusal must say why: {message}"
                );
            }
            other => panic!("expected AdapterError::Protocol, got {other:?}"),
        }
    }

    /// D5 guard direction (a): with the pinned arch injected, the seam
    /// SIGNS, and the manifest it writes carries exactly the pinned
    /// `aarch64-apple-darwin` triple. Runs on every host, Linux CI included.
    #[test]
    fn seam_signs_for_aarch64_with_pinned_triple() {
        let report = tmpdir("sign-aarch64");
        let archive = report.join("src.tar.gz");
        std::fs::write(&archive, b"pretend-archive-bytes").unwrap();
        let seam = LabManifestSeam::run_with_arch(&report, &archive, &[], "aarch64")
            .expect("aarch64 is the pinned lab fleet arch; the seam must sign here");
        let json = std::fs::read_to_string(seam.manifest_host_path()).unwrap();
        assert!(
            json.contains("\"target\": \"aarch64-apple-darwin\""),
            "source manifest must pin the aarch64 triple: {json}"
        );
        assert!(
            !json.contains("x86_64"),
            "no x86_64 triple may appear: {json}"
        );
        std::fs::remove_dir_all(&report).unwrap();
    }

    /// D5 guard direction (b): every non-aarch64 arch ("x86_64", "arm", "")
    /// is REFUSED with the exact named error, both at the triple guard and
    /// end to end before any signing material exists. This keeps the guard
    /// tested on every host, including an x86_64 Linux CI runner.
    #[test]
    fn seam_refuses_non_aarch64_arch_exact() {
        for host_arch in ["x86_64", "arm", ""] {
            let expected_message = format!(
                "lab manifest seam: this host is '{host_arch}' but every lab manifest triple is pinned to '{LAB_SEAM_TARGET_TRIPLE}' (the lab fleet is aarch64-macOS-only); signing here would mislabel the artifacts — refuse instead (fail closed; D5)"
            );
            match seam_target_triple_for_arch(host_arch) {
                Ok(triple) => panic!("arch '{host_arch}' must be refused, got triple {triple}"),
                Err(AdapterError::Protocol { message }) => {
                    assert_eq!(message, expected_message, "refusal text changed");
                }
                Err(other) => panic!("expected AdapterError::Protocol, got {other:?}"),
            }
            // End to end: the run refuses at the guard, before minting any
            // signing material.
            let report = tmpdir("refuse-non-aarch64");
            let archive = report.join("src.tar.gz");
            std::fs::write(&archive, b"x").unwrap();
            match LabManifestSeam::run_with_arch(&report, &archive, &[], host_arch) {
                Ok(_) => panic!("arch '{host_arch}' must be refused end to end"),
                Err(AdapterError::Protocol { message }) => {
                    assert_eq!(message, expected_message);
                }
                Err(other) => panic!("expected AdapterError::Protocol, got {other:?}"),
            }
            assert!(
                !report.join("lab-release-seed").exists(),
                "the refusal must happen before any seed is minted"
            );
            std::fs::remove_dir_all(&report).unwrap();
        }
    }

    /// The production entry keys the D5 guard on THIS host's arch: `run`
    /// must behave exactly like `run_with_arch(std::env::consts::ARCH)`. On
    /// a non-aarch64 build host (Linux CI) this test fails if the
    /// production wrapper hard-codes "aarch64" instead of the host arch.
    #[test]
    fn production_run_keys_on_this_host_arch() {
        let report = tmpdir("prod-arch");
        let archive = report.join("src.tar.gz");
        std::fs::write(&archive, b"x").unwrap();
        let injected =
            LabManifestSeam::run_with_arch(&report, &archive, &[], std::env::consts::ARCH).is_ok();
        let production = LabManifestSeam::run(&report, &archive, &[]).is_ok();
        assert_eq!(
            production, injected,
            "run() must key on std::env::consts::ARCH"
        );
        std::fs::remove_dir_all(&report).unwrap();
    }

    /// D5: the artifact specs carry exactly the pinned triple — the
    /// mislabelled hardcoded string is gone from both manifest paths. The
    /// pinned triple is resolved through the PURE arch-keyed
    /// [`seam_target_triple_for_arch`]: production keys the guard on
    /// `std::env::consts::ARCH` (the BUILD host's arch) inside
    /// [`LabManifestSeam::run`], so a test that unwrapped the production
    /// entry would fail on every non-aarch64 build host (N1, review
    /// macos-nits). Tests instead inject the arch via
    /// [`LabManifestSeam::run_with_arch`]; the refusal such hosts get in
    /// production is covered by `seam_refuses_non_aarch64_arch_exact` below.
    #[test]
    fn prebuilt_specs_carry_the_pinned_lab_triple() {
        let triple = seam_target_triple_for_arch("aarch64")
            .expect("aarch64 is the pinned lab fleet arch and must resolve");
        assert_eq!(triple, LAB_SEAM_TARGET_TRIPLE);
        let bins: Vec<PathBuf> = PREBUILT_ARTIFACT_NAMES
            .iter()
            .map(|name| PathBuf::from(format!("/tmp/fake-target-dir/{name}")))
            .collect();
        for spec in prebuilt_artifact_specs(&bins, triple).expect("specs") {
            assert!(
                spec.contains(":aarch64-apple-darwin:"),
                "every spec must carry the pinned triple: {spec}"
            );
        }
    }

    #[test]
    fn parallel_seam_runs_get_distinct_manifest_paths() {
        let report = tmpdir("parallel");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"pretend-archive").unwrap();
        // Two installs into the SAME report dir (what --max-parallel-node-workers
        // produces): the second must never overwrite the first's signed manifest,
        // or the first guest receives a manifest whose signature does not match
        // its env-pinned key.
        let seam_a = LabManifestSeam::run_with_arch(&report, &arch, &[], "aarch64").unwrap();
        let seam_b = LabManifestSeam::run_with_arch(&report, &arch, &[], "aarch64").unwrap();
        let path_a = seam_a.manifest_host_path().to_path_buf();
        let path_b = seam_b.manifest_host_path().to_path_buf();
        assert_ne!(
            path_a, path_b,
            "concurrent seam runs must not share a manifest path"
        );
        assert!(path_a.exists());
        assert!(path_b.exists());
        let seed_dir = report.join("lab-release-seed");
        let seeds: Vec<_> = std::fs::read_dir(&seed_dir).unwrap().collect();
        assert_eq!(seeds.len(), 2, "both live runs hold their own seed");
        drop(seam_a);
        drop(seam_b);
        assert!(
            std::fs::read_dir(&seed_dir).unwrap().next().is_none(),
            "both seeds must be gone once both runs drop"
        );
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn stale_seed_files_are_swept_at_mint() {
        let report = tmpdir("sweep");
        let seed_dir = report.join("lab-release-seed");
        std::fs::create_dir_all(&seed_dir).unwrap();
        let stale = seed_dir.join("seed-123-999.hex");
        std::fs::write(&stale, "ab".repeat(32)).unwrap();
        let two_hours_ago = SystemTime::now() - std::time::Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();
        // A fresh foreign seed (a concurrent live install) must survive.
        let fresh = seed_dir.join("seed-456-1000.hex");
        std::fs::write(&fresh, "cd".repeat(32)).unwrap();
        let (minted, _) = mint_throwaway_seed(&report).unwrap();
        assert!(
            !stale.exists(),
            "a seed left by a SIGKILLed run must be swept at the next mint"
        );
        assert!(
            fresh.exists(),
            "a fresh seed from a concurrent live install must never be swept"
        );
        assert!(minted.exists());
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn seed_dir_mode_is_reasserted_on_preexisting_dir() {
        use std::os::unix::fs::PermissionsExt;
        let report = tmpdir("mode");
        let seed_dir = report.join("lab-release-seed");
        std::fs::create_dir_all(&seed_dir).unwrap();
        std::fs::set_permissions(&seed_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (path, _) = mint_throwaway_seed(&report).unwrap();
        let dir_mode = std::fs::metadata(&seed_dir).unwrap().permissions().mode();
        assert_eq!(
            dir_mode & 0o777,
            0o700,
            "a pre-existing weaker seed dir must be re-asserted to 0700"
        );
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn end_to_end_source_manifest_verifies_with_pinned_key_and_wrong_key_fails() {
        let report = tmpdir("e2e");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"pretend-archive-bytes").unwrap();

        let seam = LabManifestSeam::run_with_arch(&report, &arch, &[], "aarch64").unwrap();
        let manifest = seam.manifest_host_path().to_path_buf();
        // The guest's source verify reads every manifest artifact from its
        // private staging dir; mirror that with the seam run dir, which holds
        // the staged archive.
        let verify_dir = manifest.parent().unwrap().to_path_buf();

        // Wrong key must fail closed.
        let wrong = crate::ops_release_manifest::execute_ops_verify_release_manifest(
            manifest.clone(),
            Some(VALID_KEY.to_owned()),
            None,
            Some(verify_dir.clone()),
            vec!["rn_source.tar.gz".to_owned()],
        );
        assert!(
            wrong.is_err(),
            "manifest must not verify under a foreign key"
        );

        // Verify with the seam's own pinned key… but the pinned key is
        // private to the seed; the verifier needs the *public* key. The
        // manifest embeds verifier_key_hex, so extract it and require-artifact.
        let key = verifier_key_from_manifest(&manifest).unwrap();
        // The verifier derives the public key from the signing seed's
        // counterpart embedded in the manifest; verification with the
        // manifest's own key binding must succeed.
        let ok = crate::ops_release_manifest::execute_ops_verify_release_manifest(
            manifest.clone(),
            Some(key.clone()),
            None,
            Some(verify_dir.clone()),
            vec!["rn_source.tar.gz".to_owned()],
        );
        assert!(ok.is_ok(), "verify with pinned key failed: {ok:?}");

        // require-artifact must bind the basename.
        let bad_name = crate::ops_release_manifest::execute_ops_verify_release_manifest(
            manifest,
            Some(key),
            None,
            Some(verify_dir),
            vec!["totally-different.tar.gz".to_owned()],
        );
        assert!(bad_name.is_err(), "require-artifact must bind basename");

        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn verifier_key_from_manifest_rejects_missing_field() {
        let report = tmpdir("nokey");
        let m = report.join("m.json");
        std::fs::write(&m, "{\"something\":1}").unwrap();
        assert!(verifier_key_from_manifest(&m).is_err());
        assert!(verifier_key_from_manifest(&report.join("nope.json")).is_err());
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn seed_bytes_never_leak_into_manifest_or_env_lines() {
        let report = tmpdir("leak");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"x").unwrap();
        let (seed_path, seed_hex) = mint_throwaway_seed(&report).unwrap();
        let run_dir = seam_run_dir(&report).unwrap();
        let staged = stage_source_archive(&run_dir, &arch).unwrap();
        let manifest = create_lab_manifest(
            &[format!(
                "rn_source.tar.gz:aarch64-apple-darwin:{}",
                staged.display()
            )],
            &seed_path,
            run_dir.join("release-manifest.json"),
        )
        .unwrap();
        let json = std::fs::read_to_string(&manifest).unwrap();
        assert!(
            !json.contains(&seed_hex),
            "manifest must not embed the raw seed"
        );
        // env lines built from the manifest key only
        let key = verifier_key_from_manifest(&manifest).unwrap();
        let lines = lab_manifest_env_lines(&key, false).unwrap();
        assert!(!lines.contains(&seed_hex));
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn append_none_is_identity() {
        let base = "ROLE=Validator\nNODE_ID=n1\n".to_owned();
        assert_eq!(
            append_lab_manifest_env(base.clone(), None).unwrap(),
            base,
            "OFF path must be byte-identical"
        );
    }

    #[test]
    fn append_some_adds_manifest_env_and_source_archive() {
        let report = tmpdir("append");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"x").unwrap();
        let seam = LabManifestSeam::run_with_arch(&report, &arch, &[], "aarch64").unwrap();
        let out = append_lab_manifest_env("ROLE=Validator\n".to_owned(), Some(&seam)).unwrap();
        assert!(out.contains("RUSTYNET_RELEASE_MANIFEST=/tmp/rn_release_manifest.json\n"));
        assert!(out.contains("RUSTYNET_RELEASE_PINNED_KEY_HEX="));
        assert!(out.ends_with("SOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n"));
        assert!(
            !out.contains("RN_PREBUILT_RELEASE_MANIFEST="),
            "source-only runs must not emit the prebuilt manifest override: {out}"
        );
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn append_prebuilt_adds_prebuilt_manifest_override() {
        let report = tmpdir("append-pre");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"x").unwrap();
        let mut paths = Vec::new();
        for name in ["rustynetd", "rustynet-cli", "rustynet-relay"] {
            let p = report.join(name);
            std::fs::write(&p, b"elf-bytes").unwrap();
            paths.push(p);
        }
        let seam = LabManifestSeam::run_with_arch(&report, &arch, &paths, "aarch64").unwrap();
        let out = append_lab_manifest_env("ROLE=Validator\n".to_owned(), Some(&seam)).unwrap();
        assert!(
            out.contains("RN_PREBUILT_RELEASE_MANIFEST=/tmp/rn_prebuilt_release_manifest.json\n")
        );
        assert!(out.contains("RUSTYNET_RELEASE_MANIFEST=/tmp/rn_release_manifest.json\n"));
        assert!(out.ends_with("SOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n"));
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn prebuilt_manifest_rejects_foreign_names() {
        let report = tmpdir("prebuilt");
        let bin = report.join("evil-binary");
        std::fs::write(&bin, b"MZ").unwrap();
        assert!(prebuilt_artifact_specs(&[bin], LAB_SEAM_TARGET_TRIPLE).is_err());
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn prebuilt_flavour_refuses_incomplete_binary_set() {
        let report = tmpdir("prebuilt-sub");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"x").unwrap();
        // The guest bootstrap hard-fails if ANY of the three prebuilt names is
        // missing from RN_PREBUILT_DIR, so a subset would only move the failure
        // to the guest — the seam must refuse it here.
        for name in ["rustynetd", "rustynet-cli"] {
            std::fs::write(report.join(name), b"elf-bytes").unwrap();
        }
        let paths = vec![report.join("rustynetd"), report.join("rustynet-cli")];
        let err = LabManifestSeam::run_with_arch(&report, &arch, &paths, "aarch64");
        assert!(
            err.is_err(),
            "a prebuilt set missing rustynet-relay must be refused host-side"
        );
        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn prebuilt_flavour_covers_both_guest_verifications() {
        let report = tmpdir("prebuilt-ok");
        let arch = report.join("src.tar.gz");
        std::fs::write(&arch, b"pretend-archive-bytes").unwrap();
        let mut paths = Vec::new();
        for name in ["rustynetd", "rustynet-cli", "rustynet-relay"] {
            let p = report.join(name);
            std::fs::write(&p, b"elf-bytes").unwrap();
            paths.push(p);
        }
        let seam = LabManifestSeam::run_with_arch(&report, &arch, &paths, "aarch64").unwrap();
        let source_manifest = seam.manifest_host_path().to_path_buf();
        let prebuilt_manifest = seam
            .prebuilt_manifest_host_path()
            .expect("prebuilt run must produce a binaries manifest")
            .to_path_buf();
        let key = verifier_key_from_manifest(&source_manifest).unwrap();
        assert_eq!(
            verifier_key_from_manifest(&prebuilt_manifest).unwrap(),
            key,
            "both manifests must be signed by the same throwaway key"
        );

        // Guest source verify: private staging dir holds ONLY the archive
        // (Bootstrap-RustyNetMacos.sh copies SOURCE_ARCHIVE into RN_VERIFY_STAGE
        // and passes that dir as --artifacts-dir), so the source manifest must
        // list nothing but the archive.
        let source_stage = report.join("guest-source-stage");
        std::fs::create_dir_all(&source_stage).unwrap();
        std::fs::copy(&arch, source_stage.join("rn_source.tar.gz")).unwrap();
        let ok = crate::ops_release_manifest::execute_ops_verify_release_manifest(
            source_manifest.clone(),
            Some(key.clone()),
            None,
            Some(source_stage),
            vec!["rn_source.tar.gz".to_owned()],
        );
        assert!(ok.is_ok(), "source verify failed: {ok:?}");

        // Guest prebuilt verify: private staging dir holds ONLY the three
        // binaries + the manifest copy named release-manifest.json; the
        // binaries manifest must list nothing but those three.
        let prebuilt_stage = report.join("guest-prebuilt-stage");
        std::fs::create_dir_all(&prebuilt_stage).unwrap();
        for name in ["rustynetd", "rustynet-cli", "rustynet-relay"] {
            std::fs::copy(report.join(name), prebuilt_stage.join(name)).unwrap();
        }
        std::fs::copy(
            &prebuilt_manifest,
            prebuilt_stage.join("release-manifest.json"),
        )
        .unwrap();
        let ok = crate::ops_release_manifest::execute_ops_verify_release_manifest(
            prebuilt_stage.join("release-manifest.json"),
            Some(key),
            None,
            Some(prebuilt_stage),
            vec![
                "rustynetd".to_owned(),
                "rustynet-cli".to_owned(),
                "rustynet-relay".to_owned(),
            ],
        );
        assert!(ok.is_ok(), "prebuilt verify failed: {ok:?}");

        std::fs::remove_dir_all(&report).unwrap();
    }

    #[test]
    fn missing_source_archive_is_rejected() {
        let report = tmpdir("missing");
        let seam_err =
            LabManifestSeam::run_with_arch(&report, &report.join("nope.tar.gz"), &[], "aarch64");
        assert!(seam_err.is_err());
        std::fs::remove_dir_all(&report).unwrap();
    }
}
