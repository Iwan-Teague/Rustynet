//! `ops create-release-manifest` / `ops verify-release-manifest` — the CI-side
//! producer and the pinned-key verifier for the signed release manifest
//! (`crate::release_manifest`). The release workflow calls `create` after
//! building+signing every binary; `verify` is the local/gate check that the
//! manifest signature and each artifact digest hold. The installer's
//! verified-download path reuses the same `ReleaseManifest::verify_*` methods.

use crate::release_manifest::{
    ManifestArtifact, ReleaseManifest, build_signed_manifest, sha256_hex,
};
use std::path::{Path, PathBuf};

/// CI side: read each `--artifact <name>:<target>:<path>`, compute its sha256 +
/// size, sign the aggregate manifest with the release seed, and write it to
/// `output`. The signing seed (private) is read from a file and never logged;
/// only the verifier (public) key is reported.
pub fn execute_ops_create_release_manifest(
    artifacts: Vec<String>,
    release_track: String,
    signing_seed_file: PathBuf,
    key_id: String,
    output: PathBuf,
    generated_at_unix: u64,
) -> Result<String, String> {
    if artifacts.is_empty() {
        return Err(
            "create-release-manifest requires at least one --artifact <name>:<target>:<path>"
                .to_owned(),
        );
    }
    let mut entries = Vec::with_capacity(artifacts.len());
    for spec in &artifacts {
        let (name, target, path) = parse_artifact_spec(spec)?;
        let bytes =
            std::fs::read(&path).map_err(|err| format!("cannot read artifact {path}: {err}"))?;
        let filename = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{name}-{target}"));
        entries.push(ManifestArtifact {
            name,
            target,
            filename,
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }

    let seed = read_seed_file(&signing_seed_file)?;
    let manifest = build_signed_manifest(&release_track, generated_at_unix, &key_id, seed, entries)
        .map_err(|err| format!("build signed manifest: {err}"))?;
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|err| format!("serialize release manifest: {err}"))?;

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    std::fs::write(&output, json.as_bytes())
        .map_err(|err| format!("cannot write {}: {err}", output.display()))?;

    Ok(format!(
        "wrote signed release manifest ({} artifact(s), track={release_track}) to {} — pin this verifier key in the installer: {}",
        manifest.artifacts.len(),
        output.display(),
        manifest.verifier_key_hex
    ))
}

/// Verify a manifest's signature against the **pinned** verifier key, and — if
/// `--artifacts-dir` is given — that every listed artifact's bytes on disk match
/// its manifest sha256+size. `require_artifacts` (repeatable
/// `--require-artifact <filename>`) binds the verification to the exact files
/// the caller is about to consume: each name must be listed in the signed
/// manifest, so "the directory verified" can never stand in for "this file
/// verified". Fail-closed: any deviation returns `Err`.
pub fn execute_ops_verify_release_manifest(
    manifest: PathBuf,
    pinned_verifier_key_hex: Option<String>,
    pinned_verifier_key_file: Option<PathBuf>,
    artifacts_dir: Option<PathBuf>,
    require_artifacts: Vec<String>,
) -> Result<String, String> {
    let pinned = resolve_pinned_key(pinned_verifier_key_hex, pinned_verifier_key_file)?;
    let json = std::fs::read_to_string(&manifest)
        .map_err(|err| format!("cannot read manifest {}: {err}", manifest.display()))?;
    let doc: ReleaseManifest =
        serde_json::from_str(&json).map_err(|err| format!("cannot parse manifest: {err}"))?;

    doc.verify_signed_with_pinned_key(&pinned)
        .map_err(|err| format!("manifest signature verification failed: {err}"))?;

    // A required artifact is matched by its manifest `filename` field. A
    // caller that just ran a file named X can then trust X only if X itself is
    // signed, not merely some sibling in the same directory.
    for required in &require_artifacts {
        validate_required_artifact_name(required)?;
        if !doc.artifacts.iter().any(|a| &a.filename == required) {
            return Err(format!(
                "required artifact '{required}' is not listed in the signed manifest; \
                 refusing to bless an unlisted file"
            ));
        }
    }

    let mut verified = 0usize;
    if let Some(dir) = &artifacts_dir {
        for artifact in &doc.artifacts {
            let path = dir.join(&artifact.filename);
            let bytes = std::fs::read(&path)
                .map_err(|err| format!("cannot read artifact {}: {err}", path.display()))?;
            doc.verify_artifact(&artifact.name, &artifact.target, &bytes)
                .map_err(|err| format!("artifact verification failed: {err}"))?;
            verified += 1;
        }
    }

    Ok(match &artifacts_dir {
        Some(dir) => format!(
            "release manifest signature OK ({} artifact(s) listed; {verified} verified against {}; \
             required artifacts bound: {})",
            doc.artifacts.len(),
            dir.display(),
            if require_artifacts.is_empty() {
                "none".to_owned()
            } else {
                require_artifacts.join(", ")
            }
        ),
        None => format!(
            "release manifest signature OK ({} artifact(s) listed; pass --artifacts-dir to also verify bytes)",
            doc.artifacts.len()
        ),
    })
}

/// A required artifact name is a bare filename inside the artifacts dir: no
/// path separators, no `..`, no control characters. Anything else is refused
/// before it can be used to reach outside the directory or smuggle fields.
fn validate_required_artifact_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == ".."
        || name == "."
        || name.chars().any(char::is_control)
    {
        return Err(format!(
            "invalid --require-artifact '{name}': expected a bare filename"
        ));
    }
    Ok(())
}

/// Split `name:target:path`. `name` and `target` never contain `:`, so a
/// 3-way split leaves any `:` in the path (e.g. a Windows `C:\…`) intact.
fn parse_artifact_spec(spec: &str) -> Result<(String, String, String), String> {
    let mut parts = spec.splitn(3, ':');
    let name = parts.next().unwrap_or("").trim();
    let target = parts.next().unwrap_or("").trim();
    let path = parts.next().unwrap_or("").trim();
    if name.is_empty() || target.is_empty() || path.is_empty() {
        return Err(format!(
            "invalid --artifact '{spec}'; expected <name>:<target>:<path>"
        ));
    }
    // canonical_payload delimits artifact records with newlines and their
    // fields with tabs; a control character here would let one spec forge
    // extra records or shift fields inside the signed payload.
    let controlled = |s: &str| s.chars().any(|c| c == '\t' || c == '\n' || c == '\r');
    if controlled(name) || controlled(target) || controlled(path) {
        return Err(format!(
            "invalid --artifact '{spec}'; tab/newline characters would corrupt the signed payload"
        ));
    }
    // name/target become the manifest `filename` (`{name}-{target}`), which
    // the verifier joins under the artifacts dir — path separators or `..`
    // components would let a signed manifest address files outside it.
    for field in [name, target] {
        if field.contains('/')
            || field.contains('\\')
            || field.split(['-', '_']).any(|part| part == "..")
        {
            return Err(format!(
                "invalid --artifact '{spec}'; '{field}' must not contain path separators or '..'"
            ));
        }
    }
    Ok((name.to_owned(), target.to_owned(), path.to_owned()))
}

/// Read a 32-byte Ed25519 seed from a hex file (64 hex chars; trailing newline
/// tolerated, e.g. `artifacts/release/provenance/signing_seed.hex`). Never
/// logged. Fail-closed on any malformed length/content.
fn read_seed_file(path: &Path) -> Result<[u8; 32], String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read signing seed {}: {err}", path.display()))?;
    let hex = raw.trim();
    let bytes = decode_hex(hex)
        .ok_or_else(|| format!("signing seed {} is not valid hex", path.display()))?;
    bytes.try_into().map_err(|_| {
        format!(
            "signing seed {} must be 32 bytes (64 hex chars)",
            path.display()
        )
    })
}

fn resolve_pinned_key(hex: Option<String>, file: Option<PathBuf>) -> Result<String, String> {
    match (hex, file) {
        (Some(_), Some(_)) => {
            Err("pass only one of --pinned-verifier-key-hex / --pinned-verifier-key-file".to_owned())
        }
        (Some(h), None) => {
            let trimmed = h.trim();
            if trimmed.is_empty() {
                return Err("--pinned-verifier-key-hex is empty".to_owned());
            }
            Ok(trimmed.to_owned())
        }
        (None, Some(p)) => {
            let raw = std::fs::read_to_string(&p)
                .map_err(|err| format!("cannot read pinned key {}: {err}", p.display()))?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(format!("pinned key file {} is empty", p.display()));
            }
            Ok(trimmed.to_owned())
        }
        (None, None) => Err(
            "verify-release-manifest requires --pinned-verifier-key-hex or --pinned-verifier-key-file"
                .to_owned(),
        ),
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || (bytes.len() & 1) != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_artifact_spec_splits_three_fields_and_keeps_path_colons() {
        let (n, t, p) =
            parse_artifact_spec("rustynetd:x86_64-unknown-linux-gnu:/tmp/out/rustynetd").unwrap();
        assert_eq!(n, "rustynetd");
        assert_eq!(t, "x86_64-unknown-linux-gnu");
        assert_eq!(p, "/tmp/out/rustynetd");
        // Windows-style path with a drive colon survives the 3-way split.
        let (_, _, wp) =
            parse_artifact_spec("rustynetd:x86_64-pc-windows-msvc:C:\\out\\rustynetd.exe").unwrap();
        assert_eq!(wp, "C:\\out\\rustynetd.exe");
    }

    #[test]
    fn parse_artifact_spec_rejects_incomplete() {
        assert!(parse_artifact_spec("rustynetd:x86_64-unknown-linux-gnu").is_err());
        assert!(parse_artifact_spec("::/path").is_err());
        assert!(parse_artifact_spec("").is_err());
        // A trailing colon leaves an empty path: staging a binary from an
        // empty source string must not be expressible.
        assert!(parse_artifact_spec("rustynetd:x86_64-unknown-linux-gnu:").is_err());
    }

    #[test]
    fn parse_artifact_spec_rejects_tab_and_newline_field_injection() {
        // canonical_payload delimits records with \n and fields with \t;
        // either character inside a field would let one --artifact spec
        // forge extra signed records or shift payload fields.
        assert!(
            parse_artifact_spec("rustynetd\textra:x86_64:/p").is_err(),
            "tab in name must be rejected"
        );
        assert!(
            parse_artifact_spec("rustynetd:x86_64\nextra:evil:/p").is_err(),
            "mid-field newline in target must be rejected"
        );
    }

    #[test]
    fn parse_artifact_spec_rejects_path_traversal_in_name_and_target() {
        // name/target become the manifest filename joined under the
        // artifacts dir; separators or `..` must not be expressible.
        assert!(parse_artifact_spec("../rustynetd:x86_64:/p").is_err());
        assert!(parse_artifact_spec("a/b:x86_64:/p").is_err());
        assert!(parse_artifact_spec("rustynetd:..\\win:/p").is_err());
        assert!(parse_artifact_spec("rustynetd-..-x:x86_64:/p").is_err());
        // Dots that do not form a `..` path component are legitimate.
        assert!(parse_artifact_spec("rustynetd-x..y:x86_64:/p").is_ok());
        // Legitimate matrix names still parse.
        assert!(parse_artifact_spec("rustynetd:x86_64-unknown-linux-gnu:/p").is_ok());
    }

    #[test]
    fn create_ops_requires_at_least_one_artifact_before_touching_disk() {
        let dir = std::env::temp_dir().join(format!(
            "rn-relmanifest-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let seed_file = dir.join("seed.hex");
        std::fs::write(&seed_file, "0".repeat(64)).unwrap();
        let err = execute_ops_create_release_manifest(
            Vec::new(),
            "beta".to_owned(),
            seed_file,
            "ed25519:test".to_owned(),
            dir.join("release-manifest.json"),
            1_700_000_000,
        )
        .expect_err("an empty artifact list must refuse before any signing work");
        assert!(err.contains("requires at least one"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_seed_file_fails_closed_on_malformed_content() {
        let dir = std::env::temp_dir().join(format!(
            "rn-seedparse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let write_case = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            path
        };
        // Happy path first: trailing newline tolerated.
        let good = write_case(
            "good.hex",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n",
        );
        assert_eq!(
            read_seed_file(&good).expect("well-formed 64-hex seed parses"),
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20
            ]
        );
        let odd = write_case("odd.hex", "abc");
        assert!(read_seed_file(&odd).is_err(), "odd-length hex must reject");
        let nonhex = write_case("nonhex.hex", "zzzz");
        assert!(
            read_seed_file(&nonhex).is_err(),
            "non-hex content must reject"
        );
        let short = write_case(
            "short.hex",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert!(
            read_seed_file(&short).is_err(),
            "31-byte seed must not be silently padded"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_pinned_key_requires_exactly_one_source() {
        assert!(resolve_pinned_key(None, None).is_err());
        assert!(resolve_pinned_key(Some("ab".into()), Some(PathBuf::from("/x"))).is_err());
        assert_eq!(
            resolve_pinned_key(Some("  abcd  ".into()), None).unwrap(),
            "abcd"
        );
    }

    #[test]
    fn ops_pipeline_surfaces_zero_seed_as_an_operator_error() {
        let dir = std::env::temp_dir().join(format!(
            "rn-relmanifest-zero-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let art = dir.join("rustynetd-x86_64-unknown-linux-gnu");
        std::fs::write(&art, b"fake-rustynetd-binary-bytes").unwrap();
        // A blank seed file: 64 hex zeros. The pipeline must refuse with the
        // operator-facing message, not mint a manifest under the known key.
        let seed_file = dir.join("seed.hex");
        std::fs::write(&seed_file, "0".repeat(64)).unwrap();
        let result = execute_ops_create_release_manifest(
            vec![format!(
                "rustynetd:x86_64-unknown-linux-gnu:{}",
                art.display()
            )],
            "beta".to_owned(),
            seed_file,
            "ed25519:test".to_owned(),
            dir.join("release-manifest.json"),
            1_700_000_000,
        );
        let err = result.expect_err("an all-zero signing seed must abort the create command");
        assert!(
            err.contains("all zeros"),
            "error should name the zero-seed cause, got: {err}"
        );
        assert!(
            !dir.join("release-manifest.json").exists(),
            "no manifest may be written when signing refuses"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_then_verify_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "rn-relmanifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A fake artifact + a seed file, both on disk.
        let art = dir.join("rustynetd-x86_64-unknown-linux-gnu");
        std::fs::write(&art, b"fake-rustynetd-binary-bytes").unwrap();
        let seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let seed_file = dir.join("seed.hex");
        std::fs::write(&seed_file, seed_hex).unwrap();
        let manifest = dir.join("release-manifest.json");

        let msg = execute_ops_create_release_manifest(
            vec![format!(
                "rustynetd:x86_64-unknown-linux-gnu:{}",
                art.display()
            )],
            "beta".into(),
            seed_file.clone(),
            "ed25519:test".into(),
            manifest.clone(),
            1_700_000_000,
        )
        .expect("create manifest");
        // The reported verifier key is the one to pin.
        let pin = msg
            .rsplit(": ")
            .next()
            .expect("verifier key in message")
            .to_owned();

        // Verify signature + bytes against the artifacts dir.
        execute_ops_verify_release_manifest(
            manifest.clone(),
            Some(pin.clone()),
            None,
            Some(dir.clone()),
            vec![],
        )
        .expect("verify manifest + artifact bytes");

        // Tamper the artifact on disk → byte verification must now fail closed.
        std::fs::write(&art, b"tampered-binary-bytes-different").unwrap();
        let err = execute_ops_verify_release_manifest(
            manifest,
            Some(pin),
            None,
            Some(dir.clone()),
            vec![],
        )
        .expect_err("tampered artifact must fail verification");
        assert!(err.contains("artifact verification failed"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_binds_required_artifact_by_name() {
        let (dir, manifest, pin) = round_trip_manifest_fixture("rn-relmanifest-req");
        // The exact file the caller is about to consume is listed → verify OK,
        // and the success message says which names were bound.
        let msg = execute_ops_verify_release_manifest(
            manifest.clone(),
            Some(pin.clone()),
            None,
            Some(dir.clone()),
            vec!["rustynetd-x86_64-unknown-linux-gnu".to_owned()],
        )
        .expect("required artifact listed in manifest must verify");
        assert!(
            msg.contains("required artifacts bound: rustynetd-x86_64-unknown-linux-gnu"),
            "success must name the bound artifact, got: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_refuses_required_artifact_missing_from_manifest() {
        let (dir, manifest, pin) = round_trip_manifest_fixture("rn-relmanifest-unlisted");
        // A validly-signed manifest that simply does not list the consumed
        // file must NOT pass when that file is required (AQ-11 F3).
        let err = execute_ops_verify_release_manifest(
            manifest.clone(),
            Some(pin.clone()),
            None,
            Some(dir.clone()),
            vec!["payload-not-in-manifest.tar.gz".to_owned()],
        )
        .expect_err("unlisted required artifact must fail verification");
        assert!(err.contains("not listed in the signed manifest"), "{err}");
        // Back-compat: without --require-artifact the same call still passes.
        execute_ops_verify_release_manifest(manifest, Some(pin), None, Some(dir.clone()), vec![])
            .expect("no requirement → previous behaviour");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_path_like_required_artifact_names() {
        let (dir, _manifest, pin) = round_trip_manifest_fixture("rn-relmanifest-path");
        for bad in ["../evil", "a/b", "a\\b", ".", "..", ""] {
            let err = execute_ops_verify_release_manifest(
                _manifest.clone(),
                Some(pin.clone()),
                None,
                Some(dir.clone()),
                vec![bad.to_owned()],
            )
            .expect_err("path-like required name must be refused");
            assert!(err.contains("invalid --require-artifact"), "{err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shared fixture: one fake artifact, its signed manifest, the pinned key.
    fn round_trip_manifest_fixture(tag: &str) -> (std::path::PathBuf, PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let art = dir.join("rustynetd-x86_64-unknown-linux-gnu");
        std::fs::write(&art, b"fake-rustynetd-binary-bytes").unwrap();
        let seed_file = dir.join("seed.hex");
        std::fs::write(
            &seed_file,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
        .unwrap();
        let manifest = dir.join("release-manifest.json");
        let msg = execute_ops_create_release_manifest(
            vec![format!(
                "rustynetd:x86_64-unknown-linux-gnu:{}",
                art.display()
            )],
            "beta".into(),
            seed_file,
            "ed25519:test".into(),
            manifest.clone(),
            1_700_000_000,
        )
        .expect("create manifest");
        let pin = msg.rsplit(": ").next().expect("verifier key").to_owned();
        (dir, manifest, pin)
    }
}

/// Tripwire for the lab-only release-manifest seam: with the `vm-lab`
/// feature OFF (i.e. every default/production build), no seam code may
/// exist outside `src/vm_lab/`. Scans the crate sources for seam
/// markers so the seam cannot silently escape the lab-only module
/// boundary. Marker literals are assembled by concatenation so this
/// file does not trip itself.
#[cfg(test)]
#[cfg(not(feature = "vm-lab"))]
mod lab_seam_stays_inside_vm_lab {
    #[test]
    fn no_lab_manifest_seam_sources_outside_vm_lab() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let markers = [
            format!("macos_manifest_{}", "seam"),
            format!("LabManifest{}", "Seam"),
            format!("mint_{}", "throwaway_seed"),
            format!("with_lab_release_manifest_{}", "seam"),
        ];
        let mut stack = vec![src.clone()];
        let mut scanned = 0usize;
        let mut hits: Vec<String> = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src tree").flatten() {
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if path.is_dir() {
                    if name == "vm_lab" {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if !name.ends_with(".rs") {
                    continue;
                }
                let bytes = std::fs::read(&path).expect("read rust source");
                let contents = String::from_utf8_lossy(&bytes);
                scanned += 1;
                for marker in &markers {
                    if contents.contains(marker.as_str()) {
                        hits.push(format!(
                            "{} contains lab-seam marker '{}'",
                            path.display(),
                            marker
                        ));
                    }
                }
            }
        }
        assert!(
            scanned > 50,
            "tripwire scanned only {scanned} sources; src tree changed?"
        );
        assert!(
            hits.is_empty(),
            "lab-manifest-seam code escaped src/vm_lab in a default build: {hits:?}"
        );
    }
}
