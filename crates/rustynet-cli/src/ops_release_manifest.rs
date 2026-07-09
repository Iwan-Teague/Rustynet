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
    let manifest = build_signed_manifest(&release_track, generated_at_unix, &key_id, seed, entries);
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
/// its manifest sha256+size. Fail-closed: any deviation returns `Err`.
pub fn execute_ops_verify_release_manifest(
    manifest: PathBuf,
    pinned_verifier_key_hex: Option<String>,
    pinned_verifier_key_file: Option<PathBuf>,
    artifacts_dir: Option<PathBuf>,
) -> Result<String, String> {
    let pinned = resolve_pinned_key(pinned_verifier_key_hex, pinned_verifier_key_file)?;
    let json = std::fs::read_to_string(&manifest)
        .map_err(|err| format!("cannot read manifest {}: {err}", manifest.display()))?;
    let doc: ReleaseManifest =
        serde_json::from_str(&json).map_err(|err| format!("cannot parse manifest: {err}"))?;

    doc.verify_signed_with_pinned_key(&pinned)
        .map_err(|err| format!("manifest signature verification failed: {err}"))?;

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
            "release manifest signature OK ({} artifact(s) listed; {verified} verified against {})",
            doc.artifacts.len(),
            dir.display()
        ),
        None => format!(
            "release manifest signature OK ({} artifact(s) listed; pass --artifacts-dir to also verify bytes)",
            doc.artifacts.len()
        ),
    })
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
        )
        .expect("verify manifest + artifact bytes");

        // Tamper the artifact on disk → byte verification must now fail closed.
        std::fs::write(&art, b"tampered-binary-bytes-different").unwrap();
        let err = execute_ops_verify_release_manifest(manifest, Some(pin), None, Some(dir.clone()))
            .expect_err("tampered artifact must fail verification");
        assert!(err.contains("artifact verification failed"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
