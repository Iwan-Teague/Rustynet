//! Safe scenario-artifact validation (L0.5,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §2.4).
//!
//! A scenario references its raw evidence (captures, transcripts, firewall
//! dumps) by report-root-relative path. Before the verifier reads any of it,
//! the reference must be proven safe: never an absolute path, never a `..`
//! escape, never a symlink (or symlinked parent) that resolves OUTSIDE the
//! report root, and never over a byte budget. Each opened artifact is bound to
//! its SHA-256 so a later mutation of the file is detected, and to the exact
//! reference the scenario gave. A reference that fails any check is rejected —
//! an unverifiable artifact is never evidence (§2.4), so at the verifier
//! boundary each of these maps to a NotProven, never a pass.

use std::path::{Component, Path, PathBuf};

/// Why an artifact reference was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The reference was an absolute path; artifacts are report-root-relative.
    AbsolutePath(String),
    /// The reference contained a `..`, `.`, root, or prefix component.
    NonNormalComponent(String),
    /// The path, after resolving symlinks, is not beneath the report root.
    EscapesReportRoot(String),
    /// The path does not exist, or is not a regular file (dir, device, …).
    NotARegularFile(String),
    /// The file exceeds the per-artifact byte budget.
    OverBudget {
        reference: String,
        size: u64,
        budget: u64,
    },
    /// An I/O error resolving or reading the artifact.
    Io(String),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::AbsolutePath(r) => {
                write!(
                    f,
                    "artifact reference `{r}` is an absolute path; must be report-root-relative"
                )
            }
            ArtifactError::NonNormalComponent(r) => write!(
                f,
                "artifact reference `{r}` has a `..`/`.`/root component; only plain relative components are allowed"
            ),
            ArtifactError::EscapesReportRoot(r) => write!(
                f,
                "artifact reference `{r}` resolves (via symlink) outside the report root"
            ),
            ArtifactError::NotARegularFile(r) => {
                write!(
                    f,
                    "artifact reference `{r}` is missing or not a regular file"
                )
            }
            ArtifactError::OverBudget {
                reference,
                size,
                budget,
            } => write!(
                f,
                "artifact `{reference}` is {size} bytes, over the {budget}-byte budget"
            ),
            ArtifactError::Io(m) => write!(f, "artifact I/O error: {m}"),
        }
    }
}

/// A validated artifact: a real regular file beneath the report root, within
/// budget, bound to its content digest and the reference the scenario gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArtifact {
    /// Canonical absolute path (symlinks resolved), guaranteed beneath the root.
    pub path: PathBuf,
    /// The report-root-relative reference exactly as the scenario gave it.
    pub reference: String,
    pub size: u64,
    pub sha256: String,
}

/// Validate and bind the artifact referenced by `reference` beneath
/// `report_root`, enforcing the §2.4 containment + budget rules.
pub fn validate_artifact(
    report_root: &Path,
    reference: &str,
    max_bytes: u64,
) -> Result<ValidatedArtifact, ArtifactError> {
    let rel = Path::new(reference);

    // 1. Reject an absolute reference outright.
    if rel.is_absolute() {
        return Err(ArtifactError::AbsolutePath(reference.to_owned()));
    }

    // 2. Reject any non-plain component (`..`, `.`, root, Windows prefix). This
    //    catches the textual `..` escape before any filesystem access.
    for comp in rel.components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(ArtifactError::NonNormalComponent(reference.to_owned()));
        }
    }

    // 3. Canonicalize the report root (must exist).
    let root_canon = report_root.canonicalize().map_err(|e| {
        ArtifactError::Io(format!(
            "canonicalize report root {}: {e}",
            report_root.display()
        ))
    })?;

    // 4. Join + canonicalize the artifact. `canonicalize` resolves EVERY
    //    symlink in the path (the file itself and any parent), so a symlink
    //    escape shows up as a canonical path outside the root in step 5. A
    //    missing target fails here and is reported as not-a-regular-file.
    let canon = root_canon
        .join(rel)
        .canonicalize()
        .map_err(|_| ArtifactError::NotARegularFile(reference.to_owned()))?;

    // 5. Containment: the resolved artifact must live beneath the resolved root.
    if !canon.starts_with(&root_canon) {
        return Err(ArtifactError::EscapesReportRoot(reference.to_owned()));
    }

    // 6. Must be a regular file.
    let meta = std::fs::metadata(&canon).map_err(|e| ArtifactError::Io(e.to_string()))?;
    if !meta.is_file() {
        return Err(ArtifactError::NotARegularFile(reference.to_owned()));
    }

    // 7. Budget — checked from metadata BEFORE reading, so an over-budget file
    //    is never slurped into memory.
    let size = meta.len();
    if size > max_bytes {
        return Err(ArtifactError::OverBudget {
            reference: reference.to_owned(),
            size,
            budget: max_bytes,
        });
    }

    // 8. Read + digest-bind.
    let bytes = std::fs::read(&canon).map_err(|e| ArtifactError::Io(e.to_string()))?;
    let sha256 = crate::vm_lab::sha256_hex_bytes(&bytes);

    Ok(ValidatedArtifact {
        path: canon,
        reference: reference.to_owned(),
        size,
        sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-artifact-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_real_file_beneath_the_root_validates_with_size_and_digest() {
        let root = temp_root("ok");
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/capture.txt"), b"hello").unwrap();
        let v = validate_artifact(&root, "state/capture.txt", 1024).expect("valid");
        assert_eq!(v.size, 5);
        assert_eq!(v.reference, "state/capture.txt");
        assert_eq!(v.sha256, crate::vm_lab::sha256_hex_bytes(b"hello"));
        assert!(v.path.starts_with(root.canonicalize().unwrap()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absolute_reference_is_rejected() {
        let root = temp_root("abs");
        assert!(matches!(
            validate_artifact(&root, "/etc/passwd", 1024),
            Err(ArtifactError::AbsolutePath(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dotdot_escape_is_rejected_textually_before_any_fs_access() {
        let root = temp_root("dotdot");
        assert!(matches!(
            validate_artifact(&root, "../../etc/passwd", 1024),
            Err(ArtifactError::NonNormalComponent(_))
        ));
        // Even a `..` that would resolve back inside is refused — the rule is
        // "plain components only", so there is no path-arithmetic to reason about.
        std::fs::write(root.join("f.txt"), b"x").unwrap();
        assert!(matches!(
            validate_artifact(&root, "sub/../f.txt", 1024),
            Err(ArtifactError::NonNormalComponent(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_file_and_a_directory_are_not_regular_files() {
        let root = temp_root("missing");
        assert!(matches!(
            validate_artifact(&root, "nope.txt", 1024),
            Err(ArtifactError::NotARegularFile(_))
        ));
        std::fs::create_dir_all(root.join("adir")).unwrap();
        assert!(matches!(
            validate_artifact(&root, "adir", 1024),
            Err(ArtifactError::NotARegularFile(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_over_budget_file_is_rejected_by_size() {
        let root = temp_root("budget");
        std::fs::write(root.join("big.bin"), vec![0u8; 100]).unwrap();
        match validate_artifact(&root, "big.bin", 50) {
            Err(ArtifactError::OverBudget { size, budget, .. }) => {
                assert_eq!(size, 100);
                assert_eq!(budget, 50);
            }
            other => panic!("expected OverBudget, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_resolving_outside_the_root_is_rejected() {
        // Create an "outside" secret and a symlink inside the report root that
        // points at it. `canonicalize` resolves the symlink, so containment
        // fails — the classic artifact-forgery-via-symlink escape.
        let root = temp_root("symlink");
        let outside = temp_root("symlink-outside");
        std::fs::write(outside.join("secret"), b"exfil").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("link")).unwrap();
        assert!(matches!(
            validate_artifact(&root, "link", 1024),
            Err(ArtifactError::EscapesReportRoot(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
