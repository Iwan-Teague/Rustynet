#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Which tree the source archive shipped to the guests is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArchiveSourceMode {
    /// Package the committed tree at `HEAD` — reproducible, the default.
    #[default]
    Head,
    /// Package the working tree *including uncommitted tracked changes*
    /// (via `git stash create`), so a fix can be guest-tested before it is
    /// committed. Untracked files are not captured.
    WorkingTree,
}

/// Map a `--source-mode` CLI value onto the archive mode the Rust-native
/// orchestrator supports.
///
/// `None`, the empty string, and the committed-tree aliases select `Head`;
/// `working-tree`/`worktree` select `WorkingTree`. Any other recognised
/// source mode (`commit-ref`, `repo-url`, `local-source`) is **rejected**:
/// the Rust-native archive path only builds from the local repo, so silently
/// falling back to `HEAD` would mis-report provenance. Fail closed instead.
pub fn parse_archive_source_mode(value: Option<&str>) -> Result<ArchiveSourceMode, String> {
    match value.map(str::trim) {
        None | Some("") | Some("head") | Some("local-head") => Ok(ArchiveSourceMode::Head),
        Some("worktree") | Some("working-tree") => Ok(ArchiveSourceMode::WorkingTree),
        Some(other) => Err(format!(
            "unsupported --source-mode '{other}' for the Rust-native orchestrator; \
             use 'local-head' (default) or 'working-tree'"
        )),
    }
}

/// Resolve the git tree-ish the archive is built from for `mode`, run in
/// `repo_dir`.
///
/// `Head` → `"HEAD"`. `WorkingTree` → the SHA produced by `git stash create`,
/// which snapshots the working tree (staged + unstaged *tracked* changes) into
/// a dangling commit **without** touching the index, working tree, or stash
/// list. When the tree is clean, `git stash create` prints nothing, so we fall
/// back to `HEAD`.
fn resolve_source_tree_ish(repo_dir: &Path, mode: ArchiveSourceMode) -> Result<String, String> {
    match mode {
        ArchiveSourceMode::Head => Ok("HEAD".to_owned()),
        ArchiveSourceMode::WorkingTree => {
            let out = std::process::Command::new("git")
                .args(["stash", "create"])
                .current_dir(repo_dir)
                .output()
                .map_err(|e| format!("git stash create spawn failed: {e}"))?;
            if !out.status.success() {
                return Err(format!("git stash create exited with {}", out.status));
            }
            let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if sha.is_empty() {
                // Clean tree (nothing to stash) — equivalent to HEAD.
                Ok("HEAD".to_owned())
            } else {
                Ok(sha)
            }
        }
    }
}

/// Build a `tar.gz` source archive at `out_path` from `repo_dir` for `mode`.
fn build_source_tarball(
    repo_dir: &Path,
    mode: ArchiveSourceMode,
    out_path: &Path,
) -> Result<(), String> {
    let tree_ish = resolve_source_tree_ish(repo_dir, mode)?;
    let mut tar_path = out_path.to_path_buf();
    tar_path.set_extension("tar");
    let _ = std::fs::remove_file(&tar_path);
    let status = std::process::Command::new("git")
        .args(["archive", "--format=tar", "-o"])
        .arg(&tar_path)
        .arg(&tree_ish)
        .current_dir(repo_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("git archive spawn failed: {e}"))?;
    if !status.success() {
        return Err(format!("git archive exited with {status}"));
    }

    append_source_commit_marker(repo_dir, &tar_path, &tree_ish)?;

    let output = std::process::Command::new("gzip")
        .args(["-c"])
        .arg(&tar_path)
        .current_dir(repo_dir)
        .output()
        .map_err(|e| format!("gzip spawn failed: {e}"))?;
    let _ = std::fs::remove_file(&tar_path);
    if !output.status.success() {
        return Err(format!("gzip exited with {}", output.status));
    }
    std::fs::write(out_path, output.stdout)
        .map_err(|e| format!("write compressed source archive failed: {e}"))?;
    Ok(())
}

fn append_source_commit_marker(
    repo_dir: &Path,
    tar_path: &Path,
    tree_ish: &str,
) -> Result<(), String> {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", tree_ish])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| format!("git rev-parse --short {tree_ish} spawn failed: {e}"))?;
    if !commit.status.success() {
        return Err(format!(
            "git rev-parse --short {tree_ish} exited with {}",
            commit.status
        ));
    }
    let commit = String::from_utf8(commit.stdout)
        .map_err(|e| format!("git rev-parse --short {tree_ish} returned non-UTF-8 output: {e}"))?;

    let marker_dir =
        std::env::temp_dir().join(format!("rustynet-source-marker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&marker_dir);
    std::fs::create_dir_all(&marker_dir)
        .map_err(|e| format!("create source commit marker tempdir failed: {e}"))?;
    let marker = marker_dir.join("RUSTYNET_SOURCE_COMMIT");
    std::fs::write(&marker, commit.trim())
        .map_err(|e| format!("write source commit marker failed: {e}"))?;

    let status = std::process::Command::new("tar")
        .args(["-rf"])
        .arg(tar_path)
        .args(["-C"])
        .arg(&marker_dir)
        .arg("RUSTYNET_SOURCE_COMMIT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("tar append source commit marker spawn failed: {e}"))?;
    let _ = std::fs::remove_dir_all(&marker_dir);
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "tar append source commit marker exited with {status}"
        ))
    }
}

pub struct PrepareSourceArchiveStage {
    source_mode: ArchiveSourceMode,
}

impl PrepareSourceArchiveStage {
    pub fn new(source_mode: ArchiveSourceMode) -> Self {
        PrepareSourceArchiveStage { source_mode }
    }
}

impl OrchestrationStage for PrepareSourceArchiveStage {
    fn id(&self) -> StageId {
        StageId::PrepareSourceArchive
    }
    fn name(&self) -> &str {
        "prepare_source_archive"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::Preflight]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if ctx.source_archive.is_some() {
            return StageOutcome::Passed;
        }
        let archive_path = {
            let mut p = std::env::temp_dir();
            p.push(format!("rn_source_{}.tar.gz", std::process::id()));
            p
        };
        // The orchestrator runs from the repo root, so the working dir is the
        // source tree we want to package.
        match build_source_tarball(Path::new("."), self.source_mode, &archive_path) {
            Ok(()) => match SourceArchive::from_existing(archive_path) {
                Ok(archive) => {
                    ctx.source_archive = Some(archive);
                    StageOutcome::Passed
                }
                Err(e) => StageOutcome::Failed(format!("source archive validation failed: {e}")),
            },
            Err(e) => StageOutcome::Failed(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::collections::HashMap;
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    fn make_ctx_with_archive() -> (OrchestrationContext, NamedTempFile) {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "placeholder").unwrap();
        let archive = SourceArchive::from_existing(f.path().to_path_buf()).unwrap();
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: Some(archive),
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        (ctx, f)
    }

    #[test]
    fn already_present_archive_passes_immediately() {
        let (mut ctx, _f) = make_ctx_with_archive();
        let outcome = PrepareSourceArchiveStage::new(ArchiveSourceMode::Head).execute(&mut ctx);
        assert_eq!(outcome, StageOutcome::Passed);
    }

    #[test]
    fn parse_archive_source_mode_maps_known_values() {
        assert_eq!(parse_archive_source_mode(None), Ok(ArchiveSourceMode::Head));
        assert_eq!(
            parse_archive_source_mode(Some("")),
            Ok(ArchiveSourceMode::Head)
        );
        assert_eq!(
            parse_archive_source_mode(Some("local-head")),
            Ok(ArchiveSourceMode::Head)
        );
        assert_eq!(
            parse_archive_source_mode(Some("working-tree")),
            Ok(ArchiveSourceMode::WorkingTree)
        );
        assert_eq!(
            parse_archive_source_mode(Some("worktree")),
            Ok(ArchiveSourceMode::WorkingTree)
        );
        assert!(parse_archive_source_mode(Some("repo-url")).is_err());
        assert!(parse_archive_source_mode(Some("garbage")).is_err());
    }

    // ── git-backed archive content tests ──────────────────────────────────────

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(repo)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed in {repo:?}");
    }

    /// Build an *uncompressed* tar for `mode` (so the test can scan the bytes
    /// for file content without an extraction step) using the same tree-ish
    /// resolution the real `.tar.gz` path uses.
    fn archive_tar_bytes(repo: &Path, mode: ArchiveSourceMode) -> Vec<u8> {
        let tree_ish = resolve_source_tree_ish(repo, mode).unwrap();
        let out = Command::new("git")
            .args(["archive", "--format=tar", &tree_ish])
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(out.status.success(), "git archive {tree_ish} failed");
        out.stdout
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn marker_from_built_archive(repo: &Path, mode: ArchiveSourceMode) -> String {
        let archive = tempfile::NamedTempFile::new().unwrap();
        build_source_tarball(repo, mode, archive.path()).unwrap();
        let extract = tempfile::tempdir().unwrap();
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(archive.path())
            .arg("-C")
            .arg(extract.path())
            .status()
            .unwrap();
        assert!(status.success(), "tar extract failed");
        std::fs::read_to_string(extract.path().join("RUSTYNET_SOURCE_COMMIT")).unwrap()
    }

    #[test]
    fn worktree_mode_includes_dirty_tracked_file_head_omits() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        let tracked = repo.join("tracked.txt");
        std::fs::write(&tracked, b"committed-content-marker\n").unwrap();
        git(repo, &["add", "tracked.txt"]);
        git(repo, &["commit", "-q", "-m", "initial"]);

        // Dirty the tracked file (uncommitted working-tree change).
        std::fs::write(&tracked, b"dirty-worktree-content-marker\n").unwrap();

        let head = archive_tar_bytes(repo, ArchiveSourceMode::Head);
        let worktree = archive_tar_bytes(repo, ArchiveSourceMode::WorkingTree);

        // HEAD carries the committed content and omits the uncommitted change.
        assert!(
            bytes_contain(&head, b"committed-content-marker"),
            "HEAD archive must contain the committed content"
        );
        assert!(
            !bytes_contain(&head, b"dirty-worktree-content-marker"),
            "HEAD archive must NOT contain the uncommitted change"
        );
        // WorkingTree carries the uncommitted change.
        assert!(
            bytes_contain(&worktree, b"dirty-worktree-content-marker"),
            "worktree archive must contain the uncommitted change"
        );
    }

    #[test]
    fn worktree_mode_on_clean_tree_falls_back_to_head() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        std::fs::write(repo.join("a.txt"), b"only-committed\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "initial"]);

        // Clean tree: `git stash create` prints nothing, so resolve to HEAD.
        let tree_ish = resolve_source_tree_ish(repo, ArchiveSourceMode::WorkingTree).unwrap();
        assert_eq!(tree_ish, "HEAD");
    }

    #[test]
    fn source_archive_marker_matches_worktree_snapshot_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        let tracked = repo.join("tracked.txt");
        std::fs::write(&tracked, b"committed\n").unwrap();
        git(repo, &["add", "tracked.txt"]);
        git(repo, &["commit", "-q", "-m", "initial"]);

        std::fs::write(&tracked, b"dirty\n").unwrap();
        let tree_ish = resolve_source_tree_ish(repo, ArchiveSourceMode::WorkingTree).unwrap();
        assert_ne!(tree_ish, "HEAD");
        let expected = Command::new("git")
            .args(["rev-parse", "--short", &tree_ish])
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(expected.status.success());
        let expected = String::from_utf8(expected.stdout).unwrap();

        let marker = marker_from_built_archive(repo, ArchiveSourceMode::WorkingTree);

        assert_eq!(marker.trim(), expected.trim());
    }
}
