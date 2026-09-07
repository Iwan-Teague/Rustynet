//! Runtime workspace-root resolution for the vm-lab orchestrator (QH-74).
//!
//! Evidence ledgers, triage state, provenance, and reviewed static assets must
//! be resolved from the tree the binary RUNS in, not the tree it was COMPILED
//! in. The resolution order is fixed:
//!
//! 1. the `--inventory` path's ancestor directories (the path is made
//!    absolute against `cwd` first, when relative),
//! 2. the current directory's ancestors,
//! 3. the compile-time root (derived from `env!("CARGO_MANIFEST_DIR")`),
//!    accepted ONLY if it still carries the workspace markers.
//!
//! A directory is a workspace root when it contains BOTH a `Cargo.toml` file
//! and a `documents/operations` directory. The winning root is canonicalized
//! and must pass an ownership/writability check (both markers owned by the
//! account that owns the running binary, neither group/world-writable) or
//! resolution is REFUSED — planted or overly permissive marker dirs must not
//! capture evidence resolution (see [`validate_accepted_root`]).
//!
//! Fail closed: when no candidate
//! carries the markers this module errors — and, for the infallible
//! [`workspace_root_path`] accessor, panics loudly — it never guesses a
//! directory and never creates one.
//!
//! The design contract lives in
//! `documents/operations/active/LedgerRuntimeRootResolutionPlan_2026-09-07.md`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The two markers that identify the Rustynet workspace root: a `Cargo.toml`
/// FILE and a `documents/operations` DIRECTORY in the same candidate dir.
pub(crate) fn is_workspace_root(p: &Path) -> bool {
    p.join("Cargo.toml").is_file() && p.join("documents/operations").is_dir()
}

/// The compile-time root derived from this crate's location inside the
/// workspace. Only the derivation lives here; validation against the markers
/// happens at the single fallback site in [`resolve_workspace_root_from`].
pub(crate) fn compiled_in_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "compiled-in crate path has no workspace-level parent".to_owned())
}

/// Validate and canonicalize a marker-carrying root before it is accepted
/// (review F3). The winning root is canonicalized so a symlinked invocation
/// path lands on the real directory, and it is REFUSED when either marker
/// (`Cargo.toml` or `documents/operations`) is owned by a different uid or is
/// group/world-writable: a directory planted by another account, or writable
/// by more than its owner, must not capture evidence resolution.
///
/// Reference-uid choice: the Rust standard library exposes no uid of the
/// running process (and this crate deliberately pulls in neither `libc` nor
/// `nix`), so the reference is the owner of the binary's own executable
/// ([`std::env::current_exe`]). A rustynet build lives in the operator's
/// target directory and is owned by the same account that runs it, which is
/// exactly the local trust domain this check guards; a root whose markers are
/// owned by anyone else is foreign. Recorded in the review disposition.
fn validate_accepted_root(root: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(root).map_err(|e| {
        format!(
            "workspace root `{}` cannot be canonicalized: {e}",
            root.display()
        )
    })?;
    let exe =
        std::env::current_exe().map_err(|e| format!("current executable unavailable: {e}"))?;
    let exe_uid = std::fs::metadata(&exe)
        .map_err(|e| {
            format!(
                "current executable `{}` metadata unavailable: {e}",
                exe.display()
            )
        })?
        .uid();
    for marker in [
        canonical.join("Cargo.toml"),
        canonical.join("documents/operations"),
    ] {
        let meta = std::fs::metadata(&marker).map_err(|e| {
            format!(
                "workspace root `{}` marker `{}` metadata unavailable: {e}",
                canonical.display(),
                marker.display()
            )
        })?;
        let uid = meta.uid();
        if uid != exe_uid {
            return Err(format!(
                "workspace root `{}` rejected: `{}` is owned by uid {uid} but the \
                 running binary is owned by uid {exe_uid}; a root planted by \
                 another account must not capture evidence resolution",
                canonical.display(),
                marker.display()
            ));
        }
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "workspace root `{}` rejected: `{}` is group/world-writable \
                 (mode {mode:o})",
                canonical.display(),
                marker.display()
            ));
        }
    }
    Ok(canonical)
}

/// Core resolution, parameterized over the compiled-in crate dir and the
/// acceptance hook so tests can exercise every branch without depending on
/// where this binary was built or who owns the process.
fn resolve_workspace_root_from(
    inventory: Option<&Path>,
    cwd: &Path,
    compiled_crate_dir: &Path,
) -> Result<PathBuf, String> {
    resolve_workspace_root_with(inventory, cwd, compiled_crate_dir, &validate_accepted_root)
}

fn resolve_workspace_root_with(
    inventory: Option<&Path>,
    cwd: &Path,
    compiled_crate_dir: &Path,
    accept: &dyn Fn(&Path) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(inv) = inventory {
        let start = if inv.is_absolute() {
            inv.to_path_buf()
        } else {
            cwd.join(inv)
        };
        // A bare-filename inventory yields `Some("")` as its parent; that
        // parent IS the cwd, so name it explicitly instead of probing the
        // empty path (review F5). The start dir is canonicalized first so a
        // symlinked inventory path walks its REAL ancestor chain (review F3).
        let dir = match start.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => cwd.to_path_buf(),
        };
        candidates.push(std::fs::canonicalize(&dir).unwrap_or(dir));
    }
    candidates.push(std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()));
    for start in &candidates {
        for dir in start.ancestors() {
            if is_workspace_root(dir) {
                // Fail closed on a winner that fails the ownership or
                // writability check (review F3): refuse the root outright
                // rather than falling through to a lower-precedence
                // candidate, so an invalid high-precedence root can never be
                // traded for a different tree.
                return accept(dir);
            }
        }
    }
    let compiled = compiled_crate_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    match compiled {
        Some(root) if is_workspace_root(&root) => accept(&root),
        _ => Err(
            "no workspace root with Cargo.toml + documents/operations found from \
             --inventory or cwd; compiled-in root is also invalid"
                .to_owned(),
        ),
    }
}

/// Resolve the workspace root for real: the pure core against this binary's
/// actual compile-time location.
pub(crate) fn resolve_workspace_root(
    inventory: Option<&Path>,
    cwd: &Path,
) -> Result<PathBuf, String> {
    resolve_workspace_root_from(inventory, cwd, Path::new(env!("CARGO_MANIFEST_DIR")))
}

/// The process-wide resolved root. Fixed once by [`init_workspace_root`] at
/// verb-parse time; if init never ran (tests, non-CLI callers) this lazily
/// resolves without an inventory. FAIL CLOSED: an unresolvable root panics —
/// the two per-call-site `expect`s this module replaced panicked the same
/// way, but this is ONE loud failure at a single choke point instead of a
/// silent write into the wrong tree.
static RESOLVED_ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Initialize the process-wide workspace root from the `--inventory` path the
/// operator handed the CLI. Set-once with a divergence check: the FIRST call
/// fixes the value; a later call is accepted ONLY when it resolves to the
/// SAME root — a divergent re-initialization is a bug (e.g. the cell having
/// been silently pre-initialized from cwd before `--inventory` was consulted)
/// and is refused with an error, never absorbed as a no-op. Call at verb-parse
/// time, before any evidence path is derived. When the resolved root differs
/// from the compiled-in root, both paths are printed once for transparency
/// (no secrets — directory paths only).
pub fn init_workspace_root(inventory: Option<&Path>) -> Result<(), String> {
    match std::env::current_dir() {
        Ok(cwd) => init_workspace_root_in(&RESOLVED_ROOT, inventory, &cwd),
        // The cell may already hold a usable value; fail closed only when it
        // does not.
        Err(e) => match RESOLVED_ROOT.get() {
            Some(existing) => existing.clone().map(|_| ()),
            None => Err(format!("current directory unavailable: {e}")),
        },
    }
}

/// The init core, parameterized over the cell and cwd so tests can drive the
/// full set-once/divergence semantics without touching the process-global
/// [`RESOLVED_ROOT`] or the process cwd (the test runner shares one process
/// across threads, and a cwd mutation would race unrelated tests).
pub(crate) fn init_workspace_root_in(
    cell: &OnceLock<Result<PathBuf, String>>,
    inventory: Option<&Path>,
    cwd: &Path,
) -> Result<(), String> {
    if let Some(existing) = cell.get() {
        let candidate = resolve_workspace_root(inventory, cwd);
        return match (existing, &candidate) {
            (Ok(stored), Ok(same)) if stored == same => Ok(()),
            (Ok(stored), Ok(other)) => Err(format!(
                "workspace root already initialized to `{}`; refusing \
                 divergent re-initialization to `{}`",
                stored.display(),
                other.display()
            )),
            // First call wins for every other shape: a stored failure stays
            // the stored failure.
            (stored, _) => stored.clone().map(|_| ()),
        };
    }
    let resolved = cell.get_or_init(|| {
        let resolved = resolve_workspace_root(inventory, cwd);
        if let Ok(root) = &resolved {
            if let Ok(compiled) = compiled_in_root() {
                if compiled != *root {
                    eprintln!(
                        "rustynet: workspace root resolved at runtime to `{}` \
                         (compiled-in root is `{}`)",
                        root.display(),
                        compiled.display()
                    );
                }
            }
        }
        resolved
    });
    resolved.clone().map(|_| ())
}

/// The resolved workspace root, deriving it on first use when
/// [`init_workspace_root`] has not run yet.
pub(crate) fn workspace_root_path() -> PathBuf {
    #[cfg(test)]
    if let Some(forced) = test_forced_root() {
        return forced;
    }
    match RESOLVED_ROOT.get_or_init(|| {
        std::env::current_dir().map_or_else(
            |e| Err(format!("current directory unavailable: {e}")),
            |cwd| resolve_workspace_root(None, &cwd),
        )
    }) {
        Ok(root) => root.clone(),
        Err(msg) => panic!("workspace root unresolvable (fail-closed): {msg}"),
    }
}

// ---- Test-only global-state plumbing ---------------------------------------
//
// The pinning tests in `live_lab_run_matrix.rs` must prove that a run launched
// with a copied tree records beside the COPY, which means `workspace_root_path`
// has to observe the copy. A `OnceLock` cannot be reset, and under the plain
// `cargo test` runner every test in the binary shares one process, so tests
// that touch this global state serialize on [`TEST_SERIALIZER`] and the
// pinning tests inject through [`set_workspace_root_for_tests`]. None of this
// exists in a production build (`#[cfg(test)]`).

#[cfg(test)]
static TEST_FORCED_ROOT: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Serializes every test that reads or writes the workspace-root globals so
/// `cargo test`'s shared-process execution cannot interleave them.
#[cfg(test)]
pub(crate) static TEST_SERIALIZER: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn test_forced_root() -> Option<PathBuf> {
    TEST_FORCED_ROOT
        .lock()
        .expect("workspace-root test mutex poisoned")
        .clone()
}

/// Test-only: force [`workspace_root_path`] to return `path`. Hold
/// [`TEST_SERIALIZER`] for the whole test body; restore with the returned
/// prior value (or `None`) when done.
#[cfg(test)]
pub(crate) fn set_workspace_root_for_tests(path: Option<PathBuf>) {
    *TEST_FORCED_ROOT
        .lock()
        .expect("workspace-root test mutex poisoned") = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::MutexGuard;

    /// Build a directory carrying the full workspace markers.
    fn marked_root(base: &Path, name: &str) -> PathBuf {
        let root = base.join(name);
        fs::create_dir_all(root.join("documents/operations")).expect("marker dir");
        fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("marker file");
        root
    }

    /// An inventory FILE nested under `root` (the walk starts at its parent).
    fn inventory_under(root: &Path, rel: &str) -> PathBuf {
        let inv = root.join(rel);
        fs::create_dir_all(inv.parent().expect("inv parent")).expect("inv dir");
        fs::write(&inv, "{}").expect("inv file");
        inv
    }

    /// Resolution returns the CANONICALIZED winning root (review F3), so
    /// expectations are compared in canonical form too (macOS tempdirs live
    /// behind a `/var` → `/private/var` symlink).
    fn canon(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).expect("canonicalize expectation")
    }

    #[test]
    fn marker_requires_cargo_toml_file_and_documents_operations_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let full = marked_root(base, "full");
        assert!(is_workspace_root(&full));

        // Cargo.toml present but documents/operations missing.
        let partial = base.join("partial");
        fs::create_dir_all(&partial).expect("dir");
        fs::write(partial.join("Cargo.toml"), "[workspace]\n").expect("file");
        assert!(!is_workspace_root(&partial));

        // documents/operations present but Cargo.toml missing.
        let partial2 = base.join("partial2");
        fs::create_dir_all(partial2.join("documents/operations")).expect("dir");
        assert!(!is_workspace_root(&partial2));

        // Cargo.toml as a DIRECTORY does not count.
        let partial3 = base.join("partial3");
        fs::create_dir_all(partial3.join("Cargo.toml")).expect("dir");
        fs::create_dir_all(partial3.join("documents/operations")).expect("dir");
        assert!(!is_workspace_root(&partial3));
    }

    #[test]
    fn inventory_ancestors_win_over_cwd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let root_a = marked_root(base, "root_a");
        let inv = inventory_under(&root_a, "configs/sub/inv.json");

        let root_b = marked_root(base, "root_b");
        let _ = &root_b; // cwd-side marker root; presence is what matters
        let cwd = base.join("root_b/plain/nested");
        fs::create_dir_all(&cwd).expect("cwd");

        let resolved =
            resolve_workspace_root_from(Some(&inv), &cwd, base.join("nowhere/crate").as_path())
                .expect("resolution must succeed");
        assert_eq!(
            resolved,
            canon(&root_a),
            "inventory-side root must win, in canonical form"
        );
    }

    #[test]
    fn relative_inventory_resolves_against_cwd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let root = marked_root(base, "root");
        inventory_under(&root, "configs/inv.json");
        let cwd = root.join("runner");
        fs::create_dir_all(&cwd).expect("cwd");

        let resolved = resolve_workspace_root_from(
            Some(Path::new("configs/inv.json")),
            &cwd,
            base.join("nowhere/crate").as_path(),
        )
        .expect("resolution must succeed");
        assert_eq!(resolved, canon(&root));
    }

    #[test]
    fn cwd_ancestors_are_walked_without_inventory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let root = marked_root(base, "root");
        let cwd = root.join("deep/deeper");
        fs::create_dir_all(&cwd).expect("cwd");

        let resolved =
            resolve_workspace_root_from(None, &cwd, base.join("nowhere/crate").as_path())
                .expect("resolution must succeed");
        assert_eq!(resolved, canon(&root));
    }

    #[test]
    fn validated_compiled_in_root_is_the_last_resort() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        // Neither the inventory nor the cwd chain carries markers.
        let inv = base.join("plain/inv.json");
        fs::create_dir_all(base.join("plain")).expect("dir");
        fs::write(&inv, "{}").expect("file");
        let cwd = base.join("plain2/deep");
        fs::create_dir_all(&cwd).expect("dir");

        // ...but the compiled-in crate dir sits in a marked tree.
        let compiled_root = marked_root(base, "compiled_root");
        let compiled_crate = compiled_root.join("crates/mycrate");

        let resolved = resolve_workspace_root_from(Some(&inv), &cwd, &compiled_crate)
            .expect("compiled fallback must validate");
        assert_eq!(resolved, canon(&compiled_root));
    }

    #[test]
    fn no_markers_anywhere_is_a_hard_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let inv = base.join("plain/inv.json");
        fs::create_dir_all(base.join("plain")).expect("dir");
        fs::write(&inv, "{}").expect("file");
        let cwd = base.join("plain2");
        fs::create_dir_all(&cwd).expect("dir");

        // Compiled-in crate dir without markers either.
        let compiled_crate = base.join("unmarked/crate");
        fs::create_dir_all(&compiled_crate).expect("dir");

        let err = resolve_workspace_root_from(Some(&inv), &cwd, &compiled_crate)
            .expect_err("fail closed with no markers anywhere");
        assert_eq!(
            err,
            "no workspace root with Cargo.toml + documents/operations found \
             from --inventory or cwd; compiled-in root is also invalid"
        );
    }

    #[test]
    fn compiled_in_root_matches_this_checkout() {
        // The real compiled-in root of THIS test binary is the actual
        // rustynet-cli crate inside the real workspace, so it must carry the
        // markers.
        let compiled = compiled_in_root().expect("compiled-in derivation");
        assert!(
            is_workspace_root(&compiled),
            "compiled-in root must be marked"
        );
    }

    #[test]
    fn second_init_is_idempotent_and_first_call_wins() {
        // Serialize against every other test touching the global root state
        // (the pinning tests in live_lab_run_matrix share this process under
        // `cargo test`).
        let _guard: MutexGuard<'_, ()> = TEST_SERIALIZER.lock().expect("serializer");

        init_workspace_root(None).expect("first init from checkout cwd");
        let before = workspace_root_path();

        // A second init with a different inventory must NOT change the value.
        let tmp = tempfile::tempdir().expect("tempdir");
        let inv = inventory_under(tmp.path(), "late/inv.json");
        init_workspace_root(Some(&inv)).expect("second init observes stored value");

        assert_eq!(workspace_root_path(), before);
    }

    #[test]
    fn forced_test_root_is_honored_and_restorable() {
        let _guard: MutexGuard<'_, ()> = TEST_SERIALIZER.lock().expect("serializer");

        let tmp = tempfile::tempdir().expect("tempdir");
        let copy = marked_root(tmp.path(), "copy");
        let prior = test_forced_root();
        set_workspace_root_for_tests(Some(copy.clone()));
        assert_eq!(workspace_root_path(), copy);
        set_workspace_root_for_tests(prior);
    }

    /// Review F2: `init_workspace_root` must honor the inventory-ancestor
    /// rule against a CONFLICTING marked cwd. The init core is driven through
    /// a fresh cell with an explicit cwd because the process `OnceLock`
    /// cannot be reset and the test runner shares one process across threads
    /// (mutating the process cwd would race unrelated tests); the production
    /// `init_workspace_root` feeds `current_dir()` into this same core.
    #[test]
    fn init_from_inventory_ancestors_wins_over_conflicting_cwd() {
        let _guard: MutexGuard<'_, ()> = TEST_SERIALIZER.lock().expect("serializer");
        let tmp = tempfile::tempdir().expect("tempdir");

        let inventory_root = marked_root(tmp.path(), "inventory_root");
        let inv = inventory_under(&inventory_root, "configs/inv.json");
        let cwd_tree = marked_root(tmp.path(), "cwd_root");

        let cell = OnceLock::new();
        init_workspace_root_in(&cell, Some(&inv), &cwd_tree).expect("init must resolve");
        let stored = cell.get().expect("cell set").clone().expect("stored value");
        assert_eq!(
            stored,
            canon(&inventory_root),
            "the inventory-ancestor root must win over a conflicting marked cwd"
        );
    }

    /// Review F1/F2: a second init that resolves to a DIFFERENT root is a
    /// bug and must be refused loudly, never absorbed as a no-op. Pre-seeding
    /// the cell from the cwd-side tree reproduces the pre-fix ordering, where
    /// an eager default evaluation fixed the root from cwd before the
    /// operator's `--inventory` was consulted (this test fails on pre-fix
    /// code, which silently kept the cwd-side root).
    #[test]
    fn divergent_second_init_is_a_hard_error_not_a_noop() {
        let _guard: MutexGuard<'_, ()> = TEST_SERIALIZER.lock().expect("serializer");
        let tmp = tempfile::tempdir().expect("tempdir");

        let inventory_root = marked_root(tmp.path(), "inventory_root");
        let inv = inventory_under(&inventory_root, "configs/inv.json");
        let cwd_tree = marked_root(tmp.path(), "cwd_root");

        let cell = OnceLock::new();
        cell.set(Ok(cwd_tree.clone())).expect("fresh cell");

        let err = init_workspace_root_in(&cell, Some(&inv), &cwd_tree)
            .expect_err("a divergent second init must be refused");
        assert!(err.contains("already initialized"), "{err}");
        assert_eq!(
            cell.get().expect("cell").clone().expect("value"),
            cwd_tree,
            "the first fixed value must stay"
        );
    }

    /// Review F3: a group/world-writable marker must refuse the root.
    #[test]
    fn group_writable_marker_refuses_the_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = marked_root(tmp.path(), "root");
        let cargo = root.join("Cargo.toml");
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o664)).expect("chmod");

        let err = validate_accepted_root(&root)
            .expect_err("a group-writable marker must refuse the root");
        assert!(err.contains("group/world-writable"), "{err}");
    }

    /// Review F3: a winner that fails ownership validation must fail the
    /// WHOLE resolution (hard error), not fall through to a lower-precedence
    /// candidate. Direct chown needs privileges, so the parameterized
    /// acceptance hook models the foreign-owned case.
    #[test]
    fn foreign_owned_winner_is_refused_via_accept_hook() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();
        let root = marked_root(base, "root");
        let cwd = root.join("deep");
        fs::create_dir_all(&cwd).expect("cwd");

        let err =
            resolve_workspace_root_with(None, &cwd, base.join("nowhere/crate").as_path(), &|_| {
                Err("foreign-owned root".to_owned())
            })
            .expect_err("a refused winner must fail the resolution");
        assert_eq!(err, "foreign-owned root");
    }

    /// Review F3: a symlinked inventory path must resolve against the REAL
    /// ancestor chain and return the canonical root.
    #[test]
    fn symlinked_inventory_start_resolves_to_canonical_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path();

        let real = marked_root(base, "real_root");
        inventory_under(&real, "configs/inv.json");
        let link = base.join("link_root");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let inv = link.join("configs/inv.json");
        let cwd = base.join("plain_cwd");
        fs::create_dir_all(&cwd).expect("cwd");

        let resolved =
            resolve_workspace_root_from(Some(&inv), &cwd, base.join("nowhere/crate").as_path())
                .expect("resolution must succeed");
        assert_eq!(
            resolved,
            canon(&real),
            "the canonical (post-symlink) root must be returned"
        );
    }

    /// Review F5: a bare-filename inventory (`Some("")` parent) must walk
    /// from the cwd explicitly, not probe the empty path.
    #[test]
    fn bare_filename_inventory_walks_from_cwd_explicitly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = marked_root(tmp.path(), "root");
        let cwd = root.join("runner");
        fs::create_dir_all(&cwd).expect("cwd");
        fs::write(cwd.join("inv.json"), "{}").expect("inv");

        let resolved = resolve_workspace_root_from(
            Some(Path::new("inv.json")),
            &cwd,
            tmp.path().join("nowhere/crate").as_path(),
        )
        .expect("resolution must succeed");
        assert_eq!(resolved, canon(&root));
    }
}
