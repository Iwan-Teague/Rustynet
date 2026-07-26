//! QH-18 — mutual exclusion for live-lab runs, scoped to the GUESTS a run
//! claims rather than to the host it runs on.
//!
//! ## What was wrong
//!
//! The only "is a run already in flight?" gate lived in `HOST_LAUNCH_SCRIPT`
//! and was a `pgrep -f vm-lab-orchestrate-live-lab` pattern match. That gate
//! is wrong in both directions:
//!
//!  - **False positive:** driving a launch inline over SSH
//!    (`ssh box '<script text>'`) puts the literal subcommand string into the
//!    remote `bash -c` argv, so the gate matches its own launcher and reports
//!    a busy host that is idle.
//!  - **False negative (the dangerous one):** the gate is not in the
//!    orchestrator at all. `ops vm-lab-orchestrate-live-lab` — the form the
//!    runbook documents — reaches no exclusion whatsoever, so two operators
//!    following the runbook get two concurrent runs on the same guests,
//!    silently, and each corrupts the other's evidence.
//!
//! ## Why the unit is the guest, not the host
//!
//! Concurrent runs on ONE host are deliberate: `MAX_CONCURRENT_LAB_RUNS = 3`
//! in the MCP agent server, whose own refusal text tells callers to pass
//! `allow_concurrent` *"AND disjoint guests"*, and CLAUDE.md §12.5 documents
//! "≤3 overlapping" for the macOS↔Windows pipeline. A per-host lock would
//! break parallelism the project built on purpose. What two runs actually
//! contend for is a GUEST — so runs with disjoint guest sets pass through and
//! runs that overlap are refused, naming the guest they collide on.
//!
//! ## Why `flock` and not a pidfile
//!
//! The kernel releases an advisory lock when the holder dies, so there is no
//! recorded pid to argv-verify, and the stale-lock and pid-recycling classes
//! do not exist. (The argv-verifying pidfile remains correct for the *stop*
//! path, which must signal a pid it did not create.) This mirrors the shape
//! already used for the run-matrix append lock in `live_lab_run_matrix.rs`.
//!
//! Acquisition is **non-blocking**: a live-lab run takes hours, so queueing
//! behind one is never what the caller wanted. Refuse immediately and say
//! which guest is busy.
//!
//! ## What this does NOT cover — stated so it is not assumed shut
//!
//!  - **Different users on one driver host do not exclude each other.** The
//!    lock directory defaults under `$HOME`, so a run as `iwan` and a run as
//!    `root` claim different files. Point both at one directory with
//!    `RUSTYNET_LAB_LOCK_DIR` if a host is driven by more than one user.
//!  - **Different driver hosts do not exclude each other.** Two machines can
//!    still both reach one guest over SSH; this is a host-local lock, not a
//!    fleet-wide lease.
//!  - **A run whose topology cannot be resolved claims nothing** (an
//!    unreadable profile, a form with no guest flags). It runs UNPROTECTED and
//!    says so on stderr rather than reporting exclusion it does not have.
//!  - The **false-positive** half of QH-18 — `pgrep` self-tripping on an
//!    inline-over-SSH launch — is untouched here. Closing it means editing the
//!    host launch template and the two assertions pinning that string, in a
//!    file that just landed; an annoyance is not worth disturbing a settled
//!    security boundary. This module closes the dangerous direction.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Override for the lock directory. Set it to make two checkouts on one host
/// share (or deliberately not share) an exclusion domain.
pub const LOCK_DIR_ENV: &str = "RUSTYNET_LAB_LOCK_DIR";

/// Where the per-guest lock files live.
///
/// Deliberately NOT under the repo: `git_worktree_is_dirty` counts untracked
/// paths under the tree, and a run must not flip its own provenance check by
/// taking a lock. Deliberately NOT under `/tmp` either — a tmp reaper that
/// unlinks a held lock file does not release the `flock`, but the NEXT
/// process then creates a fresh file, locks that, and both runs proceed
/// believing they hold exclusion (QH-11 is the same lesson for durable
/// state). `$HOME` is the stable, per-user, non-reaped choice; the workspace
/// `state/` directory (gitignored) is the fallback when `HOME` is unset.
pub fn lock_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(LOCK_DIR_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(dir);
    }
    match std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        Some(home) => PathBuf::from(home).join(".rustynet/lab-locks"),
        None => super::workspace_root_path().join("state/live-lab-locks"),
    }
}

/// Reduce one guest reference to the key both naming forms share.
///
/// A run may name a guest by inventory alias (`--node debian-headless-1:exit`)
/// or by SSH target (`EXIT_TARGET=debian@192.168.18.65` in a profile). Those
/// are the same machine, so they MUST collapse to the same key or the lock
/// silently fails to exclude a run that spells its guests the other way.
///
/// `alias_by_key` maps every known spelling (alias, ssh target, and the host
/// part of that target) to the canonical alias. A reference the inventory does
/// not know keys as itself, normalized — exclusion still works between two
/// runs that spell it identically, which is strictly better than none.
fn canonical_key(
    reference: &str,
    alias_by_key: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if let Some(alias) = alias_by_key.get(lowered.as_str()) {
        return Some(alias.clone());
    }
    // `user@host` → `host`: the user is an access detail, the host is the
    // machine. Two runs reaching one guest as different users still collide.
    let host = lowered.rsplit('@').next().unwrap_or(lowered.as_str());
    if let Some(alias) = alias_by_key.get(host) {
        return Some(alias.clone());
    }
    Some(host.to_owned())
}

/// Build the spelling→alias table from the inventory. An unreadable or absent
/// inventory is NOT fatal: the caller degrades to raw keys (and says so), a
/// weaker guarantee than the mapped one but never a false claim of exclusion.
///
/// A spelling that two entries claim (a stale `last_known_ip` since reassigned
/// to another guest, say) is AMBIGUOUS and is dropped rather than resolved to
/// whichever entry was parsed first. Guessing there would lock the wrong guest
/// and leave the right one open — worse than keying the reference as itself.
fn alias_lookup(inventory_path: Option<&Path>) -> std::collections::BTreeMap<String, String> {
    let mut lookup: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut ambiguous: BTreeSet<String> = BTreeSet::new();
    let Some(path) = inventory_path else {
        return lookup;
    };
    let Ok(entries) = super::load_inventory(path) else {
        return lookup;
    };
    for entry in &entries {
        let alias = entry.alias.trim().to_ascii_lowercase();
        if alias.is_empty() {
            continue;
        }
        // Every spelling this guest answers to. `ssh_target` is a bare host in
        // this schema and `ssh_user` is separate, so the `user@host` form used
        // in live-lab profiles reduces to the host before it gets here.
        let mut spellings = vec![alias.clone(), entry.ssh_target.trim().to_ascii_lowercase()];
        if let Some(ip) = entry.last_known_ip.as_deref() {
            spellings.push(ip.trim().to_ascii_lowercase());
        }
        for spelling in spellings {
            if spelling.is_empty() {
                continue;
            }
            match lookup.get(spelling.as_str()) {
                Some(existing) if existing != &alias => {
                    ambiguous.insert(spelling);
                }
                _ => {
                    lookup.insert(spelling, alias.clone());
                }
            }
        }
    }
    for spelling in &ambiguous {
        lookup.remove(spelling);
    }
    lookup
}

/// Canonicalize a run's guest references into the key set to lock.
pub fn canonical_guest_keys<I, S>(inventory_path: Option<&Path>, references: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let lookup = alias_lookup(inventory_path);
    references
        .into_iter()
        .filter_map(|reference| canonical_key(reference.as_ref(), &lookup))
        .collect()
}

/// ★ MAINTENANCE HAZARD, stated because nothing enforces it: the three
/// `guest_refs_for_*` functions below are hand-maintained field lists. Adding a
/// new guest-bearing field to one of those configs without adding it here
/// silently shrinks the exclusion set — the run still claims to hold locks, it
/// just does not hold one for the new guest. Rust cannot reflect over the
/// struct, so when you add a `*_vm` / `*_target` field, add it here too.
///
/// Every guest `ops vm-lab-orchestrate-live-lab` will touch.
///
/// `--node <alias>:<role>` is the Rust-native engine's topology; the legacy
/// `--exit-vm`/`--client-vm`/… flags are the bash path's. A run uses one or
/// the other (W5.6 translates the legacy flags into `--node` assignments), so
/// taking the union costs nothing and cannot miss the form in use.
/// `--rebuild-nodes` is a subset of the topology, folded in anyway so a
/// rebuild-only run of a node not otherwise named still claims it.
pub fn guest_refs_for_orchestrate(config: &super::VmLabOrchestrateLiveLabConfig) -> Vec<String> {
    let mut refs: Vec<String> = config
        .node_assignments
        .iter()
        .map(|assignment| assignment.alias.clone())
        .collect();
    refs.extend(
        [
            &config.exit_vm,
            &config.client_vm,
            &config.entry_vm,
            &config.aux_vm,
            &config.extra_vm,
            &config.fifth_client_vm,
            &config.relay_vm,
        ]
        .into_iter()
        .flatten()
        .cloned(),
    );
    if let Some(nodes) = config.rebuild_nodes.as_ref() {
        refs.extend(nodes.iter().cloned());
    }
    refs
}

/// Every guest `ops vm-lab-setup-live-lab` will touch.
pub fn guest_refs_for_setup(config: &super::VmLabSetupLiveLabConfig) -> Vec<String> {
    [
        &config.exit_vm,
        &config.client_vm,
        &config.entry_vm,
        &config.aux_vm,
        &config.extra_vm,
        &config.fifth_client_vm,
        &config.relay_vm,
        &config.linux_blind_exit_vm,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect()
}

/// Every guest `ops vm-lab-iterate-live-lab` will touch. This form accepts a
/// guest by alias OR by raw SSH target, which is exactly why canonicalization
/// has to collapse both spellings onto one key.
pub fn guest_refs_for_iterate(config: &super::VmLabIterateLiveLabConfig) -> Vec<String> {
    [
        &config.exit_vm,
        &config.exit_target,
        &config.client_vm,
        &config.client_target,
        &config.entry_vm,
        &config.entry_target,
        &config.aux_vm,
        &config.aux_target,
        &config.extra_vm,
        &config.extra_target,
        &config.fifth_client_vm,
        &config.fifth_client_target,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect()
}

/// Every guest named by a live-lab profile (`ops vm-lab-run-live-lab` takes
/// only `--profile`, so its topology lives in the file).
///
/// Profiles are `KEY=value` env files whose guests appear as `*_TARGET`
/// (`EXIT_TARGET=debian@192.168.18.65`) and occasionally `*_VM`. An unreadable
/// profile yields nothing — the caller then reports that no exclusion was
/// taken rather than proceeding as though it had been.
pub fn guest_refs_from_profile(path: &Path) -> Vec<String> {
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim().trim_start_matches("export ").trim();
            if !(key.ends_with("_TARGET") || key.ends_with("_VM")) {
                return None;
            }
            let value = value.trim().trim_matches(['"', '\'']).trim();
            if value.is_empty() {
                return None;
            }
            Some(value.to_owned())
        })
        .collect()
}

/// Canonicalize `references`, take the locks, and report what was claimed.
///
/// An empty resolved set is NOT silently treated as success: it means the run
/// is unprotected, and the operator is told so on stderr. Anything else would
/// reproduce the defect this exists to fix — a gate that reads as exclusion
/// while enforcing nothing.
pub fn claim_guests(
    command: &str,
    inventory_path: Option<&Path>,
    references: Vec<String>,
) -> Result<GuestRunLocks, String> {
    let keys = canonical_guest_keys(inventory_path, references);
    if keys.is_empty() {
        eprintln!(
            "warning: {command} claimed NO guests for run exclusion — its topology could not \
             be resolved from the command line or profile. This run is NOT protected against \
             a concurrent run on the same guests (QH-18)."
        );
    }
    let held = acquire_guest_run_locks(&keys)?;
    if !held.keys().is_empty() {
        eprintln!(
            "run exclusion: {command} holds {} guest lock(s): {}",
            held.keys().len(),
            held.keys().join(", ")
        );
    }
    Ok(held)
}

/// One lock file per guest. Keep the whole set alive for the run's duration:
/// dropping this releases every lock it holds.
///
/// `Debug` prints the keys only — the held descriptors are not interesting and
/// `Flock` is not `Debug`.
pub struct GuestRunLocks {
    keys: Vec<String>,
    #[cfg(unix)]
    _locks: Vec<Flock<File>>,
    #[cfg(not(unix))]
    paths: Vec<PathBuf>,
}

impl GuestRunLocks {
    /// The canonical guest keys this guard holds. Empty means NO exclusion was
    /// taken — callers must say so rather than let it read as protection.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
}

impl std::fmt::Debug for GuestRunLocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestRunLocks")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

#[cfg(not(unix))]
impl Drop for GuestRunLocks {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

/// Map a guest key to a lock filename. Every character outside `[a-z0-9_-]`
/// becomes `_` — including `.`, so no amount of dots in an alias can produce a
/// `.`/`..` component or a hidden file, and the only dot in the result is the
/// one in `.lock`. The full key is appended as a hex digest so two distinct
/// keys can never sanitize onto one file and silently share a lock.
fn lock_file_name(key: &str) -> String {
    let safe: String = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let digest = super::sha256_hex_bytes(key.as_bytes());
    let truncated: String = safe.chars().take(48).collect();
    format!("guest-{truncated}-{}.lock", &digest[..16])
}

/// Take an exclusive advisory lock on every guest in `keys`.
///
/// Keys are locked in sorted order so two processes claiming overlapping sets
/// always contend on the same first guest; combined with non-blocking
/// acquisition there is no lock-ordering deadlock. Failure releases everything
/// already taken (the `Vec` drops), so a refused run never leaves a guest
/// pinned.
pub fn acquire_guest_run_locks(keys: &BTreeSet<String>) -> Result<GuestRunLocks, String> {
    acquire_guest_run_locks_in(lock_dir().as_path(), keys)
}

/// Directory-explicit form. The public entry point resolves [`lock_dir`] and
/// calls this; tests pass a temp dir, so no test ever mutates process-wide
/// environment to exercise the locking itself.
pub fn acquire_guest_run_locks_in(
    dir: &Path,
    keys: &BTreeSet<String>,
) -> Result<GuestRunLocks, String> {
    if !keys.is_empty() {
        fs::create_dir_all(dir)
            .map_err(|err| format!("create lab lock dir failed ({}): {err}", dir.display()))?;
    }

    let mut held = GuestRunLocks {
        keys: Vec::new(),
        #[cfg(unix)]
        _locks: Vec::new(),
        #[cfg(not(unix))]
        paths: Vec::new(),
    };

    for key in keys {
        let path = dir.join(lock_file_name(key));
        acquire_one(&mut held, key, path.as_path())?;
    }
    Ok(held)
}

#[cfg(unix)]
fn acquire_one(held: &mut GuestRunLocks, key: &str, path: &Path) -> Result<(), String> {
    // create(true), NOT create_new: a lock file legitimately survives a crash.
    // Exclusion comes from the advisory lock, never from the file existing.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("open lab guest lock failed ({}): {err}", path.display()))?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(flock) => {
            held._locks.push(flock);
            held.keys.push(key.to_owned());
            Ok(())
        }
        Err((_file, _errno)) => Err(format!(
            "guest '{key}' is already claimed by a live-lab run in flight on this host \
             (lock {}). Concurrent runs are supported ONLY on disjoint guests: give this \
             run different guests, or wait for the in-flight run to finish. A dead run's \
             lock is released by the kernel, so this is live contention, not a stale file.",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn acquire_one(held: &mut GuestRunLocks, key: &str, path: &Path) -> Result<(), String> {
    // No advisory locks: the file's existence IS the lock, so a crash CAN
    // strand it. Mirrors the run-matrix append lock's non-unix fallback.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {
            held.paths.push(path.to_path_buf());
            held.keys.push(key.to_owned());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
            "guest '{key}' is already claimed by a live-lab run in flight on this host \
             (lock {}). Concurrent runs are supported ONLY on disjoint guests. NOTE: on \
             this platform the lock is a plain file, so a crashed run can strand it — \
             delete the file if you have confirmed no run is live.",
            path.display()
        )),
        Err(err) => Err(format!(
            "open lab guest lock failed ({}): {err}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn overlapping_guest_sets_are_refused_and_disjoint_ones_are_not() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();

        let first =
            acquire_guest_run_locks_in(dir, &keys(&["debian-1", "windows-1"])).expect("first run");
        assert_eq!(first.keys(), ["debian-1", "windows-1"]);

        // Disjoint: allowed, because concurrent runs on one host are intended.
        let second =
            acquire_guest_run_locks_in(dir, &keys(&["rocky-2", "macos-2"])).expect("disjoint run");
        assert_eq!(second.keys().len(), 2);

        // Overlapping on ONE guest: refused, and the message names that guest.
        let err = acquire_guest_run_locks_in(dir, &keys(&["rocky-9", "windows-1"]))
            .expect_err("overlapping run must be refused");
        assert!(
            err.contains("windows-1"),
            "refusal must name the contended guest: {err}"
        );

        // The refused attempt must not strand the guest it DID lock first.
        // ("rocky-9" sorts before "windows-1", so it was taken then dropped.)
        drop(
            acquire_guest_run_locks_in(dir, &keys(&["rocky-9"]))
                .expect("a refused run must release what it already took"),
        );

        // Releasing the holder frees the guest for the next run.
        drop(first);
        let third = acquire_guest_run_locks_in(dir, &keys(&["windows-1"])).expect("after release");
        assert_eq!(third.keys(), ["windows-1"]);
    }

    #[test]
    fn an_empty_guest_set_takes_no_lock_and_says_so() {
        // A run whose guests could not be resolved must not read as protected:
        // `keys()` is empty, which is the caller's cue to warn.
        let tmp = tempfile::tempdir().expect("tempdir");
        let held = acquire_guest_run_locks_in(tmp.path(), &BTreeSet::new()).expect("empty set");
        assert!(held.keys().is_empty());
        // Two "runs" with no resolvable guests do NOT exclude each other —
        // pinned deliberately so the gap is visible rather than assumed shut.
        let other = acquire_guest_run_locks_in(tmp.path(), &BTreeSet::new()).expect("empty set");
        assert!(other.keys().is_empty());
    }

    #[test]
    fn lock_file_name_cannot_escape_the_lock_directory() {
        for hostile in [
            "../../etc/passwd",
            "/absolute/alias",
            "..",
            "a/b",
            "alias with spaces",
        ] {
            let name = lock_file_name(hostile);
            assert!(
                !name.contains('/') && !name.contains(".."),
                "lock file name must be a single safe component: {hostile} -> {name}"
            );
            assert_eq!(
                Path::new(&name).components().count(),
                1,
                "{hostile} -> {name} must be one path component"
            );
        }
    }

    #[test]
    fn distinct_keys_never_share_a_lock_file() {
        // Both sanitize to the same visible text; the digest suffix is what
        // keeps them apart. Without it, two different guests would silently
        // share one lock — exclusion where none was asked for, and (worse) a
        // pair of guests that can never run concurrently for no visible reason.
        assert_ne!(lock_file_name("a/b"), lock_file_name("a:b"));
        assert_ne!(lock_file_name("node-1"), lock_file_name("node_1"));
    }

    fn write_inventory(dir: &Path, entries: &str) -> PathBuf {
        let path = dir.join("inventory.json");
        std::fs::write(
            &path,
            format!(r#"{{"version": 1, "entries": [{entries}]}}"#),
        )
        .expect("write inventory");
        path
    }

    #[test]
    fn alias_and_ssh_target_spellings_collapse_to_one_key() {
        // The exclusion is worthless if `--node debian-headless-1:exit` and a
        // profile's `EXIT_TARGET=debian@192.168.18.65` lock different keys.
        let tmp = tempfile::tempdir().expect("tempdir");
        let inventory = write_inventory(
            tmp.path(),
            r#"{"alias": "debian-headless-1", "ssh_target": "192.168.18.65", "ssh_user": "debian"}"#,
        );

        let from_alias = canonical_guest_keys(Some(inventory.as_path()), ["debian-headless-1"]);
        assert_eq!(
            from_alias,
            keys(&["debian-headless-1"]),
            "the inventory fixture must actually parse — an unparsed one degrades to raw \
             keys and would make every assertion below pass for the wrong reason"
        );
        for spelling in [
            "192.168.18.65",
            "debian@192.168.18.65",
            "root@192.168.18.65",
            "DEBIAN-HEADLESS-1",
        ] {
            assert_eq!(
                canonical_guest_keys(Some(inventory.as_path()), [spelling]),
                from_alias,
                "'{spelling}' names the same machine and must lock the same key"
            );
        }
    }

    #[test]
    fn profile_targets_and_cli_aliases_lock_the_same_guest() {
        // The cross-FORM property, and the one most likely to rot silently:
        // `ops vm-lab-run-live-lab --profile p.env` names its guests as
        // `EXIT_TARGET=debian@<ip>`, while `ops vm-lab-orchestrate-live-lab`
        // names the same machine as `--node <alias>:exit`. If those two key
        // differently, both runs "hold exclusion" and both trash the guest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let inventory = write_inventory(
            tmp.path(),
            r#"{"alias": "debian-headless-1", "ssh_target": "192.168.18.65", "ssh_user": "debian"},
               {"alias": "ubuntu-1", "ssh_target": "192.168.18.52", "ssh_user": "ubuntu"}"#,
        );
        let profile = tmp.path().join("four_node.env");
        std::fs::write(
            &profile,
            "# Default four-node live-lab profile.\n\
             EXIT_TARGET=debian@192.168.18.65\n\
             CLIENT_TARGET=ubuntu@192.168.18.52\n\
             EXTRA_TARGET=\n\
             SSH_ALLOW_CIDRS=192.168.18.0/24\n",
        )
        .expect("write profile");

        let refs = guest_refs_from_profile(profile.as_path());
        assert_eq!(
            refs,
            vec!["debian@192.168.18.65", "ubuntu@192.168.18.52"],
            "empty values and non-guest keys must not become guests"
        );
        assert!(
            !refs.iter().any(|value| value.contains("192.168.18.0/24")),
            "SSH_ALLOW_CIDRS is not a guest"
        );

        let from_profile = canonical_guest_keys(Some(inventory.as_path()), refs);
        let from_cli =
            canonical_guest_keys(Some(inventory.as_path()), ["debian-headless-1", "ubuntu-1"]);
        assert_eq!(
            from_profile, from_cli,
            "a profile-driven run and a --node run must contend on the same keys"
        );
    }

    #[test]
    fn an_ip_two_guests_both_claim_is_left_ambiguous_not_guessed() {
        // A stale `last_known_ip` since reassigned to another guest must not
        // resolve to whichever entry parsed first: that would lock the wrong
        // guest AND leave the right one open. Keying it as itself is honest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let inventory = write_inventory(
            tmp.path(),
            r#"{"alias": "guest-a", "ssh_target": "10.0.0.5", "last_known_ip": "10.0.0.9"},
               {"alias": "guest-b", "ssh_target": "10.0.0.9"}"#,
        );

        assert_eq!(
            canonical_guest_keys(Some(inventory.as_path()), ["10.0.0.5"]),
            keys(&["guest-a"]),
            "an unambiguous spelling still resolves"
        );
        assert_eq!(
            canonical_guest_keys(Some(inventory.as_path()), ["10.0.0.9"]),
            keys(&["10.0.0.9"]),
            "a contested spelling keys as itself rather than picking a guest"
        );
    }

    #[test]
    fn unknown_references_key_as_themselves_rather_than_vanishing() {
        // A guest the inventory does not know must still be lockable — a
        // reference that silently produced NO key would be a run claiming
        // exclusion it never took.
        let got = canonical_guest_keys(None, ["ubuntu@10.0.0.9", "  ", "Weird-Alias"]);
        assert_eq!(got, keys(&["10.0.0.9", "weird-alias"]));
    }
}
