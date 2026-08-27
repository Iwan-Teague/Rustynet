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
//!    `RUSTYNET_LAB_LOCK_DIR` if a host is driven by more than one user. The
//!    lock files are made 0o666 for exactly this reason — under 0o600 the second
//!    user cannot open the first user's lock and every subsequent run on that
//!    guest fails permanently with a message that reads like a tool bug. The
//!    mode is applied with an explicit `set_permissions` after creation, because
//!    `OpenOptions::mode` is masked by `umask` and the common default of 022
//!    turns 0o666 into 0o644 — which reproduces the failure exactly. The
//!    DIRECTORY is still umask-subject, so a shared lock dir must be created
//!    group-writable by whoever sets it up.
//!  - **Different driver hosts do not exclude each other.** Two machines can
//!    still both reach one guest over SSH; this is a host-local lock, not a
//!    fleet-wide lease.
//!  - **Guests named only by platform are not claimed.** `--exit-platform` and
//!    its siblings become an alias only after an inventory lookup the
//!    orchestrator performs later; resolving them here would duplicate that
//!    logic. They are reported as UNRESOLVED so the warning can name them, and
//!    a run that resolves nothing at all is REFUSED rather than run unprotected
//!    (`RUSTYNET_LAB_ALLOW_UNPROTECTED_RUN=1` overrides). A partial claim still
//!    excludes on everything it did resolve.
//!  - **Different driver hosts do not exclude each other** (restated because it
//!    is the gap most likely to be mistaken for coverage): this is a host-local
//!    lock, not a fleet-wide lease.
//!
//! ## When the lock is released — every exit path, including the ugly one
//!
//! The guard is a value ([`GuestRunLocks`]) held for the duration of the run by
//! a NAMED binding in `execute_ops`, so release is tied to scope exit, not to
//! any cleanup code that could be skipped:
//!
//!  - **Normal exit.** The guard drops when `execute_ops` returns; the `Flock`
//!    values close their descriptors and the kernel drops the advisory locks.
//!  - **Error exit.** Identical: an early `return Err(..)` or a `?` unwinds
//!    through the same scope, and the guard drops on the way out. Nothing has
//!    to remember to unlock.
//!  - **Panic.** Unwinding runs `Drop`; and even under `panic = "abort"` the
//!    process dies, which is the SIGKILL case below.
//!  - **SIGTERM / SIGINT / ^C.** No handler is installed, so the default action
//!    terminates the process. `Drop` does NOT run — and it does not need to:
//!    the kernel closes every descriptor of a dying process and releases the
//!    advisory locks with them.
//!  - **SIGKILL / power loss / OOM kill.** Nothing user-space runs at all. The
//!    kernel still closes the descriptors, so the locks are still released. The
//!    lock FILE remains on disk, which is correct and deliberate: the file's
//!    existence never meant anything, only the lock on it did. The next run
//!    opens the same file and acquires it normally.
//!
//! That is why there is **no stale-lock detection, no timeout, and no
//! auto-break** on unix — there is no stale state to break. A refusal here is
//! always live contention, which is what the refusal message asserts. If you
//! ever find yourself wanting a `--force` that unlinks a lock file, note that
//! unlinking does not release anything: the holder keeps its lock on the now
//! unlinked inode while the next run creates a NEW file and locks that, and
//! both then believe they hold exclusion.
//!
//! The **non-unix** fallback is the exception and says so loudly in its own
//! refusal text: with no advisory locks the file's existence IS the lock, so a
//! crash CAN strand it and an operator must delete it by hand after confirming
//! no run is live. That is an explicit, loud, human-performed break — never an
//! automatic one.
//!
//! ## The `pgrep` gate is gone
//!
//! The **false-positive** half of QH-18 is closed by deletion rather than by
//! repair. `HOST_LAUNCH_SCRIPT` no longer carries a concurrency gate at all: a
//! `pgrep -f` pattern cannot be made correct there, because driving the launcher
//! inline over ssh puts the whole script text into the remote `bash -c` argv and
//! the script must contain the subcommand string it runs — so it always matches
//! itself. It was also per-HOST, refusing the disjoint-guest concurrency this
//! module exists to preserve. The process that launcher starts reaches this
//! module like every other invocation form, so removing it loses no coverage.
//! Its pidfile prune became liveness-checked in the same change, since a
//! concurrent disjoint-guest run's pidfile is now legitimately present and must
//! not be deleted out from under the stop path.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Override for the lock directory. Set it to make two checkouts on one host
/// share (or deliberately not share) an exclusion domain.
pub const LOCK_DIR_ENV: &str = "RUSTYNET_LAB_LOCK_DIR";

/// Process-local redirect for [`lock_dir`], taking precedence over the env var.
///
/// This exists for one reason: the wiring test has to drive the real
/// `execute_ops` claim path — that is the only way to catch a claim that is
/// unwired or whose guard is dropped early — and it must not write into the
/// operator's `~/.rustynet` while doing so. The crate is `#![forbid(unsafe_code)]`
/// and `std::env::set_var` is `unsafe` under edition 2024, so a test cannot
/// redirect this through the environment. A safe, explicit override is the
/// alternative to weakening that lint.
static LOCK_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Redirect [`lock_dir`] for this process. `None` restores the normal lookup.
///
/// `cfg(test)` rather than `allow(dead_code)`: this exists only so the wiring
/// test can drive the real claim path without touching `~/.rustynet`, and a
/// production build should not carry a way to redirect the exclusion domain.
#[cfg(test)]
pub fn set_lock_dir_override(dir: Option<PathBuf>) {
    let mut guard = LOCK_DIR_OVERRIDE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = dir;
}

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
    if let Some(dir) = LOCK_DIR_OVERRIDE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
    {
        return dir;
    }
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

/// What a command's config says about the guests it will touch.
///
/// `unresolved` exists so an incomplete claim can name what it could not
/// resolve. A run that claims three guests but silently ignores a fourth
/// selector reads as protected and is not, which is the exact defect QH-18
/// exists to close — so the gap is reported rather than dropped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GuestClaimRefs {
    /// Guests this run will touch, in any spelling. Canonicalized later.
    pub refs: Vec<String>,
    /// Selectors that name a guest only indirectly and could not be resolved
    /// from the config alone, as operator-facing flag names.
    pub unresolved: Vec<&'static str>,
    /// The run will not touch a guest at all, so it needs no locks and its
    /// empty claim is not a warning.
    pub touches_no_guest: bool,
}

impl GuestClaimRefs {
    fn no_guests() -> Self {
        Self {
            touches_no_guest: true,
            ..Self::default()
        }
    }
}

/// Guests named by a `--topology-profile` document, best effort.
///
/// An unreadable or invalid profile is NOT an error here: the run itself
/// parses the same file and fails properly on it. Returning `None` lets the
/// caller record the selector as unresolved instead of pretending the run
/// touches nothing.
fn guest_refs_from_topology_profile(path: &Path) -> Option<Vec<String>> {
    let profile = super::topology::parse_topology_profile_file(path).ok()?;
    Some(
        [
            profile.exit.as_deref(),
            profile.relay.as_deref(),
            profile.anchor.as_deref(),
            profile.blind_exit.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::to_owned)
        .collect(),
    )
}

/// Every guest `ops vm-lab-orchestrate-live-lab` will touch.
///
/// `--node <alias>:<role>` is the Rust-native engine's topology; the legacy
/// `--exit-vm`/`--client-vm`/… flags are the bash path's. A run uses one or
/// the other (W5.6 translates the legacy flags into `--node` assignments), so
/// taking the union costs nothing and cannot miss the form in use.
/// `--rebuild-nodes` is a subset of the topology, folded in anyway so a
/// rebuild-only run of a node not otherwise named still claims it.
pub fn guest_refs_for_orchestrate(config: &super::VmLabOrchestrateLiveLabConfig) -> GuestClaimRefs {
    // Exhaustive destructuring is deliberate, and is the enforcement the
    // hand-maintained list did not have. Add a field to the config and this
    // function stops compiling until someone classifies it as guest-bearing or
    // not. The previous list was not merely AT RISK of rotting — it shipped
    // already rotten, missing `windows_vm`, `macos_vm`, `profile_path` and
    // `topology_profile`. That gap was not academic: the documented
    // ≤3-concurrent-disjoint-guest workflow varies `exit_vm` while holding
    // `windows_vm` constant, so exclusion keyed only on what varies, and two
    // runs could share one Windows guest with both believing they were
    // protected.
    let super::VmLabOrchestrateLiveLabConfig {
        // ── guests named directly ──
        node_assignments,
        exit_vm,
        client_vm,
        entry_vm,
        aux_vm,
        extra_vm,
        fifth_client_vm,
        relay_vm,
        windows_vm,
        macos_vm,
        rebuild_nodes,
        // ── guests named indirectly, resolvable here ──
        profile_path,
        topology_profile,
        // ── guests named indirectly, NOT resolvable here ──
        //
        // These select a guest by PLATFORM, which only becomes an alias after
        // an inventory lookup the orchestrator performs later. Resolving them
        // here would duplicate that logic; leaving them silent would be the
        // original defect. They are reported as unresolved instead.
        exit_platform,
        relay_platform,
        anchor_platform,
        admin_platform,
        blind_exit_platform,
        role_switch_platform,
        // ── a dry run validates wiring and touches no guest ──
        dry_run,
        // ── everything below names no guest ──
        inventory_path: _,
        profile_output_path: _,
        network_profile: _,
        ssh_identity_file: _,
        known_hosts_path: _,
        require_same_network: _,
        report_dir: _,
        source_mode: _,
        repo_ref: _,
        max_parallel_node_workers: _,
        skip_gates: _,
        skip_soak: _,
        skip_cross_network: _,
        cross_network_nat_profiles: _,
        cross_network_required_nat_profiles: _,
        cross_network_impairment_profile: _,
        cross_network_substrate: _,
        utm_documents_root: _,
        utmctl_path: _,
        ssh_port: _,
        discovery_timeout_secs: _,
        ready_timeout_secs: _,
        timeout_secs: _,
        collect_artifacts_on_failure: _,
        skip_diagnose_on_failure: _,
        setup_only: _,
        run_only: _,
        stop_after_ready: _,
        resume_from: _,
        rerun_stage: _,
        trust_inventory_ready: _,
        windows_only: _,
        no_fail_on_authenticode: _,
        validate_linux_daemon_state: _,
        orchestrate_ssh_allow_cidrs: _,
        macos_promote_exit: _,
        enable_chaos_suite: _,
        enable_negative_control: _,
        stage_timeout_secs: _,
        skip_linux_live_suite: _,
    } = config;

    if *dry_run {
        return GuestClaimRefs::no_guests();
    }

    let mut refs: Vec<String> = node_assignments
        .iter()
        .map(|assignment| assignment.alias.clone())
        .collect();
    refs.extend(
        [
            exit_vm,
            client_vm,
            entry_vm,
            aux_vm,
            extra_vm,
            fifth_client_vm,
            relay_vm,
            windows_vm,
            macos_vm,
        ]
        .into_iter()
        .flatten()
        .cloned(),
    );
    if let Some(nodes) = rebuild_nodes.as_ref() {
        refs.extend(nodes.iter().cloned());
    }

    let mut unresolved: Vec<&'static str> = Vec::new();
    if let Some(path) = profile_path.as_ref() {
        refs.extend(guest_refs_from_profile(path.as_path()));
    }
    if let Some(path) = topology_profile.as_ref() {
        match guest_refs_from_topology_profile(path.as_path()) {
            Some(aliases) => refs.extend(aliases),
            None => unresolved.push("--topology-profile"),
        }
    }
    for (value, flag) in [
        (exit_platform, "--exit-platform"),
        (relay_platform, "--relay-platform"),
        (anchor_platform, "--anchor-platform"),
        (admin_platform, "--admin-platform"),
        (blind_exit_platform, "--blind-exit-platform"),
        (role_switch_platform, "--role-switch-platform"),
    ] {
        if value.is_some() {
            unresolved.push(flag);
        }
    }

    GuestClaimRefs {
        refs,
        unresolved,
        touches_no_guest: false,
    }
}

/// Every guest `ops vm-lab-setup-live-lab` will touch.
///
/// `profile_path` matters as much as the explicit flags here: `scripts/e2e`
/// documents `setup-live-lab` → `run-live-lab` as the primary operator path,
/// `execute_ops_vm_lab_setup_live_lab` reads the profile on its reuse/resume
/// path, and `run-live-lab` keys entirely off that same profile. Omitting it
/// meant the two halves of one documented workflow keyed differently and did
/// not exclude each other at all.
pub fn guest_refs_for_setup(config: &super::VmLabSetupLiveLabConfig) -> GuestClaimRefs {
    // Exhaustive: see `guest_refs_for_orchestrate`.
    let super::VmLabSetupLiveLabConfig {
        exit_vm,
        client_vm,
        entry_vm,
        aux_vm,
        extra_vm,
        fifth_client_vm,
        relay_vm,
        linux_blind_exit_vm,
        profile_path,
        dry_run,
        inventory_path: _,
        profile_output_path: _,
        ssh_identity_file: _,
        known_hosts_path: _,
        require_same_network: _,
        report_dir: _,
        source_mode: _,
        repo_ref: _,
        resume_from: _,
        rerun_stage: _,
        max_parallel_node_workers: _,
        timeout_secs: _,
        stage_timeout_secs: _,
        orchestrated: _,
    } = config;

    if *dry_run {
        return GuestClaimRefs::no_guests();
    }

    let mut refs: Vec<String> = [
        exit_vm,
        client_vm,
        entry_vm,
        aux_vm,
        extra_vm,
        fifth_client_vm,
        relay_vm,
        linux_blind_exit_vm,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    if let Some(path) = profile_path.as_ref() {
        refs.extend(guest_refs_from_profile(path.as_path()));
    }

    GuestClaimRefs {
        refs,
        unresolved: Vec::new(),
        touches_no_guest: false,
    }
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

/// Every guest `ops vm-lab-run-suite` will touch.
///
/// `--all` selects every guest in the inventory, which cannot be expanded from
/// the config alone. It is reported as unresolved rather than ignored: a suite
/// run over the whole lab is the case where exclusion matters most, so it must
/// not be the case that silently claims nothing.
pub fn guest_refs_for_run_suite(config: &super::VmLabRunSuiteConfig) -> GuestClaimRefs {
    // Exhaustive: see `guest_refs_for_orchestrate`.
    let super::VmLabRunSuiteConfig {
        vm_aliases,
        profile_path,
        topology_path,
        select_all,
        dry_run,
        inventory_path: _,
        suite: _,
        ssh_identity_file: _,
        nat_profile: _,
        impairment_profile: _,
        report_dir: _,
        timeout_secs: _,
    } = config;

    if *dry_run {
        return GuestClaimRefs::no_guests();
    }

    let mut refs: Vec<String> = vm_aliases.clone();
    let mut unresolved: Vec<&'static str> = Vec::new();

    // `--topology` here is the run-suite topology document
    // (`{version, suite, roles, nodes}`), NOT the `--topology-profile` schema
    // (`{exit, relay, anchor, blind_exit}`) that `orchestrate` takes. The two
    // are `deny_unknown_fields` and mutually exclusive — each rejects the
    // other's document — so resolving this with the profile parser meant it
    // could NEVER resolve. That was worse than not trying: the run warned about
    // an unresolved selector, claimed only its `--vm` aliases, and then drove
    // every guest in the topology, including one another run was holding.
    if let Some(path) = topology_path.as_ref() {
        match super::load_vm_lab_topology(path.as_path()) {
            Ok(topology) => refs.extend(
                topology
                    .nodes
                    .values()
                    .flat_map(|node| [node.alias.clone(), node.normalized_target.clone()]),
            ),
            // The run parses the same file and fails properly on it; record the
            // selector rather than pretending the run touches nothing.
            Err(_) => unresolved.push("--topology"),
        }
    }

    // `--all` expands against the inventory, which this function does not have.
    if *select_all {
        unresolved.push("--all");
    }

    // `profile_path` is deliberately NOT read: `execute_ops_vm_lab_run_suite`
    // never looks at it, so collecting guests from it would claim locks for a
    // file this command does not act on.
    let _ = profile_path;

    GuestClaimRefs {
        refs,
        unresolved,
        touches_no_guest: false,
    }
}

/// Escape hatch for the empty-claim refusal below. Set to `1` to run anyway.
pub const ALLOW_UNPROTECTED_ENV: &str = "RUSTYNET_LAB_ALLOW_UNPROTECTED_RUN";

/// Canonicalize the claim, take the locks, and report what was claimed.
///
/// An empty resolved set REFUSES the run. It previously warned and proceeded,
/// which is the defect this module exists to close wearing a different hat: a
/// run that claims nothing is a run with no exclusion at all, and printing a
/// warning nobody reads on a lab host is indistinguishable from having no gate.
/// Refusing converts every gap in the collection functions — including any
/// added later — from silent to loud. `RUSTYNET_LAB_ALLOW_UNPROTECTED_RUN=1`
/// overrides it for the operator who genuinely means it.
///
/// A PARTIAL claim (some guests resolved, some selectors not) warns and
/// proceeds, naming the selectors. Refusing there would break `--exit-platform`
/// runs outright, and a partial claim still excludes on everything it did
/// resolve, so the proportionate response is to say exactly what is unguarded.
pub fn claim_guests(
    command: &str,
    inventory_path: Option<&Path>,
    claim: GuestClaimRefs,
) -> Result<GuestRunLocks, String> {
    if claim.touches_no_guest {
        let no_keys: BTreeSet<String> = BTreeSet::new();
        return acquire_guest_run_locks(&no_keys);
    }
    let unresolved = claim.unresolved.clone();
    let keys = canonical_guest_keys(inventory_path, claim.refs);
    if keys.is_empty() {
        if std::env::var(ALLOW_UNPROTECTED_ENV).as_deref() != Ok("1") {
            return Err(format!(
                "{command} resolved NO guests for run exclusion, so it would run with no \
                 protection against a concurrent run on the same guests (QH-18). Name the \
                 guests explicitly, or set {ALLOW_UNPROTECTED_ENV}=1 to run unprotected \
                 deliberately.{}",
                unresolved_suffix(&unresolved)
            ));
        }
        eprintln!(
            "warning: {command} claimed NO guests for run exclusion and \
             {ALLOW_UNPROTECTED_ENV}=1 is set. This run is NOT protected against a \
             concurrent run on the same guests (QH-18).{}",
            unresolved_suffix(&unresolved)
        );
    } else if !unresolved.is_empty() {
        eprintln!(
            "warning: {command} claimed {} guest(s) but could not resolve {} from this \
             config, so any guest named only that way is NOT protected (QH-18).",
            keys.len(),
            unresolved.join(", ")
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

fn unresolved_suffix(unresolved: &[&'static str]) -> String {
    if unresolved.is_empty() {
        String::new()
    } else {
        format!(" Unresolved selector(s): {}.", unresolved.join(", "))
    }
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
    // 0o666, not 0o600. The module recommends pointing two users at one
    // directory via RUSTYNET_LAB_LOCK_DIR, and 0o600 made that advice
    // self-defeating: user B cannot open user A's lock file, so every future
    // run on that guest fails with "Permission denied" — permanently, and with
    // a message that reads like a tool bug rather than a chmod. The file holds
    // no secret; exclusion comes from the advisory lock, not from the mode.
    // umask still applies, so a restrictive umask reintroduces the problem —
    // hence the note in the module docs.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666)
        .open(path)
        .inspect(|_| {
            // `mode()` is masked by umask, and the common default (022) turns
            // 0o666 into 0o644 — under which the second user still cannot open
            // the first user's lock, which is the exact failure this is meant to
            // prevent. Set the mode explicitly afterwards so the shared-directory
            // remedy the module docs recommend actually works.
            //
            // Best effort: only the owner may chmod, so when the file already
            // belongs to the other user this call fails and the existing mode —
            // which that user already made group-writable, or did not — stands.
            let _ = fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
        })
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
