//! Run-instance identity + the exclusive report-directory lease.
//!
//! L0.2 of the truth-preserving framework
//! (`LiveLabTestCoverageImplementationDesign_2026-08-19` §3.1.1). A report
//! directory is reused across resume/rerun invocations, and the shared
//! `stages.tsv` writer asserted — but never enforced — a single-writer
//! contract. This module supplies both halves of the fix:
//!
//! * [`RunInstanceId`] — a CSPRNG 128-bit identifier that binds every artifact
//!   of ONE native invocation together, so a later generation cannot read a
//!   prior invocation's terminal row as fresh evidence. (Threading the id
//!   through the recorder/manifest is the following L0.2 increment; this module
//!   mints it.)
//! * [`ReportDirLease`] — an advisory `flock(LOCK_EX)` on
//!   `<report_dir>/state/.orchestrator.lock` that makes two concurrent
//!   orchestrator runs against the same report directory impossible: the second
//!   aborts with a named error instead of racing the recorder's
//!   read-modify-write. The kernel releases the lock when the descriptor closes
//!   — including on process death — so a crashed holder never wedges the next
//!   run. Mirrors the hardened `enrollment_token::acquire_ledger_lock` posture.
//!
//! The id is minted ONLY after the lease is confirmed held, so a run id never
//! exists without the exclusive right to write that report directory.
#![allow(dead_code)] // lease acquisition is wired into native.rs in the next L0.2 increment

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A CSPRNG 128-bit run-instance identifier, lowercase hex (32 chars).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInstanceId(String);

impl RunInstanceId {
    /// Mint a fresh id from the OS CSPRNG. Fails closed if OS randomness is
    /// unavailable rather than returning a predictable id.
    pub fn generate() -> Result<Self, String> {
        use rand::{TryRngCore, rngs::OsRng};
        let mut bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|err| format!("run_instance_id: OS randomness unavailable: {err}"))?;
        let mut hex = String::with_capacity(32);
        for b in bytes {
            let _ = write!(hex, "{b:02x}");
        }
        Ok(Self(hex))
    }

    /// The hex identifier, as recorded verbatim into evidence artifacts.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The lock file path inside a report directory's `state/` dir.
fn lock_path(report_dir: &Path) -> PathBuf {
    report_dir.join("state").join(".orchestrator.lock")
}

/// Read this run's `run_instance_id` back from the report directory's lease
/// stamp — the single canonical on-disk source, written once at lease
/// acquisition (before any stage runs) by [`acquire_report_dir_lease`].
///
/// This is the seam by which a T5 control's `execute` (which only sees
/// `&mut OrchestrationContext`, and through it `report_dir`) stamps its
/// `scenario.v1` `run_identity`, while the finalizer binds the pass certificate
/// to the same id it minted from the lease. Both sides therefore derive the
/// generation binding from ONE source and cannot drift.
///
/// Fails CLOSED: a missing, empty, or malformed stamp is an error, never a
/// silent empty id — an empty `run_identity` would neuter the verifier's
/// generation-binding gate (§10.1 fail-closed).
pub fn read_leased_run_instance_id(report_dir: &Path) -> Result<String, String> {
    let path = lock_path(report_dir);
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("read report-dir lease stamp {}: {e}", path.display()))?;
    parse_run_instance_id_stamp(&body).ok_or_else(|| {
        format!(
            "report-dir lease stamp {} has no valid run_instance_id (content: {:?})",
            path.display(),
            body.trim()
        )
    })
}

/// Extract the `run_instance_id=<hex>` value from a lease stamp
/// (`pid=<pid> run_instance_id=<hex>\n`). Returns `None` if the token is absent
/// or its value is not the exact 32-char lowercase hex a mint produces, so a
/// corrupt or truncated stamp is rejected rather than propagated as a bogus id.
fn parse_run_instance_id_stamp(body: &str) -> Option<String> {
    for token in body.split_whitespace() {
        if let Some(id) = token.strip_prefix("run_instance_id=") {
            let valid = id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
            return valid.then(|| id.to_owned());
        }
    }
    None
}

// ── Unix: real advisory-flock lease ──────────────────────────────────────────

/// Exclusive, process-lifetime lease on one report directory. Dropping it (or
/// the process dying) releases the advisory lock.
#[cfg(unix)]
pub struct ReportDirLease {
    // Held for the lease's lifetime; the kernel releases the advisory lock when
    // this descriptor closes. Never read directly — its existence IS the lease.
    _flock: nix::fcntl::Flock<std::fs::File>,
    lock_path: PathBuf,
    run_instance_id: RunInstanceId,
}

#[cfg(unix)]
impl ReportDirLease {
    /// This run's minted identity. Every artifact of the invocation binds to it.
    pub fn run_instance_id(&self) -> &RunInstanceId {
        &self.run_instance_id
    }

    /// The lock file backing this lease.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

/// Acquire the exclusive lease on `report_dir` and mint this run's id.
///
/// Fails CLOSED: if a *live* holder already owns the lease (two orchestrator
/// runs pointed at the same report directory — an operator error, not transient
/// contention), this returns an error naming the holder rather than racing the
/// recorder. A dead holder's advisory lock is already released by the kernel,
/// so acquisition only rejects genuine live overlap. The id is minted only
/// after the lock is confirmed held.
#[cfg(unix)]
pub fn acquire_report_dir_lease(report_dir: &Path) -> Result<ReportDirLease, String> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let lock_path = lock_path(report_dir);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create lease dir {}: {e}", parent.display()))?;
    }

    // create(true), not create_new: a lock file may legitimately survive a
    // crash; mutual exclusion is the advisory flock below, not the file's
    // existence. read(true) so a contender can read the holder stamp.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| format!("open report-dir lease {}: {e}", lock_path.display()))?;

    let mut flock = match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
    {
        Ok(flock) => flock,
        Err((mut held, _errno)) => {
            // A live holder owns the lease. Read its stamp (best effort) so
            // the operator sees which run to stop.
            let mut existing = String::new();
            let _ = held.read_to_string(&mut existing);
            let holder = existing.trim();
            let detail = if holder.is_empty() {
                "another orchestrator run holds it".to_owned()
            } else {
                format!("held by {holder}")
            };
            return Err(format!(
                "report dir {} is already leased by a running orchestrator ({detail}); \
                     use a fresh report dir or the matching resume path — \
                     refusing to race the stages.tsv recorder",
                report_dir.display()
            ));
        }
    };

    // Lock held. Mint the id, then stamp pid + id so a later contender's error
    // names this run. Truncate any stale crashed-holder content first.
    let run_instance_id = RunInstanceId::generate()?;
    let stamp = format!(
        "pid={} run_instance_id={}\n",
        std::process::id(),
        run_instance_id.as_str()
    );
    flock
        .set_len(0)
        .and_then(|()| flock.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| flock.write_all(stamp.as_bytes()))
        .and_then(|()| flock.flush())
        .map_err(|e| format!("stamp report-dir lease {}: {e}", lock_path.display()))?;

    Ok(ReportDirLease {
        _flock: flock,
        lock_path,
        run_instance_id,
    })
}

// ── Non-unix: fail closed (the orchestrator host is always unix) ──────────────

#[cfg(not(unix))]
pub struct ReportDirLease {
    run_instance_id: RunInstanceId,
}

#[cfg(not(unix))]
impl ReportDirLease {
    pub fn run_instance_id(&self) -> &RunInstanceId {
        &self.run_instance_id
    }
}

#[cfg(not(unix))]
pub fn acquire_report_dir_lease(_report_dir: &Path) -> Result<ReportDirLease, String> {
    Err("report-dir lease requires a unix host (advisory flock); \
         the live-lab orchestrator does not run on this platform"
        .to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tmp_report_dir(tag: &str) -> PathBuf {
        // Process- and tag-scoped so parallel test processes never collide
        // (nextest runs a process per test).
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "rustynet-run-instance-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).expect("create report dir");
        dir
    }

    #[test]
    fn id_is_128_bit_lowercase_hex_and_unique() {
        let a = RunInstanceId::generate().expect("id a");
        let b = RunInstanceId::generate().expect("id b");
        assert_eq!(a.as_str().len(), 32, "128 bits = 32 hex chars");
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            a.as_str().chars().all(|c| !c.is_ascii_uppercase()),
            "lowercase hex only"
        );
        assert_ne!(a, b, "two mints must differ (CSPRNG)");
    }

    #[test]
    fn second_acquire_is_refused_while_the_first_is_held() {
        let dir = tmp_report_dir("exclusion");
        let first = acquire_report_dir_lease(&dir).expect("first lease");
        // `let Err(..) else` rather than `unwrap_err()`: the Ok type wraps a
        // `nix::Flock` that is not `Debug`.
        let Err(msg) = acquire_report_dir_lease(&dir) else {
            panic!(
                "a second run on the same report dir must be refused while the first holds the lease"
            );
        };
        assert!(
            msg.contains("already leased") && msg.contains(first.run_instance_id().as_str()),
            "the refusal must name the live holder's run_instance_id; got: {msg}"
        );
        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leased_id_reads_back_from_the_stamp_matching_the_holder() {
        // The reader the T5 control uses must return exactly the id the lease
        // minted, so a control's scenario.v1 run_identity binds to the same
        // generation the finalizer certifies.
        let dir = tmp_report_dir("readback");
        let lease = acquire_report_dir_lease(&dir).expect("lease");
        let read = read_leased_run_instance_id(&dir).expect("read stamp");
        assert_eq!(
            read,
            lease.run_instance_id().as_str(),
            "reader must return the leased id verbatim"
        );
        assert_eq!(read.len(), 32);
        drop(lease);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reading_the_id_fails_closed_when_no_lease_exists() {
        // No lease acquired ⇒ no stamp file ⇒ error, never a silent empty id.
        let dir = tmp_report_dir("no-lease");
        let err = read_leased_run_instance_id(&dir).expect_err("must fail closed");
        assert!(
            err.contains("lease stamp"),
            "error must name the missing stamp; got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamp_parser_rejects_malformed_values() {
        // Absent token, wrong length, and uppercase hex are all rejected; only a
        // well-formed 32-char lowercase hex value parses.
        assert!(parse_run_instance_id_stamp("pid=17\n").is_none());
        assert!(parse_run_instance_id_stamp("pid=17 run_instance_id=\n").is_none());
        assert!(parse_run_instance_id_stamp("run_instance_id=deadbeef").is_none());
        assert!(
            parse_run_instance_id_stamp(&format!("run_instance_id={}", "A".repeat(32))).is_none(),
            "uppercase hex is not a mint output"
        );
        let good = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_run_instance_id_stamp(&format!("pid=9 run_instance_id={good}\n")).as_deref(),
            Some(good)
        );
    }

    #[test]
    fn lease_is_reacquirable_after_the_holder_is_dropped() {
        // Dropping the guard (or the process dying) releases the advisory lock,
        // so a fresh run reclaims the report dir — a crashed run never wedges it.
        let dir = tmp_report_dir("reclaim");
        let first_id = {
            let lease = acquire_report_dir_lease(&dir).expect("first lease");
            lease.run_instance_id().clone()
        }; // dropped here
        let second = acquire_report_dir_lease(&dir).expect("lease reclaimed after drop");
        assert_ne!(
            second.run_instance_id(),
            &first_id,
            "the reclaiming run mints its own distinct id"
        );
        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
