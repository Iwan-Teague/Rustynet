//! D12.e — Tamper-evident audit log for node-role transitions.
//!
//! Canonical taxonomy:
//! `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md` §10
//! (Security controls — "Tamper-evident transition audit").
//!
//! Every role transition (success, blocked, irreversible-needs-ack,
//! staged) emits an append-only log entry with the same hash-chain
//! shape as the membership audit log
//! (`crate::membership::verify_membership_log_chain`):
//!
//! ```text
//! index=<N>
//! previous_hash=<sha256(previous entry) or "genesis">
//! entry_hash=sha256(index|previous_hash|canonical_payload_hex)
//! event_hex=<lowercase hex of the canonicalised event payload>
//! ```
//!
//! Tampering with any field — including the event payload — breaks
//! the chain on the next `verify_role_audit_chain` call. Replays,
//! reorders, and inserts also fail the verifier because each entry
//! binds to the previous one.
//!
//! The canonical event payload is a deterministic UTF-8 string of
//! sorted `key=value\n` lines (mirrors the membership canonical
//! payload pattern). All payload tokens are restricted to ASCII
//! printable so the log itself remains operator-readable + can be
//! consumed by simple grep / awk pipelines on remote hosts.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::role_presets::{Capability, RolePreset};

/// What happened. Used as the audit-log `outcome=` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleTransitionOutcome {
    /// Transition completed successfully end-to-end.
    Succeeded,
    /// Transition refused by the validator / planner (e.g.
    /// `blind_exit` is immutable; capability schema not yet
    /// available; staged transition required).
    Blocked,
    /// Transition attempted but a side-effect failed (e.g. IPC
    /// returned an error, env-file write failed). Operator-visible
    /// fail-closed event.
    Failed,
}

impl RoleTransitionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            RoleTransitionOutcome::Succeeded => "succeeded",
            RoleTransitionOutcome::Blocked => "blocked",
            RoleTransitionOutcome::Failed => "failed",
        }
    }
}

impl fmt::Display for RoleTransitionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of role-related event happened. We log normal preset
/// transitions and capability mutations through the same chain so
/// auditors get one ordered history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleTransitionEvent {
    /// Preset transition: from → to. `error_category` is the
    /// short tag returned by `RoleCliError` (e.g.
    /// `blind_exit_immutable`, `blocked_by_capability_schema`) when
    /// outcome is Blocked or Failed.
    PresetTransition {
        from: RolePreset,
        to: RolePreset,
        outcome: RoleTransitionOutcome,
        error_category: Option<&'static str>,
    },
    /// Capability mutation: add or remove a single flag. Today
    /// (pre-D11.a) these always log as Blocked with
    /// `blocked_by_capability_schema`; once D11.a lands the path
    /// reuses the same chain.
    CapabilityMutation {
        capability: Capability,
        mutation: CapabilityMutationKind,
        outcome: RoleTransitionOutcome,
        error_category: Option<&'static str>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityMutationKind {
    Add,
    Remove,
}

impl CapabilityMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityMutationKind::Add => "add",
            CapabilityMutationKind::Remove => "remove",
        }
    }
}

impl RoleTransitionEvent {
    /// Deterministic canonical payload string for this event.
    /// Sorted `key=value\n` lines so equality is structural, not
    /// field-order-dependent.
    pub fn canonical_payload(&self, timestamp_unix: u64) -> String {
        let mut kvs: BTreeMap<&'static str, String> = BTreeMap::new();
        kvs.insert("timestamp_unix", timestamp_unix.to_string());
        match self {
            RoleTransitionEvent::PresetTransition {
                from,
                to,
                outcome,
                error_category,
            } => {
                kvs.insert("event_kind", "preset_transition".to_owned());
                kvs.insert("from", from.as_str().to_owned());
                kvs.insert("to", to.as_str().to_owned());
                kvs.insert("outcome", outcome.as_str().to_owned());
                kvs.insert(
                    "error_category",
                    error_category.unwrap_or("none").to_owned(),
                );
            }
            RoleTransitionEvent::CapabilityMutation {
                capability,
                mutation,
                outcome,
                error_category,
            } => {
                kvs.insert("event_kind", "capability_mutation".to_owned());
                kvs.insert("capability", capability.as_str().to_owned());
                kvs.insert("mutation", mutation.as_str().to_owned());
                kvs.insert("outcome", outcome.as_str().to_owned());
                kvs.insert(
                    "error_category",
                    error_category.unwrap_or("none").to_owned(),
                );
            }
        }
        let mut out = String::new();
        for (key, value) in kvs {
            // Reject newlines + control chars defensively. None of
            // the static `as_str()` values contain them; this is
            // belt-and-braces against future variant additions.
            debug_assert!(
                !value.chars().any(|c| c == '\n' || c.is_control()),
                "audit value must not contain control chars: {key}={value:?}"
            );
            out.push_str(&format!("{key}={value}\n"));
        }
        out
    }
}

/// One entry in the audit log. `entry_hash` binds to the previous
/// entry via `previous_hash`; tampering with any field — including
/// `event_canonical_payload` — invalidates the chain from this
/// position forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuditEntry {
    pub index: u64,
    pub previous_hash: String,
    pub entry_hash: String,
    /// Lowercase hex of the canonical event payload bytes. Storing
    /// hex (not raw UTF-8) keeps the log line strictly ASCII and
    /// avoids quoting/escape ambiguity.
    pub event_hex: String,
}

/// Hash placeholder used in the `previous_hash` field of the very
/// first entry. The membership log uses the same convention.
pub const GENESIS_PREVIOUS_HASH: &str = "genesis";

/// Maximum allowed size for a role audit log file (8 MiB). Prevents
/// memory exhaustion from adversarially grown audit files.
pub const MAX_ROLE_AUDIT_LOG_BYTES: usize = 8 * 1024 * 1024;

/// Lowercase hex alphabet for the nibble-lookup encoder.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(hasher.finalize().as_slice())
}

/// Encode bytes as lowercase hex via a nibble lookup (no per-byte
/// `format!` allocation). Byte-identical to the previous formatter;
/// the hash-chain determinism tests pin it.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        // Each nibble is a 4-bit value and HEX_LOWER has exactly 16 entries,
        // so `get` always yields the digit and the fallback is unreachable;
        // the output is byte-identical to the previous indexed form.
        let hi = HEX_LOWER.get((byte >> 4) as usize).copied().unwrap_or(b'0');
        let lo = HEX_LOWER
            .get((byte & 0x0f) as usize)
            .copied()
            .unwrap_or(b'0');
        out.push(hi as char);
        out.push(lo as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, RoleAuditError> {
    if !s.len().is_multiple_of(2) {
        return Err(RoleAuditError::Malformed(format!(
            "hex string length is odd: {} chars",
            s.len()
        )));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| RoleAuditError::Malformed("hex chunk is not utf-8".to_owned()))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| RoleAuditError::Malformed(format!("invalid hex pair {pair:?}")))?;
        out.push(byte);
    }
    Ok(out)
}

/// Compute the bound entry hash for `(index, previous_hash, payload)`.
/// Pure function; same shape as `verify_membership_log_chain`.
pub fn compute_entry_hash(index: u64, previous_hash: &str, event_payload: &str) -> String {
    let event_hex = hex_encode(event_payload.as_bytes());
    sha256_hex(format!("{index}|{previous_hash}|{event_hex}").as_bytes())
}

/// Append a single event to the audit log at `path`.
///
/// RSA-0012: the previous shape read the chain by path and then
/// re-opened the file to append, so two concurrent writers could both
/// observe the same last entry, both compute the same next index, and
/// both append (CWE-362 / duplicated or broken chain). This append now
/// opens the file ONCE and holds an exclusive advisory lock across the
/// whole read-modify-append, reading the prior chain back through the
/// SAME locked descriptor. Contention is bounded (see
/// [`APPEND_LOCK_MAX_WAIT`]); on timeout the write is REFUSED with
/// [`RoleAuditError::Locked`] — fail closed, never written unlocked.
///
/// Non-unix (e.g. Windows) uses a create-new `<log>.lock` sidecar
/// instead of `flock`. A crash while holding it leaves the sidecar on
/// disk, so appends keep failing closed with [`RoleAuditError::Locked`]
/// (permanent denial): recovery is for an operator to delete the
/// sidecar file — only when no rustynet process is running — and retry.
pub fn append_role_audit_entry(
    path: &Path,
    timestamp_unix: u64,
    event: &RoleTransitionEvent,
) -> Result<RoleAuditEntry, RoleAuditError> {
    #[cfg(unix)]
    {
        append_role_audit_entry_inner(path, timestamp_unix, event, |file| {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o640))
        })
    }
    #[cfg(not(unix))]
    {
        // No POSIX mode to pin on non-unix platforms (RSA-0013 is a
        // unix-mode concern); the injected step is a no-op that can
        // never fail there.
        append_role_audit_entry_inner(path, timestamp_unix, event, |_| Ok(()))
    }
}

/// RSA-0013: the permission-pinning step is injected as a closure so
/// tests can exercise the chmod-failure path portably (a real
/// `set_permissions` failure needs e.g. a non-owned or immutable file,
/// which cannot be reproduced reliably in a unit test). The production
/// step is the real `set_permissions(0o640)` in
/// [`append_role_audit_entry`].
fn append_role_audit_entry_inner<F>(
    path: &Path,
    timestamp_unix: u64,
    event: &RoleTransitionEvent,
    pin_new_log_mode: F,
) -> Result<RoleAuditEntry, RoleAuditError>
where
    F: FnOnce(&mut fs::File) -> std::io::Result<()>,
{
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| RoleAuditError::Io(format!("create_dir_all: {err}")))?;
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|err| RoleAuditError::Io(format!("open append: {err}")))?;
    let mut lock = acquire_role_audit_append_lock(path, file)?;

    // Read the existing chain back through the SAME locked descriptor
    // (no path re-open) so no writer can interleave between our read
    // and our append.
    let existing = read_capped_role_audit_body(lock.file_mut())?;
    let entries = parse_role_audit_body(&existing)?;
    let (next_index, previous_hash) = match entries.last() {
        Some(last) => (last.index + 1, last.entry_hash.clone()),
        None => (0_u64, GENESIS_PREVIOUS_HASH.to_owned()),
    };

    let payload = event.canonical_payload(timestamp_unix);
    let entry_hash = compute_entry_hash(next_index, &previous_hash, &payload);
    let event_hex = hex_encode(payload.as_bytes());
    let line = format!(
        "index={next_index} previous_hash={previous_hash} entry_hash={entry_hash} event_hex={event_hex}\n"
    );

    // Pin restrictive perms when the file is newly created. We
    // don't downgrade existing perms (operator might have widened
    // intentionally) but we tighten on create.
    //
    // RSA-0013: the pin previously discarded its `set_permissions`
    // result (`let _ = ...`), so a failed chmod left the fresh log
    // with a umask-derived (possibly group/world-readable) mode and
    // the entry was written anyway (CWE-732). Now the failure is
    // propagated BEFORE the write: the append is refused with
    // [`RoleAuditError::Io`] and nothing is removed — the still-empty
    // file stays on disk (no data was written; unlinking by path
    // under a held lock invites TOCTOU and an operator-visible empty
    // log is the honest failure state).
    if existing.is_empty() {
        pin_new_log_mode(lock.file_mut()).map_err(|err| {
            RoleAuditError::Io(format!(
                "pin newly created role audit log to 0o640; refusing to write: {err}"
            ))
        })?;
    }

    lock.file_mut()
        .write_all(line.as_bytes())
        .map_err(|err| RoleAuditError::Io(format!("write: {err}")))?;
    lock.file_mut()
        .flush()
        .map_err(|err| RoleAuditError::Io(format!("flush: {err}")))?;
    Ok(RoleAuditEntry {
        index: next_index,
        previous_hash,
        entry_hash,
        event_hex,
    })
}

/// Contention bound for the role audit append lock. Mirrors the
/// enrollment ledger lock posture in
/// `rustynetd/src/enrollment_token.rs`: bounded retry, then fail
/// closed with [`RoleAuditError::Locked`] rather than writing unlocked.
const APPEND_LOCK_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(3);
const APPEND_LOCK_WAIT_MS: u64 = 10;

/// Sidecar lock path for the non-unix append lock. Only used on
/// platforms without `flock(2)`; unix builds never touch it.
#[cfg(not(unix))]
fn append_lock_path(path: &Path) -> std::path::PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(".lock");
    std::path::PathBuf::from(raw)
}

/// Guard holding the exclusive append lock for the audit log.
///
/// Unix: an `flock(LOCK_EX)`-held descriptor (nix `Flock`; unlocking
/// happens on drop). Non-unix (e.g. Windows): a create-new sidecar
/// `.lock` file removed on drop.
///
/// Non-unix stale sidecar: a crash while holding the lock leaves
/// `<log>.lock` behind (it is NOT auto-recovered); appends then fail
/// closed until an operator deletes the sidecar file when no rustynet
/// process is running, then retries.
struct RoleAuditAppendLock {
    #[cfg(unix)]
    flock: nix::fcntl::Flock<fs::File>,
    #[cfg(not(unix))]
    data: fs::File,
    #[cfg(not(unix))]
    lock_path: std::path::PathBuf,
    #[cfg(not(unix))]
    _lock_handle: Option<fs::File>,
}

impl RoleAuditAppendLock {
    #[cfg(unix)]
    fn file_mut(&mut self) -> &mut fs::File {
        // Deref coercion through Flock<T>: hand out the locked descriptor.
        &mut self.flock
    }

    #[cfg(not(unix))]
    fn file_mut(&mut self) -> &mut fs::File {
        &mut self.data
    }
}

#[cfg(not(unix))]
impl Drop for RoleAuditAppendLock {
    fn drop(&mut self) {
        // Release the lock handle (close the descriptor) BEFORE
        // removing the sidecar: on Windows, unlinking while the handle
        // is still open leaves the name delete-pending, which turns an
        // ordinary contention window into a spurious access-denied for
        // the next `create_new` (mirrors resilience.rs / enrollment_token.rs).
        drop(self._lock_handle.take());
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(unix)]
fn acquire_role_audit_append_lock(
    _path: &Path,
    file: fs::File,
) -> Result<RoleAuditAppendLock, RoleAuditError> {
    let deadline = std::time::Instant::now() + APPEND_LOCK_MAX_WAIT;
    let mut file = file;
    loop {
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(flock) => return Ok(RoleAuditAppendLock { flock }),
            // Flock::lock hands the file back on failure, so the
            // descriptor is never dropped mid-retry.
            Err((retry_file, errno)) => {
                file = retry_file;
                match errno {
                    // Only these mean "held elsewhere" (contention):
                    // EWOULDBLOCK/EAGAIN on a non-blocking flock, EINTR
                    // if a signal interrupted the call. Anything else
                    // (ENOLCK, EINVAL/EOPNOTSUPP, EBADF, ...) is not
                    // contention — report the errno immediately instead
                    // of sleeping and reporting a misleading `Locked`.
                    nix::errno::Errno::EWOULDBLOCK | nix::errno::Errno::EINTR => {
                        if std::time::Instant::now() >= deadline {
                            return Err(RoleAuditError::Locked(
                                "role audit log is locked by another writer (contention timeout)"
                                    .to_owned(),
                            ));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(APPEND_LOCK_WAIT_MS));
                    }
                    other => {
                        return Err(RoleAuditError::Io(format!("flock role audit log: {other}")));
                    }
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn acquire_role_audit_append_lock(
    path: &Path,
    data: fs::File,
) -> Result<RoleAuditAppendLock, RoleAuditError> {
    let lock_path = append_lock_path(path);
    let deadline = std::time::Instant::now() + APPEND_LOCK_MAX_WAIT;
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut lock_handle) => {
                // Stamp owner + age into the sidecar so a stale lock
                // left by a crashed writer is diagnosable (mirrors
                // resilience.rs / enrollment_token.rs).
                let stamp = format!(
                    "pid={} ts={}\n",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|age| age.as_secs())
                        .unwrap_or(0),
                );
                lock_handle.write_all(stamp.as_bytes()).map_err(|err| {
                    RoleAuditError::Io(format!(
                        "stamp role audit lock {}: {err}",
                        lock_path.display()
                    ))
                })?;
                return Ok(RoleAuditAppendLock {
                    data,
                    lock_path,
                    _lock_handle: Some(lock_handle),
                });
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::AlreadyExists
                    || err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                // PermissionDenied is contention here, exactly like
                // AlreadyExists: the releasing guard unlinks the sidecar
                // while its own handle is still open, and on Windows that
                // leaves the name delete-pending so a concurrent
                // `create_new` gets ERROR_ACCESS_DENIED (mirrors
                // resilience.rs / enrollment_token.rs).
                if std::time::Instant::now() >= deadline {
                    return Err(match err.kind() {
                        std::io::ErrorKind::PermissionDenied => RoleAuditError::Io(format!(
                            "create role audit lock {} (delete-pending contention): {err}",
                            lock_path.display()
                        )),
                        _ => RoleAuditError::Locked(format!(
                            "role audit lock {} held (timeout); if no rustynet process is \
                             running, delete that file and retry",
                            lock_path.display()
                        )),
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(APPEND_LOCK_WAIT_MS));
            }
            Err(err) => {
                return Err(RoleAuditError::Io(format!(
                    "create role audit lock {}: {err}",
                    lock_path.display()
                )));
            }
        }
    }
}

/// Read all entries from the log at `path`. Returns an empty vec if
/// the file doesn't exist (genesis case). Fails closed if the file
/// exceeds [`MAX_ROLE_AUDIT_LOG_BYTES`] to prevent memory exhaustion
/// from adversarially grown audit files.
pub fn read_role_audit_log(path: &Path) -> Result<Vec<RoleAuditEntry>, RoleAuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata =
        fs::metadata(path).map_err(|err| RoleAuditError::Io(format!("metadata: {err}")))?;
    if metadata.len() > MAX_ROLE_AUDIT_LOG_BYTES as u64 {
        return Err(RoleAuditError::Io(format!(
            "role audit log exceeds {} byte cap (got {} bytes); refusing to read",
            MAX_ROLE_AUDIT_LOG_BYTES,
            metadata.len()
        )));
    }
    let mut file =
        fs::File::open(path).map_err(|err| RoleAuditError::Io(format!("open: {err}")))?;
    let body = read_capped_role_audit_body(&mut file)?;
    parse_role_audit_body(&body)
}

/// Capped read of the whole log from an already-open descriptor.
/// Split out of [`read_role_audit_log`] so [`append_role_audit_entry`]
/// can read the prior chain back through the SAME locked descriptor
/// (RSA-0012) without re-opening by path.
///
/// Reads at most cap+1 bytes so a file grown between the metadata
/// check and this read cannot bypass the cap via TOCTOU. Reading
/// cap+1 lets us distinguish exactly-at-cap (accepted) from
/// over-cap (refused) without a second stat.
fn read_capped_role_audit_body(file: &mut fs::File) -> Result<String, RoleAuditError> {
    let mut capped = vec![0u8; MAX_ROLE_AUDIT_LOG_BYTES + 1];
    let mut filled = 0usize;
    loop {
        // `filled` never exceeds `capped.len()` (the `filled == capped.len()`
        // check below stops the loop), so the range is always valid and the
        // `else` arm is unreachable.
        let Some(unfilled) = capped.get_mut(filled..) else {
            break;
        };
        let read = file
            .read(unfilled)
            .map_err(|err| RoleAuditError::Io(format!("read: {err}")))?;
        if read == 0 {
            break;
        }
        filled += read;
        if filled == capped.len() {
            break;
        }
    }
    capped.truncate(filled);
    if capped.len() > MAX_ROLE_AUDIT_LOG_BYTES {
        return Err(RoleAuditError::Io(format!(
            "role audit log exceeds {MAX_ROLE_AUDIT_LOG_BYTES} byte cap; refusing to parse"
        )));
    }
    String::from_utf8(capped)
        .map_err(|_| RoleAuditError::Io("utf8: invalid encoding in role audit log".to_string()))
}

/// Parse the capped log body into entries. Split out of
/// [`read_role_audit_log`] for the same reason as
/// [`read_capped_role_audit_body`].
fn parse_role_audit_body(body: &str) -> Result<Vec<RoleAuditEntry>, RoleAuditError> {
    let mut out = Vec::new();
    for (line_no, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for token in line.split_whitespace() {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                RoleAuditError::Malformed(format!(
                    "line {}: token {token:?} missing '='",
                    line_no + 1
                ))
            })?;
            // Fail closed on non-canonical lines: the entry hash covers
            // only the four canonical fields, so an UNKNOWN field would
            // be invisible tampering (attacker appends `note=pwned` and
            // the chain still verifies), and a DUPLICATE key would let
            // a later value silently overwrite the signed one
            // (`index=1 index=2`). Reject both shapes outright.
            if !matches!(key, "index" | "previous_hash" | "entry_hash" | "event_hex") {
                return Err(RoleAuditError::Malformed(format!(
                    "line {}: unknown field {key:?}",
                    line_no + 1
                )));
            }
            if fields.insert(key, value).is_some() {
                return Err(RoleAuditError::Malformed(format!(
                    "line {}: duplicate field {key:?}",
                    line_no + 1
                )));
            }
        }
        let index: u64 = fields
            .get("index")
            .ok_or_else(|| {
                RoleAuditError::Malformed(format!("line {}: missing index", line_no + 1))
            })?
            .parse()
            .map_err(|err| {
                RoleAuditError::Malformed(format!("line {}: index parse: {err}", line_no + 1))
            })?;
        let previous_hash = fields
            .get("previous_hash")
            .ok_or_else(|| {
                RoleAuditError::Malformed(format!("line {}: missing previous_hash", line_no + 1))
            })?
            .to_string();
        let entry_hash = fields
            .get("entry_hash")
            .ok_or_else(|| {
                RoleAuditError::Malformed(format!("line {}: missing entry_hash", line_no + 1))
            })?
            .to_string();
        let event_hex = fields
            .get("event_hex")
            .ok_or_else(|| {
                RoleAuditError::Malformed(format!("line {}: missing event_hex", line_no + 1))
            })?
            .to_string();
        out.push(RoleAuditEntry {
            index,
            previous_hash,
            entry_hash,
            event_hex,
        });
    }
    Ok(out)
}

/// Verify the hash chain from genesis. Returns `Ok(())` if every
/// entry binds to its predecessor and its own `entry_hash` matches
/// the recomputed value. Returns the first detected break.
pub fn verify_role_audit_chain(entries: &[RoleAuditEntry]) -> Result<(), RoleAuditError> {
    for (position, entry) in entries.iter().enumerate() {
        if entry.index != position as u64 {
            return Err(RoleAuditError::ChainBroken(format!(
                "entry at position {position} has index={} (expected {position})",
                entry.index
            )));
        }
        // position comes from enumerate(), so `position - 1` is always a
        // valid index into `entries`; the fallback is unreachable.
        let expected_previous = if position == 0 {
            GENESIS_PREVIOUS_HASH.to_owned()
        } else {
            entries
                .get(position - 1)
                .map(|previous| previous.entry_hash.clone())
                .unwrap_or_default()
        };
        if entry.previous_hash != expected_previous {
            return Err(RoleAuditError::ChainBroken(format!(
                "entry index={}: previous_hash mismatch (expected {expected_previous}, got {})",
                entry.index, entry.previous_hash
            )));
        }
        let payload_bytes = hex_decode(&entry.event_hex)?;
        let payload = std::str::from_utf8(&payload_bytes).map_err(|err| {
            RoleAuditError::Malformed(format!(
                "entry index={}: event payload is not UTF-8: {err}",
                entry.index
            ))
        })?;
        let recomputed = compute_entry_hash(entry.index, &entry.previous_hash, payload);
        if recomputed != entry.entry_hash {
            return Err(RoleAuditError::ChainBroken(format!(
                "entry index={}: entry_hash mismatch (expected {recomputed}, got {})",
                entry.index, entry.entry_hash
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum RoleAuditError {
    Io(String),
    Malformed(String),
    ChainBroken(String),
    /// RSA-0012: the append lock was contended beyond the bounded wait;
    /// the write was refused (fail-closed) rather than performed unlocked.
    Locked(String),
}

impl fmt::Display for RoleAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleAuditError::Io(msg) => write!(f, "audit log io error: {msg}"),
            RoleAuditError::Malformed(msg) => write!(f, "audit log malformed: {msg}"),
            RoleAuditError::ChainBroken(msg) => write!(f, "audit log chain broken: {msg}"),
            RoleAuditError::Locked(msg) => write!(f, "audit log locked: {msg}"),
        }
    }
}

impl std::error::Error for RoleAuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        dir.join(format!("rustynet-role-audit-{label}-{pid}-{nanos}.log"))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
    }

    fn preset_event() -> RoleTransitionEvent {
        RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        }
    }

    // RSA-0012 witness: with another live descriptor holding the exclusive
    // advisory lock on the log, append must FAIL CLOSED (refuse) rather
    // than write unlocked and race the other writer's read-modify-append.
    #[test]
    fn append_refuses_while_log_is_locked_elsewhere() {
        let path = tmp_path("locked_append");
        let event = preset_event();
        append_role_audit_entry(&path, 1_700_000_000, &event)
            .unwrap_or_else(|err| panic!("baseline unlocked append must succeed: {err}"));
        #[cfg(unix)]
        {
            let held = fs::OpenOptions::new()
                .read(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("open for external lock: {err}"));
            let guard = nix::fcntl::Flock::lock(held, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .unwrap_or_else(|(_, errno)| panic!("acquire external lock: {errno}"));
            let result = append_role_audit_entry(&path, 1_700_000_001, &event);
            assert!(
                result.is_err(),
                "append must refuse while another descriptor locks the log, got {result:?}"
            );
            if let Err(err) = result {
                assert!(
                    matches!(err, RoleAuditError::Locked(_)),
                    "expected RoleAuditError::Locked, got {err:?}"
                );
            }
            drop(guard);
        }
        cleanup(&path);
    }

    // RSA-0012 supporting test: with the append lock held across each
    // read-modify-append, N concurrent writers must serialise into one
    // contiguous, verifiable chain with no lost or duplicated entries.
    #[test]
    fn concurrent_appenders_produce_contiguous_chain() {
        let path = tmp_path("concurrent_append");
        let event = preset_event();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for offset in 0..25_u64 {
                        append_role_audit_entry(&path, 1_700_000_000 + offset, &event)
                            .unwrap_or_else(|err| {
                                panic!("contended append must eventually succeed: {err}")
                            });
                    }
                });
            }
        });
        let entries = read_role_audit_log(&path)
            .unwrap_or_else(|err| panic!("read after concurrent appends: {err}"));
        assert_eq!(entries.len(), 100, "every append must land exactly once");
        verify_role_audit_chain(&entries)
            .unwrap_or_else(|err| panic!("chain must stay contiguous: {err}"));
        cleanup(&path);
    }

    // RSA-0012 witness (non-unix): a pre-existing sidecar `.lock`
    // (e.g. left behind by a crashed writer) must make the append fail
    // CLOSED with `Locked`, and removing the sidecar must let the next
    // append succeed with a verifiable chain.
    #[cfg(not(unix))]
    #[test]
    fn stale_sidecar_lock_refuses_then_recovers_once_removed() {
        let path = tmp_path("stale_sidecar_lock");
        let event = preset_event();
        let lock_path = append_lock_path(&path);
        fs::write(&lock_path, b"pid=0 ts=0\n")
            .unwrap_or_else(|err| panic!("create stale sidecar: {err}"));
        let refused = append_role_audit_entry(&path, 1_700_000_000, &event);
        assert!(
            matches!(&refused, Err(RoleAuditError::Locked(_))),
            "pre-existing sidecar must refuse with Locked, got {refused:?}"
        );
        fs::remove_file(&lock_path).unwrap_or_else(|err| panic!("remove stale sidecar: {err}"));
        append_role_audit_entry(&path, 1_700_000_001, &event)
            .unwrap_or_else(|err| panic!("append after sidecar removal must succeed: {err}"));
        let entries =
            read_role_audit_log(&path).unwrap_or_else(|err| panic!("read after recovery: {err}"));
        assert_eq!(entries.len(), 1, "exactly the recovered append landed");
        verify_role_audit_chain(&entries)
            .unwrap_or_else(|err| panic!("chain must verify after recovery: {err}"));
        cleanup(&path);
    }

    // RSA-0012 supporting witness (unix): a failed append (malformed
    // log body) must RELEASE the append lock — the next append must
    // re-acquire it (re-failing with Malformed on the still-broken
    // body) rather than spin to the 3 s deadline and return Locked.
    #[cfg(unix)]
    #[test]
    fn failed_append_releases_lock() {
        let path = tmp_path("failed_append_releases_lock");
        let event = preset_event();
        fs::write(&path, b"garbage that is not an audit entry\n")
            .unwrap_or_else(|err| panic!("seed malformed log: {err}"));
        let first = append_role_audit_entry(&path, 1_700_000_000, &event);
        assert!(
            matches!(&first, Err(RoleAuditError::Malformed(_))),
            "malformed body must fail the append with Malformed, got {first:?}"
        );
        let second = append_role_audit_entry(&path, 1_700_000_001, &event);
        assert!(
            matches!(&second, Err(RoleAuditError::Malformed(_))),
            "lock must be released after the failed append (second attempt must re-acquire \
             and hit Malformed, not Locked), got {second:?}"
        );
        cleanup(&path);
    }

    #[test]
    fn oversized_audit_log_fails_closed_at_cap() {
        let path = tmp_path("oversized");
        let oversized = vec![b'a'; MAX_ROLE_AUDIT_LOG_BYTES + 1];
        fs::write(&path, &oversized).expect("write oversized log");
        let err = read_role_audit_log(&path).expect_err("over-cap read must fail closed");
        match &err {
            RoleAuditError::Io(msg) => {
                assert!(
                    msg.contains("byte cap"),
                    "expected byte-cap refusal, got: {msg}"
                );
            }
            other => panic!("expected Io error at cap, got: {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn audit_log_at_exact_cap_boundary_is_accepted() {
        // Exactly-at-cap must NOT trigger the byte-cap refusal — it
        // should fall through to the parser (which rejects the single
        // '#' line as Malformed). This distinguishes the cap path from
        // the parser path so a regression that refuses everything
        // cannot hide as "still failing closed".
        let path = tmp_path("exact_cap");
        let exact = vec![b'#'; MAX_ROLE_AUDIT_LOG_BYTES];
        fs::write(&path, &exact).expect("write exact-cap log");
        let err = read_role_audit_log(&path).expect_err("parser must reject '#' line");
        assert!(
            matches!(err, RoleAuditError::Malformed(_)),
            "expected Malformed from parser (cap NOT triggered), got: {err:?}"
        );
        cleanup(&path);
    }

    #[test]
    fn canonical_payload_is_deterministic() {
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let a = event.canonical_payload(1_700_000_000);
        let b = event.canonical_payload(1_700_000_000);
        assert_eq!(a, b);
        // Sorted key order means timestamp_unix < to < ... whatever
        // sort BTreeMap uses (alphabetical). Pin a representative
        // key appears.
        assert!(a.contains("timestamp_unix=1700000000"));
        assert!(a.contains("from=admin"));
        assert!(a.contains("to=exit"));
        assert!(a.contains("outcome=succeeded"));
        assert!(a.contains("event_kind=preset_transition"));
    }

    #[test]
    fn canonical_payload_distinguishes_outcomes() {
        let succeeded = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        }
        .canonical_payload(1);
        let blocked = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Blocked,
            error_category: Some("blocked_by_capability_schema"),
        }
        .canonical_payload(1);
        assert_ne!(succeeded, blocked);
    }

    #[test]
    fn capability_mutation_payload_contains_capability() {
        let event = RoleTransitionEvent::CapabilityMutation {
            capability: Capability::AnchorGossipSeed,
            mutation: CapabilityMutationKind::Add,
            outcome: RoleTransitionOutcome::Blocked,
            error_category: Some("blocked_by_capability_schema"),
        };
        let payload = event.canonical_payload(42);
        assert!(payload.contains("event_kind=capability_mutation"));
        assert!(payload.contains("capability=anchor.gossip_seed"));
        assert!(payload.contains("mutation=add"));
    }

    #[test]
    fn append_creates_genesis_entry() {
        let path = tmp_path("genesis");
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Client,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let entry = append_role_audit_entry(&path, 100, &event).expect("append");
        assert_eq!(entry.index, 0);
        assert_eq!(entry.previous_hash, GENESIS_PREVIOUS_HASH);
        let entries = read_role_audit_log(&path).expect("read");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
        verify_role_audit_chain(&entries).expect("chain valid");
        cleanup(&path);
    }

    #[test]
    fn append_chains_subsequent_entries() {
        let path = tmp_path("chain");
        let event1 = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let event2 = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Exit,
            to: RolePreset::Admin,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let event3 = RoleTransitionEvent::CapabilityMutation {
            capability: Capability::AnchorBundlePull,
            mutation: CapabilityMutationKind::Add,
            outcome: RoleTransitionOutcome::Blocked,
            error_category: Some("blocked_by_capability_schema"),
        };
        let e1 = append_role_audit_entry(&path, 100, &event1).unwrap();
        let e2 = append_role_audit_entry(&path, 200, &event2).unwrap();
        let e3 = append_role_audit_entry(&path, 300, &event3).unwrap();

        assert_eq!(e1.index, 0);
        assert_eq!(e2.index, 1);
        assert_eq!(e3.index, 2);
        assert_eq!(e2.previous_hash, e1.entry_hash);
        assert_eq!(e3.previous_hash, e2.entry_hash);

        let entries = read_role_audit_log(&path).unwrap();
        assert_eq!(entries.len(), 3);
        verify_role_audit_chain(&entries).expect("chain valid");
        cleanup(&path);
    }

    #[test]
    fn tampering_with_entry_hash_breaks_chain() {
        let path = tmp_path("tamper-entry-hash");
        append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        let mut entries = read_role_audit_log(&path).unwrap();
        // Flip a single hex digit.
        let first_char = entries[0].entry_hash[0..1].to_owned();
        let replacement = if first_char == "0" { "1" } else { "0" };
        entries[0].entry_hash.replace_range(0..1, replacement);
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => assert!(msg.contains("entry_hash mismatch")),
            other => panic!("expected ChainBroken, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn tampering_with_payload_breaks_chain() {
        let path = tmp_path("tamper-payload");
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        append_role_audit_entry(&path, 100, &event).unwrap();
        let mut entries = read_role_audit_log(&path).unwrap();
        // Tamper: replace the event payload with an attacker's
        // version (different outcome). The entry_hash no longer
        // matches what the bytes now hash to.
        let attacker_event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Failed,
            error_category: Some("malicious"),
        };
        let attacker_payload = attacker_event.canonical_payload(100);
        entries[0].event_hex = hex_encode(attacker_payload.as_bytes());
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => assert!(msg.contains("entry_hash mismatch")),
            other => panic!("expected ChainBroken, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn tampering_with_previous_hash_breaks_chain_at_second_entry() {
        let path = tmp_path("tamper-prev");
        append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        append_role_audit_entry(
            &path,
            200,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Exit,
                to: RolePreset::Admin,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        let mut entries = read_role_audit_log(&path).unwrap();
        entries[1].previous_hash =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned();
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => assert!(msg.contains("previous_hash mismatch")),
            other => panic!("expected ChainBroken, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn reordering_entries_breaks_chain() {
        let path = tmp_path("reorder");
        append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        append_role_audit_entry(
            &path,
            200,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Exit,
                to: RolePreset::Admin,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        let mut entries = read_role_audit_log(&path).unwrap();
        // Swap entries 0 and 1.
        entries.swap(0, 1);
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(_) => {}
            other => panic!("expected ChainBroken, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn verify_role_audit_chain_rejects_replayed_duplicate_entry() {
        // An attacker replays a genuine record verbatim to fabricate
        // two identical events. The verifier must reject the replay:
        // position 1 demands index 1 bound to entry 0's hash, but the
        // duplicate still claims index 0.
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload = event.canonical_payload(100);
        let genuine = RoleAuditEntry {
            index: 0,
            previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
            entry_hash: compute_entry_hash(0, GENESIS_PREVIOUS_HASH, &payload),
            event_hex: hex_encode(payload.as_bytes()),
        };
        let err = verify_role_audit_chain(&[genuine.clone(), genuine]).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => {
                assert!(msg.contains("position 1"), "unexpected message: {msg}");
                assert!(msg.contains("index=0"), "unexpected message: {msg}");
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn verify_role_audit_chain_rejects_tampered_genesis_binding() {
        // An attacker rewrites the log's root: entry 0 must bind to
        // the fixed genesis hash, but the forged entry claims a
        // different predecessor. The rest of the entry is kept
        // self-consistent (its entry_hash matches its own payload
        // under the forged predecessor) so ONLY the genesis link can
        // trigger the rejection.
        let attacker_previous = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload = event.canonical_payload(100);
        let forged_genesis = RoleAuditEntry {
            index: 0,
            previous_hash: attacker_previous.to_owned(),
            entry_hash: compute_entry_hash(0, attacker_previous, &payload),
            event_hex: hex_encode(payload.as_bytes()),
        };
        let err = verify_role_audit_chain(&[forged_genesis]).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => {
                assert!(
                    msg.contains("previous_hash mismatch"),
                    "unexpected message: {msg}"
                );
                assert!(
                    msg.contains("expected genesis"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn verify_role_audit_chain_rejects_non_monotonic_index_entry() {
        // An attacker deletes a middle record and leaves the later
        // indices untouched: positions 0 and 1 now carry indices 0
        // and 2. The remaining entry is otherwise fully self-consistent
        // (its previous_hash binds to entry 0 and its entry_hash covers
        // its own payload) so ONLY the index monotonicity check can
        // reject the gap.
        let event0 = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let event2 = RoleTransitionEvent::CapabilityMutation {
            capability: Capability::ServesExit,
            mutation: CapabilityMutationKind::Remove,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload0 = event0.canonical_payload(100);
        let genuine = RoleAuditEntry {
            index: 0,
            previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
            entry_hash: compute_entry_hash(0, GENESIS_PREVIOUS_HASH, &payload0),
            event_hex: hex_encode(payload0.as_bytes()),
        };
        let payload2 = event2.canonical_payload(300);
        let gapped = RoleAuditEntry {
            index: 2,
            previous_hash: genuine.entry_hash.clone(),
            entry_hash: compute_entry_hash(2, &genuine.entry_hash, &payload2),
            event_hex: hex_encode(payload2.as_bytes()),
        };
        let err = verify_role_audit_chain(&[genuine, gapped]).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => {
                assert!(
                    msg.contains("entry at position 1 has index=2 (expected 1)"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn verify_role_audit_chain_rejects_second_entry_with_corrupted_stored_hash() {
        // A valid two-entry chain whose second record's stored
        // entry_hash no longer matches what its canonical payload
        // hashes to must be rejected at that record.
        let event0 = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let event1 = RoleTransitionEvent::CapabilityMutation {
            capability: Capability::AnchorGossipSeed,
            mutation: CapabilityMutationKind::Add,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload0 = event0.canonical_payload(100);
        let payload1 = event1.canonical_payload(200);
        let mut entries = vec![
            RoleAuditEntry {
                index: 0,
                previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
                entry_hash: compute_entry_hash(0, GENESIS_PREVIOUS_HASH, &payload0),
                event_hex: hex_encode(payload0.as_bytes()),
            },
            RoleAuditEntry {
                index: 1,
                previous_hash: String::new(),
                entry_hash: String::new(),
                event_hex: hex_encode(payload1.as_bytes()),
            },
        ];
        entries[1].previous_hash = entries[0].entry_hash.clone();
        entries[1].entry_hash = compute_entry_hash(1, &entries[0].entry_hash, &payload1);
        verify_role_audit_chain(&entries).expect("chain valid before corruption");
        // Corrupt the stored hash of the second entry: flip one hex
        // digit so it stays a plausible digest but no longer matches.
        let first_char = entries[1].entry_hash[0..1].to_owned();
        let replacement = if first_char == "0" { "1" } else { "0" };
        entries[1].entry_hash.replace_range(0..1, replacement);
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(msg) => {
                assert!(
                    msg.contains("entry index=1") && msg.contains("entry_hash mismatch"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn inserting_an_entry_breaks_chain() {
        let path = tmp_path("insert");
        append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        append_role_audit_entry(
            &path,
            200,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Exit,
                to: RolePreset::Admin,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        let mut entries = read_role_audit_log(&path).unwrap();
        // Forge an entry with valid index 1 but bogus binding.
        let forged_payload = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::BlindExit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        }
        .canonical_payload(150);
        entries.insert(
            1,
            RoleAuditEntry {
                index: 1,
                previous_hash: entries[0].entry_hash.clone(),
                entry_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    .to_owned(),
                event_hex: hex_encode(forged_payload.as_bytes()),
            },
        );
        // Bump the genuine entry's index.
        entries[2].index = 2;
        let err = verify_role_audit_chain(&entries).unwrap_err();
        match err {
            RoleAuditError::ChainBroken(_) => {}
            other => panic!("expected ChainBroken, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn append_to_existing_log_continues_chain() {
        let path = tmp_path("continue");
        let e1 = append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        // Simulate a second process picking up the log: it reads
        // the existing entries to figure out the next index +
        // previous_hash. The append path does this internally;
        // verify the chain stays intact across the boundary.
        let e2 = append_role_audit_entry(
            &path,
            200,
            &RoleTransitionEvent::CapabilityMutation {
                capability: Capability::ServesExit,
                mutation: CapabilityMutationKind::Remove,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        assert_eq!(e2.index, 1);
        assert_eq!(e2.previous_hash, e1.entry_hash);
        let entries = read_role_audit_log(&path).unwrap();
        verify_role_audit_chain(&entries).expect("chain valid across append");
        cleanup(&path);
    }

    #[test]
    fn empty_log_verifies_as_valid() {
        let path = tmp_path("empty");
        let entries = read_role_audit_log(&path).unwrap();
        assert!(entries.is_empty());
        verify_role_audit_chain(&entries).expect("empty log is valid");
        cleanup(&path);
    }

    #[test]
    fn read_handles_blank_lines() {
        let path = tmp_path("blank-lines");
        append_role_audit_entry(
            &path,
            100,
            &RoleTransitionEvent::PresetTransition {
                from: RolePreset::Admin,
                to: RolePreset::Exit,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
        )
        .unwrap();
        // Inject blank lines.
        let mut body = fs::read_to_string(&path).unwrap();
        body.push('\n');
        body.push('\n');
        fs::write(&path, body).unwrap();
        let entries = read_role_audit_log(&path).unwrap();
        assert_eq!(entries.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn reader_rejects_unknown_and_duplicate_fields_on_valid_lines() {
        // Adversarial finding, hardened: the canonical hash covers only
        // the four known fields, so a reader that IGNORED unknown tokens
        // or let DUPLICATE keys overwrite silently would accept tampered
        // lines the hash cannot see. Both shapes must be rejected.
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload = event.canonical_payload(100);
        let entry_hash = compute_entry_hash(0, GENESIS_PREVIOUS_HASH, &payload);
        let canonical_line = format!(
            "index=0 previous_hash={GENESIS_PREVIOUS_HASH} entry_hash={entry_hash} event_hex={}\n",
            hex_encode(payload.as_bytes())
        );

        // Control: the canonical line parses and verifies.
        let path = tmp_path("canonical-line");
        fs::write(&path, &canonical_line).unwrap();
        let entries = read_role_audit_log(&path).expect("canonical line must parse");
        verify_role_audit_chain(&entries).expect("canonical chain valid");
        cleanup(&path);

        // Unknown extra field: invisible to the hash, so must be refused.
        let junk_line = canonical_line.replace("event_hex=", "note=pwned event_hex=");
        assert_ne!(junk_line, canonical_line);
        let path = tmp_path("junk-field");
        fs::write(&path, &junk_line).unwrap();
        match read_role_audit_log(&path) {
            Err(RoleAuditError::Malformed(msg)) => {
                assert!(msg.contains("unknown field"), "got: {msg}");
            }
            other => panic!("expected Malformed for unknown field, got {other:?}"),
        }
        cleanup(&path);

        // Duplicate key: last-write-wins would hide the real value.
        let dup_line = canonical_line.replace("index=0", "index=0 index=7");
        let path = tmp_path("duplicate-field");
        fs::write(&path, &dup_line).unwrap();
        match read_role_audit_log(&path) {
            Err(RoleAuditError::Malformed(msg)) => {
                assert!(msg.contains("duplicate field"), "got: {msg}");
            }
            other => panic!("expected Malformed for duplicate field, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn verify_role_audit_chain_rejects_non_hex_event_payload() {
        // A payload that is not valid hex cannot hash to any stored
        // entry_hash: the reader's decode must fail with Malformed
        // before any chain comparison runs.
        let forged = RoleAuditEntry {
            index: 0,
            previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
            entry_hash: "0123456789abcdef".to_owned(),
            event_hex: "not-hex!".to_owned(),
        };
        let err = verify_role_audit_chain(&[forged]).unwrap_err();
        assert!(matches!(err, RoleAuditError::Malformed(_)));
    }

    #[test]
    fn verify_role_audit_chain_rejects_odd_length_event_hex() {
        // Odd-length event_hex cannot be valid hex: the dedicated
        // length guard must fire BEFORE any pair decoding, producing
        // its own "length is odd" Malformed — distinct from the
        // invalid-hex-pair rejection.
        let forged = RoleAuditEntry {
            index: 0,
            previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
            entry_hash: "0123456789abcdef".to_owned(),
            event_hex: "abc".to_owned(),
        };
        let err = verify_role_audit_chain(&[forged]).unwrap_err();
        match err {
            RoleAuditError::Malformed(msg) => {
                assert!(msg.contains("length is odd"), "unexpected message: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn verify_role_audit_chain_rejects_non_hex_pair_in_event_hex() {
        // Valid even length, but the PAIR "zz" is not hex: the pair
        // decoder must reject it as Malformed naming the offending
        // pair.
        let forged = RoleAuditEntry {
            index: 0,
            previous_hash: GENESIS_PREVIOUS_HASH.to_owned(),
            entry_hash: "0123456789abcdef".to_owned(),
            event_hex: "zz".to_owned(),
        };
        let err = verify_role_audit_chain(&[forged]).unwrap_err();
        match err {
            RoleAuditError::Malformed(msg) => {
                assert!(
                    msg.contains("invalid hex pair"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn reader_rejects_simultaneous_unknown_and_duplicate_fields() {
        // Multiple simultaneous violations: the parser must fail
        // closed reporting the FIRST violation encountered — not
        // panic, not skip, not collapse into a wrong variant.
        let event = RoleTransitionEvent::PresetTransition {
            from: RolePreset::Admin,
            to: RolePreset::Exit,
            outcome: RoleTransitionOutcome::Succeeded,
            error_category: None,
        };
        let payload = event.canonical_payload(100);
        let entry_hash = compute_entry_hash(0, GENESIS_PREVIOUS_HASH, &payload);
        let hex = hex_encode(payload.as_bytes());
        let canonical_line = format!(
            "index=0 previous_hash={GENESIS_PREVIOUS_HASH} entry_hash={entry_hash} event_hex={hex}\n"
        );

        // Unknown + duplicate on same line: must reject as Malformed
        // regardless of which violation the parser encounters first.
        let combo = canonical_line.replace("event_hex=", "junk=1 event_hex=");
        let combo = combo.replace("index=0", "index=0 index=7");
        assert_ne!(combo, canonical_line);
        let path = tmp_path("combo-violations");
        fs::write(&path, &combo).unwrap();
        match read_role_audit_log(&path) {
            Err(RoleAuditError::Malformed(_)) => {}
            other => panic!("expected Malformed for simultaneous violations, got {other:?}"),
        }
        cleanup(&path);
    }

    #[test]
    fn malformed_line_returns_typed_error() {
        let path = tmp_path("malformed");
        fs::write(&path, "this is not a valid line\n").unwrap();
        let err = read_role_audit_log(&path).unwrap_err();
        assert!(matches!(err, RoleAuditError::Malformed(_)));
        cleanup(&path);
    }

    // RSA-0013 witness: on a NEWLY created (empty) log, a failing
    // permission pin must FAIL CLOSED — the append is refused with a
    // `RoleAuditError::Io` naming the 0o640 pin, NOTHING is written,
    // and nothing is removed (the still-empty file stays on disk).
    // The old code discarded the `set_permissions` result with
    // `let _ =` and wrote the entry anyway. This test drives the
    // injected pin step, which did not exist before the fix, so on
    // the pre-fix tree the RED is a compile failure (cannot find
    // function `append_role_audit_entry_inner`).
    #[cfg(unix)]
    #[test]
    fn pin_failure_on_new_log_refuses_write_and_removes_nothing() {
        let path = tmp_path("pin-failure-new");
        let result =
            append_role_audit_entry_inner(&path, 1_700_000_000, &preset_event(), |_file| {
                Err(std::io::Error::other("injected chmod failure"))
            });
        let err = result.expect_err("failing pin must refuse the append");
        assert!(
            matches!(&err, RoleAuditError::Io(msg) if msg.contains("0o640")),
            "expected Io error naming the 0o640 pin, got {err:?}"
        );
        let body = fs::read(&path).unwrap_or_else(|err| panic!("file must not be removed: {err}"));
        assert!(
            body.is_empty(),
            "refused append must write nothing, got {} bytes",
            body.len()
        );
        cleanup(&path);
    }

    // RSA-0013 companion: the pin step is attempted ONLY for a newly
    // created (empty) log. An existing log is never chmod'ed, so an
    // operator's mode is preserved and an injected failing pin step
    // must never fire for it (never downgrade; never block an append
    // to an existing log over permissions).
    #[cfg(unix)]
    #[test]
    fn pin_step_not_attempted_for_existing_log() {
        let path = tmp_path("pin-existing");
        let event = preset_event();
        append_role_audit_entry(&path, 1_700_000_000, &event)
            .unwrap_or_else(|err| panic!("baseline append must succeed: {err}"));
        let second = append_role_audit_entry_inner(&path, 1_700_000_001, &event, |_file| {
            Err(std::io::Error::other("injected chmod failure"))
        });
        assert!(
            second.is_ok(),
            "existing log must not be pinned; injected failure must not fire, got {second:?}"
        );
        let entries = read_role_audit_log(&path).unwrap_or_else(|err| panic!("read back: {err}"));
        assert_eq!(entries.len(), 2, "second append must have landed");
        verify_role_audit_chain(&entries).unwrap_or_else(|err| panic!("chain must verify: {err}"));
        cleanup(&path);
    }

    // RSA-0013 supporting (unix): the happy path still pins a newly
    // created log to 0o640 through the injected-step refactor.
    #[cfg(unix)]
    #[test]
    fn new_log_pinned_to_0640() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("pin-new-0640");
        append_role_audit_entry(&path, 1_700_000_000, &preset_event())
            .unwrap_or_else(|err| panic!("append must succeed: {err}"));
        let mode = fs::metadata(&path)
            .unwrap_or_else(|err| panic!("metadata: {err}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "newly created log must be pinned to 0o640");
        cleanup(&path);
    }

    // RSA-0013 supporting (unix): an EXISTING log with a STRICTER
    // mode than 0o640 must never be widened by an append.
    #[cfg(unix)]
    #[test]
    fn existing_log_stricter_mode_is_never_widened() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("pin-existing-stricter");
        let event = preset_event();
        append_role_audit_entry(&path, 1_700_000_000, &event)
            .unwrap_or_else(|err| panic!("baseline append must succeed: {err}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|err| panic!("chmod 600: {err}"));
        append_role_audit_entry(&path, 1_700_000_001, &event)
            .unwrap_or_else(|err| panic!("second append must succeed: {err}"));
        let mode = fs::metadata(&path)
            .unwrap_or_else(|err| panic!("metadata: {err}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "existing stricter mode must be preserved verbatim"
        );
        cleanup(&path);
    }
}
