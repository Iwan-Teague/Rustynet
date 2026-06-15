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
use std::io::Write;
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
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize]);
        out.push(HEX_LOWER[(byte & 0x0f) as usize]);
    }
    String::from_utf8(out).expect("hex alphabet is valid ASCII")
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

/// Append a single event to the audit log at `path`. Atomic
/// per-line append: opens with `OPEN_APPEND` and writes the whole
/// log line in one `write_all` call so a concurrent reader sees
/// either the full prior log or the full prior log plus this
/// entry — never a torn line.
pub fn append_role_audit_entry(
    path: &Path,
    timestamp_unix: u64,
    event: &RoleTransitionEvent,
) -> Result<RoleAuditEntry, RoleAuditError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| RoleAuditError::Io(format!("create_dir_all: {err}")))?;
    }

    let existing = read_role_audit_log(path)?;
    let (next_index, previous_hash) = match existing.last() {
        Some(last) => (last.index + 1, last.entry_hash.clone()),
        None => (0_u64, GENESIS_PREVIOUS_HASH.to_owned()),
    };

    let payload = event.canonical_payload(timestamp_unix);
    let entry_hash = compute_entry_hash(next_index, &previous_hash, &payload);
    let event_hex = hex_encode(payload.as_bytes());
    let line = format!(
        "index={next_index} previous_hash={previous_hash} entry_hash={entry_hash} event_hex={event_hex}\n"
    );

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| RoleAuditError::Io(format!("open append: {err}")))?;

    // Pin restrictive perms when the file is newly created. We
    // don't downgrade existing perms (operator might have widened
    // intentionally) but we tighten on create.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if existing.is_empty() {
            let _ = file.set_permissions(fs::Permissions::from_mode(0o640));
        }
    }

    file.write_all(line.as_bytes())
        .map_err(|err| RoleAuditError::Io(format!("write: {err}")))?;
    file.flush()
        .map_err(|err| RoleAuditError::Io(format!("flush: {err}")))?;
    Ok(RoleAuditEntry {
        index: next_index,
        previous_hash,
        entry_hash,
        event_hex,
    })
}

/// Read all entries from the log at `path`. Returns an empty vec if
/// the file doesn't exist (genesis case).
pub fn read_role_audit_log(path: &Path) -> Result<Vec<RoleAuditEntry>, RoleAuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = fs::read_to_string(path)
        .map_err(|err| RoleAuditError::Io(format!("read_to_string: {err}")))?;
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
            fields.insert(key, value);
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
        let expected_previous = if position == 0 {
            GENESIS_PREVIOUS_HASH.to_owned()
        } else {
            entries[position - 1].entry_hash.clone()
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
}

impl fmt::Display for RoleAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleAuditError::Io(msg) => write!(f, "audit log io error: {msg}"),
            RoleAuditError::Malformed(msg) => write!(f, "audit log malformed: {msg}"),
            RoleAuditError::ChainBroken(msg) => write!(f, "audit log chain broken: {msg}"),
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
    fn malformed_line_returns_typed_error() {
        let path = tmp_path("malformed");
        fs::write(&path, "this is not a valid line\n").unwrap();
        let err = read_role_audit_log(&path).unwrap_err();
        assert!(matches!(err, RoleAuditError::Malformed(_)));
        cleanup(&path);
    }
}
