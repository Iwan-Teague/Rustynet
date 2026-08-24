#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestionPath {
    Mdm,
    EnvVar,
    CliArg,
    ApiPayload,
    UiForm,
    LogField,
}

pub fn redact_fields(
    _path: IngestionPath,
    input: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in input {
        if is_sensitive_key(key) || looks_sensitive_value(value) {
            out.insert(key.clone(), "REDACTED".to_owned());
        } else {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

fn is_sensitive_key(key: &str) -> bool {
    // Canonicalize separators BEFORE matching: kebab-case variants
    // ("private-key", "auth-header", "api-key") must hit the same
    // needles as their snake_case twins, or they log cleartext.
    let lowered = key.to_ascii_lowercase().replace('-', "_");
    [
        "token",
        "secret",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "private_key",
        "nonce",
        "api_key",
        "apikey",
        "authorization",
        "auth_header",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn looks_sensitive_value(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    // Scheme prefixes may be followed by a space OR a tab (header
    // folding); match both so "bearer\tTOKEN" cannot slip through.
    // Also match mid-string occurrences ("use bearer abc123") which
    // starts_with alone misses, plus quote-delimited (JSON-embedded
    // `"Basic dXNlcjpwYXNz"` inside a dumped request body) and
    // newline-delimited (multi-line error text) occurrences. Errs
    // toward over-redaction: a missed credential in a log line is a
    // leak; an over-redacted diagnostic is only noise.
    let scheme_gated = ["bearer", "basic"].iter().any(|scheme| {
        lowered.starts_with(&format!("{scheme} "))
            || lowered.contains(&format!(" {scheme} "))
            || lowered.contains(&format!("\t{scheme} "))
            || lowered.contains(&format!("{scheme}\t"))
            || lowered.contains(&format!("\"{scheme} "))
            || lowered.contains(&format!("\n{scheme} "))
    });
    scheme_gated
        || lowered.starts_with("sk_")
        || lowered.starts_with("sk-ant-")
        || lowered.starts_with("ghp_")
        || lowered.starts_with("github_pat_")
        || lowered.starts_with("vault://")
        // JWT: base64 of '{"' produces "eyJ" but after to_ascii_lowercase()
        // the capital J becomes lowercase, yielding "eyj". Match against
        // the lowercased form and require a dot separator (header.payload).
        // Mirror the scheme handling above: an occurrence may be the whole
        // value or be preceded by a space, a tab (header folding), a quote
        // (JSON-dumped request body), or a newline (multi-line error
        // text). Errs toward over-redaction.
        || lowered.contains('.')
            && ["eyj", " eyj", "\teyj", "\"eyj", "\neyj"]
                .iter()
                .any(|needle| lowered.contains(needle))
        || lowered.contains("-----begin")
}

#[derive(Debug, Default)]
pub struct StructuredLogger {
    lines: Mutex<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationsError {
    Internal,
    Io,
    IntegrityMismatch,
    InvalidFormat,
}

impl fmt::Display for OperationsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationsError::Internal => f.write_str("internal operations error"),
            OperationsError::Io => f.write_str("i/o error"),
            OperationsError::IntegrityMismatch => f.write_str("integrity mismatch"),
            OperationsError::InvalidFormat => f.write_str("invalid format"),
        }
    }
}

impl std::error::Error for OperationsError {}

impl StructuredLogger {
    pub fn log(
        &self,
        path: IngestionPath,
        fields: &BTreeMap<String, String>,
    ) -> Result<(), OperationsError> {
        let redacted = redact_fields(path, fields);
        let mut encoded = String::from("{");
        let mut first = true;
        for (key, value) in &redacted {
            if !first {
                encoded.push(',');
            }
            first = false;
            // Fail closed on structural characters: an unescaped quote
            // or newline would let a field value break out of (or add
            // lines to) the JSON frame — same injection class as the
            // audit-log delimiter fix.
            encoded.push('"');
            encoded.push_str(&json_escape(key));
            encoded.push_str("\":\"");
            encoded.push_str(&json_escape(value));
            encoded.push('"');
        }
        encoded.push('}');

        let mut guard = self.lines.lock().map_err(|_| OperationsError::Internal)?;
        guard.push(encoded);
        Ok(())
    }

    pub fn lines(&self) -> Result<Vec<String>, OperationsError> {
        let guard = self.lines.lock().map_err(|_| OperationsError::Internal)?;
        Ok(guard.clone())
    }
}

/// Minimal JSON string escaping for the structured log frame: quotes,
/// backslashes, and control characters cannot break out of the value.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub component: String,
    pub healthy: bool,
    pub detail: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsSummary {
    pub components: Vec<HealthSnapshot>,
    pub relay_in_use: bool,
    pub peer_count: usize,
}

impl DiagnosticsSummary {
    pub fn overall_healthy(&self) -> bool {
        self.components.iter().all(|entry| entry.healthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp_unix: u64,
    pub actor: String,
    pub action: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone)]
pub struct TamperEvidentAuditLog {
    entries: Vec<AuditEntry>,
    retention_days: u32,
}

impl TamperEvidentAuditLog {
    pub fn new(retention_days: u32) -> Self {
        Self {
            entries: Vec::new(),
            retention_days,
        }
    }

    pub fn append(
        &mut self,
        actor: &str,
        action: &str,
        timestamp_unix: u64,
    ) -> Result<(), OperationsError> {
        // Fail closed on delimiters: '|' would shift fields on
        // restore (unrestorable log), '\n'/'\r' would inject forged
        // entry lines that backup+restore then faithfully accept.
        if actor.contains('|')
            || actor.contains('\n')
            || actor.contains('\r')
            || action.contains('|')
            || action.contains('\n')
            || action.contains('\r')
        {
            return Err(OperationsError::InvalidFormat);
        }
        let index = self.entries.len() as u64;
        let previous_hash = self
            .entries
            .last()
            .map_or_else(|| "genesis".to_owned(), |entry| entry.entry_hash.clone());
        let payload = format!("{index}|{timestamp_unix}|{actor}|{action}|{previous_hash}");
        let entry_hash = sha256_hex(payload.as_bytes());
        self.entries.push(AuditEntry {
            index,
            timestamp_unix,
            actor: actor.to_owned(),
            action: action.to_owned(),
            previous_hash,
            entry_hash,
        });
        Ok(())
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }

    pub fn verify_integrity(&self) -> bool {
        for (position, entry) in self.entries.iter().enumerate() {
            if entry.index != position as u64 {
                return false;
            }
            let expected_previous = if position == 0 {
                "genesis".to_owned()
            } else {
                self.entries[position - 1].entry_hash.clone()
            };
            if entry.previous_hash != expected_previous {
                return false;
            }
            let payload = format!(
                "{}|{}|{}|{}|{}",
                entry.index, entry.timestamp_unix, entry.actor, entry.action, entry.previous_hash
            );
            let expected_hash = sha256_hex(payload.as_bytes());
            if entry.entry_hash != expected_hash {
                return false;
            }
        }

        true
    }

    pub fn backup_to_file(&self, path: impl AsRef<Path>) -> Result<(), OperationsError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| OperationsError::Io)?;
        }

        let mut body = format!("retention_days={}\n", self.retention_days);
        for entry in &self.entries {
            body.push_str(&format!(
                "entry={}|{}|{}|{}|{}|{}\n",
                entry.index,
                entry.timestamp_unix,
                entry.actor,
                entry.action,
                entry.previous_hash,
                entry.entry_hash
            ));
        }
        let digest = sha256_hex(body.as_bytes());
        body.push_str(&format!("digest={digest}\n"));

        std::fs::write(path, body).map_err(|_| OperationsError::Io)?;
        Ok(())
    }

    pub fn restore_from_file(path: impl AsRef<Path>) -> Result<Self, OperationsError> {
        let content = std::fs::read_to_string(path).map_err(|_| OperationsError::Io)?;
        let mut retention_days: Option<u32> = None;
        let mut entries = Vec::new();
        let mut digest: Option<String> = None;
        let mut body_without_digest = String::new();

        for line in content.lines() {
            if let Some(value) = line.strip_prefix("retention_days=") {
                retention_days = value.parse::<u32>().ok();
                body_without_digest.push_str(line);
                body_without_digest.push('\n');
                continue;
            }
            if let Some(value) = line.strip_prefix("entry=") {
                let fields = value.split('|').collect::<Vec<_>>();
                if fields.len() != 6 {
                    return Err(OperationsError::InvalidFormat);
                }
                let entry = AuditEntry {
                    index: fields[0]
                        .parse::<u64>()
                        .map_err(|_| OperationsError::InvalidFormat)?,
                    timestamp_unix: fields[1]
                        .parse::<u64>()
                        .map_err(|_| OperationsError::InvalidFormat)?,
                    actor: fields[2].to_owned(),
                    action: fields[3].to_owned(),
                    previous_hash: fields[4].to_owned(),
                    entry_hash: fields[5].to_owned(),
                };
                entries.push(entry);
                body_without_digest.push_str(line);
                body_without_digest.push('\n');
                continue;
            }
            if let Some(value) = line.strip_prefix("digest=") {
                digest = Some(value.to_owned());
                continue;
            }
            return Err(OperationsError::InvalidFormat);
        }

        let expected = digest.ok_or(OperationsError::InvalidFormat)?;
        let actual = sha256_hex(body_without_digest.as_bytes());
        if expected != actual {
            return Err(OperationsError::IntegrityMismatch);
        }

        let log = Self {
            entries,
            retention_days: retention_days.ok_or(OperationsError::InvalidFormat)?,
        };
        if !log.verify_integrity() {
            return Err(OperationsError::IntegrityMismatch);
        }

        Ok(log)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        DiagnosticsSummary, HealthSnapshot, IngestionPath, OperationsError, StructuredLogger,
        TamperEvidentAuditLog, looks_sensitive_value, redact_fields,
    };

    #[test]
    fn restore_rejects_unknown_line_prefixes() {
        // Fail-closed framing: any line that is not `retention_days=`,
        // `entry=`, or `digest=` must be rejected outright — never
        // silently skipped — so a tampered backup cannot smuggle
        // content past the reader.
        let unique = format!(
            "rustynet-ops-junkline-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(
            &path,
            "retention_days=30\nsmuggled_field=1\nentry=0|1|actor|action|prev|hash\ndigest=00\n",
        )
        .unwrap();

        let err = TamperEvidentAuditLog::restore_from_file(&path).unwrap_err();
        assert!(matches!(err, OperationsError::InvalidFormat));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn structured_logger_escapes_quotes_and_newlines_in_fields() {
        // Adversarial finding: values were interpolated into the JSON
        // frame unescaped, so a quote/newline in ANY field value could
        // break out of the frame or inject a second line.
        let logger = StructuredLogger::default();
        let mut fields = BTreeMap::new();
        fields.insert(
            "hostname".to_string(),
            "host\"},{\"injected\":\"1".to_string(),
        );
        fields.insert("note".to_string(), "line1\nline2".to_string());

        logger.log(IngestionPath::LogField, &fields).expect("log");
        let lines = logger.lines().expect("lines readable");

        assert_eq!(lines.len(), 1, "one log call must emit exactly one line");
        let line = &lines[0];
        assert!(!line.contains("\n"), "emitted frame must be a single line");
        assert!(
            line.contains("host\\\"},\\\\\\\"") || line.contains("\\\"injected\\\""),
            "quotes must be escaped: {line}"
        );
        assert!(
            line.contains("line1\\nline2"),
            "newlines inside values must be escaped: {line}"
        );
    }

    #[test]
    fn redaction_catches_mid_string_bearer_and_basic_references() {
        // Regression: switching from contains() to starts_with() broke
        // mid-string scheme detection. A value like "please use bearer
        // abc123" must still be redacted even though it doesn't START
        // with "bearer".
        assert!(looks_sensitive_value(
            "please use bearer abc123 to authenticate"
        ));
        assert!(looks_sensitive_value("credentials: basic dXNlcjpwYXNz"));
        assert!(looks_sensitive_value("send bearer TOKEN here"));
        // JSON-embedded scheme reference: the quote before the scheme
        // defeats every space/tab-delimited pattern, so a dumped
        // request body carrying `"Authorization": "Basic …"` must
        // still be flagged.
        assert!(looks_sensitive_value(
            "{\"error\":\"denied\",\"authorization\":\"basic dXNlcjpwYXNz\"}"
        ));
        assert!(looks_sensitive_value("{\"header\":\"bearer abc123\"}"));
        // Newline-delimited scheme reference in multi-line error text.
        assert!(looks_sensitive_value("auth failed\nbearer abc123 rejected"));
        // Control: non-scheme text is not flagged.
        assert!(!looks_sensitive_value("standard policy update completed"));
    }

    #[test]
    fn redaction_covers_kebab_case_secret_key_variants() {
        // Separator-canonicalization pin: hyphenated variants must
        // hit the snake_case needles — "private-key" previously
        // logged cleartext because the needle was "private_key".
        let input: BTreeMap<String, String> = [
            ("private-key", "raw-key-material"),
            ("auth-header", "Bearer abc"),
            ("api-key", "sk_live_abc"),
            ("client-passwd", "hunter2"),
            ("signing-secret", "topsecret"),
            ("enrollment-token", "tok_123"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let redacted = redact_fields(IngestionPath::LogField, &input);
        for (key, value) in &redacted {
            assert_eq!(
                value, "REDACTED",
                "kebab-case secret key {key:?} must be redacted"
            );
        }

        // Control: a benign kebab-case key is untouched.
        let benign: BTreeMap<String, String> = [("node-count".to_string(), "7".to_string())]
            .into_iter()
            .collect();
        let passed = redact_fields(IngestionPath::LogField, &benign);
        assert_eq!(passed.get("node-count").map(String::as_str), Some("7"));
    }

    #[test]
    fn redaction_catches_jwt_tokens_in_values() {
        // JWTs (starting with base64 of `{"` = "eyJ") are active session
        // credentials. A leaked JWT in logs allows session hijacking.
        // The dot separator distinguishes real JWTs from random "eyJ" text.
        assert!(looks_sensitive_value(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ));
        assert!(looks_sensitive_value(
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIn0.sig"
        ));

        // Mid-string JWT embedded in an error message must also be caught
        // (mirrors the bearer/basic mid-string precedent).
        assert!(looks_sensitive_value(
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig rejected"
        ));

        // Tab-, quote-, and newline-preceded occurrences mirror the
        // scheme handling: header folding, JSON-dumped bodies, and
        // multi-line error text.
        assert!(looks_sensitive_value(
            "auth\teyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
        ));
        assert!(looks_sensitive_value(
            "{\"authorization\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig\"}"
        ));
        assert!(looks_sensitive_value(
            "auth failed\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig rejected"
        ));

        // Control: a value starting with "eyj" but without a dot is not
        // a JWT — it should NOT be flagged as sensitive.
        assert!(!looks_sensitive_value("eyjust_a_word"));
    }

    #[test]
    fn redaction_covers_common_secret_key_and_value_shapes() {
        // Adversarial sweep: the needle lists previously missed
        // api_key/apikey/passwd/authorization key shapes and
        // Basic/GitHub/Anthropic value shapes. Every one of these
        // must redact — a miss logs cleartext secrets.
        let input: BTreeMap<String, String> = [
            ("api_key", "sk_live_abc123"),
            ("apikey", "sk_live_abc123"),
            ("API_KEY", "value-does-not-matter"),
            ("passwd", "hunter2"),
            ("Authorization", "Basic dXNlcjpwYXNz"),
            ("auth_header", "Bearer abc"),
            ("folded_header", "bearer\tTAB-separat ed-token"),
            ("github_token_field", "ghp_16charsXXXXXXXXXXXXXX"),
            ("anthropic_note", "sk-ant-api03-xxxx"),
            ("ssh_key_pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let redacted = redact_fields(IngestionPath::ApiPayload, &input);
        for (key, value) in &redacted {
            assert_eq!(
                value, "REDACTED",
                "field {key:?} must be redacted, got cleartext {value:?}"
            );
        }

        // Control: innocuous fields pass through untouched.
        let benign: BTreeMap<String, String> = [("node_count".to_string(), "42".to_string())]
            .into_iter()
            .collect();
        let passed = redact_fields(IngestionPath::ApiPayload, &benign);
        assert_eq!(passed.get("node_count").map(String::as_str), Some("42"));
    }

    #[test]
    fn redaction_covers_all_ingestion_paths() {
        let mut payload = BTreeMap::new();
        payload.insert("api_token".to_owned(), "Bearer super-secret".to_owned());
        payload.insert("username".to_owned(), "alice".to_owned());
        payload.insert("vault_ref".to_owned(), "vault://path".to_owned());

        for path in [
            IngestionPath::Mdm,
            IngestionPath::EnvVar,
            IngestionPath::CliArg,
            IngestionPath::ApiPayload,
            IngestionPath::UiForm,
            IngestionPath::LogField,
        ] {
            let redacted = redact_fields(path, &payload);
            assert_eq!(redacted.get("api_token"), Some(&"REDACTED".to_owned()));
            assert_eq!(redacted.get("vault_ref"), Some(&"REDACTED".to_owned()));
            assert_eq!(redacted.get("username"), Some(&"alice".to_owned()));
        }
    }

    #[test]
    fn structured_logger_never_writes_cleartext_secrets() {
        let logger = StructuredLogger::default();
        let mut payload = BTreeMap::new();
        payload.insert("credential".to_owned(), "super-secret".to_owned());
        payload.insert("status".to_owned(), "ok".to_owned());

        logger
            .log(IngestionPath::ApiPayload, &payload)
            .expect("log should succeed");
        let lines = logger.lines().expect("lines should be readable");
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains("super-secret"));
        assert!(lines[0].contains("REDACTED"));
    }

    #[test]
    fn restore_rejects_entry_lines_with_wrong_field_count() {
        // Adversarial sweep finding: the 6-field guard on entry lines
        // (extra '|' segments would otherwise shift every field) must
        // be pinned — a 7-segment entry is structurally invalid even
        // before digest checks run.
        let unique = format!(
            "rustynet-ops-badcount-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = std::env::temp_dir().join(unique.clone());
        std::fs::write(
            &path,
            "retention_days=30\nentry=0|1|actor|action|prev|hash|EXTRA\ndigest=00\n",
        )
        .unwrap();

        let err = TamperEvidentAuditLog::restore_from_file(&path).unwrap_err();
        assert!(matches!(err, OperationsError::InvalidFormat));
        let _ = std::fs::remove_file(&path);

        // Control: a well-formed 6-field entry line passes the count
        // guard (it may fail later on digest, which is a DIFFERENT
        // error — here the file has only this one entry and no valid
        // digest, so assert it does not fail with InvalidFormat from
        // the field-count arm).
        let good = std::env::temp_dir().join(format!("rustynet-ops-goodcount-{unique}"));
        std::fs::write(
            &good,
            "retention_days=30\nentry=0|1|actor|action|prev|hash\ndigest=00\n",
        )
        .unwrap();
        if let Err(OperationsError::InvalidFormat) = TamperEvidentAuditLog::restore_from_file(&good)
        {
            panic!("6-field entry must pass the count guard");
        }
        let _ = std::fs::remove_file(&good);
    }

    #[test]
    fn append_rejects_delimiters_that_would_inject_or_shift_entries() {
        // Adversarial finding: append previously accepted '|' and
        // newlines in actor/action. '|' shifts fields on restore
        // (unrestorable log); '\n' injects a forged `entry=` line
        // that backup+restore faithfully accept as history.
        let mut log = TamperEvidentAuditLog::new(90);
        assert!(matches!(
            log.append("attacker\nentry=1|0|x|y|z|forged", "act", 100),
            Err(OperationsError::InvalidFormat)
        ));
        assert!(matches!(
            log.append("actor", "act\nentry=2|0|x|y|z|forged", 100),
            Err(OperationsError::InvalidFormat)
        ));
        assert!(matches!(
            log.append("at|tacker", "act", 100),
            Err(OperationsError::InvalidFormat)
        ));
        assert!(
            log.entries().is_empty(),
            "rejected appends must not mutate the log"
        );

        // Control: clean values still append, and the round-trip holds.
        log.append("alice", "policy.update", 100)
            .expect("clean append");
        let path = std::env::temp_dir().join(format!(
            "rustynet-ops-injection-guard-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        log.backup_to_file(&path).expect("backup");
        let restored =
            TamperEvidentAuditLog::restore_from_file(&path).expect("clean log must round-trip");
        assert_eq!(restored.entries().len(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn tamper_evident_audit_log_detects_corruption() {
        let mut log = TamperEvidentAuditLog::new(90);
        log.append("alice", "policy.update", 100)
            .expect("valid actor/action");
        log.append("alice", "exit_node.select", 101)
            .expect("valid actor/action");
        assert!(log.verify_integrity());

        let unique = format!(
            "rustynet-audit-backup-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        log.backup_to_file(&path).expect("backup should succeed");

        let restored = TamperEvidentAuditLog::restore_from_file(&path)
            .expect("restore with matching digest should succeed");
        assert_eq!(restored.retention_days(), 90);
        assert_eq!(restored.entries().len(), 2);

        let mut tampered = std::fs::read_to_string(&path).expect("read backup file");
        tampered = tampered.replace("policy.update", "policy.hijack");
        std::fs::write(&path, tampered).expect("write tampered backup");
        let restore_err = TamperEvidentAuditLog::restore_from_file(&path);
        assert_eq!(restore_err.err(), Some(OperationsError::IntegrityMismatch));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn audit_chain_rejects_entry_whose_hash_does_not_cover_its_payload() {
        let mut log = TamperEvidentAuditLog::new(30);
        log.append("alice", "policy.update", 100)
            .expect("valid actor/action");
        log.append("alice", "exit_node.select", 101)
            .expect("valid actor/action");

        let unique = format!(
            "rustynet-audit-rehash-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        log.backup_to_file(&path).expect("backup should succeed");

        // Rewrite an action INSIDE the body and refresh the trailing digest so
        // the file-level integrity check PASSES; only the per-entry hash-chain
        // recomputation inside verify_integrity can now catch the forgery.
        let body = std::fs::read_to_string(&path).expect("read backup");
        let mut forged_body = String::new();
        for line in body.lines() {
            if line.starts_with("digest=") {
                continue;
            }
            if line.starts_with("entry=") {
                forged_body.push_str(&line.replacen("policy.update", "policy.hijack", 1));
            } else {
                forged_body.push_str(line);
            }
            forged_body.push('\n');
        }
        let digest = format!("digest={}\n", super::sha256_hex(forged_body.as_bytes()));
        forged_body.push_str(&digest);
        std::fs::write(&path, &forged_body).expect("write forged backup");

        // The forged action changes the first entry's payload while its stored
        // entry_hash still covers the original payload, and every later link
        // stays intact, so the per-entry hash recomputation is the ONLY
        // remaining defense.
        let err = TamperEvidentAuditLog::restore_from_file(&path)
            .expect_err("digest-valid body with a broken chain must be refused");
        assert_eq!(err, OperationsError::IntegrityMismatch);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn audit_chain_rejects_reordered_entries_with_consistent_digest() {
        let mut log = TamperEvidentAuditLog::new(30);
        log.append("alice", "a.first", 100)
            .expect("valid actor/action");
        log.append("bob", "b.second", 101)
            .expect("valid actor/action");

        let unique = format!(
            "rustynet-audit-reorder-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        log.backup_to_file(&path).expect("backup should succeed");

        // Swap the two entry lines and refresh the digest: every line is a
        // well-formed entry whose own hash is untouched, but the sequence
        // indexes no longer match their positions.
        let body = std::fs::read_to_string(&path).expect("read backup");
        let mut entry_lines: Vec<&str> = body
            .lines()
            .filter(|line| line.starts_with("entry="))
            .collect();
        assert_eq!(entry_lines.len(), 2);
        entry_lines.reverse();
        let mut forged_body = String::new();
        for line in body.lines() {
            if line.starts_with("entry=") {
                continue;
            }
            if line.starts_with("digest=") {
                continue;
            }
            forged_body.push_str(line);
            forged_body.push('\n');
        }
        for line in &entry_lines {
            forged_body.push_str(line);
            forged_body.push('\n');
        }
        let digest = format!("digest={}\n", super::sha256_hex(forged_body.as_bytes()));
        forged_body.push_str(&digest);
        std::fs::write(&path, &forged_body).expect("write reordered backup");

        let err = TamperEvidentAuditLog::restore_from_file(&path)
            .expect_err("reordered entries must break the positional chain");
        assert_eq!(err, OperationsError::IntegrityMismatch);

        let _ = std::fs::remove_file(path);
    }

    /// Forge an append whose OWN hash is self-consistent but whose
    /// previous-hash link points nowhere: only the linkage check inside
    /// verify_integrity can reject this, the per-entry hash cannot.
    #[test]
    fn audit_chain_rejects_entry_linked_to_a_nonexistent_predecessor() {
        let mut log = TamperEvidentAuditLog::new(30);
        log.append("alice", "policy.update", 100)
            .expect("valid actor/action");

        let unique = format!(
            "rustynet-audit-dangling-link-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        log.backup_to_file(&path).expect("backup should succeed");

        let body = std::fs::read_to_string(&path).expect("read backup");
        let mut forged_body = String::new();
        for line in body.lines() {
            if line.starts_with("digest=") {
                continue;
            }
            forged_body.push_str(line);
            forged_body.push('\n');
        }
        // A perfectly well-formed second entry whose previous_hash names a
        // predecessor that does not exist anywhere in the log.
        let dangling_previous = "dangling-link-not-a-real-hash";
        let forged_payload = format!("1|101|bob|exit_node.select|{dangling_previous}");
        let forged_line = format!(
            "entry={forged_payload}|{}",
            super::sha256_hex(forged_payload.as_bytes())
        );
        forged_body.push_str(&forged_line);
        forged_body.push('\n');
        let digest = format!("digest={}\n", super::sha256_hex(forged_body.as_bytes()));
        forged_body.push_str(&digest);
        std::fs::write(&path, &forged_body).expect("write dangling-link backup");

        let err = TamperEvidentAuditLog::restore_from_file(&path)
            .expect_err("an entry linked to a nonexistent predecessor must be refused");
        assert_eq!(err, OperationsError::IntegrityMismatch);

        let _ = std::fs::remove_file(path);
    }

    /// Forge a SINGLE entry whose hash is recomputed over a WRONG sequence
    /// index: the payload hash is internally consistent, the genesis link is
    /// correct, so only the positional-index check can reject this.
    #[test]
    fn audit_chain_rejects_self_consistent_entry_at_the_wrong_position() {
        let unique = format!(
            "rustynet-audit-wrong-index-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        let payload = format!(
            "{}|{}|{}|{}|{}",
            7, 100, "alice", "policy.update", "genesis"
        );
        let body = format!(
            "retention_days=30\nentry={payload}|{}\ndigest={}\n",
            super::sha256_hex(payload.as_bytes()),
            {
                let inner = format!("retention_days=30\nentry={payload}|{}\n", {
                    super::sha256_hex(payload.as_bytes())
                });
                super::sha256_hex(inner.as_bytes())
            }
        );
        std::fs::write(&path, &body).expect("write wrong-index backup");

        let err = TamperEvidentAuditLog::restore_from_file(&path)
            .expect_err("a self-consistent entry claiming index 7 at position 0 must be refused");
        assert_eq!(err, OperationsError::IntegrityMismatch);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn diagnostics_summary_reports_overall_health() {
        let summary = DiagnosticsSummary {
            components: vec![
                HealthSnapshot {
                    component: "control".to_owned(),
                    healthy: true,
                    detail: "ok".to_owned(),
                    timestamp_unix: 100,
                },
                HealthSnapshot {
                    component: "relay".to_owned(),
                    healthy: true,
                    detail: "ok".to_owned(),
                    timestamp_unix: 100,
                },
            ],
            relay_in_use: false,
            peer_count: 4,
        };
        assert!(summary.overall_healthy());
    }
}
