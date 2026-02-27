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
            out.insert(key.clone(), "REDACTED".to_string());
        } else {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

fn is_sensitive_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passphrase",
        "credential",
        "private_key",
        "nonce",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn looks_sensitive_value(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("bearer ")
        || lowered.starts_with("sk_")
        || lowered.starts_with("vault://")
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
            encoded.push('"');
            encoded.push_str(key);
            encoded.push_str("\":\"");
            encoded.push_str(value);
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

    pub fn append(&mut self, actor: &str, action: &str, timestamp_unix: u64) {
        let index = self.entries.len() as u64;
        let previous_hash = self
            .entries
            .last()
            .map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        let payload = format!("{index}|{timestamp_unix}|{actor}|{action}|{previous_hash}");
        let entry_hash = sha256_hex(payload.as_bytes());
        self.entries.push(AuditEntry {
            index,
            timestamp_unix,
            actor: actor.to_string(),
            action: action.to_string(),
            previous_hash,
            entry_hash,
        });
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
                "genesis".to_string()
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
                    actor: fields[2].to_string(),
                    action: fields[3].to_string(),
                    previous_hash: fields[4].to_string(),
                    entry_hash: fields[5].to_string(),
                };
                entries.push(entry);
                body_without_digest.push_str(line);
                body_without_digest.push('\n');
                continue;
            }
            if let Some(value) = line.strip_prefix("digest=") {
                digest = Some(value.to_string());
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
        TamperEvidentAuditLog, redact_fields,
    };

    #[test]
    fn redaction_covers_all_ingestion_paths() {
        let mut payload = BTreeMap::new();
        payload.insert("api_token".to_string(), "Bearer super-secret".to_string());
        payload.insert("username".to_string(), "alice".to_string());
        payload.insert("vault_ref".to_string(), "vault://path".to_string());

        for path in [
            IngestionPath::Mdm,
            IngestionPath::EnvVar,
            IngestionPath::CliArg,
            IngestionPath::ApiPayload,
            IngestionPath::UiForm,
            IngestionPath::LogField,
        ] {
            let redacted = redact_fields(path, &payload);
            assert_eq!(redacted.get("api_token"), Some(&"REDACTED".to_string()));
            assert_eq!(redacted.get("vault_ref"), Some(&"REDACTED".to_string()));
            assert_eq!(redacted.get("username"), Some(&"alice".to_string()));
        }
    }

    #[test]
    fn structured_logger_never_writes_cleartext_secrets() {
        let logger = StructuredLogger::default();
        let mut payload = BTreeMap::new();
        payload.insert("credential".to_string(), "super-secret".to_string());
        payload.insert("status".to_string(), "ok".to_string());

        logger
            .log(IngestionPath::ApiPayload, &payload)
            .expect("log should succeed");
        let lines = logger.lines().expect("lines should be readable");
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains("super-secret"));
        assert!(lines[0].contains("REDACTED"));
    }

    #[test]
    fn tamper_evident_audit_log_detects_corruption() {
        let mut log = TamperEvidentAuditLog::new(90);
        log.append("alice", "policy.update", 100);
        log.append("alice", "exit_node.select", 101);
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
    fn diagnostics_summary_reports_overall_health() {
        let summary = DiagnosticsSummary {
            components: vec![
                HealthSnapshot {
                    component: "control".to_string(),
                    healthy: true,
                    detail: "ok".to_string(),
                    timestamp_unix: 100,
                },
                HealthSnapshot {
                    component: "relay".to_string(),
                    healthy: true,
                    detail: "ok".to_string(),
                    timestamp_unix: 100,
                },
            ],
            relay_in_use: false,
            peer_count: 4,
        };
        assert!(summary.overall_healthy());
    }
}
