#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

use crate::credential_unwrap::{CredentialDescriptor, CredentialUnwrapBackend};

/// Wall-clock budget for the OS-keystore unwrap of the control-db key.
/// Bounds a stuck helper (systemd-creds / security / DPAPI helper) so it
/// cannot wedge the caller indefinitely.
const CONTROL_DB_KEY_UNWRAP_TIMEOUT: Duration = Duration::from_secs(10);

/// SQLCipher format pins (SQLCipher 4 defaults, set explicitly so a
/// linked-SQLCipher upgrade can never silently re-format the database):
/// 4096-byte pages, 256000 PBKDF2 iterations, SHA-512 HMAC and KDF.
const SQLCIPHER_PAGE_SIZE: u32 = 4096;
const SQLCIPHER_KDF_ITER: u32 = 256_000;
const SQLCIPHER_HMAC_ALGORITHM: &str = "HMAC_SHA512";
const SQLCIPHER_KDF_ALGORITHM: &str = "PBKDF2_HMAC_SHA512";

/// 32-byte SQLCipher raw key. Held in `Zeroizing` so the key material is
/// wiped on drop. `Debug` is implemented MANUALLY and redacts the bytes:
/// a derived impl would print the key material (secrets-hygiene, AGENTS
/// §10.6).
#[derive(Clone)]
pub struct SqlcipherKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for SqlcipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqlcipherKey(REDACTED)")
    }
}

impl SqlcipherKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Unwrap the control-db key from OS-secure custody via the platform
    /// credential backend (systemd-creds on Linux, System keychain on
    /// macOS, DPAPI blob on Windows). The keystore item is dedicated to
    /// the control database — the WG-key and signing-key passphrases are
    /// never reused. Fails closed on missing item, backend error, or a
    /// plaintext that is not exactly 32 bytes.
    pub fn from_keystore(backend: &dyn CredentialUnwrapBackend) -> Result<Self, PersistenceError> {
        let descriptor: CredentialDescriptor =
            crate::credential_unwrap::control_db_key_descriptor();
        let secret = backend
            .unwrap_credential(&descriptor, CONTROL_DB_KEY_UNWRAP_TIMEOUT)
            .map_err(|_| {
                PersistenceError::InvariantViolation(
                    "control-db key keystore unwrap failed; refusing to open (fail closed)",
                )
            })?;
        let bytes: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            PersistenceError::InvariantViolation(
                "control-db keystore item must unwrap to exactly 32 bytes (fail closed)",
            )
        })?;
        Ok(Self::from_bytes(bytes))
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Apply the raw key as `PRAGMA key = "x'<hex>'"`. The statement string is
/// built in a `Zeroizing` buffer with capacity 96 so the push never
/// reallocs (a grow would free the key-hex buffer unzeroized); the buffer
/// and the hex string are both wiped on drop, and the pragma is never
/// logged.
fn set_key(conn: &Connection, key: &SqlcipherKey) -> Result<(), PersistenceError> {
    let hex = Zeroizing::new(
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let mut stmt = Zeroizing::new(String::with_capacity(96));
    stmt.push_str("PRAGMA key = \"x'");
    stmt.push_str(&hex);
    stmt.push_str("'\";");
    conn.execute_batch(&stmt)?;
    Ok(())
}

/// Fail-closed codec check: refuse to proceed unless the linked SQLCipher
/// codec is real. A plain-SQLite build would open the file unencrypted and
/// silently write a plaintext database; the runtime `PRAGMA cipher_version`
/// check turns that into a hard error instead.
fn require_sqlcipher_codec(conn: &Connection) -> Result<(), PersistenceError> {
    let cipher: String = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .map_err(|_| {
            PersistenceError::InvariantViolation(
                "SQLCipher codec unavailable; refusing keyed open (fail closed)",
            )
        })?;
    if cipher.trim().is_empty() {
        return Err(PersistenceError::InvariantViolation(
            "SQLCipher codec unavailable; refusing keyed open (fail closed)",
        ));
    }
    Ok(())
}

/// Pin the SQLCipher format parameters after keying, then verify the
/// read-back matches. Pinning to explicit constants (the SQLCipher 4
/// defaults) means a future SQLCipher version with different defaults
/// cannot silently re-format the database, and a database created under a
/// divergent parameter set is refused instead of being read with a
/// mismatched derivation.
fn pin_cipher_parameters(conn: &Connection) -> Result<(), PersistenceError> {
    conn.execute_batch(&format!(
        "PRAGMA cipher_page_size = {SQLCIPHER_PAGE_SIZE}; \
         PRAGMA kdf_iter = {SQLCIPHER_KDF_ITER}; \
         PRAGMA cipher_hmac_algorithm = {SQLCIPHER_HMAC_ALGORITHM}; \
         PRAGMA cipher_kdf_algorithm = {SQLCIPHER_KDF_ALGORITHM};"
    ))?;
    // SQLCipher builds are inconsistent about the dynamic type of the
    // numeric pragma read-backs (integer or text depending on build), so
    // read them as generic values and normalize.
    let read_value = |pragma: &str| -> Result<rusqlite::types::Value, PersistenceError> {
        conn.query_row(pragma, [], |r| r.get(0))
            .map_err(PersistenceError::from)
    };
    let as_i64 = |v: &rusqlite::types::Value| -> Option<i64> {
        match v {
            rusqlite::types::Value::Integer(i) => Some(*i),
            rusqlite::types::Value::Text(t) => t.trim().parse().ok(),
            _ => None,
        }
    };
    let as_str = |v: &rusqlite::types::Value| -> Option<String> {
        match v {
            rusqlite::types::Value::Text(t) => Some(t.clone()),
            rusqlite::types::Value::Integer(i) => Some(i.to_string()),
            _ => None,
        }
    };
    let page = read_value("PRAGMA cipher_page_size")?;
    let iter = read_value("PRAGMA kdf_iter")?;
    let hmac = read_value("PRAGMA cipher_hmac_algorithm")?;
    let kdf = read_value("PRAGMA cipher_kdf_algorithm")?;
    let pinned = as_i64(&page) == Some(i64::from(SQLCIPHER_PAGE_SIZE))
        && as_i64(&iter) == Some(i64::from(SQLCIPHER_KDF_ITER))
        && as_str(&hmac).as_deref() == Some(SQLCIPHER_HMAC_ALGORITHM)
        && as_str(&kdf).as_deref() == Some(SQLCIPHER_KDF_ALGORITHM);
    if !pinned {
        return Err(PersistenceError::InvariantViolation(
            "SQLCipher cipher parameters did not take; refusing keyed open (fail closed)",
        ));
    }
    Ok(())
}

/// A wrong key must fail loudly, not read as an empty database: decrypting
/// page 1 under the wrong key yields garbage, so any query against the
/// schema catalog errors.
fn verify_readable(conn: &Connection) -> Result<(), PersistenceError> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|_| ())
    .map_err(|_| PersistenceError::WrongKeyOrCorrupt)
}

/// Append a sqlite sidecar suffix (`-wal` / `-shm`) to a DB path.
fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// RSA-0017: reject a control-plane DB / sidecar that already exists with
/// insecure permissions (symlink, group/other-accessible, or foreign owner) on
/// unix. A non-existent path is fine (it will be created and tightened). Fails
/// closed: any stat error on an existing, accessible path is an error.
fn enforce_sqlite_path_secure(path: &Path) -> Result<(), PersistenceError> {
    let link_metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(PersistenceError::InvariantViolation(
                "control-plane DB path is not statable; refusing to open (fail closed)",
            ));
        }
    };
    if link_metadata.file_type().is_symlink() {
        return Err(PersistenceError::InvariantViolation(
            "control-plane DB path is a symlink; refusing to open (fail closed)",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|_| {
            PersistenceError::InvariantViolation(
                "control-plane DB path is not statable; refusing to open (fail closed)",
            )
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PersistenceError::InvariantViolation(
                "control-plane DB is group/other-accessible; refusing to open (fail closed)",
            ));
        }
        if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
            return Err(PersistenceError::InvariantViolation(
                "control-plane DB is owned by another user; refusing to open (fail closed)",
            ));
        }
    }
    Ok(())
}

/// Tighten an existing sqlite DB / sidecar to `0o600` (owner-only). No-op if the
/// file does not exist or on non-unix (Windows ACL custody is RSA-0002/0025).
fn tighten_sqlite_file(path: &Path) -> Result<(), PersistenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(_) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| {
                    PersistenceError::InvariantViolation(
                        "could not restrict control-plane DB permissions to 0o600 (fail closed)",
                    )
                })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(PersistenceError::InvariantViolation(
                    "control-plane DB path is not statable after open (fail closed)",
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[derive(Debug)]
pub enum PersistenceError {
    Sqlite(rusqlite::Error),
    InvariantViolation(&'static str),
    /// The database exists but does not decrypt under the supplied key
    /// (wrong keystore item) or its pages are corrupt. Never carries key
    /// material.
    WrongKeyOrCorrupt,
    /// The on-disk control-db path is not a readable SQLite file.
    NotASqliteFile,
    /// One-time plaintext→SQLCipher migration failure. Carries a static
    /// stage label, never key material.
    Migration(String),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::Sqlite(err) => write!(f, "sqlite error: {err}"),
            PersistenceError::InvariantViolation(message) => f.write_str(message),
            PersistenceError::WrongKeyOrCorrupt => {
                f.write_str("control-db open failed: wrong key or corrupt database (fail closed)")
            }
            PersistenceError::NotASqliteFile => {
                f.write_str("control-db path is not a readable sqlite file (fail closed)")
            }
            PersistenceError::Migration(stage) => {
                write!(f, "control-db plaintext migration failed at {stage}")
            }
        }
    }
}

impl std::error::Error for PersistenceError {}

impl From<rusqlite::Error> for PersistenceError {
    fn from(value: rusqlite::Error) -> Self {
        PersistenceError::Sqlite(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub user_id: String,
    pub email: String,
    pub mfa_enabled: bool,
    pub updated_at_unix: u64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRow {
    pub node_id: String,
    pub owner_user_id: String,
    pub hostname: String,
    pub os: String,
    pub tags_csv: String,
    pub public_key_hex: String,
    pub last_seen_unix: u64,
    pub updated_at_unix: u64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRow {
    pub credential_id: String,
    pub creator_user_id: String,
    pub scope: String,
    pub credential_kind: String,
    pub state: String,
    pub max_uses: u8,
    pub uses: u8,
    pub expires_at_unix: u64,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub storage_policy: String,
}

/// One-time migration of an existing plaintext control.db to SQLCipher.
/// Detection is header-based and deterministic: plaintext SQLite starts
/// with the magic `SQLite format 3\x00`; a SQLCipher 4 file starts with a
/// random 16-byte salt.
///
/// No plaintext copy of the destination ever exists: the export is written
/// to `<path>.migrate` (keyed attach + `sqlcipher_export`), fsynced by the
/// source connection close, then atomically renamed OVER the plaintext
/// file. A crash mid-migration leaves the original plaintext db plus a
/// partial `.migrate`; the next run re-detects plaintext and restarts
/// cleanly (the stale `.migrate` is removed before the export). A
/// too-short file (no full magic) holds no SQLite data and is treated as
/// fresh-install; a foreign/garbage file is left alone and the subsequent
/// keyed open fails closed on it.
pub fn migrate_plaintext_control_db(
    path: &Path,
    key: &SqlcipherKey,
) -> Result<(), PersistenceError> {
    enforce_sqlite_path_secure(path)?;
    let mut header = [0u8; 16];
    match std::fs::File::open(path) {
        Ok(mut file) => {
            use std::io::Read;
            // A file shorter than the magic carries no migratable data
            // (0-byte and partial-header files are fresh-install shapes).
            if file.read_exact(&mut header).is_err() {
                return Ok(());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(PersistenceError::NotASqliteFile),
    }
    if header != *b"SQLite format 3\x00" {
        // Already SQLCipher (random salt) — or a foreign file the keyed
        // open will refuse below.
        return Ok(());
    }

    // Source: SQLCipher builds read plaintext freely while NO key is set
    // (Zetetic-documented behavior). Checkpoint WAL first so no committed
    // page is left only in the sidecar, then export.
    let src = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| PersistenceError::NotASqliteFile)?;
    src.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

    // Destination: attach the temp file WITH the key (Zeroizing SQL text,
    // same technique as `set_key`); `sqlcipher_export` copies schema and
    // rows page-by-page into the encrypted target.
    let migrate_path = sidecar_path(path, ".migrate");
    let _ = std::fs::remove_file(&migrate_path);
    std::fs::write(&migrate_path, b"")
        .map_err(|_| PersistenceError::Migration("scratch create".to_owned()))?;
    #[cfg(unix)]
    tighten_sqlite_file(&migrate_path)?;
    let hex = Zeroizing::new(
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let mut attach = Zeroizing::new(String::with_capacity(160));
    attach.push_str("ATTACH DATABASE '");
    attach.push_str(&migrate_path.to_string_lossy().replace('\'', "''"));
    attach.push_str("' AS migrate_target KEY \"x'");
    attach.push_str(&hex);
    attach.push_str("'\";");
    src.execute_batch(&attach)
        .map_err(|e| PersistenceError::Migration(format!("attach: {e}")))?;
    src.execute_batch("SELECT sqlcipher_export('migrate_target');")
        .map_err(|_| PersistenceError::Migration("export".to_owned()))?;
    src.execute_batch("DETACH DATABASE migrate_target;")
        .map_err(|_| PersistenceError::Migration("detach".to_owned()))?;
    drop(src); // close + journal fsync before rename

    // Verify the destination is readable under the key BEFORE destroying
    // the source; migrations are idempotent (CREATE TABLE IF NOT EXISTS).
    {
        let probe = SqliteStore::open_keyed(&migrate_path, key)?;
        probe.apply_migrations()?;
        drop(probe);
    }

    // Atomic cutover: encrypted file replaces plaintext; then remove the
    // plaintext sidecars (source -wal was truncated above; -shm is
    // wal-index metadata only).
    std::fs::rename(&migrate_path, path)
        .map_err(|_| PersistenceError::Migration("cutover rename".to_owned()))?;
    let _ = std::fs::remove_file(sidecar_path(path, "-wal"));
    let _ = std::fs::remove_file(sidecar_path(path, "-shm"));
    tighten_sqlite_file(path)?;
    Ok(())
}

#[derive(Debug)]
pub struct SqliteStore {
    conn: Connection,
    /// On-disk location (`None` for the in-memory test store). Kept so the
    /// first WAL-creating write can re-tighten the DB and sidecars: SQLite
    /// creates `-wal`/`-shm` lazily under the caller's umask, so the
    /// tighten at open time cannot cover them.
    path: Option<PathBuf>,
}

impl SqliteStore {
    /// Re-tighten the DB and its sidecars to 0o600 after WAL files may
    /// have been created. Idempotent; a no-op for the in-memory store.
    fn tighten_all(&self) -> Result<(), PersistenceError> {
        if let Some(path) = &self.path {
            tighten_sqlite_file(path)?;
            tighten_sqlite_file(&sidecar_path(path, "-wal"))?;
            tighten_sqlite_file(&sidecar_path(path, "-shm"))?;
        }
        Ok(())
    }
    /// Keyed open — the ONLY disk path. The control database is encrypted
    /// at rest with SQLCipher (every page encrypted on write; the key
    /// exists only in process memory inside `SqlcipherKey`). There is no
    /// unkeyed disk open and no plaintext fallback: AGENTS §3 requires one
    /// hardened execution path per security-sensitive workflow.
    ///
    /// Sequence is load-bearing: RSA-0017 permission guards, then the
    /// codec check, then `PRAGMA key` as the FIRST page-touching
    /// statement, then the format pins, then the readability probe so a
    /// wrong key fails loudly instead of reading as an empty database.
    pub fn open_keyed(
        path: impl AsRef<Path>,
        key: &SqlcipherKey,
    ) -> Result<Self, PersistenceError> {
        let path = path.as_ref();
        // RSA-0017: the control-plane DB holds node pubkeys, user MFA posture and
        // single-use credential state. Fail closed on a pre-existing insecure DB
        // or sidecar, then enforce 0o600 on the (possibly freshly created) files.
        enforce_sqlite_path_secure(path)?;
        let wal = sidecar_path(path, "-wal");
        let shm = sidecar_path(path, "-shm");
        enforce_sqlite_path_secure(&wal)?;
        enforce_sqlite_path_secure(&shm)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Lock down whatever `open` (or a prior WAL checkpoint) created.
        tighten_sqlite_file(path)?;
        tighten_sqlite_file(&wal)?;
        tighten_sqlite_file(&shm)?;
        require_sqlcipher_codec(&conn)?;
        set_key(&conn, key)?;
        pin_cipher_parameters(&conn)?;
        verify_readable(&conn)?;
        Ok(Self {
            conn,
            path: Some(path.to_path_buf()),
        })
    }

    pub fn open_in_memory() -> Result<Self, PersistenceError> {
        let conn = Connection::open_in_memory()?;
        Ok(Self { conn, path: None })
    }

    pub fn apply_migrations(&self) -> Result<(), PersistenceError> {
        self.conn
            .execute_batch(include_str!("../migrations/0001_init.sql"))?;
        // `journal_mode = WAL` above just created `-wal`/`-shm` under the
        // caller's umask; re-tighten so RSA-0017 holds on the next open.
        self.tighten_all()?;
        Ok(())
    }

    pub fn upsert_user(&self, user: &UserRow) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT INTO users (user_id, email, mfa_enabled, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id) DO UPDATE SET
                email = excluded.email,
                mfa_enabled = excluded.mfa_enabled,
                updated_at_unix = excluded.updated_at_unix",
            params![
                user.user_id,
                user.email,
                i64::from(user.mfa_enabled),
                user.created_at_unix as i64,
                user.updated_at_unix as i64
            ],
        )?;
        Ok(())
    }

    pub fn upsert_node(&self, node: &NodeRow) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT INTO nodes (
                node_id, owner_user_id, hostname, os, tags_csv, public_key_hex,
                last_seen_unix, created_at_unix, updated_at_unix
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(node_id) DO UPDATE SET
                owner_user_id = excluded.owner_user_id,
                hostname = excluded.hostname,
                os = excluded.os,
                tags_csv = excluded.tags_csv,
                public_key_hex = excluded.public_key_hex,
                last_seen_unix = excluded.last_seen_unix,
                updated_at_unix = excluded.updated_at_unix",
            params![
                node.node_id,
                node.owner_user_id,
                node.hostname,
                node.os,
                node.tags_csv,
                node.public_key_hex,
                node.last_seen_unix as i64,
                node.created_at_unix as i64,
                node.updated_at_unix as i64
            ],
        )?;
        Ok(())
    }

    pub fn insert_credential(&self, row: &CredentialRow) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT INTO enrollment_credentials (
                credential_id, creator_user_id, scope, credential_kind, state, max_uses, uses,
                expires_at_unix, created_at_unix, updated_at_unix, storage_policy
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.credential_id,
                row.creator_user_id,
                row.scope,
                row.credential_kind,
                row.state,
                i64::from(row.max_uses),
                i64::from(row.uses),
                row.expires_at_unix as i64,
                row.created_at_unix as i64,
                row.updated_at_unix as i64,
                row.storage_policy
            ],
        )?;
        Ok(())
    }

    pub fn consume_single_use_credential(
        &mut self,
        credential_id: &str,
        now_unix: u64,
    ) -> Result<bool, PersistenceError> {
        let transaction = self.conn.transaction()?;
        let consumed = consume_single_use_credential_tx(&transaction, credential_id, now_unix)?;
        transaction.commit()?;
        Ok(consumed)
    }

    pub fn insert_credential_audit_event(
        &self,
        credential_id: &str,
        from_state: Option<&str>,
        to_state: &str,
        event_at_unix: u64,
        actor_user_id: &str,
    ) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT INTO credential_audit_events (
                credential_id, from_state, to_state, event_at_unix, actor_user_id
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                credential_id,
                from_state,
                to_state,
                event_at_unix as i64,
                actor_user_id
            ],
        )?;
        Ok(())
    }

    pub fn credential_state(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, PersistenceError> {
        let state = self
            .conn
            .query_row(
                "SELECT state FROM enrollment_credentials WHERE credential_id = ?1",
                params![credential_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        Ok(state)
    }

    pub fn user_exists(&self, user_id: &str) -> Result<bool, PersistenceError> {
        let exists = self
            .conn
            .query_row(
                "SELECT 1 FROM users WHERE user_id = ?1",
                params![user_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn node_exists(&self, node_id: &str) -> Result<bool, PersistenceError> {
        let exists = self
            .conn
            .query_row(
                "SELECT 1 FROM nodes WHERE node_id = ?1",
                params![node_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn credential_audit_event_count(
        &self,
        credential_id: &str,
    ) -> Result<u64, PersistenceError> {
        let count = self.conn.query_row(
            "SELECT COUNT(1) FROM credential_audit_events WHERE credential_id = ?1",
            params![credential_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as u64)
    }
}

fn consume_single_use_credential_tx(
    tx: &Transaction<'_>,
    credential_id: &str,
    now_unix: u64,
) -> Result<bool, PersistenceError> {
    let result = tx.execute(
        "UPDATE enrollment_credentials
         SET uses = uses + 1,
             state = 'used',
             updated_at_unix = ?2
         WHERE credential_id = ?1
           AND state = 'created'
           AND uses < max_uses
           AND expires_at_unix >= ?2",
        params![credential_id, now_unix as i64],
    )?;

    Ok(result == 1)
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialRow, NodeRow, PersistenceError, SqlcipherKey, SqliteStore, UserRow,
        migrate_plaintext_control_db,
    };
    use crate::credential_unwrap::{CredentialDescriptor, CredentialUnwrapBackend};
    use std::time::Duration;

    fn test_key() -> SqlcipherKey {
        SqlcipherKey::from_bytes([7u8; 32])
    }

    fn other_key() -> SqlcipherKey {
        SqlcipherKey::from_bytes([9u8; 32])
    }

    /// Stub keystore backend: returns the canned plaintext, or an error
    /// when seeded with `None` (missing item).
    struct StubBackend(Option<Vec<u8>>);

    impl CredentialUnwrapBackend for StubBackend {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn unwrap_credential(
            &self,
            _descriptor: &CredentialDescriptor,
            _timeout: Duration,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
            self.0
                .clone()
                .map(zeroize::Zeroizing::new)
                .ok_or_else(|| "missing credential".to_owned())
        }
    }

    /// Seed a PLAINTEXT control.db the way the pre-SQLCipher code did:
    /// unkeyed connection, schema migration, one user row.
    fn seed_plaintext_db(db: &std::path::Path) {
        let conn = rusqlite::Connection::open(db).expect("plaintext open");
        conn.execute_batch(include_str!("../migrations/0001_init.sql"))
            .expect("plaintext schema");
        conn.execute(
            "INSERT INTO users (user_id, email, mfa_enabled, created_at_unix, updated_at_unix)
             VALUES ('user-1', 'alice@example.local', 1, 100, 100)",
            [],
        )
        .expect("seed user row");
        // A real RSA-0017-compliant deployment keeps the plaintext db at
        // 0o600; mimic that so the migration guard sees a legitimate file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(db, std::fs::Permissions::from_mode(0o600))
                .expect("chmod seeded plaintext db");
        }
    }

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_rejects_group_readable_db() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        std::fs::write(&db, b"").expect("seed db file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        let err = SqliteStore::open_keyed(&db, &test_key())
            .expect_err("group/other-readable DB must fail closed");
        assert!(format!("{err}").contains("group/other-accessible"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_rejects_group_readable_wal_sidecar() {
        // The DB itself is locked to 0o600, but WAL mode writes
        // `-wal`/`-shm` sidecars that carry the same credential and
        // single-use state. A group/other-readable SIDECAR must fail
        // closed exactly like the main DB file.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017-wal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        std::fs::write(&db, b"").expect("seed db file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
        let wal = dir.join("control.db-wal");
        std::fs::write(&wal, b"").expect("seed wal");
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

        let err = SqliteStore::open_keyed(&db, &test_key())
            .expect_err("group-readable WAL must fail closed");
        assert!(
            format!("{err}").contains("group/other-accessible"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_creates_and_tightens_db_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        let store = SqliteStore::open_keyed(&db, &test_key()).expect("fresh DB opens");
        store.apply_migrations().expect("migrations");
        let mode = std::fs::metadata(&db)
            .expect("stat db")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "freshly created DB must be locked to 0o600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_rejects_symlinked_db_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017c-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let target = dir.join("real-control.db");
        std::fs::write(&target, b"").expect("seed target db file");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
        let link = dir.join("link-to-control.db");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let err = SqliteStore::open_keyed(&link, &test_key())
            .expect_err("symlinked DB path must be refused even when the target is 0600");
        assert!(format!("{err}").contains("symlink"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlite_store_applies_schema_and_persists_core_records() {
        let store = SqliteStore::open_in_memory().expect("open in-memory sqlite");
        store
            .apply_migrations()
            .expect("schema migration should succeed");

        store
            .upsert_user(&UserRow {
                user_id: "user-1".to_owned(),
                email: "alice@example.local".to_owned(),
                mfa_enabled: true,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("user upsert should succeed");

        store
            .upsert_node(&NodeRow {
                node_id: "node-1".to_owned(),
                owner_user_id: "user-1".to_owned(),
                hostname: "mini-pc-1".to_owned(),
                os: "linux".to_owned(),
                tags_csv: "servers,exit-capable".to_owned(),
                public_key_hex: "aa".repeat(32),
                last_seen_unix: 120,
                updated_at_unix: 120,
                created_at_unix: 100,
            })
            .expect("node upsert should succeed");

        let user_exists = store
            .user_exists("user-1")
            .expect("user existence query should succeed");
        let node_exists = store
            .node_exists("node-1")
            .expect("node existence query should succeed");
        let missing_user_exists = store
            .user_exists("missing-user")
            .expect("missing user existence query should succeed");
        let missing_node_exists = store
            .node_exists("missing-node")
            .expect("missing node existence query should succeed");

        assert!(user_exists);
        assert!(node_exists);
        assert!(!missing_user_exists);
        assert!(!missing_node_exists);
    }

    #[test]
    fn sqlite_store_enforces_single_use_consume_semantics() {
        let mut store = SqliteStore::open_in_memory().expect("open in-memory sqlite");
        store
            .apply_migrations()
            .expect("schema migration should succeed");

        store
            .upsert_user(&UserRow {
                user_id: "user-1".to_owned(),
                email: "alice@example.local".to_owned(),
                mfa_enabled: true,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("user upsert should succeed");

        store
            .insert_credential(&CredentialRow {
                credential_id: "cred-1".to_owned(),
                creator_user_id: "user-1".to_owned(),
                scope: "tag:servers".to_owned(),
                credential_kind: "throwaway".to_owned(),
                state: "created".to_owned(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 300,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_owned(),
            })
            .expect("credential insert should succeed");

        let first = store
            .consume_single_use_credential("cred-1", 150)
            .expect("consume should execute");
        let second = store
            .consume_single_use_credential("cred-1", 151)
            .expect("second consume should execute");

        assert!(first);
        assert!(!second);
        let state = store
            .credential_state("cred-1")
            .expect("state query should succeed")
            .expect("credential should exist");
        assert_eq!(state, "used");
    }

    #[test]
    fn sqlcipher_keyed_open_survives_reopen_under_same_key() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        {
            let store = SqliteStore::open_keyed(&db, &test_key()).expect("keyed open");
            store.apply_migrations().expect("migrations");
            store
                .upsert_user(&UserRow {
                    user_id: "user-1".to_owned(),
                    email: "alice@example.local".to_owned(),
                    mfa_enabled: true,
                    created_at_unix: 100,
                    updated_at_unix: 100,
                })
                .expect("user upsert");
        }
        let reopened = SqliteStore::open_keyed(&db, &test_key()).expect("reopen under same key");
        reopened.apply_migrations().expect("re-apply migrations");
        assert!(
            reopened
                .user_exists("user-1")
                .expect("row survives close/reopen"),
            "data written before close must be readable after keyed reopen"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlcipher_wrong_key_fails_closed() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-wrongkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        {
            let store = SqliteStore::open_keyed(&db, &test_key()).expect("keyed open");
            store.apply_migrations().expect("migrations");
        }
        let err = SqliteStore::open_keyed(&db, &other_key())
            .expect_err("wrong key must fail loudly, not read as empty db");
        assert!(
            matches!(err, PersistenceError::WrongKeyOrCorrupt),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlcipher_database_on_disk_is_not_plaintext_sqlite() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-magic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        {
            let store = SqliteStore::open_keyed(&db, &test_key()).expect("keyed open");
            store.apply_migrations().expect("migrations");
            store
                .upsert_user(&UserRow {
                    user_id: "user-1".to_owned(),
                    email: "alice@example.local".to_owned(),
                    mfa_enabled: false,
                    created_at_unix: 100,
                    updated_at_unix: 100,
                })
                .expect("user upsert");
        } // drop: sqlite checkpoints WAL into the main db on last close
        let bytes = std::fs::read(&db).expect("read db");
        assert!(
            bytes.len() < 16 || bytes[..16] != *b"SQLite format 3\x00",
            "on-disk control.db must not start with the plaintext SQLite magic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_roundtrip_plaintext_to_sqlcipher_preserves_rows() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        seed_plaintext_db(&db);
        let plaintext = std::fs::read(&db).expect("read plaintext db");
        assert!(plaintext.len() >= 16 && plaintext[..16] == *b"SQLite format 3\x00");

        migrate_plaintext_control_db(&db, &test_key()).expect("migration succeeds");

        let after = std::fs::read(&db).expect("read migrated db");
        assert!(
            after.len() < 16 || after[..16] != *b"SQLite format 3\x00",
            "post-migration db must not be plaintext sqlite"
        );
        assert!(
            !dir.join("control.db.migrate").exists(),
            "migration scratch file must be gone after cutover"
        );
        let store = SqliteStore::open_keyed(&db, &test_key()).expect("keyed open post-migration");
        assert!(
            store
                .user_exists("user-1")
                .expect("pre-migration row readable under key"),
            "rows must survive the plaintext->sqlcipher migration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_restarts_cleanly_after_crash_residue() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-crash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        seed_plaintext_db(&db);
        std::fs::write(dir.join("control.db.migrate"), b"partial ciphertext")
            .expect("seed crash residue");

        migrate_plaintext_control_db(&db, &test_key())
            .expect("stale .migrate must not block a rerun");

        let store = SqliteStore::open_keyed(&db, &test_key()).expect("keyed open post-migration");
        assert!(
            store.user_exists("user-1").expect("row check"),
            "rows must survive crash-restart migration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_fresh_install_is_a_noop() {
        let dir = std::env::temp_dir().join(format!("rn-atrest-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        migrate_plaintext_control_db(&db, &test_key()).expect("no file: fresh install");
        assert!(
            !db.exists(),
            "fresh-install migration must not create files"
        );
        // A partial-header (too short) file carries no data: treated as fresh.
        std::fs::write(&db, b"short").expect("seed short file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))
                .expect("chmod short file");
        }
        migrate_plaintext_control_db(&db, &test_key()).expect("short file: fresh install");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keystore_key_unwrap_is_strictly_32_bytes() {
        let good = SqlcipherKey::from_keystore(&StubBackend(Some(vec![0x11u8; 32])))
            .expect("32-byte keystore plaintext accepted");
        let dir = std::env::temp_dir().join(format!("rn-atrest-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        SqliteStore::open_keyed(&db, &good).expect("keystore-sourced key opens the database");
        let _ = std::fs::remove_dir_all(&dir);

        let short = SqlcipherKey::from_keystore(&StubBackend(Some(vec![0x11u8; 31])))
            .expect_err("31-byte plaintext must fail closed");
        assert!(
            matches!(short, PersistenceError::InvariantViolation(_)),
            "unexpected error: {short}"
        );

        let missing = SqlcipherKey::from_keystore(&StubBackend(None))
            .expect_err("missing keystore item must fail closed");
        assert!(
            matches!(missing, PersistenceError::InvariantViolation(_)),
            "unexpected error: {missing}"
        );
    }
}
