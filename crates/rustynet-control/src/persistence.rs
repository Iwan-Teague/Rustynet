#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Transaction, params};

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
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::Sqlite(err) => write!(f, "sqlite error: {err}"),
            PersistenceError::InvariantViolation(message) => f.write_str(message),
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

#[derive(Debug)]
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let path = path.as_ref();
        // RSA-0017: the control-plane DB holds node pubkeys, user MFA posture and
        // single-use credential state. The file-based TrustState gates access via
        // a permission check; the sqlite path had none, and WAL mode creates
        // group/other-readable `-wal`/`-shm` sidecars under the default umask. Fail
        // closed on a pre-existing insecure DB or sidecar, then enforce 0o600 on
        // the (possibly freshly created) files.
        enforce_sqlite_path_secure(path)?;
        let wal = sidecar_path(path, "-wal");
        let shm = sidecar_path(path, "-shm");
        enforce_sqlite_path_secure(&wal)?;
        enforce_sqlite_path_secure(&shm)?;
        let conn = Connection::open(path)?;
        // Lock down whatever `open` (or a prior WAL checkpoint) created.
        tighten_sqlite_file(path)?;
        tighten_sqlite_file(&wal)?;
        tighten_sqlite_file(&shm)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, PersistenceError> {
        let conn = Connection::open_in_memory()?;
        Ok(Self { conn })
    }

    pub fn apply_migrations(&self) -> Result<(), PersistenceError> {
        self.conn
            .execute_batch(include_str!("../migrations/0001_init.sql"))?;
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
    use super::{CredentialRow, NodeRow, SqliteStore, UserRow};

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_rejects_group_readable_db() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        std::fs::write(&db, b"").expect("seed db file");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        let err = SqliteStore::open(&db).expect_err("group/other-readable DB must fail closed");
        assert!(format!("{err}").contains("group/other-accessible"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0017_open_creates_and_tightens_db_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rn-rsa0017b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        let store = SqliteStore::open(&db).expect("fresh DB opens");
        store.apply_migrations().expect("migrations");
        let mode = std::fs::metadata(&db)
            .expect("stat db")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "freshly created DB must be locked to 0o600");
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
}
