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
        // ADR-027 / AQ-249: `users.email` is no longer part of the schema
        // (owner ids are local handles, never email addresses). Stores created
        // before the removal still carry the column; the rebuild-and-evict
        // migration runs only when the column is present, so the step is
        // idempotent and free for fresh stores.
        let has_email_column: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'email')",
            [],
            |row| row.get(0),
        )?;
        if has_email_column {
            self.conn
                .execute_batch(include_str!("../migrations/0002_drop_users_email.sql"))?;
        }
        // AQ-249 review D3: the batch's bare `PRAGMA foreign_key_check;`
        // statement only REPORTS violation rows — it cannot abort anything
        // (0002's `COMMIT` has already happened). Fail closed here instead:
        // a non-empty check means the store carries a child row whose parent
        // is gone, and the store must not open.
        let fk_violations: i64 =
            self.conn
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get(0)
                })?;
        if fk_violations != 0 {
            return Err(PersistenceError::InvariantViolation(
                "control-plane DB failed the post-migration foreign-key check; refusing to open (fail closed)",
            ));
        }
        Ok(())
    }

    pub fn upsert_user(&self, user: &UserRow) -> Result<(), PersistenceError> {
        self.conn.execute(
            "INSERT INTO users (user_id, mfa_enabled, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(user_id) DO UPDATE SET
                mfa_enabled = excluded.mfa_enabled,
                updated_at_unix = excluded.updated_at_unix",
            params![
                user.user_id,
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
    // Only the unix-gated AQ-249 migration test matches on this type; on
    // other targets the import would be unused.
    #[cfg(unix)]
    use super::PersistenceError;

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

        let err = SqliteStore::open(&db).expect_err("group-readable WAL must fail closed");
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
        let err = SqliteStore::open(&link)
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

    /// AQ-249 / ADR-027 witness: a store created by the pre-AQ-249 schema
    /// (with `users.email`) must come out of `apply_migrations` with the
    /// column gone, the row data intact, foreign keys intact, and — byte
    /// level — the old email value absent from both the main database file
    /// and the `-wal` sidecar (AQ-45 §5 eviction pattern: secure_delete +
    /// VACUUM + wal_checkpoint(TRUNCATE)).
    #[cfg(unix)]
    #[test]
    fn aq249_migration_drops_legacy_email_column_and_evicts_its_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let known_email = "alice@example.local";
        let dir = std::env::temp_dir().join(format!("rn-aq249-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        let wal = dir.join("control.db-wal");

        // Build a legacy (0001-shaped, pre-AQ-249) store by hand: the exact
        // users/nodes declarations the old 0001 shipped, one known email
        // value, and one node row that references the user through the
        // foreign key the rebuild must preserve.
        {
            let conn = rusqlite::Connection::open(&db).expect("legacy db opens");
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS users (
                     user_id TEXT PRIMARY KEY,
                     email TEXT NOT NULL UNIQUE,
                     mfa_enabled INTEGER NOT NULL DEFAULT 0,
                     created_at_unix INTEGER NOT NULL,
                     updated_at_unix INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS nodes (
                     node_id TEXT PRIMARY KEY,
                     owner_user_id TEXT NOT NULL,
                     hostname TEXT NOT NULL,
                     os TEXT NOT NULL,
                     tags_csv TEXT NOT NULL,
                     public_key_hex TEXT NOT NULL,
                     last_seen_unix INTEGER NOT NULL,
                     created_at_unix INTEGER NOT NULL,
                     updated_at_unix INTEGER NOT NULL,
                     FOREIGN KEY(owner_user_id) REFERENCES users(user_id)
                 );
                 INSERT INTO users (user_id, email, mfa_enabled, created_at_unix, updated_at_unix)
                     VALUES ('alice', 'alice@example.local', 0, 100, 100);
                 INSERT INTO nodes (
                     node_id, owner_user_id, hostname, os, tags_csv, public_key_hex,
                     last_seen_unix, created_at_unix, updated_at_unix
                 ) VALUES ('node-1', 'alice', 'mini-pc-1', 'linux', 'servers', 'aa', 120, 100, 100);",
            )
            .expect("legacy schema and rows");
        }
        // The legacy file was created outside `SqliteStore::open`, so it has
        // no RSA-0017 lockdown yet; apply it the way the store would.
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))
            .expect("chmod legacy db");

        let store = SqliteStore::open(&db).expect("legacy store opens");
        store.apply_migrations().expect("migration should succeed");

        let email_column_gone: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'email')",
                [],
                |row| row.get(0),
            )
            .expect("pragma_table_info query");
        assert!(
            !email_column_gone,
            "users.email must be gone after migration"
        );

        let fk_violations: i64 = store
            .conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("foreign_key_check query");
        assert_eq!(fk_violations, 0, "rebuild must not break foreign keys");

        let user_survives = store
            .user_exists("alice")
            .expect("user lookup after migration");
        assert!(user_survives, "the user row must survive the rebuild");
        let node_survives = store
            .node_exists("node-1")
            .expect("node lookup after migration");
        assert!(node_survives, "the child node row must survive the rebuild");

        // Byte-level eviction witness: neither the main db nor the -wal
        // sidecar may still contain the old email value.
        let db_bytes = std::fs::read(&db).expect("read raw db bytes");
        assert!(
            !db_bytes
                .windows(known_email.len())
                .any(|w| w == known_email.as_bytes()),
            "known email value must not survive in the main database bytes"
        );
        let wal_bytes = std::fs::read(&wal).unwrap_or_default();
        assert!(
            !wal_bytes
                .windows(known_email.len())
                .any(|w| w == known_email.as_bytes()),
            "known email value must not survive in the -wal sidecar bytes"
        );

        // Idempotence: a second apply on the migrated store is a no-op.
        store
            .apply_migrations()
            .expect("second apply_migrations is idempotent");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AQ-249: a store created by the current schema never has the email
    /// column, so the drop migration must not run for it (fresh stores are
    /// created email-less and stay that way).
    #[test]
    fn aq249_fresh_store_is_created_without_email_column() {
        let dir = std::env::temp_dir().join(format!("rn-aq249-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        let store = SqliteStore::open(&db).expect("fresh store opens");
        store.apply_migrations().expect("migrations");

        let email_column_present: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'email')",
                [],
                |row| row.get(0),
            )
            .expect("pragma_table_info query");
        assert!(
            !email_column_present,
            "fresh stores must be created without users.email"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AQ-249 review D3 witness: a legacy store that already carries a
    /// foreign-key violation (a node row whose owner user is gone, inserted
    /// with `foreign_keys = OFF`) must make `apply_migrations` fail closed
    /// instead of opening. The bare `PRAGMA foreign_key_check;` inside the
    /// 0002 batch cannot do this — it only reports rows — so the check lives
    /// in `apply_migrations`.
    #[cfg(unix)]
    #[test]
    fn aq249_d3_apply_migrations_fails_closed_on_foreign_key_violation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rn-aq249-d3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");

        // Build a legacy (0001-shaped, pre-AQ-249) store by hand and inject
        // an orphaned child row while foreign-key enforcement is off — the
        // way a real damaged store could have come to carry one.
        {
            let conn = rusqlite::Connection::open(&db).expect("legacy db opens");
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = OFF;
                 CREATE TABLE IF NOT EXISTS users (
                     user_id TEXT PRIMARY KEY,
                     email TEXT NOT NULL UNIQUE,
                     mfa_enabled INTEGER NOT NULL DEFAULT 0,
                     created_at_unix INTEGER NOT NULL,
                     updated_at_unix INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS nodes (
                     node_id TEXT PRIMARY KEY,
                     owner_user_id TEXT NOT NULL,
                     hostname TEXT NOT NULL,
                     os TEXT NOT NULL,
                     tags_csv TEXT NOT NULL,
                     public_key_hex TEXT NOT NULL,
                     last_seen_unix INTEGER NOT NULL,
                     created_at_unix INTEGER NOT NULL,
                     updated_at_unix INTEGER NOT NULL,
                     FOREIGN KEY(owner_user_id) REFERENCES users(user_id)
                 );
                 INSERT INTO users (user_id, email, mfa_enabled, created_at_unix, updated_at_unix)
                     VALUES ('alice', 'alice@example.local', 0, 100, 100);
                 INSERT INTO nodes (
                     node_id, owner_user_id, hostname, os, tags_csv, public_key_hex,
                     last_seen_unix, created_at_unix, updated_at_unix
                 ) VALUES ('orphan-node', 'ghost-user', 'mini-pc-2', 'linux', 'servers',
                           'bb', 120, 100, 100);",
            )
            .expect("legacy schema and orphaned row");
        }
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))
            .expect("chmod legacy db");

        let store = SqliteStore::open(&db).expect("legacy store opens");
        let err = store
            .apply_migrations()
            .expect_err("a store with an orphaned node row must fail closed");
        match err {
            PersistenceError::InvariantViolation(message) => {
                assert!(
                    message.contains("foreign-key check"),
                    "unexpected invariant message: {message}"
                );
            }
            other => panic!("expected InvariantViolation, got: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AQ-249 review D3 counterpart: a clean store — legacy or fresh — must
    /// still migrate; the fail-closed check must never fire on a healthy
    /// database.
    #[test]
    fn aq249_d3_clean_store_still_migrates_with_zero_foreign_key_violations() {
        let dir = std::env::temp_dir().join(format!("rn-aq249-d3-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let db = dir.join("control.db");
        let store = SqliteStore::open(&db).expect("clean store opens");
        store
            .apply_migrations()
            .expect("a clean store must migrate without error");

        let fk_violations: i64 = store
            .conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("foreign_key_check query");
        assert_eq!(fk_violations, 0, "a clean store has no FK violations");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
