#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params};

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
        let conn = Connection::open(path)?;
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

    #[test]
    fn sqlite_store_applies_schema_and_persists_core_records() {
        let store = SqliteStore::open_in_memory().expect("open in-memory sqlite");
        store
            .apply_migrations()
            .expect("schema migration should succeed");

        store
            .upsert_user(&UserRow {
                user_id: "user-1".to_string(),
                email: "alice@example.local".to_string(),
                mfa_enabled: true,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("user upsert should succeed");

        store
            .upsert_node(&NodeRow {
                node_id: "node-1".to_string(),
                owner_user_id: "user-1".to_string(),
                hostname: "mini-pc-1".to_string(),
                os: "linux".to_string(),
                tags_csv: "servers,exit-capable".to_string(),
                public_key_hex: "aa".repeat(32),
                last_seen_unix: 120,
                updated_at_unix: 120,
                created_at_unix: 100,
            })
            .expect("node upsert should succeed");
    }

    #[test]
    fn sqlite_store_enforces_single_use_consume_semantics() {
        let mut store = SqliteStore::open_in_memory().expect("open in-memory sqlite");
        store
            .apply_migrations()
            .expect("schema migration should succeed");

        store
            .upsert_user(&UserRow {
                user_id: "user-1".to_string(),
                email: "alice@example.local".to_string(),
                mfa_enabled: true,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("user upsert should succeed");

        store
            .insert_credential(&CredentialRow {
                credential_id: "cred-1".to_string(),
                creator_user_id: "user-1".to_string(),
                scope: "tag:servers".to_string(),
                credential_kind: "throwaway".to_string(),
                state: "created".to_string(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 300,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_string(),
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
