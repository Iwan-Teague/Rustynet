-- Rustynet Phase 2 SQLite baseline schema.
-- Designed so table-level concepts are portable to PostgreSQL in later phases.

PRAGMA journal_mode = WAL;
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

CREATE TABLE IF NOT EXISTS enrollment_credentials (
    credential_id TEXT PRIMARY KEY,
    creator_user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    credential_kind TEXT NOT NULL CHECK (credential_kind IN ('throwaway','reusable')),
    state TEXT NOT NULL CHECK (state IN ('created','used','expired','revoked')),
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    expires_at_unix INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    storage_policy TEXT NOT NULL,
    FOREIGN KEY(creator_user_id) REFERENCES users(user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_single_use_guard
ON enrollment_credentials(credential_id, state, uses, max_uses);

CREATE TABLE IF NOT EXISTS credential_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    event_at_unix INTEGER NOT NULL,
    actor_user_id TEXT NOT NULL,
    FOREIGN KEY(credential_id) REFERENCES enrollment_credentials(credential_id)
);

CREATE TABLE IF NOT EXISTS trust_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    generation INTEGER NOT NULL,
    signing_fingerprint TEXT NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    integrity_digest_hex TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    identity TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    failure_class TEXT NOT NULL,
    limiter_decision TEXT NOT NULL,
    event_at_unix INTEGER NOT NULL
);
