-- AQ-249 / ADR-027: remove email-based identity from Rustynet. Owner and
-- user ids are local handles, never email addresses. This migration drops
-- the legacy `users.email` column (and its UNIQUE index) from stores
-- created before the removal.
--
-- `ALTER TABLE ... DROP COLUMN` cannot be used here: SQLite refuses to drop
-- a column carrying a UNIQUE constraint, so the table is rebuilt instead
-- (the documented 12-step procedure, reduced to the steps this schema
-- needs: no triggers or views reference `users`).
--
-- Applied by `persistence.rs::apply_migrations` only when
-- `pragma_table_info('users')` still lists `email`, which makes the step
-- idempotent; fresh stores never run it.
--
-- Eviction (AQ-45 §5 pattern): `secure_delete = ON` before the rebuild so
-- the dropped pages are zero-filled, then VACUUM compacts the file and
-- `wal_checkpoint(TRUNCATE)` truncates the -wal sidecar, so the old email
-- values survive in neither free pages nor the -wal.

PRAGMA foreign_keys = OFF;
PRAGMA secure_delete = ON;
BEGIN IMMEDIATE;
CREATE TABLE users_email_rebuild (
    user_id TEXT PRIMARY KEY,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);
INSERT INTO users_email_rebuild (user_id, mfa_enabled, created_at_unix, updated_at_unix)
    SELECT user_id, mfa_enabled, created_at_unix, updated_at_unix FROM users;
DROP TABLE users;
ALTER TABLE users_email_rebuild RENAME TO users;
COMMIT;
PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
VACUUM;
PRAGMA wal_checkpoint(TRUNCATE);
