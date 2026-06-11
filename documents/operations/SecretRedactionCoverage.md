# Secret Redaction Coverage

## Covered Ingestion Paths
- MDM configuration payloads.
- Environment-variable ingestion.
- CLI argument ingestion.
- API payload ingestion.
- UI form ingestion.
- Structured log fields.

## Enforcement
- `crates/rustynet-control/src/operations.rs` applies key/value redaction rules before logging.
- Sensitive key names (`token`, `secret`, `password`, `credential`, `private_key`, `nonce`) are always redacted.
- Sensitive value signatures (`Bearer`, `sk_`, `vault://`, PEM markers) are always redacted.

## Verification
- Unit test `redaction_covers_all_ingestion_paths`.
- Unit test `structured_logger_never_writes_cleartext_secrets`.
- Token and credential debug redaction tests in `crates/rustynet-control/src/lib.rs`.

## Service-Hosting Surfaces (D13: `nas`, `llm`)

- `rustynet-nas` logs carry peer ids, session ids, byte/chunk
  counts, and refusal reasons only — never file contents, chunk
  plaintext, content beyond its hash, or at-rest key material. The
  at-rest key is held in process memory and zeroized on drop
  (`NasStore::drop`).
- `rustynet-llm-gateway` logs carry peer ids, model names, token
  COUNTS, and refusal reasons only — never prompt text, completion
  text, or uploaded context (uploaded context is session-memory
  only and is dropped on connection end, never persisted or
  logged).
- Session tokens are never logged; audit events carry the token
  THUMBPRINT only (`SessionToken::thumbprint`, 16 hex chars of a
  SHA-256 over payload+signature).
- The daemon-side access audit type
  (`rustynetd::service_exposure::ServiceAccessEvent`) is
  redaction-safe by construction: its `Display` emits
  ids/decision/session/thumbprint fields only.

### Verification
- Session-token thumbprint tests in
  `crates/rustynet-llm-gateway/src/session.rs`.
- Service-binary code review pin: no `Debug`/format of chunk
  plaintext, prompts, or key bytes in `crates/rustynet-nas/src/main.rs`
  / `crates/rustynet-llm-gateway/src/main.rs` log statements.
