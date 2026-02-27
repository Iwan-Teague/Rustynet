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
