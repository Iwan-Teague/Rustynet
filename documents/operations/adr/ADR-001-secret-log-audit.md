# ADR-001: Static no-secret-leakage source-walk audit

- Status: Accepted
- Date: 2026-05-17

## Context

Rustynet handles several classes of long-lived secret material:
WireGuard private keys, passphrases that unlock encrypted credential
stores, signing keys, and wrapped key material. The security minimum
bar forbids any of these from reaching a log sink, a stderr line, a
panic message, a backtrace, or any other operator-visible output.

The codebase already enforces structural defences:

- Secret-bearing types (`PassphraseMaterial`, `WrappedKeyMaterial`,
  `RuntimePrivateKey`, `SigningKeyMaterial`) have no `Debug` /
  `Display` / `ToString` impls — `{:?}` on them does not compile.
- The production logger has a redaction layer.

These are necessary but not sufficient. Two leak shapes routinely
slip past them:

1. **Dev-loop debug prints.** A contributor adds an
   `eprintln!("dbg: passphrase_bytes={passphrase_bytes:?}")` while
   tracking down a bug. The redaction layer in the production logger
   never sees the formatter — `eprintln!` writes straight to stderr.
   If the line survives review, the leak ships.
2. **Encoder-laundered prints.** `hex::encode(passphrase_bytes)`,
   `base64::engine::general_purpose::STANDARD.encode(secret_bytes)`,
   and similar shapes convert the typed material to a `String` and
   then format the `String` — the no-`Debug` defence is bypassed.

Alternatives considered:

- **Runtime redaction at the logger boundary.** Rejected: only catches
  output that goes through the logger. `eprintln!`, `println!`,
  `panic!`, `dbg!`, `write!` to a borrowed `Stderr`, and direct
  `io::stderr().write_all(...)` all bypass it. This is the most
  common dev-loop leak shape.
- **Forbid `eprintln!` / `println!` workspace-wide via clippy.**
  Rejected as too coarse: those macros have legitimate uses in
  CLI binaries that emit user-facing output, in test harnesses, and
  in operator-facing error paths.
- **Trust review + CI grep.** Rejected as fragile: a `grep "passphrase"`
  has high false-positive volume (every config-key name matches), and
  the encoder-laundered shapes have no single literal to grep for.

## Decision

Land a `cargo test`-time static source-walk audit at
`crates/rustynetd/src/secret_log_audit.rs` with multiple
complementary scanners. Every `cargo test` invocation walks every
`.rs` file under `crates/rustynetd/src/` and
`crates/rustynet-cli/src/` and fails closed when any of these shapes
appears outside the narrow `audited_path_allowlist`:

1. **Forbidden placeholder tokens in format-string macros** — the
   canonical secret identifiers (`passphrase_bytes`,
   `private_key_bytes`, `signing_key_bytes`, `wrapped_secret`,
   `decrypted_secret`, `plaintext_key`, `raw_passphrase`,
   `secret_bytes`) appearing inside `{token}` / `{token:?}` /
   `{token:x?}` shapes in `println!` / `eprintln!` / `print!` /
   `format!` / `write!` / `writeln!` / `panic!` / tracing macros.
   Commented-out lines and pure path-only logs are ignored.
2. **Forbidden `Debug` derive / impl on secret-bearing types** —
   re-asserts the structural guarantee at audit time so a future
   `#[derive(Debug)]` on `PassphraseMaterial` trips this gate
   before it trips a production leak.
3. **Forbidden hex-encoder shapes** — `hex::encode(forbidden_ident)`
   and `format!("{:02x}…", forbidden_ident[..])` inside any log
   macro.
4. **Forbidden base64-encoder shapes** — `base64::*encode(...)` and
   `STANDARD.encode(...)` (covers both the legacy free-function
   form and the modern fully-qualified engine form).
5. **Forbidden `Display` / `ToString` impl on canonical secret-bearing
   types** — same identifier list as scanner 2.

The audit runs as a regular `#[test]` so it participates in every
`cargo test --workspace`, every PR check, and every local pre-commit
run — no separate gate to forget.

## Consequences

**Positive**

- Catches the canonical leak shapes at PR time instead of at
  post-mortem time.
- Defence-in-depth alongside the structural `Debug` / `Display` bans:
  even if a contributor adds `#[derive(Debug)]` accidentally, scanner
  2 fails the build.
- Zero runtime cost (audit runs only under `cargo test`).
- Fast feedback loop: each scanner is a regex-driven file walk and
  finishes in well under a second.
- Encoder-laundered shapes (`hex::encode`, `base64::encode`) are
  caught — the no-`Debug` defence alone cannot see them.

**Negative**

- False-positive surface when a legitimate identifier matches a
  forbidden token name. Mitigated by:
  - keeping the forbidden-identifier list small and unambiguous
    (no contributor would name a non-secret `passphrase_bytes`);
  - the `audited_path_allowlist`, narrowly scoped to the audit
    module itself, which necessarily mentions the forbidden tokens
    as match constants.
- Each new secret-bearing type requires a deliberate addition to the
  forbidden-identifier list. This is intentional: the cost of adding
  one line forces the contributor to think about the leak surface
  for the new type.
- Scope is limited to `crates/rustynetd/src/` and
  `crates/rustynet-cli/src/`. Other crates rely on the structural
  bans plus review. Extension to additional crates is straightforward
  when justified.

## Implementation

Primary module: `crates/rustynetd/src/secret_log_audit.rs`.

Composition at acceptance (2026-05-17):

- 5 scanners (one per forbidden shape listed in the Decision section).
- 3 workspace sweeps (one each for `crates/rustynetd/src/`,
  `crates/rustynet-cli/src/`, and the joint walk).
- Self-tests that construct synthetic offending lines in-memory and
  assert the scanner flags them — these are the audit's own
  regression coverage and live next to the scanner code.
- `audited_path_allowlist` — narrow allowlist of paths that may
  legitimately mention the forbidden tokens (the audit module itself).

Composition as of 2026-05-18 (tracked here so the ADR doesn't drift
from the live module; X3 backlog #2 + #3 + #4 extensions landed):

- **7 scanners total**:
  - the original 5 above,
  - **`scan_source_for_secret_material_equality`** — raw `==`/`!=`
    on forbidden tokens (token / csrf / session_key / nonce / mac /
    hmac / session_id / signature) without `ct_eq` on the line, with
    a structured `(path, line, justification)` allowlist
    (X3 extension #2, commit 8bc02ce).
  - **`scan_source_for_deprecated_crypto_imports`** — rejects
    `use sha1` / `use md5` / `use md_5` / `use des` / `use des3` /
    `use triple_des` with a boundary-terminator check that rejects
    safe-name lookalikes (`sha2`, `sha3`, `descriptor`, `md_hashlib`)
    (X3 extension #4, commit ca85269).
- Forbidden-placeholder-tokens list grew from 8 → 9 with the
  addition of `signing_seed` (X3 extension #3, commit 8935dfb).
- Workspace sweeps expanded — the secret-material-equality + the
  deprecated-crypto-imports scanners both walk `crates/` workspace-
  wide (broader than the original `crates/rustynetd/src` +
  `crates/rustynet-cli/src` scope, because the patterns can leak
  outside the daemon crate).
- Self-test count grew from ~22 to 45 (pinned by the
  `secret_log_audit:45` floor in the shared regression-coverage
  group; see ADR-002).

Current tree: **0 offenders** across all 7 scanners.

The audit is reachable from `cargo test --lib secret_log_audit` for
fast iteration when adding a new scanner or a new forbidden token.

## Related

- [`../SecurityPostureSummary.md`](../SecurityPostureSummary.md) — Section 3 documents the live offender count and scanner inventory.
- [`../SecretRedactionCoverage.md`](../SecretRedactionCoverage.md) — runtime-redaction coverage map, complementary to this static audit.
- Backlog item X3 (Platform Improvement Backlog 2026-05-14).
- [ADR-002](./ADR-002-regression-coverage-floor-gate.md) — the regression-coverage gate that pins this module's test count so its scanners cannot be silently deleted.
