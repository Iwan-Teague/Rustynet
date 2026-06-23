# Test Coverage Improvement Plan (2026-05-24)

Status: active planning ledger. This document proposes prioritized test
coverage work for the Rustynet workspace. It is the owning ledger for the
test-coverage track; record progress and evidence here as items land.

## Scope and method

Findings combine: per-crate source/test density metrics, the coverage-gate
machinery (`scripts/ci/regression_coverage_gates.sh`), the fuzz/property-test
inventory, and line-level audits of the daemon internals, the security
crates, and the CLI/backends.

Line numbers are indicative (captured 2026-05-24) and must be re-confirmed
when writing each test. Everything is framed against the CLAUDE.md security
bar: default-deny, fail-closed, anti-replay/rollback, signed-state
validation, no secret logging, argv-only exec, and the rule that every
security control needs both an enforcement point and a verification test.

## Per-crate density snapshot (2026-05-24)

| Crate | Src lines | Inline unit tests | Notes |
|---|---|---|---|
| rustynet-sysinfo | 6,677 | 0 | single `lib.rs`, 175 internal fns, not in coverage gates |
| rustynet-backend-userspace | 228 | 0 | 2 trivial integration tests only |
| rustynet-windows-native | 1,263 | 3 | cfg-gated; Linux CI cannot exercise |
| rustynet-policy | 641 | 10 | default-deny ACL/route engine |
| rustynet-local-security | 384 | 6 | key custody / permission checks |
| rustynet-control | 15,596 | 233 | `roles.rs` (147 lines) has 0 tests |
| rustynet-crypto | 1,623 | 23 | signing/verification primitives |
| rustynet-dns-zone | 1,078 | 13 | signed zone wire format |
| rustynet-relay | 7,252 | 134 | — |
| rustynet-backend-wireguard | 19,286 | ~200 | `userspace_shared/engine.rs` (633 lines) has 0 tests |
| rustynet-cli | 155,306 | 1,393 | large; mix of product logic + lab tooling |
| rustynetd | 92,920 | 1,618 | dense overall; some low-density security files |

## Part A — Structural findings (high-leverage levers)

These shape how gaps should be closed, not just where.

1. **The coverage gate protects a narrow surface.**
   `regression_coverage_gates.sh` pins floors for ~20 platform-hardening
   verifier modules (`linux_*` / `macos_*` / `windows_*`) plus
   `secret_log_audit`. The dataplane, traversal, gossip, enrollment,
   key-rotation, and the entire `control` / `policy` / `crypto` /
   `dns-zone` / `sysinfo` / backend code have no floor; silent test-count
   regressions there are invisible.

2. **No line/branch coverage measurement exists.** Floors count tests, not
   lines. A `cargo llvm-cov` baseline would have surfaced sysinfo
   automatically.

3. **No property-based testing (0 proptest/quickcheck).** Yet the gate
   comments describe dozens of hand-written per-variant serde round-trip and
   boundary tests — exactly what proptest generalizes (round-trip
   invariants, parser-never-panics, monotonicity, idempotence).

4. **Fuzzing is narrow (3 targets):** IPC command parse + membership state /
   signed-update decode. Other untrusted-input decoders are unfuzzed.

5. **A recurring shape: IO fused to parsing.** Most untested logic is not
   untestable — it is welded to a syscall. sysinfo is the extreme case
   (136 `Command::new` + 78 file reads with inline parsing). The dominant
   refactor pattern is "extract `parse_X(&str) -> T` from the IO shim," then
   test the pure function.

6. **Audits are happy-path heavy; negative tests are the gap.** Many
   security controls are tested for the accept path but lack the reject path
   (invalid signature, stale/expired state, wrong permissions, malformed
   input, integer wraparound). This is the most common deficiency and the
   one the security bar most directly requires.

## Part B — Prioritized workstreams

### P0 — Security-critical, do first

#### P0.1 — `rustynet-control/src/roles.rs`: zero tests on role-capability parsing/enforcement
147 lines, 0 tests; controls the capability set used in trust decisions.

Status 2026-05-27: landed the seed unit-test batch in
`crates/rustynet-control/src/roles.rs` covering canonical/alias parsing,
empty/whitespace/unknown rejection, CSV trimming/trailing-comma behavior,
mixed-invalid rejection, canonicalization idempotence, anchor preset
completeness, and stable CSV rendering. Evidence:
`CARGO_TARGET_DIR=/private/tmp/rustynet-target-roles cargo test -p rustynet-control --lib roles::tests`
passed 9/9 tests.

- `RoleCapability::parse()` (~L37-63): reject unknown/empty/whitespace; accept each known variant.
- `parse_role_capability_csv()` (~L127): empty CSV, trailing commas, whitespace-only items, mixed valid/invalid.
- `canonicalize_role_capabilities()` (~L118): dedup + sort idempotence (`[Client,Client]` -> `[Client]`).
- `anchor_role_capabilities()` (~L85): completeness assertion (Anchor + RelayHost + all 5 sub-caps) so a dropped capability is caught.

#### P0.2 — `rustynet-control/src/membership.rs`: negative tests for signed-state validation
Accept paths are covered; the security-relevant reject paths are not.

Status 2026-06-23: landed the `apply_signed_update` reject matrix + `validate()`
reject batch (9 new tests via a shared `signed_add_node_fixture` helper that
asserts the untampered control still applies, so no negative test can pass for
the wrong reason). Covered: expired record (`Expired`), future-dated /
clock-skew with the skew-window boundary accepted (`FutureDated`),
`prev_state_root` mismatch (`PrevStateRootMismatch`), network-id mismatch and
apply-time epoch-chain break (`InvalidTransition`), raw signature-byte tampering
— all-zero / single-bit-flip (`SignatureInvalid`) + truncated (fail-closed
decode error), and `validate()` rejecting empty network_id / zero quorum /
duplicate node_ids / quorum > active approvers. (`new_state_root` tampering was
already pinned by `replay_cache_not_updated_on_failed_update` →
`NewStateRootMismatch`; direct payload-capability tampering by
`tampered_service_hosting_capability_invalidates_signature`.) Evidence:
`cargo test -p rustynet-control --lib membership::tests` → 36/36; crate-wide
`cargo test -p rustynet-control --all-targets --all-features` → 296/296; fmt +
clippy `-D warnings` clean.

Follow-up landed 2026-06-23: membership-log chain-break detection is now pinned
by `membership_log_chain_tampering_is_detected`, which builds a 3-entry chained
log on disk and asserts `load_membership_log` fails closed
(`IntegrityMismatch`) on each of: reordering the middle/last entries, removing
the middle entry, and flipping a stored per-entry hash. **P0.2 complete.**

#### P0.3 — `rustynet-crypto`: negative tests on verification + fail-closed CSPRNG
Status 2026-05-27: added negative coverage for expired algorithm exceptions
and 63/65-byte attestation signatures. Existing CSPRNG regression coverage
already pins fallible key-custody material generation. Evidence:
`CARGO_TARGET_DIR=/private/tmp/rustynet-target-crypto-quick cargo test -p rustynet-crypto --lib`
passed 32/32 tests.

- Signature length validation: reject 63/65-byte sigs in `verify_attestation()` (~L796).
- Algorithm policy: reject an algorithm that is neither allowlisted nor denylisted (default-deny) and reject expired exceptions — `AlgorithmPolicy::validate()` (~L195).
- CSPRNG fail-closed: `try_generate_key_custody_material()` returns Err when OsRng is unavailable (inject failure) (~L918) — the failure branch is currently unexercised.

#### P0.4 — `rustynet-dns-zone`: untrusted wire-format parser under-tested
Status 2026-05-27: added malformed DNS-name and wire-parser negative tests
covering forbidden labels, label/name length, oversized bundle, oversized
line, excessive line count, unsupported version, duplicate field, and
field-count mismatch, plus tampered-signature rejection. Evidence:
`CARGO_TARGET_DIR=/private/tmp/rustynet-target-dns-quick cargo test -p rustynet-dns-zone --lib`
passed 17/17 tests.

- Bounds: oversized bundle / oversized line / too many lines rejected — `parse_signed_dns_zone_bundle_wire()` (~L291).
- Tampered signature rejected — `verify_signed_dns_zone_bundle()` (~L273).
- Unsupported version rejected (~L357); duplicate field rejected (~L344); field-count mismatch rejected (~L399).
- Malformed DNS names rejected (leading `.`, `*`, label >63, total >253) — `canonicalize_dns_relative_name()` (~L138).
- Then add a fuzz target over the wire decoder.

#### P0.5 — `rustynetd/src/dataplane.rs`: multi-factor default-deny truth tables
`ensure_lan_route_allowed()` (~L455) requires 4 independent conditions; only
the all-true path is tested. Add the full reject matrix:
`lan_access_enabled=false`, `selected_exit_node=None`, unadvertised CIDR,
ACL-deny-despite-advertised. Also verify the `connect_peer()` short-circuit:
flood-guard rejection must not bypass or hide policy evaluation (~L349-363).

#### P0.6 — `rustynetd/src/gossip_runtime.rs`: anti-replay watermark persistence failure modes
The watermark spool is the anti-replay authority but only in-memory happy
paths are tested.
- Persist-failure rolls back in-memory sequence (no skip) — `maybe_mint_and_broadcast()` (~L287).
- Restart after failed persist does not skip/replay a sequence.
- `load_gossip_watermark()` (~L576) rejects corrupt / missing-field / digest-mismatch files, and enforces a max-size cap (it currently lacks the size cap `key_rotation.rs` has).
- Confirm watermark IO error messages do not log the state-dir path (secret/PII-log mandate; flagged at ~L577).

### P1 — High value

#### P1.1 — `rustynet-sysinfo`: the largest single gap (6,677 lines, 0 tests; not in any gate)
The fix is architectural:
- **Split parse from IO**: for each `*_internal`, extract a pure `fn parse_X(output: &str) -> T`. Canonical example: `listening_sockets_summary_internal` fuses `Command::new("ss")` with bug-prone parsing (IPv6 colon slicing via `rfind(':')`, silent `parse().unwrap_or(0)`).
- **Test the parsers with golden fixtures** (captured `ss -tlnp`, `wg show`, `/proc/*`, cert, `getfacl`, `sysctl` outputs), including malformed/truncated/adversarial inputs — these parse OS-command output and are security-relevant.
- **Test the pure analysis fns directly** (no IO): `performance_regression_detection_internal`, `compare_to_baseline_internal` (threshold/percentage math).
- **Confirmed latent bug**: in `performance_regression_detection_internal` the `"decreasing"` arm is dead code (nested under `if change_percent > 50.0`), so `trend` is always `"increasing"`. A test should pin and fix this.
- Add the crate to the coverage-gate floor set once seeded.

Status 2026-06-23: **latent bug FIXED + pinned, first tests seeded.** The
`performance_regression_detection_internal` gate was `change_percent > 50.0`,
which not only made the `"decreasing"` arm dead code but *silently dropped every
significant decrease* (a real regression class — e.g. throughput falling). Now
gates on `change_percent.abs() > 50.0` with the sign selecting the trend label,
plus a guard skipping a zero first-sample (the division would yield inf/NaN).
Seeded the crate's first-ever `#[cfg(test)] mod tests` (7 tests): <2-sample
no-op, large-increase→increasing, **large-decrease→decreasing (the bug-fix
regression guard)**, within-threshold ignored both directions, zero-first-sample
skipped without panic, first/last-span semantics, and multi-metric grouping.
Evidence: `cargo test -p rustynet-sysinfo --lib` → 7/7. The only caller passes
`&[]`, so the behavior change has no downstream effect.

**Blocker discovered (separate from this item):** `rustynet-sysinfo` already
fails `cargo clippy --lib --all-features -- -D warnings` with ~35 pre-existing
findings (unused imports/vars — several platform-gated so they need per-`cfg`
care, never-read assignments, `uninlined_format_args`). This predates the test
work (verified: identical count with the change stashed; none reference the
edited fn or tests). It must be cleared before the crate can join the workspace
clippy/coverage gate — track as its own cleanup slice (mind the macOS-only
imports: do not blind-delete).

Remaining for P1.1: the parse/IO split + golden-fixture parser tests (the bulk
of the crate, incl. the `listening_sockets_summary_internal` IPv6/`unwrap_or(0)`
hazards) is still open.

#### P1.2 — `rustynet-backend-wireguard/userspace_shared/engine.rs`: 633 lines, 0 tests, on the data path
- `from_private_key_file()` (~L82): invalid base64, wrong key size, missing file.
- `configure_peer()` / allowed-IP CIDR validation (~L130): overlapping CIDR, malformed CIDR.
- `process_inbound_ciphertext()` (~L224) / `inject_plaintext_packet()` (~L282): auth-failure handling, truncation, multi-peer fan-out — using a mock boringtun seam.

#### P1.3 — `rustynetd/src/key_rotation.rs`: rollback / crash-consistency edges
- Ledger digest mismatch (corrupt one hex char), truncated file, field-reorder determinism (~L352).
- Epoch overflow `RotationEpoch::next()` at u64::MAX (~L162).
- Failure during rollback (persist fails after finalize; `let _ = ...` swallows freeze errors at ~L845) — cascade is untested and can leave disk/memory divergent.
- Drain timeout exact-boundary and backward-clock (`saturating_duration_since` masks jumps, ~L461).

#### P1.4 — `rustynet-cli/main.rs`: user-facing control-plane logic (not lab tooling)
Status 2026-05-27: verified the existing CLI error-classification test batch
covering BadArgs, PolicyReject, ConfigError, TransientFailure, fallback, and
precedence. Evidence:
`CARGO_TARGET_DIR=/private/tmp/rustynet-target-cli-classify cargo test -p rustynet-cli --bin rustynet-cli classify_cli_error`
passed 7/7 tests.

- `classify_cli_error()` (~L1341): parametrized test for each exit-code bucket (BadArgs / PolicyReject / ConfigError / TransientFailure) — operators depend on these codes.
- Argument parsing for major subcommands rejects missing required flags (`--signing-secret`, `--target-node-id`) with BadArgs.
- DNS-zone records-manifest limit enforcement (`MAX_DNS_ZONE_RECORDS_MANIFEST_*`) and alias-cycle rejection.
- `--json` renderer edge cases (multi-line / special-char / empty values).

#### P1.5 — `rustynet-local-security`: permission-enforcement reject paths
Socket UID/GID mismatch, parent-UID mismatch, group-writable socket,
relative-path rejection, root-managed wrong-gid — the complex OR-logic in
`validate_root_managed_shared_runtime_socket_facts()` (~L146) has many
untested branches.

#### P1.6 — `rustynet-policy`: edge cases around membership-aware deny
Status 2026-05-27: added membership-aware policy negative tests covering
empty-directory node-selector denial and wildcard-rule denial for a revoked
request node. Evidence:
`CARGO_TARGET_DIR=/private/tmp/rustynet-target-policy-quick cargo test -p rustynet-policy --lib`
passed 12/12 tests.

Unpopulated membership directory behavior (`is_populated()` ~L83 — is
enforcement skipped? pin it), context mismatch (rule=SharedExit,
request=Mesh), wildcard vs literal selector semantics.

### P2 — Robustness / breadth

- **`peer_gossip.rs` / `traversal.rs` boundary & isolation tests**: sequence/nonce wraparound (u64::MAX -> 0/1), timestamp extreme drift, wire truncation inside the count field, mixed valid+invalid candidates (does iteration check all?), and isolate `verify_coordination_record_signature()` + `validate_candidates()` + the NAT-viability matrix as unit-testable functions (currently only exercised via full scenarios).
- **`enrollment_token.rs` / `relay_client.rs` / `stun_client.rs`**: expired/stale token rejection + expiry off-by-one; relay token tampering (truncated/zero HMAC); malformed STUN response decoding. Pairs well with new fuzz targets.
- **`backend-userspace` delegation**: the `platform_unavailable()` contract and per-method NotRunning paths (mostly covered for Linux; document the compile-gated unsupported-OS path).
- **`runtime.rs` worker thread**: panic recovery, channel backpressure, IPC ordering (1,180 lines / ~2 tests).
- **`operations.rs` audit log**: digest-field tampering + entry-removal detection; complete the redaction keyword-table test (`nonce`, etc.).
- **`persistence.rs`**: expired-credential and already-used-credential reject paths; `max_uses > 1` multi-consume.

## Part C — Tooling and process (alongside P0/P1)

1. **Add `cargo llvm-cov` to CI**, capture a per-crate baseline, and ratchet (fail if coverage drops). Replaces brittle count-floors with real measurement and would auto-flag the next sysinfo.
2. **Introduce `proptest`** for serde round-trips (generalizing the per-variant tests), wire-format decoders (never-panic + round-trip), and invariants (sequence monotonicity, canonicalize idempotence).
3. **Expand fuzzing** to 4 new decoders: gossip bundle, coordination record, STUN response, DNS zone wire bundle.
4. **Bring untested crates under the gate**: add `rustynet-sysinfo`, the dataplane/gossip/traversal/key_rotation modules, and the control/policy/crypto/dns-zone crates to the floor set (interim) until llvm-cov ratcheting supersedes it.
5. **Adopt a negative-test convention**: for every `accept_*` / `verify_*` / `validate_*`, require a paired `*_rejects_*` test — enforce via a lightweight source-scan gate (the `secret_log_audit` static-scanner pattern is a good template).

## Suggested sequencing

- **Sprint 1 (P0):** roles.rs; membership/crypto/dns-zone negative tests; dataplane LAN truth table; gossip watermark failure modes. Land the llvm-cov baseline in parallel.
- **Sprint 2 (P1):** sysinfo parse/IO split + golden-fixture parser tests (and fix the dead-branch bug); engine.rs data-path tests; key_rotation edges; CLI error/arg tests. Add proptest + new fuzz targets.
- **Sprint 3 (P2):** boundary/wraparound + isolation tests across gossip/traversal/relay/stun/enrollment; wire the broadened gate floors.

The highest-impact, lowest-friction starting point is P0.1 (roles.rs) plus
the negative-test batch in crypto/membership/dns-zone — small, pure-logic,
directly tied to the security bar, and immediately gate-able.
