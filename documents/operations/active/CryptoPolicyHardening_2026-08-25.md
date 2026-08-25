# Crypto / Policy / Release-Manifest Security Hardening — 2026-08-25

Status: **active** (branch `sec-hardening`, 28 commits, not yet merged).

Scope: fail-closed hardening and mutation-tested coverage for the Ed25519
signing path (`rustynet-crypto`), the ACL default-deny engine
(`rustynet-policy`), and the release-manifest sign/verify pipeline
(`rustynet-cli`). Every behavioral guard introduced here was
**mutation-tested**: the guard was neutralized in place, the pinning test
was required to FAIL, then the guard restored (commit-first protocol so
restores cannot destroy uncommitted work).

## Later additions (post-ledger)

- `5863e7d0`: pinned the installer-consumer arm — a parseable manifest whose
  signature fails self-verification hard-fails staging (`failed
  self-verification`), closing the one uncovered branch of the acquire
  contract (corrupt JSON / tampered binary / no-manifest were already pinned).
- Clippy `-D warnings` verified clean across all three touched crates.
- Duplicate-rejection attempt in the rollout controller was **retracted before
  commit**: `protocol_enumeration_no_longer_evades_the_allow_all_guard`
  (policy lib.rs:847) is a strict superset of the proposed pin.
- `7ea1a392` / `0082302c`: both membership-aware evaluators' **post-gate
  empty-set terminals were dead code to the suite** — a terminal-flip mutant
  survived everything. Root cause: tests registered directory keys like
  `"node-a"` while `node:` selectors resolve to the BARE id (`"a"`), so the
  gate denied first. Pins now use bare-id keys and reach the terminal; both
  flip mutants die.
- `0ad7f0e3`: pinned ops input guards (empty artifact list refuses before any
  signing work; trailing-colon spec leaves an inexpressible empty path).
- `59720c5f`: source-grep pin for `selector_matches`' both-sides-empty guard —
  its rule-side half is behaviourally redundant under equality matching
  (documented at the function), so removal was previously invisible to every
  behavioral test.

## Watchlist (observed, deliberately not touched)

- `rustynet-control` `evaluate`-path (lib.rs:~3465): on an **empty** membership
  directory the both-endpoints-Active requirement is skipped and issuance falls
  back to plain default-deny ACL evaluation. Same *shape* as the removed RN-11
  fail-open, but (a) it gates bundle issuance, downstream of the daemon's
  independent provisioning gate, (b) it carries an explicit pre-membership
  rationale, and (c) the crate adjoins the reverted mesh-status/L1c area this
  campaign was told not to enter. Left for the owning reviewers; recorded so
  the shape cannot be re-introduced silently elsewhere.

## Defects fixed

| Commit | Defect | Fix |
| --- | --- | --- |
| `d2e96e75` | `build_signed_manifest` signed with an all-zero seed: `from_seed` derives the publicly-known zero key, so a blank seed file produced forgeable manifests | `ManifestError::WeakSigningSeed`; signing refuses zero material |
| `5395285a` | verify-side mirror gap: a pinned all-zero verifier key validated any such manifest | `verify_signed_with_pinned_key` rejects a zero pin |
| `12b827a9` | silent fallback: a signing error emitted a manifest with an **empty signature** instead of failing the release build | signing errors abort with `SignatureInvalid`; pinned via provider injection in `c1357836`/`7f39d8e2` |
| `60afdeec` | duplicate `(name, target)` entries could enter a signed manifest while `verify_artifact` is first-match — the later entry could never be checked against a downloaded binary | `ManifestError::DuplicateArtifact`, adjacent-pair check after sort |

## API changes

- `ecf4d7bf`: added `Ed25519SigningProvider::try_from_seed -> Result<_, CryptoError>`
  (rejects all-zero seed as `WeakMaterial`, wipes the by-value seed copy on both
  paths, CRY-11-consistent); manifest signer migrated to it.
- `46843093`: `from_seed` is now `#[cfg(test)]` — after migration it had no
  production callers; the degenerate-seed-capable constructor no longer ships.

## Coverage pins added

- crypto: empty-message round-trip + tampered/truncated/oversized/cross-payload
  rejection (`7b3f75a0`, `d682e608`, `4c10d96a`), cross-key rejection
  (`c6667f91`), attestation kind/key-id bindings isolated from signature math
  (`932c6e75`), `try_from_seed` zero-seed + wipe-on-reject source-grep
  (`ecf4d7bf`, `44396370`).
- policy: ICMP on an empty ACL, plain and membership-aware (`7f09e6b7`,
  `79c81545`).
- cli: zero-seed signing refusal, zero-pin verify refusal, empty-pin decode
  failure, malformed seed files, operator-facing zero-seed e2e (no manifest
  written) (`11133cb0`, `67bac565`, `62c7cca0`, above fixes' pins).

## Mutation-testing record

Neutralized guards that were proven to be killed by their pins: manifest
zero-seed guard, zero-pin guard, attestation kind guard, key-id guard,
`try_from_seed` zero guard, `verify_attestation` length guard,
policy deny arms + empty-set default. A "drop `Protocol::Any`
special-case" mutant was tested and killed by six pre-existing tests — no new
test added for it (avoiding fabricated coverage).

## Verification

Scoped gates only (per operating constraint): `cargo test -p
rustynet-crypto|-p rustynet-policy|-p rustynet-cli --all-targets
--all-features` green at every commit; `cargo clippy -p` over all three
crates with `-D warnings` exits 0; `cargo fmt -p` clean. Full-workspace §7
suite deliberately not run (constraint), and the workspace-excluded crates
are untouched.

Final-sweep additions: §10.2 audit found zero `unwrap`/`expect`/`panic!`
in non-test production code of all five touched files; policy/crypto
doctests pass (no code fences); branch footprint vs `origin/main` is
exactly the seven intended files (+803/−20) with a clean tree.

## Merge readiness (Definition of Done walk-through)

- In-scope requirements implemented end-to-end: yes — each defect fixed at its
  enforcement point with a pin that fails under the reverted guard.
- Security minimum bar: satisfied for the touched scope; no crypto invented,
  WireGuard untouched, default-deny strengthened (empty-ACL/ICMP/membership
  terminals now executed by tests).
- Gates actually run: scoped `cargo test --all-targets --all-features` for
  rustynet-crypto, rustynet-policy, rustynet-cli (green at every commit);
  `cargo clippy -p` ×3 with `-D warnings` (exit 0); `cargo fmt -p` clean.
- Gates deliberately deferred, named so nothing is silently claimed: the
  full-workspace §7 test stage and `cargo audit`/`cargo deny` were not run
  (operating constraint: scoped testing only); workspace-excluded crates
  (`rustynet-lab-monitor`, `gui`, `fuzz`) untouched and untriggered. The
  changed crates are pure library/CI-tooling surfaces with no daemon dataplane
  behaviour change, so no live-lab run is required to merge this branch; if
  the operator disagrees, the branch is ordinary to rebase and re-gate.
- No TODO/FIXME/placeholders introduced; artifacts are the commits themselves.

## Known non-issues (checked, left alone)

- `unwrap_or_default()` remnants in `rustynet-cli` are display/report paths.
- `verify_strict` already used on both attestation and manifest verification.
- Uppercase hex pinned keys fail pin-equality (case-sensitive CT compare):
  fail-closed direction; normalization would loosen acceptance and was rejected.
