# Crypto / Policy / Release-Manifest Security Hardening — 2026-08-25

Status: **active** (branch `sec-hardening`, 20 commits, not yet merged).

Scope: fail-closed hardening and mutation-tested coverage for the Ed25519
signing path (`rustynet-crypto`), the ACL default-deny engine
(`rustynet-policy`), and the release-manifest sign/verify pipeline
(`rustynet-cli`). Every behavioral guard introduced here was
**mutation-tested**: the guard was neutralized in place, the pinning test
was required to FAIL, then the guard restored (commit-first protocol so
restores cannot destroy uncommitted work).

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

## Known non-issues (checked, left alone)

- `unwrap_or_default()` remnants in `rustynet-cli` are display/report paths.
- `verify_strict` already used on both attestation and manifest verification.
- Uppercase hex pinned keys fail pin-equality (case-sensitive CT compare):
  fail-closed direction; normalization would loosen acceptance and was rejected.
