# QH-26 Honest Retirement Plan — unreviewed delegated-edit checkpoints, the repurposed negative test, and what (if anything) is owed

**Date:** 2026-09-02 · **Status:** docs-only plan (no code). Resolves the "decide deliberately" half of QH-26 (`QualityHardeningTodo_2026-07-25.md:1937`); the process half (item 4 below) needs a small code/tooling follow-up.
**Decision lens applied:** core goals (honest, fail-closed trust path) → most secure (reject, never ignore, retired keys) → long-term (mechanical review gate, no prose promises).

## 1) What remains of `tls13_valid` in the tree today

All line numbers read against this worktree on 2026-09-02.

| Remnant | Location | Verdict |
| --- | --- | --- |
| Fixture string `b"version=2\ntls13_valid=true\n…\nsignature=zz\n"` | `crates/rustynetd/src/daemon.rs:26116`, inside fuzz-gate test `artifact_fuzzgate_bundle_parsers_never_panic_and_fail_closed` (`daemon.rs:26103`) | Stale-but-harmless; should be superseded by an explicit named pin (item 2b) |
| Parser tolerance | None. `load_trust_evidence` allows exactly seven keys (`version`, `signed_control_valid`, `signed_data_age_secs`, `clock_skew_secs`, `updated_at_unix`, `nonce`, `signature`) and returns `InvalidFormat("unknown key {key}")` for anything else (`daemon.rs:13834-13841`). A file carrying `tls13_valid=<anything>` is **rejected**, not ignored | Correct, keep |
| Version gate | Parser requires `version == 3` (`daemon.rs:13878`); producer payload writes `version=3` (`daemon.rs:13961`) | v2 evidence files (all pre-`f1ef83b1`) fail closed |
| Enforcement points | Only `signed_control_valid` remains: `verify_signed_trust_state_artifact` rejects `false` (`daemon.rs:3334`); report field at `daemon.rs:3279/3358`; `phase10.rs::validate_trust` rejects `"signed_control_invalid"` | The single real local attestation survives |
| Docs describing `tls13_valid` as a control | None found: `grep -rln tls13_valid documents/` hits only the audit/QH ledgers describing the *finding* (`DocCodeDiscrepancyAudit_2026-07-18.md:18,74`, `QualityHardeningTodo_2026-07-25.md:1954-1963`). `SecurityMinimumBar.md` no longer cites it as a control | No doc correction owed |

**Finding not recorded in the QH-26 entry:** `f1ef83b1` also bumped the required evidence version 2→3 in the same unreviewed commit (diff hunk `version != Some(2)` → `Some(3)`). This silently invalidated every previously issued v2 evidence file — fail-closed direction, and producers emit v3 today (`daemon.rs:13961`), but it belongs in the ledger note (item 5) because it is an on-disk-format break nobody reviewed.

## 2) The silently repurposed negative test — decide and pin

**Name:** `transition_to_fail_closed_when_trust_is_invalid` (`crates/rustynetd/src/phase10.rs:10253-10266`).
**What happened:** `f1ef83b1` changed its body from `tls13_valid: false, ..trust_ok()` to `signed_control_valid: false, ..trust_ok()` (diff at old line ~8157). The test still passes; the retirement of the `tls13` negative became invisible.
**What it asserts now:** `establish_control_trust` with `signed_control_valid:false` → `Err(Phase10Error::TrustRejected(_))`, state stays `Init` (`phase10.rs:10260-10265`). This is a genuine negative — it is simply no longer about TLS.

**Decision (a): keep it as the `signed_control_valid` negative, honestly annotated.** Add a comment recording the provenance: this negative formerly exercised `tls13_valid:false`; that field was retired as security theatre per DA-01 (`DocCodeDiscrepancyAudit_2026-07-18.md:74`) in `f1ef83b1`; the assertion now covers the only remaining local attestation flag. Renaming the test is **not** needed (its name never mentioned TLS); the comment is the honest retirement. Size S.

**Decision (b): add an explicit retired-key pin — REJECT, not ignore.** `AGENTS.md §10.4` says malformed/unknown → deny; the parser's existing convention for unknown keys is reject (`daemon.rs:13834-13841`, duplicate keys too, `daemon.rs:13829`), and an evidence file is *signed trust state*: silently dropping a key a future writer believes is enforced is exactly the widening DA-01 warned about. So: new test `trust_evidence_parser_rejects_retired_tls13_key` asserting `load_trust_evidence` errors with `"unknown key tls13_valid"` on a well-formed v3 payload plus that key, and — since the retired key rode a v2 file — a second case asserting the version gate rejects `version=2` (`daemon.rs:13878`) even with otherwise-valid fields. Size S. The `daemon.rs:26116` fuzz line may stay (it incidentally exercises both), but the pin test makes the intent named rather than accidental.

## 3) Is any real control owed? — No evidence field; the property lives at the listener

**Recommendation: no replacement attestation field. Do NOT restore any self-asserted boolean.**

The transport property DA-01 demanded is now genuinely enforced where it belongs — at the socket, not in a signed claim:

- TLS terminates only on opt-in LAN-exposed anchor listeners; loopback binds stay plaintext local-IPC (`SecurityMinimumBar.md:71-77` correction; `daemon.rs:1771-1798` bundle-pull, `daemon.rs:1897-1937` enrollment — `tls: Option<Arc<rustls::ServerConfig>>` on `AnchorListenerBinding`, `daemon.rs:1615`).
- Every accepted connection must complete the TLS 1.3 handshake before line protocol: `anchor_control_stream` (`daemon.rs:1624`); the rustls config omits the `tls12` feature so TLS 1.2 is not compiled in (`crates/rustynetd/Cargo.toml:41`, `SecurityMinimumBar.md:83-87`).
- Fail-closed pre-bind: `load_anchor_tls_server_config` (`daemon.rs:1662`) loads or generates the identity **before** bind; a LAN bind with no loadable identity refuses to start — no plaintext fallback.
- Verification exists as tests: `anchor_tls.rs` carries 7 `#[test]`s, including the `PinnedFingerprintVerifier` shape (SHA-256 DER pin, `verify_tls12_signature` hard-reject) at `anchor_tls.rs:673-679` region.

An evidence field would re-create DA-01's exact defect: a claim *about* transport signed by the same party that owns the transport, unverifiable against a handshake. The honest chain today is: fingerprint-pin the on-disk identity (`anchor-tls/anchor-cert.pem`, 0700 dir), verify at the listener, test the verifier. The known residual gap — **no client-side pinning in `rustynet-cli` and no fingerprint distribution field yet** (`SecurityMinimumBar.md` "NOT yet done" block; QH-26 follow-up design Item 1/2 in `QualityHardeningTodo_2026-07-25.md:2013+`) — is a real future control, but it is a *pinning* control, not an evidence boolean. Keep it in its own gated design track.

## 4) The process defect — a mechanical guard against unreviewed checkpoint merges

**Current state:** `scripts/git-hooks/pre-commit` checks only stale-base commits; `scripts/ci/` has no commit-message gate; nothing in `scripts/` or `.github/workflows/` references the marker. CI workflows: `cross-platform-ci.yml`, `release.yml` only. **UNVERIFIED:** whether GitHub branch protection on `origin/main` requires CI (repo-local evidence cannot confirm settings) — the gate below is valuable regardless.

**Proposed guard — repo-hygiene CI gate, `scripts/ci/delegated_edit_marker_gate.sh`** (thin wrapper, per `AGENTS.md §4`, over a Rust check binary `rustynet-cli/src/bin/check_delegated_edit_markers.rs` following the existing `check_*` binary pattern):

- **Exact check:** fail when any commit reachable from the CI-checked-out `main` tip (scan depth configurable via `MARKER_SCAN_DEPTH`, default 200) has a message containing the full marker pair `Committed by the delegated-edit tier` **AND** `Review before merging.` (the literal body written by the auto-checkpoint path). Output: the offending SHAs + subjects, exit non-zero.
- **Why the pair, not one string:** each half alone could appear in prose; the pair is the tier's verbatim boilerplate and has never appeared in a human commit (verified: only `f1ef83b1`, `f54edda5`, `15cf9f11` carry it in `git log --grep`).
- **False positives:** a human *reviewing* a checkpoint and merging it deliberately after rewriting the message → gate passes (message rewritten); quoting the marker in docs (this file does) → not scanned, gate reads only `git log --format=%B`; a deliberate post-hoc rescue → explicit allowlist env var `MARKER_ALLOWLIST=<sha,…>` documented in the script header, each entry requiring a rationale comment.
- **Test:** self-test mode in the binary — build a scratch git repo in a tempdir, create one marked and one clean commit, assert fail/pass/allowlist behaviours (pure-lib, runs in the normal `cargo test` gate, no network).
- **Wiring:** a lint job step in `cross-platform-ci.yml` (cheap, any runner) + `scripts/ci/` wrapper so it is runnable locally.
- **Limitation stated honestly:** a client-side hook cannot stop a *push* (hooks do not run on the receiving side here), and CI only helps if merges require green CI. The gate converts "silent unreviewed merge" into "red build naming the SHAs", which is the mechanical half; branch protection is the operator's half. Note in the ledger.

Size M (binary + wrapper + workflow step + tests). Explicitly **not** a pre-commit hook: the failure mode is on `main`, not on local commits.

## 5) Ledger wording

**QualityHardeningTodo QH-26 status flip text** (replace the open acceptance line):

> **RESOLVED 2026-09-02 (content) — see `Qh26HonestRetirementPlan_2026-09-02.md`.** `f1ef83b1`'s deletion is confirmed-correct on the merits: `tls13_valid` was DA-01's hardcoded-true theatre; the parser now rejects unknown/retired keys (`daemon.rs:13834-13841`) and requires v3 (`daemon.rs:13878`). No evidence field is owed — the real TLS 1.3 control lives at the anchor listeners (`daemon.rs:1624,1662`; `SecurityMinimumBar.md` correction 2026-08-30). The repurposed negative (`phase10.rs:10253`) keeps its new subject with an honest provenance comment, plus a named retired-key pin test. **Also record:** the same unreviewed commit bumped the evidence format 2→3, invalidating pre-2026-07-20 evidence files (fail-closed; producers emit v3 at `daemon.rs:13961`). Additive checkpoints `f54edda5` (IPC read-failure non-fatal + tests) and `15cf9f11` (immediate revocation teardown wiring) reviewed on their merits: **sound, keep.** Process half: `delegated_edit_marker_gate` proposed (plan §4); branch protection on `main` remains an operator action.

**CODE_MAP / other docs:** `documents/CODE_MAP.md` has no `anchor_tls.rs` entry (grep: zero hits) — add one line for it (the module is now a real security boundary). `SecurityMinimumBar.md` needs no further edit: its 2026-08-30 correction already reflects reality. DA-01's operator decision is already recorded as amended (`Requirements.md:168` per `SecurityMinimumBar.md:49-53`).

## 6) Implementation checklist (ordered, sizes)

1. **S** — Provenance comment on `transition_to_fail_closed_when_trust_is_invalid` (`phase10.rs:10253`).
2. **S** — New tests in `rustynetd` `daemon.rs` test module: `trust_evidence_parser_rejects_retired_tls13_key` (unknown-key error) + `version=2` rejection case.
3. **S** — CODE_MAP entry for `crates/rustynetd/src/anchor_tls.rs`.
4. **M** — `check_delegated_edit_markers` Rust binary + `scripts/ci/delegated_edit_marker_gate.sh` + self-tests + `cross-platform-ci.yml` lint step.
5. **S** — Apply item-5 wording to `QualityHardeningTodo_2026-07-25.md` after 1-4 land; verify `live_lab_node_run_matrix.csv` row only if any step needs lab evidence (none should).

**Must NOT be done:** no restored `tls13_valid`/any self-asserted transport boolean; no widening of accepted evidence keys or versions (reject stays reject); no client-side pinning built outside its gated design track (QH-26 follow-up Item 1/2); no silent suppression of the marker gate via allowlist defaults.

## 7) Open questions for adversarial review

1. Marker uniqueness: is the boilerplate string guaranteed stable across future MCP versions — and should the gate also match the `WIP: automatic checkpoint` subject prefix as a second signal, at the cost of false positives on legitimate WIP branches?
2. Scan depth: 200 commits is arbitrary; should the gate instead scan `origin/main..HEAD` on PR branches **and** the last N on `main`, and what is the right N before cost matters?
3. Is a CI-only gate acceptable given branch protection is UNVERIFIED — or does the operator want a server-side push rule (GitHub ruleset) named in the ledger as the real control?
4. The v2→3 format break: are there any persisted v2 evidence files in lab/deployment state that would now fail closed at startup, and is that failure *desired* (fresh issuance) or an operational incident waiting to happen?
5. Should `signed_control_valid` itself survive longer-term, given it too is a producer-asserted flag (verified only for signature/age/skew around it), or is its justification (signature over the assertion) strong enough that it is not theatre? Cite the chain before answering.
6. Does the retired-key pin test risk over-constraining a future legitimate `tls13_valid`-like key name collision, and should the pin assert the error class rather than the exact message?
