# QH-26 Honest Retirement Plan — Adversarial Review (2026-09-02)

Reviewer scope: refute `Qh26HonestRetirementPlan_2026-09-02.md` on its facts, its gate design, and its security framing, against the worktree at review time. Every file:line anchor in the plan was re-derived in this checkout; the marker-commit population was independently re-counted. This review is docs-only: it changes no code, no gate, and no workflow.

## §0 Verdict

| Plan section | Verdict | One-line reason |
| --- | --- | --- |
| §1 Remnant inventory | Accurate | All anchors verified; parser is the single evidence-reading path; one precision nit. |
| §2 Repurposed negative test | Sound | Keep + provenance comment + retired-key pin test is the strictest practical option; pin-test assertion form needs one amendment. |
| §3 Evidence-field question | Ready with amendments | TLS chain verified end-to-end; `signed_control_valid` is not theatre; but the plan cites test-only code (`PinnedFingerprintVerifier`) with a wrong line anchor as production evidence. |
| §4 Marker gate proposal | Needs major amendment | The plan's central factual claim ("only f1ef83b1, f54edda5, 15cf9f11 carry the marker") is false: eleven marked commits are reachable from main, three of them landed trust-sensitive daemon/TLS code unreviewed. The proposed scan design must be allowlist-primary and must expect a day-one red. |
| §5 Ledger wording | Amend | Proposed wording repeats the stale three-commit count; the QH-26 register entry itself carries the same stale count and needs correcting in the same change. |
| §6 Checklist | Amend | Complete on sizes, but missing two items: dispositioning the three trust-sensitive checkpoints, and correcting the register's count. |
| §7 Open questions | Answered | Each question is answered in §7 below. |

**Overall verdict: READY-WITH-AMENDMENTS.** The plan's §1–§3 content survives adversarial reading essentially intact. Its §4 gate design does not: it was built on a verified-false commit census, and the true census makes the plan's own subject matter (unreviewed delegated-edit checkpoints reaching main) strictly worse than the plan describes — three newer checkpoints landed the entire anchor TLS subsystem, including the very file §3 cites as evidence, without review.

## §1 Attack: remnant inventory and parser coverage

**Claim under attack:** the trust-evidence parser rejects unknown keys on every evidence-reading path, and version 3 is enforced everywhere a v2 artifact could arrive.

**Result: the claim holds.** Verified in this worktree:

- The parser's unknown-key rejection is a `matches!` allowlist at `crates/rustynetd/src/daemon.rs:13833-13846` admitting exactly seven keys (`version`, `signed_control_valid`, `signed_data_age_secs`, `clock_skew_secs`, `updated_at_unix`, `nonce`, `signature`), with duplicate-key rejection at `:13828`. Anything outside the set — including the retired `tls13_valid` — errors. All fields are required-or-error; the path is fail-closed in both directions (missing and extra).
- The version gate `version != Some(3)` → `"unsupported trust evidence version"` sits at `daemon.rs:13878-13882`, ahead of any semantic use.
- **No second parser exists.** A repo-wide search for `version=2` found hits only in artifacts with their own independent version gates: rustynet-control membership bundles, the blind-relay v2 wire format (own reject-on-unknown-version at `blind_relay.rs:1597` and `:1928-1937`), daemon watermark parsers (`"unsupported watermark version; expected version=2"` at `daemon.rs:14430`, `:15083`, `:15313`, `:16576`), enrollment tokens, PCP/NAT-PMP, and the fuzz fixtures. None of these reads trust-evidence key/value lines. There is no lenient loader and no serde path that tolerates unknown fields in this artifact — the format is hand-parsed, not derived.
- The fuzz fixture retains v2-shaped inputs as must-fail cases at `daemon.rs:26114-26116` inside `artifact_fuzzgate_bundle_parsers_never_panic_and_fail_closed` (`:26106-26129`). The plan's `daemon.rs:26116` anchor is correct.

**Precision nit (non-blocking):** the plan's "finding not recorded" note is correct that commit f1ef83b1 also performed the v2→v3 bump alongside the `tls13_valid` removal; the review confirms this from the same commit and agrees it belongs in the record.

One residual risk is worth naming even though it is not a defect: any *future* reader that deserializes persisted trust-evidence files with a derived (serde) parser would silently tolerate unknown keys. The plan's §2 pin test is the right tripwire against that regression; see §2 below.

## §2 Attack: repurposed negative test disposition

**Claim under attack:** keeping the repurposed test with a provenance comment, plus a new retired-key pin test that rejects (not ignores) retired keys, is the strictest secure option.

**Result: the claim holds, with one amendment on assertion form.**

- *Is keep the strictest option?* Yes. Deleting the test would discard the only executable proof that `signed_control_valid: false` fails closed (`crates/rustynetd/src/phase10.rs:10252-10268`: `TrustEvidence { signed_control_valid: false }` → `establish_control_trust` returns `Err(TrustRejected)`, state remains `Init`). Reverting the repurposing would resurrect the security-theatre field that DA-01 had established was hardcoded `true` at issuance. A third option — keeping both the old and new field in the test — would assert a schema that no longer exists. Keep-with-comment is the only option that preserves the proof without preserving the lie.
- *Should the test be split or renamed?* No. The test's name describes its present behavior accurately; renaming would break the audit trail the provenance comment is meant to anchor. Splitting would manufacture a second test asserting identical state transitions.
- *Is "reject, not ignore" consistent with the parser's treatment of other retired keys?* Yes. The parser has no ignore path for any key: retired keys fall into the same unknown-key error as never-known keys (`daemon.rs:13833-13846`). The pin test asserts exactly the behavior the parser already exhibits.
- *Amendment A4 (assertion form):* the plan's §7 question about exact-message over-constraint is real. The pin test should assert that parsing fails and that the failure is the unknown-key rejection — not that the error string equals a full literal. Message prose is not an API contract; pinning it converts any future wording cleanup into a test failure, which trains maintainers to weaken assertions. The plan's own §2 wording should say "asserts rejection" rather than naming the exact message.

## §3 Attack: the TLS 1.3 chain and the theatre question

**Claim under attack:** no evidence field is owed; LAN-exposed anchor control-plane listeners enforce TLS 1.3 end-to-end; `signed_control_valid` is a meaningful signal rather than theatre.

**Result: the substance holds. Two of the plan's citations do not.**

End-to-end listener chain, verified in `daemon.rs`:

- `AnchorListenerBinding { listener, tls: Option<Arc<rustls::ServerConfig>> }` at `:1615-1618`; `anchor_control_stream` at `:1624-1640` wraps each accepted connection, `None` → plain, `Some` → `rustls::StreamOwned<ServerConnection, _>` with the handshake deferred to the first bounded read/write (2-second socket timeouts).
- TLS identity is loaded at bind time by `load_anchor_tls_server_config` (`:1662-1675`); a load or config error refuses the bind rather than degrading.
- `bind_anchor_bundle_pull_listener` (`:1769-1799`) elects the TLS config *before* `TcpListener::bind` when `--allow-lan` is set (`:1781-1785`), and the doc-comment at `:1762-1768` states there is **no plaintext fallback for LAN-exposed binds**. `bind_anchor_enrollment_listener` (`:1895-1938`) follows the same pattern (`:1902-1906`).
- TLS 1.2 is not merely disabled at runtime; it is not compilable: `crates/rustynetd/Cargo.toml:41` declares rustls with `default-features = false, features = ["ring", "std", "logging"]`, omitting the `tls12` feature, with a comment at `:37-40` citing QH-26 item 4 and DA-01.

**The theatre question, argued both ways:**

- *Theatre case:* `signed_control_valid` is producer-asserted. A producer that lies about its own control-plane health signs a lie, and the consumer has no independent measurement to contradict it.
- *Not-theatre case:* the field lives inside the signed evidence payload, verified with the strict verifier against the pinned verifier key (`daemon.rs:13908-13910`) with age, skew, and replay-watermark enforcement (`:13913-13938`). The consumer independently rejects `signed_control_valid = false` (`verify_signed_trust_state_artifact`, `:3306-3362`, rejection at `:3334-3336`), and the negative test proves the fail-closed transition (`phase10.rs:10252-10268`).

**Decision: not theatre.** A producer-signed, pinned-key-verified, replay-protected attestation that the consumer acts on by refusing trust is a real control — the threat it addresses is a compromised or misconfigured producer being *forced* to confess, and an attacker being unable to forge or replay a `true`. The honest caveat, which the plan should carry: the field attests the producer's assessment of its control plane; it is not an independent measurement, and it must not be presented as one. That caveat is exactly what DA-01 originally documented about the *old* field, which was hardcoded at issuance — the new field's difference is that it is signed and consumed, not asserted.

**Amendment A1 — the citation defect.** The plan cites "PinnedFingerprintVerifier ... at anchor_tls.rs:673-679 region" as production evidence. That is wrong twice over:

1. The struct actually spans `crates/rustynetd/src/anchor_tls.rs:618-682`.
2. That range sits inside the `#[cfg(test)] mod tests` module, which begins at `:371-372`. The entire `PinnedFingerprintVerifier` — the fingerprint comparison (`:648-656`), the hard TLS 1.2 rejection in `verify_tls12_signature` (`:659-668`), the `connect_pinned` client helper (`:589-616`) — is **test-only code**. It is legitimate and useful evidence *that the server handshake works and that TLS 1.2 is rejected on the client side*, but it is not a production enforcement point, and the plan must not cite it as one. Production enforcement is the server-config path in `daemon.rs` plus the compile-time feature omission above.

## §4 Attack: the marker gate — the plan's central claim is false

**Claim under attack:** "verified: only f1ef83b1, f54edda5, 15cf9f11 carry it [the delegated-edit checkpoint marker]."

**Result: refuted.** `git log --grep='Committed by the delegated-edit tier'` on main returns **eleven** marked commits, all with subject `WIP: automatic checkpoint (timed_out)`:

- 2026-07-20: `f1ef83b1`, `f54edda5`, `15cf9f11` (the three the plan knows about; recorded in the QH-26 register).
- 2026-08-29: `726be807`.
- 2026-08-30: `5757e55c`, `2befe39e`, `1a5bcb21`, `4eeee1dd`, `9a723960`, `4c2c17da`, `d1890dae`.

The five post-July checkpoints after the register entry was written prove the QH-26 defect class is not historical — it recurred five more times, and the register itself still says "three". Each newer checkpoint was inspected (`git show --stat` plus content inspection of the trust-relevant ones):

| Commit | Content | Disposition |
| --- | --- | --- |
| `5757e55c` | daemon.rs +42/−8: wires TLS into the anchor enrollment listener (`AnchorListenerBinding`, `load_anchor_tls_server_config` at bind, hostile-handshake drop) | **Trust-sensitive, unreviewed** — must be dispositioned |
| `1a5bcb21` | daemon.rs +174/−8: `AnchorControlStream` enum (Plain/TLS), lazy in-read handshake under 2s timeouts, generic pull-request-token reader | **Trust-sensitive, unreviewed** — must be dispositioned |
| `9a723960` | **Creates `crates/rustynetd/src/anchor_tls.rs` (+664 lines)** plus Cargo feature additions in rustynetd and rustynet-cli | **Trust-sensitive, unreviewed** — must be dispositioned; this is the very module §3 relies on |
| `726be807` | source_archive.rs +128/−5 | Lab tooling; allowlist-safe |
| `2befe39e` | vm_lab mod/orchestrator/native/topology (+1 each), QualityHardeningTodo.md +46 | Lab tooling + ledger; allowlist-safe |
| `4eeee1dd` | live_lab_run_matrix.rs +110, source_archive.rs +117, run_exclusion.rs +2 | Lab tooling; allowlist-safe |
| `4c2c17da` | main.rs +1, vm_lab additions | Lab tooling; allowlist-safe |
| `d1890dae` | live_lab_run_matrix.rs +63, vm_lab/mod.rs +26 | Lab tooling; allowlist-safe |

**Consequences for the gate design:**

1. *Day-one behavior.* A gate whose allowlist holds only the three July commits goes red immediately on main — which is the correct outcome, and the plan must say so explicitly instead of implying a green-after-cleanup state. Five of the eleven commits postdate the plan's census; a "verified: only three" framing would have shipped a gate that fails its first run and made the implementer doubt the gate rather than the census.
2. *Since-commit bound vs explicit allowlist.* The plan offers a scan depth (`MARKER_SCAN_DEPTH`, default 200) over recent commits. Depth-bounded scanning of *new* commits would have caught none of the eight newer checkpoints retroactively and provides no forcing function for the ones already on main. The allowlist must be the primary mechanism: an explicit `MARKER_ALLOWLIST` of marked commit SHAs, each entry annotated with its disposition (reviewed-now, or reverted), and the gate fails on any marked commit absent from the list. Depth only bounds *where new markers are detected*; it must never be the mechanism that absolves history.
3. *Dispositioning is a work item, not a footnote.* Three checkpoints (`5757e55c`, `1a5bcb21`, `9a723960`) landed trust-sensitive daemon/TLS code without review. The plan's checklist must add: review each (or revert), record the disposition next to its allowlist entry, and correct the QH-26 register entry's stale count in the same change. The outcome of that review is expected to be "confirmed on merits" — the landed TLS work is what §3 verifies — but *expected* is not *recorded*, and QH-26's entire point is that the recording is the control.
4. *Marker-pair bypass via message rewrite.* A determined actor can rewrite a commit message to evade the marker and land the same unreviewed change. This residual risk is acceptable: history rewrite on main is itself visible in the reflog and in CI (the staleness hook and gate both operate on real SHAs), and the marker gate is a tripwire for *accidental* checkpoint landings — the dominant observed failure mode (eleven for eleven) — not a control against a malicious committer, which branch protection and review own.
5. *CI-only vs branch protection.* A CI lint step detects; it does not prevent. It is meaningful on its own (it turns every future landing into a visible red within one push), but the plan's §7 question is answerable only by evidence this review could not obtain: the repository's branch-protection/ruleset configuration showing a required status check on `main`. See §9.

**Current-state claims in §4 verified:** the proposed gate does not exist yet — no `delegated_edit_marker_gate` script, no `check_delegated_edit_markers` binary, and no `MARKER_SCAN_DEPTH`/`MARKER_ALLOWLIST` references anywhere in `.github/workflows/`, `scripts/ci/`, or `scripts/git-hooks/pre-commit`. The pre-commit hook is a stale-base check only. The plan's description of today's state is accurate.

## §5 Attack: ledger wording

The plan's §5 replacement wording for the QH-26 register entry must be amended before it is applied:

- It must not repeat the three-commit figure. The register entry at `QualityHardeningTodo_2026-07-25.md:1937-1989` says "three commits dated 2026-07-20" and is itself stale: five further marked commits landed on 2026-08-29/30. The §5 wording (amended at A3 below) must state the true count, name the three trust-sensitive ones, and record that the register entry is corrected in the same change.
- The CODE_MAP gap is real and the proposed fix is right: `grep anchor_tls documents/CODE_MAP.md` returns nothing today while `crates/rustynetd/src/anchor_tls.rs` is a 683-line module with production and test halves. One CODE_MAP entry naming the module, its server-identity production surface (`:1-369`), and its test-only verifier (`:618-682`) closes it.

## §6 Attack: checklist completeness and sizing

The five items and their S/S/S/M/S sizing are reasonable. Two items are missing and change the §6 shape:

1. **Disposition the three trust-sensitive marked checkpoints** (`5757e55c`, `1a5bcb21`, `9a723960`): review on merits or revert; annotate the allowlist entries with the outcome. This is M-sized (three commits, one of them a new 664-line module), and it is the item that actually closes the recurring defect for the landings that already happened.
2. **Correct the QH-26 register entry's commit count** (three → eleven) as part of applying the §5 wording, so the register and the gate's allowlist agree. S-sized.

With those added, the checklist covers: parser pin test, provenance comment, anchor_tls.rs citation correction (A1), gate implementation with allowlist-primary semantics (A2), ledger wording (A3), dispositioning, register correction, and CODE_MAP entry. The plan's must-not list (no revert of f1ef83b1's deletion, no reintroduction of `tls13_valid`, no ignore-path for retired keys) remains correct.

## §7 Answers to the plan's open questions

1. **Marker stability.** The marker pair is a convention of the delegated-edit harness documented in `AGENTS.md` §12.6, not a wire contract; a future harness rewrite could change the wording. The gate should fail loud if `git log --grep` for the marker returns zero hits across a window where delegated edits are known to run — silence must be distinguishable from absence. Acceptable as designed once the allowlist is primary; the marker string is also stable in practice (identical pair across eleven commits spanning six weeks).
2. **Scan depth.** Depth 200 (commit-count bound) covers the observed six-week marker span with margin and is env-overridable. Its limitation is structural: it bounds recency, not time, and it must never substitute for the allowlist on history (A2).
3. **CI-only vs branch protection.** CI-only is detection-with-one-push-latency; prevention requires the status check to be *required* on `main`. What would settle it: the repo's branch-protection/ruleset configuration naming the gate's check as required. Not verifiable from this checkout — §9.
4. **Persisted v2 evidence files.** The parser rejects any v2 artifact outright, so a persisted v2 bundle in lab or deployment state fails closed wherever the current parser reads it; the exposure is operational staleness, not trust. No exhaustive sweep of lab-state directories was performed (§9), but no code path reads such files leniently.
5. **`signed_control_valid` theatre.** Not theatre: producer-signed under the pinned verifier key with replay protection, consumer-enforced rejection, negative-tested fail-closed transition. Caveat recorded at §3: it is an attestation of the producer's assessment, not an independent measurement.
6. **Pin-test exact-message over-constraint.** Real. Assert rejection and the unknown-key classification; do not pin the full message literal (A4).

## §8 Exact replacement wording for the amendments

**A1 — replace the plan §3 sentence citing the verifier with:**

> Client-side verification exists as test-only code: `PinnedFingerprintVerifier` (`crates/rustynetd/src/anchor_tls.rs:618-682`, inside the `#[cfg(test)]` module starting at `:371`) pins the server certificate by SHA-256 fingerprint (`:648-656`) and hard-rejects TLS 1.2 (`:659-668`); it proves the server handshake behaves and that a TLS-1.3-only client refuses downgrade, but it is not a production enforcement point. Production enforcement is: TLS config loaded and bound at listener setup with errors refusing the bind (`daemon.rs:1662-1675`), elected before `TcpListener::bind` for LAN-exposed listeners with no plaintext fallback (`:1762-1768`, `:1781-1785`, `:1902-1906`), and TLS 1.2 absent at compile time (`rustynetd/Cargo.toml:41`, `tls12` feature omitted).

**A2 — replace the plan §4 census sentence and gate-semantics paragraph with:**

> The marker appears on **eleven** commits reachable from main (`git log --grep='Committed by the delegated-edit tier'`): `f1ef83b1`, `f54edda5`, `15cf9f11` (2026-07-20, recorded in QH-26), plus `726be807` (2026-08-29) and `5757e55c`, `2befe39e`, `1a5bcb21`, `4eeee1dd`, `9a723960`, `4c2c17da`, `d1890dae` (2026-08-30). Three of the newer checkpoints landed trust-sensitive daemon/TLS code unreviewed (`5757e55c`, `1a5bcb21`, `9a723960` — the last created `crates/rustynetd/src/anchor_tls.rs`); the other five are lab tooling. The gate is therefore **allowlist-primary**: `MARKER_ALLOWLIST` enumerates every marked commit SHA with an explicit per-commit disposition (reviewed-now or reverted), the scan fails on any marked commit absent from the list, and the gate is expected to be **red on main at first run** until the three trust-sensitive checkpoints are dispositioned and the five tooling checkpoints are allowlisted. Scan depth bounds only the detection of *new* markers; it never absolves history.

**A3 — replace the plan §5 ledger wording's commit census with:**

> QH-26's register entry records three marked commits; at gate-design time the true count is eleven, five of which landed after the entry was written. Applying this plan's §5 wording must also amend the register entry (`QualityHardeningTodo_2026-07-25.md:1937-1989`) to the eleven-commit census and name `5757e55c`, `1a5bcb21`, and `9a723960` as the trust-sensitive ones pending disposition, so the register, the plan, and the gate's allowlist state one consistent fact.

**A4 — replace the plan §2 pin-test assertion sentence with:**

> The retired-key pin test (`trust_evidence_parser_rejects_retired_tls13_key`, including a `version=2` case) asserts that parsing the retired key fails closed with the unknown-key rejection; it does not pin the exact error-message literal, which is prose, not contract.

**A5 — add to the plan §6 checklist:**

> - Disposition the three trust-sensitive marked checkpoints (`5757e55c`, `1a5bcb21`, `9a723960`): review on merits or revert; record the outcome beside each allowlist entry. (M)
> - Amend the QH-26 register entry's commit census from three to eleven as part of the §5 wording application. (S)

## §9 What could not be verified

- **Branch protection / ruleset configuration.** Whether the marker gate's CI check would be *required* on `main` is a repository-settings fact, not a tree fact; this review has no repo-admin API access. Settle by exporting the ruleset configuration (or a screenshot) once the gate exists.
- **Persisted v2 trust-evidence files in lab/deployment state.** No exhaustive sweep of UTM guest disks, profile directories, or historical report archives was performed; the claim "no lenient reader exists" is a code claim and holds, but "no v2 artifact sits anywhere waiting to be read" was not proven.
- **Marker-string stability across future harness versions.** The pair has been stable across eleven commits over six weeks; whether a future delegated-edit rewrite keeps the wording is unknowable in advance — the fail-loud-on-silence behavior in §7.1 is the mitigation, not a proof.
- **Live listener behavior.** §3's chain is verified by reading code and features; no lab run was executed in this docs-only review, so runtime behavior (actual handshake on a LAN-exposed bind, hostile-handshake drop) rests on the code path and the test suite, not on a fresh live observation.
