# Adversarial Review: Signed-State Epoch Rollback Apply-Layer Stage Design (GAP-5)

**Date:** 2026-09-01
**Subject:** Independent adversarial review of `LiveLabSignedStateRollbackApplyLayerStageDesign_2026-09-01.md` (this tree), per the owner decree that every recommended design gets an adversarial review before implementation.
**Method:** Every citation in the design was re-verified by direct read of the code it names; each of the eight attack axes below was answered from that code, not from the design's own claims. Confidence is deliberately under-claimed: this is a design read plus code verification, not a live reproduction. No lab run was available and no code was changed.

---

## 1. Attack 1 — Grounding verdict: is the live cell truly unexercised?

**Verdict: CONFIRMED (PARTIAL stands).** All three prongs re-verified:

1. **`security_audit` is an offline in-daemon self-audit.** `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/security_audit.rs:4-13` — each of the eight audits runs `rustynetd <check>-audit --no-fail-on-drift` over the `RemoteShellHost` seam; the table (`:42-83`) contains no entry that delivers a foreign bundle to a running daemon. The audit is the daemon examining its own persisted state, not an adversarial delivery. `AuditVerdict` (`:113-118`) with a distinct `Blocked` is exactly as the design describes.
2. **The chaos corpus is offline-fixture-only.** `crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs` — `run()` (`:128-163`) generates a fixture manifest, validates it in-process, and writes a report self-described as `"offline signed-state adversarial fixtures generated and pinned to fail-closed expectations"` (`:179`) with `"offline_only": true` / `"production_state_mutation": false` (`:186-194`). It never contacts a daemon. `chaos_replay_old_membership` exists at `:21-26` exactly as cited — as a fixture record. Registration at `stage/chaos.rs:124-131` pins target class `Offline` with `--scenario all`, as cited.
3. **No negative control and no stage drives the membership apply path live.** `negative_control.rs:1533-1706` mirrors the corpus against `verify_signed_assignment_state_artifact` — the *assignment* verifier, in-process; `ForgeryKind::Replay` (`:1663-1665`) is a genuine *current* bundle against a strictly-newer *assignment* watermark, a different shape and a different verifier. Decisive additional evidence the design does not cite: a repository-wide search of `crates/rustynet-cli/src/vm_lab/` for `membership apply` / `MembershipApply` returns **zero** hits. The daemon's membership-apply entry (`ipc.rs:92-94`, dispatch at `daemon.rs:9478` → `handle_membership_apply`, `daemon.rs:9758`) has never been driven by any orchestrator stage. The live rollback cell is genuinely uncovered.

**GAP-2 confusion check:** not a misread. The `Gap 2` marker in the code (`ipc.rs:249`, "Gap 2 daemon-side apply") is the *closed* work item that added the `MembershipApply` IPC entry itself. GAP-5 (the live adversarial replay *through* that entry) is a distinct, open item, and the design does not conflate them.

**One grounding nit (does not change the verdict):** the design's §1.2 cites the replay cache as `:728-752`; the type spans `:727-755` in this tree, and the epoch-watermark guard is `:740-742`, not `:740` alone. Same for §1.4's `ForgeryKind::Replay` at `:1663-1665` (correct). Substantively all citations check out.

## 2. Attack 2 — Capture fidelity: can the captured E-1 bundle be silently mangled?

**Verdict: RISK — the capture model as written is not implementable against the real lab path.**

Two distinct problems:

1. **"Exactly as the distribution path delivered it" is ill-defined, because the lab's live distribution path does not deliver signed-update envelopes.** The lab's epoch-advance mechanism is the `distribute_signed_bundle` adapter family (`adapter/linux_membership.rs:136`, `adapter/macos_membership.rs:305`, `adapter/windows_membership.rs:135`), which stages a **membership snapshot file** onto the guest (e.g. `/tmp/rn-membership.snapshot` → `/var/lib/rustynet/membership.snapshot`). The daemon ingests that file at bootstrap. The `encode_signed_update` **envelope** that `handle_membership_apply` consumes (`ipc.rs:82-94`: UTF-8 key=value, base64-url-safe-no-pad over the wire) never travels the setup path. So there may be no "wire bytes as delivered" to capture for an envelope-shaped artifact; the honest capture point is the **mint** (the `encode_signed_update` output at the signing step), not the delivery.
2. **Silent-mangle routes are real.** The envelope is base64url re-encoded on the IPC wire (`ipc.rs:143-149`); a trailing newline, CRLF, whitespace, or a non-canonical re-serialization turns the replay into `decode failed` (`daemon.rs:9768-9769`, surfacing `InvalidFormat`) — precisely the wrong-reason rejection the design itself says must be a failure, not a pass. A second, time-based route the design misses entirely: if the replay lands after the E-1 envelope's `expires_at_unix`, the rejection is `Expired` (`membership.rs:1046-1048`) — again a wrong-reason failure caused by stage scheduling, not by the daemon.

**Amendments (required):**
- Redefine capture as: retain the **exact envelope bytes at the mint point**, pin them with a SHA-256 digest recorded in the stage report, re-verify the digest immediately before replay, and — as a fixture-sanity precondition — offline-decode the envelope (`decode_signed_update`) and verify its signatures against the epoch E-2 state *before* submitting it, so any `InvalidFormat`/`SignatureInvalid` rejection live is provably a transport/stage defect and is graded `Blocked`, not `Failed`.
- Add a validity-window guard: the stage must assert `now_unix < expires_at_unix` for the captured envelope at replay time, else grade `Blocked` (capture expired — plumbing fault, not a control result).

## 3. Attack 3 — Distribution-path purity: does "the same path a legitimate peer uses" exist?

**Verdict: RISK — the design's mechanism wording contradicts the system it tests. The wording must change.**

What the code actually provides:

- The **only** ingestion entry for a quorum-signed membership governance update on a running daemon is the local IPC command `membership apply <base64>` (`ipc.rs:92-94`, parse at `:248-264`, dispatch `daemon.rs:9478` → `handle_membership_apply` `:9758`). The daemon's own doc comment (`:9739-9744`) defines the security model as a *dual gate*: local IPC peer-credential authorization **plus** the quorum signature — i.e. local IPC **is** the legitimate apply path.
- The gossip wire (`PushGossipBundle`, `ipc.rs:60-69`) carries `GossipBundle` peer announcements — not governance updates. The snapshot pull path (`fetcher.rs:21`, `verify_attested_snapshot` use at `daemon.rs:18837`) carries *snapshots*, and its rollback guard (`EpochRegression`/`ForkDetected`, membership.rs `:1510-1526`) is a different enforcement surface.
- Nothing in `vm_lab` drives `membership apply` today (zero hits — see Attack 1).

Consequences:

- The design's §2.3 step 3 wording — "the gossip/bundle distribution channel a legitimate peer would use — not a hand-crafted IPC poke" — forbids the **only** path that exists, and names a path that does not exist for this artifact class. As written the stage cannot be built without violating its own purity clause.
- The feared "collapse to a file/fetch injection like GAP-4" does **not** occur if the mechanism is corrected: driving the daemon's local IPC `membership apply` entry with the captured envelope *is* the normal path a legitimate operator/CLI uses, exercises the full dual gate (peer credential + quorum signature + `apply_signed_update`), and is categorically different from dropping a snapshot file into the state directory (which bypasses the apply funnel entirely and is what the stage must NOT do).

**Amendments (required):** Replace §2.3 step 3 and the §4 non-goal wording: the replay is submitted **through the daemon's membership-apply ingestion entry (local IPC `membership apply`), the same entry a legitimate quorum-approved apply uses**, driven with the node's admin-role IPC credential (the role gate at `daemon.rs:36873-36883` permits `NodeRole::Admin` and denies `Client`/`BlindExit` — the stage must drive it as admin or the rejection will be a role refusal, not an epoch rejection). Explicitly forbid the snapshot-file drop as the delivery mechanism. State the distinction: same-entry replay (in scope, legitimate surface) vs. state-file injection (out of scope, bypasses the funnel under test).

## 4. Attack 4 — Rejection-reason attribution: is the required reason the one the code actually emits?

**Verdict: RISK — the design's primary expected rejection is, with high confidence, the WRONG one for a genuinely old bundle. The grading rule as written would fail a correct daemon.**

Check-order analysis of `apply_signed_update` (`membership.rs:1032-1076`) for an E-1 bundle (whose `prev_state_root` is the epoch E-2 state root, `R_{E-2}`) replayed at a daemon holding epoch E (root `R_E`):

1. `:1038` `state.validate()` — passes (daemon state is valid).
2. `:1041-1045` network id — passes.
3. `:1046-1048` expiry — passes (within validity window, per the Attack 2 amendment).
4. `:1049-1051` future-dated — passes.
5. **`:1052-1054` `PrevStateRootMismatch` — FAILS FIRST.** `record.prev_state_root` (`R_{E-2}`) ≠ current root (`R_E`). This fires **before** the epoch-chain guard.
6. `:1055-1059` epoch chain — never reached for a genuine old bundle across ≥2 epochs, because step 5 rejects first. (It remains reachable for a same-epoch-root-shaped forgery and is correct defense-in-depth.)
7. `:1061` signatures — never reached.
8. `:1073` `replay_cache.observe` — never reached.

And the second half of the design's expected-reason set is unreachable at this surface: `EpochRegression` ("membership epoch regression…", membership.rs `:796-801` variant, `:855-861` message) is constructed **only** inside `verify_attested_snapshot` (`:1513`) — the snapshot-pull verifier — never in `apply_signed_update` or in `MembershipReplayCache::observe`. The cache's own watermark guard (`:740-742`) returns **`ReplayDetected`** ("membership replay detected", `:834`), not `EpochRegression`. The design cites `:796-868` as if it were an apply-path rejection site; it is the enum declaration plus `Display`, on a different surface.

Is the reason observable live? **Yes** — concretely: the IPC response message. `handle_membership_apply` maps every failure to `IpcResponse::err` with `"membership apply rejected: {err}"` (`daemon.rs:9808`), and decode failures to `"membership apply rejected: decode failed: …"` (`:9768-9769`). The stage runner receives that string over the same IPC response channel (`IpcResponse::to_wire`, `ipc.rs:176-179`), so reason attribution is directly gradeable — no log scraping required.

Could a wrong-reason rejection be graded as success under the design as written? Worse: **a correct daemon would be graded as failure**, because the deterministic reason for the genuine old bundle — `previous state root mismatch` — is not in the design's accept set, while reasons the design treats as pass-fatal (`decode failed`) can also arise from stage-side capture corruption (Attack 2).

**Amendments (required):** Rewrite assertion §2.3-4 as an **ordered expected-reason set on the `membership apply` IPC response**:
- Accept (deterministic primary): `"membership apply rejected: previous state root mismatch"` (`PrevStateRootMismatch`, `:1052-1054`) — this is the chain-link guard doing its job and is the expected first rejection for a genuine ≥2-epoch-old bundle;
- Accept (defensive, same family): `"epoch chain mismatch for membership update"` (`:1055-1059`) — document it as reachable only for root-matched shapes;
- Accept (id-dedup family, if ever reached): `"membership replay detected"` (`ReplayDetected`, `:737-742`);
- Reject-as-stage-failure (daemon defect): any other outcome, **including acceptance**;
- Grade as `Blocked`, not `Failed`: `"decode failed"` / `SignatureInvalid` (capture corruption — see Attack 2), `"membership update is expired"` (validity-window miss), and any role-gate refusal (stage drove the wrong role).
Keep the report's per-assertion record of the verbatim actual reason string either way.

## 5. Attack 5 — Are the watermark-unchanged and view-unchanged assertions observable, and can a rejected replay still perturb something?

**Verdict: CONFIRMED-SAFE (observability exists; no perturbation route found), with one wording amendment.**

- **Observability.** The persisted artifacts are concrete and readable over the existing RemoteShellHost seam: the snapshot, log, and watermark files — Linux `/var/lib/rustynet/membership.snapshot|membership.log|membership.watermark` (as fetched by the existing lab plumbing, `vm_lab/mod.rs:15424-15439`), macOS `/usr/local/var/rustynet/membership/…` (`macos_install.rs:45`), Windows `C:\ProgramData\RustyNet\membership\…` (`windows_paths.rs:33-37`). The watermark file format is `(epoch, state_root)` (`MembershipWatermark`, membership.rs `:1545-1549`; loader `:1572+`). The FIS-0020 identity pair cited at `:1248` is `snapshot_bytes_state_identity` (`:1252-1259`) — `(epoch, state_root_hex)`, matching the design's snapshot-identity claim. The daemon also exposes a parseable `membership status: … epoch=… state_root=…` line (consumed by existing lab checks, `vm_lab/mod.rs:47156`). So the design's "status/inspection surface" exists — but the design should **name these artifacts** rather than leaving the surface implicit.
- **No perturbation on rejection.** `handle_membership_apply` documents and implements "On failure, no snapshot/log/watermark file is mutated" (`daemon.rs:9746`; the apply at `:9807-9808` returns before the persistence boundary at `:9817+`; the watermark bump is success-only, `:9750-9752`). Two subtler candidates also fail to perturb:
  - *Replay-cache state:* the cache is **rebuilt per apply** from the on-disk log (`:9790-9800`) and is not persisted, so a rejected apply cannot leave cache residue; and `observe` inserts nothing on the rejection paths (`membership.rs:737-742` return before `:743`).
  - *Fork-detection state:* `ForkDetected` is constructed only in `verify_attested_snapshot` (`membership.rs:1519`), not on the apply path; the apply path stores no fork evidence.
  - *Eviction:* `MAX_REPLAY_CACHE_ENTRIES = 4096` (`:725`) evicts only ids on successful inserts (`:745-751`); a rejection performs no insert and therefore no eviction.
- **Amendment (wording):** the design says the watermark "still reads `(max_epoch = E, state_root = R_E)`". The on-disk `MembershipWatermark` fields are `epoch`/`state_root` (`:1546-1549`); there is no `max_epoch` field name at that surface. Use the real field names, and assert on the **file digests** of all three artifacts (snapshot, log, watermark) before/after in addition to parsed fields — byte-identical is the strongest form of the claim and is trivially checkable.

## 6. Attack 6 — Fixture staleness/eviction: E-1 id evicted AND epoch at/below the watermark

**Verdict: CONFIRMED-SAFE, with a sharpened assertion.**

Construct the adversarial case deliberately: drive ≥4096 successful updates so the E-1 envelope's `update_id` is evicted from the cache (`:745-751`), then replay it. Outcome:

- The id is gone from `seen_update_ids`, so the duplicate-id guard (`:737-739`) does not fire.
- The epoch watermark `max_epoch` is unaffected by id eviction (`:752` only ever advances), so `epoch_new <= max_epoch` (`:740-742`) would fire — but it is never reached: `PrevStateRootMismatch` (`:1052-1054`) and the epoch chain (`:1055-1059`) both precede `observe` (`:1073`). The design's quoted comment (`:718-724`: "epoch watermark alone still blocks rollback replays for evicted ids (apply_signed_update enforces the strict epoch chain before observe)") is accurate and is exactly this layering.
- Additionally, the daemon-side bootstrap watermark (`membership.watermark` + `membership_watermark_is_replay`, `daemon.rs:5324-5327`, membership.rs `:1559-1565`) provides a third, persisted layer that survives daemon restarts regardless of any in-memory cache.

So the design's rejection assertion survives eviction — **provided assertion 4 is corrected per Attack 4** (the expected reason remains the prev-state-root/epoch-chain family, not `EpochRegression`, which again is a snapshot-pull-surface error). The stage design does not need a 4096-update soak; it should simply document that eviction is orthogonal because the cache is not on the rejection path for this fault class.

## 7. Attack 7 — FAIL-LOUD completeness: can Skipped/dry-run/missing-report/blocked read as Passed?

**Verdict: CONFIRMED-SAFE as designed, with required wiring constraints.**

The design's `Blocked` verdict has a proven in-repo precedent that fails closed: `AuditVerdict::Blocked` is distinct from `Failed`, both fail the stage, and `matrix_status()` records `"blocked"`, which **outranks both `skip` and `pass`** in the recorder's `status_rank` precedence (`security_audit.rs:104-125`); additionally `outcome_for` forces `Skipped` whenever any node is reported-skipped, with skips named on disk (`:89-96`). The design should be required to inherit exactly these three mechanisms, and to add the stage-specific `Blocked` triggers identified above (capture digest mismatch, offline decode/signature sanity failure, validity-window miss, role-gate refusal, IPC entry unreachable). Also carry over the convention that a missing report artifact is a stage failure (never an absent-result pass), consistent with the run-matrix rule that a stage pass is claimed only from the stage's own report artifact. With those constraints the design's §2.3-5 is complete; without them "blocked run can never be read as a pass" is an unenforced intention.

## 8. Attack 8 — Does the design weaken any guard or the chaos corpus?

**Verdict: CONFIRMED-SAFE.** The design's §4 non-goals explicitly forbid changes to `membership.rs` guards and to the chaos fixture corpus, and nothing else in the design touches enforcement code. The offline validator tests it adds (§2.5) *strengthen* the contract — but note that the first proposed test as written ("re-submit a genuinely valid epoch E-1 update … assert `InvalidTransition` with `epoch chain mismatch`") **will fail against the real validator** for the reason established in Attack 4: a genuine E-1 update mismatches `prev_state_root` first. Rewrite that test to expect `PrevStateRootMismatch` for the genuine-old-bundle shape, and add a second shape (root-forged so `prev_state_root` matches but the epoch pair is stale) to actually reach the `:1055-1059` epoch-chain guard — this also documents that both guards are independently live. This is a correction to the design, not a weakening.

---

## 9. Overall Verdict: READY-WITH-AMENDMENTS

The stage is justified: the grounding verdict PARTIAL is confirmed by direct code reads (the fault is catalogued offline; the live apply-path cell has never been driven — `membership apply` has zero callers in the entire lab orchestrator). The guard stack is real and correctly layered. But the design as written contains one assertion that would grade a **correct** daemon as failed, and one mechanism clause that forbids the only path that exists. Both are fixable on paper before any lab time is spent.

**Required amendments (all §-references are to the design document):**

1. **Expected-reason set (§2.3-4, §2.5, §1.2).** Replace "epoch chain / replay watermark" with the ordered, code-accurate set on the `membership apply` IPC response: primary `previous state root mismatch` (`PrevStateRootMismatch`, membership.rs `:1052-1054`), defensive `epoch chain mismatch for membership update` (`:1055-1059`), id-dedup `membership replay detected` (`ReplayDetected`, `:737-742`). Remove `EpochRegression`/"membership epoch regression" from the apply-path assertion — it is constructed only in `verify_attested_snapshot` (`:1513`), a different surface. Rewrite the §2.5 first unit test to match (expect prev-root mismatch for the genuine shape; add a root-forged shape to reach the epoch-chain guard).
2. **Mechanism wording (§2.3-3, §4).** The replay goes through the daemon's membership-apply ingestion entry — local IPC `membership apply` (`ipc.rs:92-94`, `daemon.rs:9758`) — driven with the admin-role credential (role gate `daemon.rs:36873-36883`), which is the legitimate apply surface and its documented dual gate (`daemon.rs:9739-9744`). Delete the "gossip/bundle distribution channel … not a hand-crafted IPC poke" clause; explicitly forbid the snapshot-file-drop mechanism instead.
3. **Capture model (§2.2).** Capture the envelope bytes at the mint point (not "as delivered" — the lab distribution path delivers snapshot files, not envelopes), pin a SHA-256 digest in the report, re-verify it before replay, and require an offline decode + signature sanity check against the epoch E-2 state as a precondition. Add a validity-window guard (`now < expires_at_unix`) with a `Blocked` grade on expiry. Any `decode failed`/`SignatureInvalid`/`Expired`/role-refusal rejection grades `Blocked`, not `Failed`.
4. **Observability (§2.3-2/3/4).** Name the concrete surfaces: the IPC response string (`"membership apply rejected: …"`, `daemon.rs:9808`), and the snapshot/log/watermark artifacts per OS (Linux `/var/lib/rustynet/…`, macOS `/usr/local/var/rustynet/membership/…`, Windows `C:\ProgramData\RustyNet\membership\…`), with before/after **byte digests** of all three in addition to parsed `(epoch, state_root)` fields (the field is `state_root`, not `max_epoch`, membership.rs `:1546-1549`).
5. **Fail-loud wiring (§2.3-5, §2.4).** Inherit the `AuditVerdict` precedent verbatim: `Blocked` distinct from `Failed`, both fail the stage, `"blocked"` outranks skip/pass in the run-matrix `status_rank`, any reported-skipped node forces `Skipped` (naming the node on disk), and a missing report artifact is a failure.

**Considered, no change required:** GAP-2/GAP-5 separation (correct); grounding verdict PARTIAL (confirmed); non-weakening of guards or corpus (explicit and honored); eviction/watermark layering (correct as cited at `:718-724`); cross-OS stage placement pattern (§2.4 follows the existing `StageId`/registration/runner-binary conventions).

**Confidence note:** all claims above are from reading the design and the named code in this tree (membership.rs, daemon.rs, ipc.rs, the chaos/negative-control/security-audit stage sources, and the lab adapters), plus repository-wide greps for live callers of the apply entry. No live lab run was executed; the check-order reasoning (Attack 4) is derived from the validator's code path and should be confirmed by the §2.5 offline unit tests the moment they are written — those tests are cheap and will settle Attack 4 empirically before any VM is booted.
