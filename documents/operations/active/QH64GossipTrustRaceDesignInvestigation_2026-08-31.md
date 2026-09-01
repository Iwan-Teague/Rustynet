# QH-64 Design Investigation — Trust-Evidence Restart Race, `RestrictionMode::Permanent`, and the `gossip_accepted_total=0` Mechanism

**Date:** 2026-08-31
**Status:** INVESTIGATION ADVANCEMENT — QH-64 remains OPEN, not fixed. This document advances the three open questions recorded in `QualityHardeningTodo_2026-07-25.md` §QH-64 and proposes a fix *direction* only. No code has been changed.
**Method:** Repository reading only (no live lab access in this pass). Every factual claim is cited `file:line` against the tree this document was written in. Where the prior pass's conclusion is corrected by direct code reading, the correction is stated explicitly and quoted in context.

---

## 0. Executive summary

1. **Q1 (call sites).** The prior pass's "sticky by design / does not self-heal" claim is **true only while reconcile keeps failing**. Direct reading shows `daemon.rs:10557` clears `RestrictionMode::Permanent` back to `None` unconditionally on every *successful* reconcile apply, and the apply block **is reachable while Permanent** (the FailClosed dataplane state — set by the very failure that promoted the node — forces the apply block's predicate true, `daemon.rs:10348-10352`). So a daemon whose trust evidence file *returns* heals itself on the next reconcile tick without a restart. `:6015` can never fire under Permanent (explicit guard, the QH-55 change). `:8843` fires only on a successful signed bootstrap apply and nothing triggers that automatically mid-run.
2. **Q2 (gossip accept path).** The prior pass's inference — "a node that's `restrict_permanent`'d almost certainly refuses to treat inbound gossip as trustworthy" — is **not confirmed and is wrong as stated**: the inbound accept path (`gossip_runtime.rs` `validate_and_apply_inbound_bundle`, `:660-716`) contains **no check of the node's own `RestrictionMode`** (zero matches for `restrict`/`Restriction` in the whole file). The real mechanism for `gossip_accepted_total=0` is upstream: the trust reconcile failure makes `reconcile()` return early (`daemon.rs:10260-10267`) **before membership is ever loaded**, and `sync_gossip_data_plane` early-returns when `membership_state` is `None` (`daemon.rs:6464-6469`) — so the gossip transport is never bound and no peers/epoch are ever registered in the restarted daemon. Nothing arrives; nothing is accepted; and (consistent with the journal) no `gossip_reject_*` lines appear either.
3. **Q3 (lenovo-exit-1 vs ubuntu-utm-1).** The write path for the trust evidence file is **atomic** (temp file + `publish_file_with_owner_mode`, `main.rs:9550-9573`), and the only repository code path that deletes `/var/lib/rustynet` (hence `rustynetd.trust`) is the full teardown `uninstall_daemon` (`linux_install.rs:346-372`) — a between-runs cleanup, not a mid-run step. No code path deletes the file mid-run. This narrows the live cause to three candidates that code reading alone cannot separate (§3): (a) `Path::exists()` returning false on a **permission error** (EACCES) rather than true absence — `daemon.rs:13697` cannot distinguish them and maps both to `Missing`; (b) unit/path drift on that specific guest (an older installed unit pointing `RUSTYNET_TRUST_EVIDENCE` somewhere else); (c) a genuine absence window around the two-actor restart storm, with the file having been absent *before* the restarts. Decisive live probes are listed in §3.4.
4. **Fix direction (§4).** Primary recommendation: orchestrator-side pre-restart precondition + daemon-side errno disambiguation + unit hardening — all pure fail-closed additions. Explicitly **rejected**: any timer-based auto-heal of `RestrictionMode::Permanent` (the reconcile success path at `:10557` already provides principled self-heal; a timer would be fail-open pressure with no benefit). Conditionally acceptable after adversarial review: a narrowly-scoped Missing-only, fresh-start-only grace window before `promote_to_permanent_if_over_limit` (§4.4), justified by the observation that every failure in the window already forces the dataplane FailClosed (`daemon.rs:10265`), so extending the window does not un-block traffic.

---

## 1. Q1 — What each `RestrictionMode::None` write site actually requires

`restrict_recoverable` refuses to downgrade out of Permanent (`daemon.rs:10763-10770`, the QH-55 change: it records the new failure but leaves the mode alone), and `restrict_permanent` unconditionally sets Permanent (`daemon.rs:10772-10777`). The interesting writes are the three sites the QH-64 section names.

### 1.1 `daemon.rs:6015` — `complete_verified_signed_refresh` (cannot fire under Permanent)

```rust
fn complete_verified_signed_refresh(&mut self, reason: SignedStateRefreshReason) {
    if self.restriction_mode == RestrictionMode::Permanent {
        eprintln!("rustynetd: signed state refresh completed (reason={}) but node remains \
                   PERMANENTLY restricted: ...");
        return;
    }
    self.restriction_mode = RestrictionMode::None;
    ...
}
```

(`daemon.rs:6003-6021`. The doc comment above it, `:5996-6002`, states the QH-55 intent verbatim: "A successful signed-state FETCH alone must not clear a PERMANENT restriction.")

**Verdict: cannot have fired for the observed failures.** The guard is the first statement; under Permanent the function returns before the clear. This site is *by design* powerless against Permanent.

### 1.2 `daemon.rs:8843` — post-bootstrap-apply tail (correct, but not automatic)

This write sits at the end of the signed-bootstrap apply path (after membership state is installed, `sync_gossip_data_plane` runs, and auto-tunnel enforcement is applied, `daemon.rs:8821-8841`):

```rust
self.restriction_mode = RestrictionMode::None;
self.bootstrap_error = None;
if let Err(err) = self.persist_state() { ... }
```

(`daemon.rs:8843-8845`.) It is unconditional at this point — but it is only reached by a full successful signed bootstrap/apply flow (an enrollment or bootstrap IPC command), not by the periodic reconcile loop. **Nothing in the mid-run lifecycle invokes it automatically.** So: could it have fired for lenovo-exit-1? Only if the orchestrator had re-run a full signed bootstrap against the node mid-run — it did not (the restarts were systemd restarts, per the QH-64 journal). It is a correct recovery path that simply was not on the executed path. It is not "the recovery path itself has a bug."

### 1.3 `daemon.rs:10557` — reconcile success path (the real self-heal; reachable under Permanent)

The reconcile loop (`daemon.rs:10243`) **does not short-circuit when restricted** — it re-attempts `load_verified_trust()` on every tick (`:10259-10260` is the first substantive step, with no `is_restricted()` guard; `is_restricted` itself is only a predicate, `daemon.rs:10752-10754`). On trust failure it increments, restricts recoverable, forces the dataplane fail-closed, and returns early (`:10261-10267`). On success it proceeds toward the dataplane apply, whose success tail is:

```rust
self.restriction_mode = RestrictionMode::None;
self.bootstrap_error = None;
self.reconcile_failures = 0;
```

(`daemon.rs:10557-10559`.) The critical question the prior pass could not answer: **is this block entered while Permanent?** Yes — the apply block's predicate is:

```rust
if will_apply_generation
    || self.controller.state() == DataplaneState::FailClosed
    || self.restriction_mode == RestrictionMode::Recoverable
```

(`daemon.rs:10348-10352`.) Under Permanent, every prior failure has already forced the controller FailClosed (`force_fail_closed_or_restrict`, `daemon.rs:10779-10797`, which the trust-failure arm calls at `:10265`), so the second disjunct is true and the block executes. One nuance: `will_apply_generation` itself (`:10332-10339`) includes only `Recoverable`, not Permanent — but the FailClosed disjunct re-added at the apply site carries the Permanent case, and the comment at `:10342-10347` explains the disjuncts are deliberately re-read at this point.

**Verdict:** `RestrictionMode::Permanent` **does self-heal within a running process if and only if the underlying reconcile failure clears** (the trust evidence file reappears and verifies, membership verifies, and the dataplane apply succeeds). The prior statement "`RestrictionMode::Permanent` does not self-heal within a running process" is therefore **overstated**: what is true is that Permanent does not self-heal *while the failure persists*, and that `restrict_recoverable` will never *downgrade* it — but the normal reconcile success path (`:10557`) resets it outright. For the observed run this distinction is moot (the file evidently never returned during the validation window — accepts stayed 0 at the 150 s check), but it changes the fix calculus entirely: **no new in-daemon recovery mechanism is needed**; the recovery mechanism exists and is principled (a fully verified reconcile apply is exactly the condition under which restoring service is justified — the same condition QH-55 encodes for `complete_verified_signed_refresh`).

### 1.4 Consequence for Q1

None of the three sites is buggy. `:6015` correctly refuses; `:8843` is correct but off-path; `:10557` is the live self-heal and is correctly reachable under Permanent. The "sticky by design" reading should be re-worded: **Permanent is sticky against downgrade and against mere fetch success (QH-55), not against a fully verified reconcile apply.** The escalation observed in the journal — `restrict_permanent: reconcile failure threshold exceeded: 5` then `6` — is `promote_to_permanent_if_over_limit` (`daemon.rs:10799-10806`) firing once `reconcile_failures >= max_reconcile_failures`; subsequent failures keep logging through the QH-55 branch of `restrict_recoverable` (matching the repeated WARN lines).

---

## 2. Q2 — Does the gossip accept path check the node's RestrictionMode? (No.)

**The check does not exist.** `grep -n "restrict|Restriction" crates/rustynetd/src/gossip_runtime.rs` returns **zero matches** in the entire file. The accept path in `validate_and_apply_inbound_bundle` performs, in order (all inside `crates/rustynetd/src/gossip_runtime.rs`):

1. Signature/freshness/sequence verification (preceding the shown window; the comment block at `:660-666` describes it),
2. **Revoked-source refusal** — `if self.revoked_peer_ids.contains(&bundle.source_node_id)` → `gossip_reject_revoked_source` (`:668-677`),
3. **Per-origin accept budget** — `consume_origin_budget` → `gossip_reject_origin_rate_limited` (`:683-697`),
4. Watermark persist, endpoint admission, counter bump, and the `gossip_accept` log line (`:699-716`).

There is no branch consulting the daemon's `RestrictionMode` anywhere on this path. The QH-64 section's hedge — "a node that's `restrict_permanent`'d almost certainly refuses to treat inbound gossip as trustworthy under this project's fail-closed posture… which is consistent with, and very likely *is*, the actual mechanism" — is **an inference from convention, and it is incorrect at the accept-path level**.

### 2.1 The actual mechanism for `gossip_accepted_total=0`

The causal chain reachable from the code:

1. `reconcile()` hits the trust failure and **returns early** (`daemon.rs:10261-10267`) — before `load_verified_membership` (`:10269`), before the dataplane apply, and before any `sync_gossip_data_plane` call in the apply tail (`:10532-10534`).
2. On a freshly restarted daemon, `self.membership_state` starts as `None` (it is only populated by a verified membership load — `daemon.rs:8821` on the bootstrap path and the reconcile flow). The gossip sync's first guard is:
   ```rust
   let Some(membership_state) = self.membership_state.as_ref() else { return; };
   ```
   (`daemon.rs:6464-6467`.) So while reconcile keeps failing, **the gossip data plane is never synced at all**.
3. Consequences of the never-synced state, in the same function: the transport is never bound (`if self.gossip_transport.is_none() { … GossipTransport::bind … }`, `daemon.rs:6472-6487`; the `gossip transport bound; gossip data plane active` log at `:6476` therefore belongs to a daemon instance that *did* load membership — in the QH-64 journal, the 19:49:02 first instance, not the third), the verified membership epoch is never stamped (`node.set_local_membership_epoch`, `daemon.rs:6470`), and peers/revocation sets are never registered (`:6491-6499`).
4. With no transport bound, **no inbound gossip is received at all**: no accepts, and also no rejects — which matches the journal exactly (`gossip_accepted_total=0` with no `gossip_reject_*` lines reported). The stage validator's "registered peers" phrasing reflects the *validator's* expectation from the membership snapshot on the control side, not the daemon's runtime peer table.

Two secondary notes for completeness:

- Even if the transport *had* been bound (e.g. bound by an earlier successful sync before a later failure), the epoch-skew measurement and peer verification in the accept path operate against `node.peers` / the stamped epoch; a stale-but-bound transport from a pre-restart process cannot survive into the new process (state is in-memory; `restriction_mode: RestrictionMode::None` at construction, `daemon.rs:5156`). So the restarted instance starts gossip-cold by construction.
- The flap-breaker escalation in the same journal window (`flap breaker … closed -> open (intensity 0.66 → 0.94)`) remains plausibly a downstream symptom: a daemon that fails reconcile every tick presents repeated instability signals. Not confirmed; unchanged from the prior pass.

**Verdict for Q2:** `gossip_accepted_total=0` is caused by the gossip data plane never being brought up in the restarted daemon (membership never loads because trust fails first), **not** by `RestrictionMode::Permanent` gating the accept path. This also explains why `ubuntu-utm-1`'s comparison run (no restart, no trust failure) had symmetric acceptance. It sharpens the stake: the thing to fix is the *trust provisioning race*, because trust failure cascades into dataplane AND gossip silence simultaneously.

---

## 3. Q3 — What differs on `lenovo-exit-1`'s restart path

### 3.1 Where the file comes from and who writes it

- The unit bakes a fixed path: `Environment=RUSTYNET_TRUST_EVIDENCE=/var/lib/rustynet/rustynetd.trust` (`scripts/systemd/rustynetd.service:18`) and passes it as `--trust-evidence ${RUSTYNET_TRUST_EVIDENCE}` (`:67`).
- The unit **fail-closes at start** on a missing file: `ExecStartPre=/usr/bin/test -f ${RUSTYNET_TRUST_EVIDENCE}` (`scripts/systemd/rustynetd.service:100`). A daemon that is running therefore passed this check at start time.
- Bootstrap seeds it **before** `install-systemd`, explicitly so the preflight has an artifact: `ops trust issue --output /var/lib/rustynet/rustynetd.trust` → `chown root:<group>` → `chmod 0600` (`ops_e2e.rs:647-677`; comment at `:646-647`), then `install-systemd` (`:726`), then `ops refresh-trust` (`:731-750`).
- `ops refresh-trust` writes **atomically**: temp file in the target dir, `trust issue` into the temp, then `publish_file_with_owner_mode` (temp → final, owner root:daemon-gid 0640) — `main.rs:9508-9576`; on any error the temp is removed and the **previous file is left intact** (`main.rs:9559-9565`, `:9567-9573`). There is no window in which the final path does not exist due to a refresh.
- Periodic refresh is a systemd oneshot + timer: `rustynetd-trust-refresh.service` (`ExecStart=/usr/local/bin/rustynet ops refresh-trust`, gated on `LoadCredentialEncrypted=signing_key_passphrase:/etc/rustynet/credentials/signing_key_passphrase.cred`, `scripts/systemd/rustynetd-trust-refresh.service:15-20`) fired by `OnBootSec=45s` / `OnUnitActiveSec=60s` (`scripts/systemd/rustynetd-trust-refresh.timer:9-11`). install-systemd ships both (`ops_install_systemd.rs:1483-1521`).
- The **enforce** path used by the orchestrator mid-run (`enforce_daemon` → `ops e2e-enforce-host`, `linux_install.rs:151-247` and `build_enforce_script` at `:225-244`) runs **only `ops install-systemd`** (`ops_e2e.rs:838-843`) — it does **not** re-seed or re-issue trust evidence itself; it relies on the existing file plus `RUSTYNET_TRUST_AUTO_REFRESH=true` in the unit (which drives the *timer*, not a pre-restart refresh). Note: the comment at `linux_install.rs:150` ("refreshes trust evidence immediately before restart") is accurate for the *bootstrap* pass (`ops_e2e.rs:731-750` runs after `install-systemd` at `:726` in `execute_ops_e2e_bootstrap_host`) but **misleading for the enforce pass**, which contains no refresh step. This comment drift is worth fixing when the fix lands.

### 3.2 Who deletes it

Exactly one repository path removes `/var/lib/rustynet` (and thus `rustynetd.trust`): the full teardown `uninstall_daemon` — `sudo rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet /run/rustynet-relay` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:364-371`). This is a between-runs cleanup, not a step the observed run would execute mid-run. **No mid-run code path deletes the file.** (`mod.rs:37173-37176` removes only `.watermark` files, not the evidence itself; the macOS bootstrap comment at `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:769` is about not *inheriting* stale state across enrollment, on macOS.)

### 3.3 So what was absent on lenovo-exit-1? Three candidates code reading cannot separate

`TrustBootstrapError::Missing` is produced by exactly one line: `if !path.exists() { return Err(TrustBootstrapError::Missing) }` (`daemon.rs:13696-13698`; display string `daemon.rs:2775`), and `load_verified_trust` calls it with the CLI-provided path (`daemon.rs:5248-5257`). The decisive subtlety: **`Path::exists()` returns `false` for *any* stat error, including `EACCES`** — the daemon cannot currently distinguish "file absent" from "file present but not stat-able by the daemon user." The daemon runs as `User=rustynetd` / `Group=rustynetd` with `UMask=0077` (`scripts/systemd/rustynetd.service:116-117,137`), and `/var/lib/rustynet` is variously ensured as `0700 rustynetd:rustynetd` (bundle distribution, `linux_membership.rs:170`) or `0750 root:rustynetd` (`main.rs:9532`; `ops_install_systemd.rs:687-697`) depending on which step last touched it. An ownership/mode drift on the *directory* (or the file) that denies the `rustynetd` user traversal/read would present as `Missing` while `ExecStartPre` (running as root, `User=root` is not set but ExecStartPre runs under the unit's user — root by default for `test`… note `rustynetd.service` does **not** set `User=` for ExecStartPre; it runs as the service user `rustynetd` per `:116`) — in either case a root-vs-daemon readability gap between the preflight `test -f` and the daemon's later stat is exactly the kind of mismatch that reproduces "passed preflight, failed reconcile."

Ranked candidates, with the evidence each would leave behind:

1. **EACCES masquerading as Missing** (`daemon.rs:13697` cannot tell them apart). Left evidence: `namei -l /var/lib/rustynet/rustynetd.trust` or `sudo -u rustynetd test -r …` failing at failure time; also an `audit.log`/`strace` EACCES. Fits "lenovo-specific" if that guest's dir ownership drifted (it is the node with the most re-enforce cycles in the reproduced runs).
2. **Unit/path drift on that guest** — an older `install-systemd` render from a prior run (the libvirt guests on `lenovo-bot` are re-imaged less deterministically than the UTM fleet; the host runs the orchestrator from *its own* checkout, `host_id: lenovo-bot`, `vm_lab_inventory.json:27`) pointing `RUSTYNET_TRUST_EVIDENCE` at a stale path. Left evidence: `systemctl cat rustynetd.service | grep TRUST` on the guest diverging from `scripts/systemd/rustynetd.service:18`.
3. **Genuine absence window around the restart storm.** The two rapid restarts (first SIGTERM-killed) are consistent with two actors issuing restarts in overlap (the role-switch enforce restart and a second restart source, e.g. `build_relay_forward_test_daemon_restart_script`, `vm_lab/mod.rs:13933-13939`, or `restart_daemon`, `linux_install.rs:352-355`). Since nothing deletes the file mid-run, this requires the file to have been absent *before* the storm — i.e. the run's earlier provisioning of that node silently lacked the seed. Left evidence: whether the *first* instance (19:49:02) ever logged a successful trust reconcile, and whether `ExecStartPre` failed at least once (`systemctl show -p ExecStartPreStatus`), plus the exact-PID journal re-read the QH-64 section already flags as required.

### 3.4 Decisive live probes (next lab pass — cheap, no code change)

1. On `lenovo-exit-1`, at failure time or reproduced: `stat /var/lib/rustynet/rustynetd.trust; namei -l /var/lib/rustynet/rustynetd.trust; sudo -u rustynetd test -r /var/lib/rustynet/rustynetd.trust; echo $?` — separates candidate 1 from 3 in one shot.
2. `systemctl cat rustynetd.service | grep -E 'TRUST|ExecStartPre'` — tests candidate 2 against `scripts/systemd/rustynetd.service:18,100`.
3. Journal re-read keyed by PID (the QH-64 section's own flagged need): attribute each `trust reconcile failed` line to its instance; determine whether instance 3 (pid 185700) *ever* succeeded once, and whether the trust-refresh.timer unit on that guest is `active`/failing (`systemctl status rustynetd-trust-refresh.timer rustynetd-trust-refresh.service` — the oneshot fails closed if the encrypted credential is missing, `rustynetd-trust-refresh.service:15-16`).
4. Deliberately reproduce a mid-run `systemctl restart` on `ubuntu-utm-1` (the QH-64 section's proposed next step) *without* touching the file — prediction from this investigation: gossip stays healthy, proving restart alone is insufficient and the file/readability state on lenovo-exit-1 is the variable.

---

## 4. Proposed design direction (no code in this document)

Guiding constraint (from the QH-64 section, quoting it): *"weakening the stickiness without understanding the race could turn a fail-closed control into a fail-open one."* Each option below is assessed against that.

### 4.1 A — Orchestrator pre-restart precondition (RECOMMENDED, zero fail-open risk)

In every orchestrator path that (re)starts a Linux daemon — `enforce_daemon` (`linux_install.rs:151-247`), `restart_daemon` (`:352-355`), `start_daemon` (`:338-349`) — verify *before* the restart that the trust evidence file exists **and is readable by the daemon user**, e.g. `sudo -n test -f <path> && sudo -n -u rustynetd test -r <path>`, failing the stage loudly (FAIL-LOUD live-stage spec, `CrossPlatformRoleParityRoadmap_2026-06-22.md`) with the stat output in the error. Symmetrically, the enforce path should execute the same trust refresh the bootstrap path runs (`ops_e2e.rs:731-750`) before restarting, or the comment at `linux_install.rs:150` should be corrected — pick one; running the refresh is the stronger option and is idempotent (`refresh_trust_record_with_inputs` leaves the old file intact on failure, `main.rs:9559-9573`).

*Fail-open analysis:* pure addition of preconditions and a defensive refresh; the daemon's own verification (signature, watermark, permissions) still gates everything. A malicious/failed refresh leaves the prior valid file in place. No state is relaxed.

### 4.2 B — Daemon errno disambiguation (RECOMMENDED, zero fail-open risk)

`load_trust_evidence` should distinguish ENOENT from EACCES (and other stat errors) — e.g. via `fs::metadata(path)` error kind instead of a bare `exists()` — so the journal says `trust evidence is missing` vs `trust evidence is not readable by the daemon user: permission denied` (`daemon.rs:13696-13698`). Log the resolved path (it is a path, not a secret; §10.6 does not apply). This converts a misdiagnosis class ("file missing" hunts) into a one-glance diagnosis, and would have distinguished candidate 1 from 3 in the original run with zero lab access.

*Fail-open analysis:* none — error *reporting* only; `Missing`/`Invalid` still both fail closed through the identical reconcile path.

### 4.3 C — Rely on the existing `:10557` self-heal (RECOMMENDED as the *stance*; no code)

Because Permanent demonstrably clears on a fully verified reconcile apply (`daemon.rs:10348-10352`, `:10557-10559`), the correct posture is: keep Permanent sticky against everything weaker (fetch-only success, time, restart-adjacent heuristics), and make the *provisioning* fix the thing that lets the existing heal fire. Explicitly **rejected**: any timer- or attempt-count-based auto-downgrade of Permanent. A timer that restores service without a verified reconcile apply is definitionally fail-open (it would restore trust-state-dependent service while the reason for the restriction is unverified), and it duplicates a mechanism that already exists with a stronger precondition.

### 4.4 D — Bounded Missing-only grace before `promote_to_permanent_if_over_limit` (CONDITIONAL — needs the adversarial cycle)

Observation: the escalation budget is ~5 reconcile ticks (~5 s at the observed cadence, `daemon.rs:10799-10806`). For a *fresh start* racing provisioning, Permanent adds nothing over the state it passes through: every failure already forces the dataplane FailClosed (`daemon.rs:10265`) and fails the unit's own preflight on a truly absent file (`rustynetd.service:100`). A narrowly-scoped variant — only `TrustBootstrapError::Missing` (not signature/freshness/permission failures, which must keep immediate-promote semantics), only within the first N seconds of process uptime, still Recoverable + FailClosed throughout — would convert an environment race from a run-killing Permanent into a Recoverable blip while keeping every cryptographic failure path exactly as strict.

*Fail-open analysis:* the dataplane and gossip remain fully blocked for the entire window (the cascade in §2.1 is driven by the early return, which is unchanged), so no traffic can leak; the residual risk is *masking*: a deployment whose trust file is genuinely gone would sit in Recoverable for the grace window instead of screaming Permanent, weakening operator signal. Mitigations if pursued: hard cap the grace at a few seconds; count grace windows per process lifetime (one only); and require 4.2's errno split first so the grace can never apply to the EACCES case (which is *not* a provisioning race and should escalate fast). This option should not land without the full adversarial review the QH-60/blind_relay convention demands, and only if §3.4's probes confirm candidate 3 (a real absence window) rather than 1/2 — if the cause is readability or unit drift, D is the wrong tool and 4.1/4.2 suffice.

### 4.5 E — Unit hardening (RECOMMENDED, cheap)

Extend the preflight to check daemon-user readability (`ExecStartPre` running `test -r` as the service user, or a tiny `rustynetd` subcommand that validates custody of all trust/membership artifacts and exits non-zero), and add `RequiresMountsFor=/var/lib/rustynet` to the unit so a mount-state anomaly cannot present as Missing. Fails closed at start; no runtime behavior change.

### 4.6 Ordering

1. §3.4 probes (establish which candidate is real — this determines whether 4.4 is even in scope).
2. 4.2 (B) + 4.5 (E) — diagnosis quality and fail-closed preflight; no semantic risk.
3. 4.1 (A) — provisioning correctness on the enforce/restart paths; fixes the race regardless of which candidate is real.
4. 4.4 (D) — only if the evidence shows a genuine restart-vs-provisioning window that 1–3 do not already close, and only after the full adversarial cycle.

---

## 5. Open items explicitly remaining (honest ledger)

- **Which of the three §3.3 candidates is real on `lenovo-exit-1`** — requires the live probes in §3.4; repository reading rules out mid-run deletion and non-atomic writes but cannot see guest filesystem/unit state.
- **Exact PID attribution of the 19:51:19-24 failure lines** (already flagged in the QH-64 section) — determines whether instance 3 independently failed trust or inherited a cold gossip plane from its own failed reconciles; either way §2.1's mechanism holds, but the answer changes the wording of the incident record.
- **Why the trust-refresh timer did not restore the file within the 150 s validation window** (if it was genuinely absent): timer disabled on that guest, oneshot failing on the missing encrypted credential (`rustynetd-trust-refresh.service:15-16`), or the file was present-but-unreadable (candidate 1) and refresh was a no-op. Probe 3 in §3.4 answers this.
- Whether the enforce-path comment drift at `linux_install.rs:150` reflects an intended refresh that was lost in a refactor, or was always bootstrap-only (git history on that comment).

*End of investigation document. QH-64 stays OPEN; this document is an input to the eventual design + adversarial review cycle, not its conclusion.*
