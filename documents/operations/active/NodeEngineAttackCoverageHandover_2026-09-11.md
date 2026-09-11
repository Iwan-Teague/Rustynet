# --node Engine: Attack-Coverage Handover (2026-09-11)

Self-contained brief for an agent building the adversarial live-lab stages the
tough-policy audit (audit H) flagged. Read `NodeEngineToughPolicy_2026-09-11.md`
first — it is the decree this work serves. All of this is **defensive testing of
rustynet in its own lab against its own nodes**: each stage attacks the mesh from
outside the daemon to prove rustynet rejects the attack. No product code changes;
lab-bin and orchestrator-stage code only.

## The one-line problem

The live suites prove *posture* (the daemon grading itself) and *library-level
rejection* (in-process verifier tests). They never attack a **running daemon on
the wire**. These stages close that: a real forged/replayed/planted input
delivered to a live node, with detection proven by an **independent** observation
(a second node's view, a packet/ruleset capture over SSH, an on-disk hash) — never
the daemon's own `overall_ok` (tough-policy rule 2).

## The shape every stage follows (do not deviate)

Read `crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control.rs` end
to end; it is the template. Each new stage is:

1. one catalog row in `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs`
   with a QH-83 `StageEvidence::File(<inversion-transcript path>)` witness;
2. one `OrchestrationStage` impl (its own file under `stage/` or a module in
   `negative_control.rs`);
3. one `PlanBuilder` arm behind the existing opt-in flag
   (`--enable-negative-control` for NegativeControl, `--enable-chaos-suite` for
   Chaos), added to the suite list and the exact-count plan test;
4. the **inversion transcript** as the declared witness: it must record that the
   sabotage was *applied* AND *detected* (and the accept-leg: the genuine input
   still works);
5. `Skipped(<precisely-named precondition>)` when a required role/platform is
   absent — never `Failed`, never `Passed`, for a topology gap;
6. forgeries minted with **throwaway in-process keys** exactly as
   `negative_control.rs` already does; no product crypto touched.

Unit tests per stage, mandatory: (a) pin the catalog row's declared witness path;
(b) a mutation test proving the pass verdict is unreachable without the detection
half (drop the detection assertion → test goes red); (c) prove `Skipped` on the
missing precondition.

Per-stage gate (own `CARGO_TARGET_DIR`, pinned toolchain):
```
export PATH="$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH"
cargo fmt --all
cargo clippy -p rustynet-cli --all-targets --all-features --locked -- -D warnings
cargo nextest run -p rustynet-cli --all-targets --all-features --locked --retries 0 \
  -E 'test(/negative_control|chaos|plan::tests|stage::tests/)'
```
Then an adversarial GLM flash review (brief it to break the stage, file:line),
then a live re-verify on lenovo-bot AND katana before any evidence claim.

## The stages, in build order

### QH-89 `negative_control_enrollment_token_replay` (HIGH, small — do first)
Reuse the target wiring in `live_enrollment_restart_validation.rs:90-102`. Enrol
the `aux` enrollee once through the live anchor enrollment listener; capture the
token; replay it **sequentially and as two concurrent consumes** (the race
RSA-0023 closed with `acquire_ledger_lock`).
- Detection (independent): both replays rejected `already_consumed`; the
  enrollment ledger has exactly one consumed row; mesh peer count unchanged, read
  from the **orchestrator's own pubkey collection**, not the daemon's status.
- Fail-closed pass: replay rejected + ledger single-row + peer count unchanged;
  accept-leg = the first genuine enrolment succeeded.
- Product paths exercised: `crates/rustynetd/src/enrollment_token.rs:1085`
  (`was_consumed`), `enrollment_consume.rs`, the anchor enrollment listener
  (`bind_anchor_enrollment_listener` in `daemon.rs`).

### QH-90 `negative_control_killswitch_bypass` (HIGH, small)
Plant `pass out quick all` above the killswitch terminator in the guest's **live**
ruleset from outside the daemon (Linux nftables; macOS pf variant above
`MACOS_PF_TERMINAL_BLOCK_RULE`, `phase10.rs:3751`, with the egress interface NOT
acknowledged — gate that leg to macOS). Run the SAME assertion the killswitch
validators use.
- Detection (independent): the ruleset dump the lab captured, not a daemon
  self-report. Stage must FAIL naming the precedence error while the rule is
  planted; remove it and require the assertion to pass again (the inversion). The
  acknowledged-egress accept must fire only when the daemon set the flag (PF-01).
- Product path: the daemon's `assert_killswitch` /
  `evaluate_macos_killswitch_rules_acknowledging` precedence walk (`phase10.rs`).

### QH-87 `negative_control_rogue_anchor_bundle` (BLOCKER, medium)
Stand up the existing anchor, then a second "rogue anchor" process serves four
bundles over the real listener, minted in-process with throwaway keys (corpus
pattern at `negative_control.rs:1586-1745`): (a) forged attestation signature;
(b) valid signature but epoch regression; (c) same-epoch different-root fork;
(d) quorum inflation via duplicate approver pubkeys.
- Detection (independent): the guest's `pull-bundle` exits non-zero naming each
  rejection; **zero bytes land** (target-dir hash + mtime before/after); the
  on-disk watermark file hash is unchanged.
- Fail-closed pass: every forgery rejected by name with zero writes; the genuine
  control bundle still pulls and applies.
- Product path: `rustynet_control::membership::verify_attested_snapshot` + the
  daemon watermark (SecurityMinimumBar §3.C2 enforcement points).

### QH-88 `negative_control_wire_forgery` (BLOCKER, medium)
From the client node (outside the daemon, over SSH), send to the exit: a forged
signed membership update and a replayed valid-but-superseded update to the gossip
UDP socket (51821), and a forged assignment bundle via the IPC socket.
- Detection (independent): rejections in the daemon journal, PLUS the **second
  node's** converged view and the guest's on-disk snapshot hash unchanged; no
  epoch movement, no `restricted_safe_mode` flapping. Never the daemon's own
  `overall_ok`.
- Product path: `rustynet_control::membership::apply_signed_update`,
  `crates/rustynetd/src/gossip_transport.rs`.

### QH-91 `chaos_hello_flood_live` (SHOULD-FIX)
Client floods the relay's pre-auth HELLO path: (a) connection-count flood past
RSA-0037's cap; (b) maximal-length HELLO frames probing the bare `u16` length
(AUDIT-031, still open — `AdversarialSecurityRemediation_2026-07-29.md:295`:
"pre-auth limiter stores the unverified value as a map key — 1015 MiB retained").
- Detection (attacker-side + independent): refusals/resets observed by the
  client; relay `status` IPC still answering within a bound; RSS bounded
  before/after, captured over SSH (not the relay's `hello-limiter-audit`, which is
  self-report).
- Fail-closed pass: no relay panic/OOM, refusal counters rise, memory delta under
  the byte cap; else fail naming AUDIT-031.
- Product path: `rustynet-relay` hello limiter, `parse_relay_hello`.

### QH-92…QH-95 (lower priority)
- `negative_control_rogue_dns_answer`: hostile resolver answers a managed name;
  prove the client *rejects the forged answer*, not merely refuses to forward.
- `negative_control_stolen_identity_join`: a second node presents a cloned
  identity/key; join refused, no duplicate peer.
- `negative_control_host_key_swap`: host key swapped / same-IP-new-host; lab
  refuses (lab-trust, not product exploit).
- `chaos_helper_socket_race`: privileged-helper socket race; no escalation.

## Cross-cutting (tough-policy rule 2)
Six existing stages decide pass from the daemon's own audit output and need
orchestrator-side corroboration (nft dump, `ss`, file modes over SSH) rather than
daemon stdout: `dns_failclosed_validation`, `live_hello_limiter_flood_validation`,
and the `key_custody` / `secrets_not_in_logs` / `security_audit` family. Audit I
(pass-criteria strength, in `state/review/r2/I1.out` + `I2.out` when it lands)
enumerates every GUEST-TRUSTING row with the exact cheapest cross-check.

## Lab facts the builder needs
- Hosts: lenovo-bot (`ubuntu@192.168.0.29`, guests `lenovo-client-1` .30 /
  `lenovo-exit-1` .31) and katana (`debian@192.168.18.44`, guests
  `katana-client-1` 192.168.122.45 / `katana-exit-1` .222; flaky Wi-Fi — ship
  commits by `git bundle` over scp, see `ManagerHandover_2026-09-11.md` §5).
- Runs launch ON the host: `mcp__rustynet-lab-state__launch_live_lab_on_host`, or
  the host-local queue scripts in the manager state.
- After every run, fetch the appended ledger rows (`git diff -U0 … | grep '^+'`)
  and revert the host's copies; the launch gate blocks a new run on an
  unremedied prior failure (record `ops live-lab-record-stage-patch`).
- Never delegate the security verdict, crypto, membership, killswitch or dataplane
  product code to a GLM agent — those are manager-implemented, GLM-reviewed. These
  stages are lab-only, so the GLM edit tier is appropriate for the stage code.

## Audit source
Full code-cited analysis: `state/review/r2/H.out` (attack coverage) and
`state/review/r2/I.out` / `I1.out` / `I2.out` (pass-criteria strength). Filed as
QH-87…QH-95 in `QualityHardeningTodo_2026-07-25.md`.
