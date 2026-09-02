# Live-Lab macOS Exit-Serving Adapter Design (2026-09-02)

**Status:** design only — no code, no lab run, no pass claimed. This document decides the
shape of the macOS exit-serving adapter for the Rust `--node` orchestrator (Phase-C
candidate 13 in `LiveLabStagePassLikelihood_Summary_2026-09-01.md` §2, row 13) and the
killswitch-precedence fold-in that closes the `macos_pf_killswitch` coverage gap.
Adversarial review COMPLETE (verdict: READY-WITH-AMENDMENTS); design amended accordingly
and implementation-ready. Implementation remains owner-gated stage work pending lab
availability (CP-1).

**Disposition:** docs-only design/review artifact. Every tree claim below was read from
this worktree with a file:line anchor; items that could not be confirmed from source are
marked **UNVERIFIED** and repeated in §10 as open questions.

**Adversarial-review amendments folded (2026-09-02)** — amendments A1–A6 from
`LiveLabMacosExitServingAdapterDesignAdversarialReview_2026-09-02.md` §9 (plus its §8
anchor corrections) are folded into this document:
- **A1** — the orchestrator role-mapping remap is added to scope: `role.rs:160` /
  `:186-189` still map a macOS `Exit` election to the `blind_exit` daemon role (pinned
  tests `:458-476`, `:508-545`); the remap, its pinned tests, and the `active_exit.rs`
  comment refresh land with this work, with `phase10.rs:3877` / `:4485`/`:4495-4541` as
  the enforce-time proof that the regular-exit posture is real (§2, §7, §8).
- **A2** — the killswitch-precedence check is declared MUTATING (flush/tamper/restore,
  `macos_exit_killswitch_precedence.rs:3-9`, pfctl write required) and re-sequenced:
  before `activate_exit_serving`, or in a declared window with a post-check restore
  snapshot — never mid-serving. Both CLI evaluators are `#[allow(dead_code)]`-quarantined
  (`mod.rs:20075` / `mod.rs:21266`); unquarantining is in scope (§3, §5, §7).
- **A3** — Q1 gains the in-tree `pfctl -ss` caution at `adapter/macos_traffic.rs:134-135`
  and the anchors-enumeration precedent at `:113-115`; global `pfctl -s state` is the
  reliable-but-broad surface; fail-closed until a captured fixture exists (§3).
- **A4** — the rollout contract replaces "same change set as the run-matrix row" with the
  enforceable ordering + equality contract: flip commit lands committed and clean BEFORE
  the verifying run, and the appended row's `git_commit` must equal the flip commit;
  pass/fail from the stage artifact (§6).
- **A5** — stale anchor corrections folded: `windows_traffic.rs` retry/identity anchors
  re-pinned (`:305-313`, `:318-332`, `:314-328`, doc `:275-299`, assert `:257-273`/`:300`),
  `active_exit.rs:348` relabeled positive identity test (negative pair `:371`/`:406`),
  `macos_exit_nat_lifecycle.rs:58` → `:59` (§1, §3).
- **A6** — the S2 sink must sit on the exit's post-CP-1 egress segment `192.168.64.0/24`;
  the two-phase fallback is acceptable only WITH pf-state capture (§4).

## 0. Decisions at a glance

| # | Question | Decision |
| --- | --- | --- |
| 1 | Which role does the macOS exit cell prove? | The **regular `exit` role** (daemon-side `macos_exit_nat.rs` pf NAT + IPv4 forwarding). Not `blind_exit`, which is already live-proven on `--node`. |
| 2 | Adapter surface | macOS implements three `NodeAdapter` exit methods by **asserting the daemon's own lifecycle verifier** (`rustynetd macos-exit-nat-lifecycle-snapshot`) — it never re-derives pf parsing in the CLI and never mutates the product firewall directly. |
| 3 | Egress proof | Two-phase end-to-end S2 assertion: client burst (Linux client) + pf-state/translation identity on the exit + sink-observed translated source address. Written to `active_exit.egress_evidence.json`; fail-closed evaluation; dry-run can never pass. |
| 4 | `macos_pf_killswitch` coverage | Restored as a live, StageId-backed check by running the daemon's `macos-exit-killswitch-precedence-check` subcommand and evaluating its artifact inside the exit-serving cell — the mutating check runs before activation or in a declared window, never mid-serving (A2, folded). The dead ledger column name is **not** resurrected. |
| 5 | Rollout | `active_exit_runtime_implemented` stays `false` for `Macos` until the adapter is real **and** a live run passed; the predicate flip is the last commit, per the doc-comment contract. |

## 1. Grounding

- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/active_exit.rs` — stage shape
  `activate_exit_serving()` → `assert_exit_actively_serving()` → client
  `drive_exit_egress_probe()` + exit `assert_mesh_client_nat_session(expected)`
  (`:95-171`); predicate `active_exit_runtime_implemented` admits only `Linux | Windows`
  (`:184-186`); comment `:177-183` records the macOS-exit→blind_exit mapping; doc-comment
  `:191-201` states promotion follows a live macOS run, never precedes it; reported-skip
  artifacts `:188-189`; QH-25 egress evidence `:248-302`; pinned predicate test `:310`
  (`:309-314`); egress-evidence tests `:348` (POSITIVE identity-proven test,
  `egress_evidence_names_pair_and_identity_when_proven`), `:371` (weaker-claim negative),
  `:406` (no-exit-node fail-closed negative) (A5, folded).
- Daemon: `crates/rustynetd/src/macos_exit_nat.rs` — rules in the `com.rustynet/nat` pf
  anchor (`:7-22`, `DEFAULT_MACOS_EXIT_PF_ANCHOR` re-export `:33`), daemon enables IPv4
  forwarding, verification contract = `pfctl -a com.rustynet/nat -s nat` shows ≥1 `nat`
  rule AND `sysctl -n net.inet.ip.forwarding` reads 1; fail-closed ruleset parser
  `evaluate_macos_exit_nat_pf_rules` `:121` (exactly the reviewed NAT rule set; any
  smuggled filter rule is a rejection); the anchor is flushed on **every** deactivation
  (`should_remove_macos_exit_nat_anchor` `:82`) — unlike blind_exit, which persists to
  factory reset.
- Lifecycle verifier: `crates/rustynetd/src/macos_exit_nat_lifecycle.rs` — schema v1
  (`:33`), `collect_macos_exit_nat_lifecycle_snapshot` `:94` (pf anchor capture `:202` +
  sysctl capture `:229`), fail-closed RSA-0031 interpretation `:183-188` (a capture error
  reports the anchor as still present, never as cleanly removed), two-phase merge
  `merge_macos_exit_nat_lifecycle_artifact` `:149`, offline parsers `:260/:274/:297`.
- Daemon CLI: `crates/rustynetd/src/main.rs` — subcommand dispatch
  `macos-exit-nat-lifecycle-snapshot` `:454-456` (impl `:2005`, `--mesh-cidr` required,
  `--pf-anchor` optional with the default anchor `:2035-2040`, single-phase snapshot JSON
  to stdout; doc `:1998-2004` records the two-phase run/merge contract the orchestrator
  follows) and `macos-exit-killswitch-precedence-check` `:451-453`.
- Killswitch precedence: `crates/rustynetd/src/macos_exit_killswitch_precedence.rs` —
  schema v1 `:20`, killswitch anchor prefix `com.apple/rustynet_g` (`:21`; distinct from
  the NAT anchor `com.rustynet/nat`), "Presence is not precedence (PF-05)" `:127`,
  evaluator `:148`, non-filter rule classification `:169`, highest-generation anchor
  selection `:262` plus an all-anchors probe `:272+` (a daemon restart can leave an old
  generation still loaded).
- Orchestrator validators already in-tree: `evaluate_macos_exit_nat_lifecycle_artifact`
  at `crates/rustynet-cli/src/vm_lab/mod.rs:20076` (call site `:12057`; negative tests
  `rejects_leftover_anchor_after_stop` `:45571`,
  `rejects_internal_prefix_drift` `:45586`, `rejects_unknown_schema_version` `:45601`)
  and `evaluate_macos_exit_killswitch_precedence_artifact` at `mod.rs:21267` (call site
  `:12268`; negative tests `:47199-47232`).
- Adapter peers: `adapter/node_adapter.rs` — `activate_exit_serving` `:296` (default
  `:297-302` fail-closed `UnsupportedPlatform`), `assert_exit_actively_serving` `:309`,
  `drive_exit_egress_probe` `:322` (client-side, Linux-only by doc `:323-327`),
  `assert_mesh_client_nat_session` `:339-350` (QH-25 identity evidence, doc `:330-337`),
  `shell_host` `:386`. `adapter/macos.rs` currently implements **only** `shell_host`
  (`:78`). `adapter/linux_traffic.rs` holds the reference implementations:
  `activate_exit_serving` `:589` (constant-argv `route advertise 0.0.0.0/0` over the
  daemon socket, daemon rejection surfaced as `AdapterError::Protocol` `:600-605`),
  `assert_exit_actively_serving` `:622-654`, `assert_mesh_client_nat_session` `:674-723`;
  `adapter/windows_traffic.rs` is the second shape: collect-active-tunnels fn `:195`,
  `Get-NetNatSession` assertion with the identity check performed in Rust, not in the
  guest script — assert fn `:300` (preceding fn ends `:273`), doc `:275-299`, identity
  match `:314-328` (`is_none_or` at `:322-324`), 10×1.5 s bounded retry (`:305-313`
  guest script, `:318-332` outer loop) (A5, folded).
- Grounding docs: adversarial review §2
  (`LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md:49-61`, incl. the
  architectural note at `:55` and the role-mapping tension recorded as an open Phase-C
  question at `:57` and again in §10 at `:161`); summary row 13
  (`LiveLabStagePassLikelihood_Summary_2026-09-01.md:60`, `:102-103`, `:109`); macOS
  bucket §1 exit_handoff (`LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md:40-45`)
  and the `macos_pf_killswitch` dead-column caveat (`:177`); S2 drift rule
  (`CrossPlatformRoleParityRefresh_2026-07-23.md:389-398`); CP-1 verdict
  (`CrossPlatformRoleParityRefresh_2026-07-23.md:294`, `:117-133`); revocation ordering
  (`documents/SecurityMinimumBar.md:529-532`); AGENTS.md §10.7 exit-NAT teardown
  ordering.

## 2. Decision 1 — the cell proves the regular `exit` role

The orchestrator comment (`active_exit.rs:177-183`) says a macOS Exit "maps to the
blind_exit role"; the daemon (`macos_exit_nat.rs:7-22`) implements enforce-time NAT for
the *regular* `exit` role on macOS. Both statements describe different layers, and the
tension is resolvable without changing either today:

- **Product truth:** the daemon supports a regular macOS exit — `com.rustynet/nat` +
  forwarding, reversible per deactivation (`:82`). This is the role the parity mandate
  cares about ("exit works and is live-proven on macOS").
- **Orchestrator reporting:** the current macOS-exit→blind_exit mapping exists only
  because the `--node` exit-family stages had no macOS adapter; it is a skip-posture
  workaround, not a role assignment. The design removes the need for it: once the
  adapter lands, a macOS exit slot elects as `exit` and runs the real stage chain.
- `blind_exit` on macOS needs **no** new proof from this work: it passed live on
  `--node` on 2026-08-31 (`CrossPlatformRoleParityRefresh_2026-07-23.md:102`,
  run `livelab-1788172934687-17194-11`, commit `7bdcfe60`).

**A1 (folded): the remap is part of this work.** The daemon already enforces the
regular-exit posture: `phase10.rs` `apply_nat_forwarding` (`:4485`, body `:4495-4541`)
takes the killswitch filter anchor first (`:4514-4520`, so NAT failure leaves egress
blocked), then `activate_exit_nat` (`:3877`) loads `com.rustynet/nat` via the privileged
helper (`MacosPfLoadSpec::ExitNat` → `PrivilegedCommandProgram::MacosPfLoad`,
`:3926-3933`) and verifies + fail-closes on drift (`:3961-3973`); teardown flushes the
anchor before restoring forwarding (`:3987`). The orchestrator, however, still maps a
macOS `Exit` election to the `blind_exit` daemon role — `orchestrator/role.rs:160`
(`NodeRole::Exit | NodeRole::BlindExit => Ok("blind_exit")`), the macOS capability pair
at `:186-189`, and the pinned tests at `:458-476`
(`is_supported_for_platform_macos_exit_maps_to_blind_exit_pf_posture`) and `:508-545`
(daemon-role mapping pin asserting `"blind_exit"` at `:543-546`). This work therefore
includes remapping the macOS `Exit` daemon role to the regular-exit posture (daemon role
`client` + `ExitServer`, matching the Linux mapping at `role.rs:202-218`), updating those
pinned tests, and refreshing the stage comment at `active_exit.rs:177-183` — otherwise
the §8 run recipe deploys blind_exit and proves an already-proven role.

**Stage-column mapping.** The live proof targets:

- `macos_stage_exit_handoff` — the macOS face of `exit_handoff`/`active_exit`
  (currently 32 skip / 0 pass, skip text "active-exit runtime is not implemented for
  Macos", `LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md:40-45`).
- `cross_os_exit_path` — the cross-OS face (registry `cross_os: Some("cross_os_exit_path")`,
  fed by the same stages; `:143-145`; registry markings cross-checked by the adversarial
  review at `:59` against `live_lab_stage_registry.rs:1009/:1018/:1148/:1157/:1166`).
- The killswitch-precedence coverage lost with the dead `macos_pf_killswitch` column
  (§5) — closed inside this cell, not by reviving the column name.

`macos_stage_blind_exit*` columns are untouched: blind_exit is proven, and this cell
does not re-prove it.

## 3. Decision 2 — adapter surface: assert the daemon's own verifier

The adversarial review's architectural note is adopted verbatim: the adapter should
*"assert that existing verifier's observable state rather than re-deriving pf parsing in
the CLI — one source of truth for what 'exit active' means on macOS"*
(`LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md:55`).

New module `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_exit_traffic.rs`
(mirroring the `linux_traffic.rs`/`windows_traffic.rs` free-function pattern), wired into
the macOS adapter impl. All guest execution goes through the existing hardened
`shell_host` seam (`node_adapter.rs:386`), argv-only, no shell construction.

**A2 (folded): evaluator availability.** Both CLI evaluators this design reuses are
currently quarantined dead code — `#[allow(dead_code)]` at `mod.rs:20075` (fn
`evaluate_macos_exit_nat_lifecycle_artifact` `:20076`) and at `mod.rs:21266` (fn
`evaluate_macos_exit_killswitch_precedence_artifact` `:21267`), retained since the W5.7
bash-branch deletion for the G2 native re-wire. "Reuse the existing evaluator" is
therefore not free: unquarantining and re-wiring both is in scope for this work (§7).

| `NodeAdapter` method | macOS implementation |
| --- | --- |
| `activate_exit_serving` (`node_adapter.rs:296`) | **Assert, do not actuate.** macOS exit NAT is enforce-time — the daemon applies `com.rustynet/nat` + forwarding when the role is enforced, so there is no orchestrator-side actuation to perform (this is the documented mechanism divergence, `CrossPlatformRoleParityRefresh_2026-07-23.md:389-391`). The method runs the daemon's snapshot subcommand (`rustynetd macos-exit-nat-lifecycle-snapshot --mesh-cidr <cidr>`, `main.rs:454-456`, `:2005`) and returns `Ok` only if `pf_anchor_present` is true. Absent anchor → `AdapterError::Protocol` carrying the parsed snapshot reason (fail-closed; the Linux reference surfaces daemon reasons the same way, `linux_traffic.rs:600-605`). |
| `assert_exit_actively_serving` (`node_adapter.rs:309`) | Run the snapshot subcommand and require: `pf_anchor_present == true`, `sysctl net.inet.ip.forwarding == 1`, and `internal_prefix` equal to the run's expected mesh CIDR (the snapshot already parses the observed NAT-rule CIDR, `macos_exit_nat_lifecycle.rs:59/:274`). Anchors compared as the verifier reports them — the CLI never parses `pfctl` output itself. |
| `drive_exit_egress_probe` (`node_adapter.rs:322`) | **Unchanged — stays Linux-only.** The client in this cell is a Linux guest (`cross_os_exit_path` is a Linux-client→macOS-exit proof); the Linux burst implementation (`linux_traffic.rs:549-552`) already exists. A macOS *client* is out of scope for this design. |
| `assert_mesh_client_nat_session` (`node_adapter.rs:339`) | Run the snapshot subcommand for the anchor/prefix half, and `pfctl -s state` (read-only, argv-only) for the translation half: parse translation records whose original source lies in `100.64.0.0/10` and whose translated side matches the exit's egress address; the expected-client-mesh-addr identity check is applied in **Rust**, never in the guest command (the Windows pattern, `windows_traffic.rs:314-328`, match at `:322-324`), with the same 10×1.5 s bounded retry (`:305-313` guest script, `:318-332` outer loop). The `pfctl -s state` output shape is **UNVERIFIED** on the UTM guest (§10 Q1); the parser is written against a captured fixture, and until one exists the method fail-closes on parse failure. |
| two-phase lifecycle | The stage runs the snapshot subcommand twice (during exit mode + after daemon stop) and merges via `merge_macos_exit_nat_lifecycle_artifact` (`macos_exit_nat_lifecycle.rs:149`) into the artifact `evaluate_macos_exit_nat_lifecycle_artifact` (`mod.rs:20076`) validates — exactly the contract the producer doc-comment records (`main.rs:1998-2004`). The after-stop half must show the anchor flushed; a leftover anchor is a rejection (`mod.rs:45571` test). |

**A3 (folded): Q1 in-tree precedent.** `adapter/macos_traffic.rs` enumerates anchors via
`sudo -n pfctl -s Anchors` (`:113-115`) and warns at `:134-135` not to use anchor-scoped
`pfctl -a <anchor> -ss` on macOS, because an empty parent anchor can still print
unrelated global connection state. Global `pfctl -s state` is therefore the
reliable-but-broad surface; the parser filters to the client's source address in Rust
and fails closed on any unparseable line until a captured fixture exists. No
`pfctl -s state` parser or fixture exists in the tree today, so Q1 remains open exactly
as stated (§10).

`probe_denied_peer` / `collect_active_tunnels` (`node_adapter.rs:282-284`) are not part
of this cell's assertions and keep their platform defaults.

## 4. Decision 3 — the S2 end-to-end egress assertion

The drift rule is absolute: a macOS exit cell must **not** reach G2-green without an
"equivalent-strength end-to-end egress assertion — a client's packets provably egress
through the macOS exit to an external target … Lifecycle-proven ≠ egress-proven"
(`CrossPlatformRoleParityRefresh_2026-07-23.md:392-398`). A `nat` rule line existing in
the anchor is exactly the mechanism-translated assertion S2 forbids. The Linux cell's
QH-25 shape (`active_exit.rs:248-302`: `MeshClientNatSession{client_source,
translated_side, observed_via}` + `identity_proven`) is the bar, expressed via the pf
model.

**The two-phase proof** (both halves required; either missing → `Failed`):

1. **Drive:** the Linux client bursts N connections to the egress target through its
   exit-selected default route (existing backgrounded probe, `linux_traffic.rs:549-552`).
2. **Observe on the exit:** during the burst window, the macOS side must produce
   *correlated* evidence that (a) a pf state translation existed for that client's mesh
   source address (from the `pfctl -s state` capture of §3), and (b) the sink observed a
   connection whose source address equals the exit's egress address within the burst
   window. The sink is a lab-local listener on the exit's egress LAN side (a second
   guest or the host) so the *source address* is actually observable; a public target
   like `1.1.1.1` can prove reachability but cannot prove the translated source by
   itself. Where the sink cannot be arranged, a two-phase reachability fallback
   (bursts fail with the NAT anchor flushed, succeed with it present, same target,
   same client) is acceptable **only** if it also captures the pf state records — the
   decision between sink-observation and the fallback is open (§10 Q2).

**A6 (folded): sink-segment requirement.** The sink must observe the exit's egress-side
segment: after CP-1 that is `192.168.64.0/24` (the Debian bridge100 host or any bridged
guest on it); the pre-CP-1 Shared-NAT segment (`192.168.65.0/24`) is host-unobservable
and can never host the sink. Q2 resolves to: sink observation, or the two-phase
reachability fallback WITH pf-state capture — never the fallback without pf-state capture
(the Refresh §6 equivalent-strength bar at `:389-398`, esp. `:396`, admits nothing
weaker).

**Evidence artifact.** `active_exit.egress_evidence.json` is extended with the macOS
fields: `translated_side` = the exit's egress address, `observed_via = "pf_state"`,
`sink_observation` (or the fallback's two-phase record), and `identity_proven` computed
only when client mesh address, pf-state original source, and the burst window all
correlate — the QH-25 field set, unchanged in meaning.

**Fail-closed evaluation.** A new offline evaluator consumes the artifact and returns
pass only on a complete, correlated, in-window record set. Missing artifact, partial
correlation, out-of-window timestamps, or a schema mismatch is `Failed`, never `Partial`
and never a skip. The stage body refuses to report pass from a dry-run: the evaluator
rejects any artifact lacking the live run id it was produced under (mirroring the
FAIL-LOUD live-stage spec — a live result is the stage status; there is no
dry-run-as-pass path).

## 5. Decision 4 — killswitch-precedence fold-in (restoring `macos_pf_killswitch` coverage)

The `macos_pf_killswitch` ledger column is DEAD with a real coverage caveat: it was the
special of `validate_macos_exit_killswitch_precedence`, has no `StageId`, and
"killswitch-precedence proof on a macOS exit has NO live `--node` successor — the
exit-family validators are Linux-only. Flag as a real coverage gap to fold into the
macOS exit-serving work" (`LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md:177`;
column-name family confirmed in
`NeverDispatchedLinuxStagesTriage_2026-08-27.md:443`). The fold-in:

- The exit-serving cell additionally runs, on the macOS exit, the daemon's own
  `macos-exit-killswitch-precedence-check` subcommand (`main.rs:451-453`), which
  produces the schema-v1 `macos_exit_killswitch_precedence.json` artifact
  (`macos_exit_killswitch_precedence.rs:20/:66`).

**A2 (folded): the check is mutating — sequencing and privilege contract.** The
precedence check is a mutating, root-required experiment: it snapshots the active
anchor, flushes it, proves the assertion fails, and restores the exact rules
(`macos_exit_killswitch_precedence.rs:3-9`). It therefore requires pfctl *write* (root
or a privileged helper), unlike the lifecycle snapshot's read-only commands. It is run
BEFORE `activate_exit_serving` (baseline posture), or in an explicitly declared window
whose close is verified by a post-check lifecycle snapshot proving the restore; it is
never run against a live exit-serving posture mid-serving. Its artifact records the
experiment outcome only (baseline/tampered asserts; no live ruleset — evaluator contract
`mod.rs:21260-21265`), so it proves the precedence *property*, not the live posture; the
live posture is proven by the exit-serving stage's own asserts.
- The CLI evaluates it with the existing `evaluate_macos_exit_killswitch_precedence_artifact`
  (`mod.rs:21267`; its negative tests already reject tampered success and zero exit
  codes, `:47199-47232`). The daemon-side evaluator enforces PF-05 — "Presence is not
  precedence" (`:127`, rules `:148`): the terminal block must be *reachable* in the
  ordered chain, and non-filter rules (scrub/nat/rdr/anchor) are never credited as a
  filter verdict (`:169-184`).
- All `com.apple/rustynet_g*` anchors are probed, not just the highest generation
  (`:262`, `:272+`), because a daemon restart can leave an older generation loaded.
- **The dead column stays dead.** Per-stage ledger attribution reads a column name as
  proof of that stage's content; resurrecting a name whose meaning changed would
  contaminate history the same way the two_hop alias did (QH-07). The coverage is
  restored as evidence **inside** the exit-serving stage's report artifacts; if a
  dedicated column is ever wanted, it takes a new name.

## 6. Decision 5 — fail-closed rollout

`active_exit_runtime_implemented` (`active_exit.rs:184-186`) **stays `false` for
`Macos`** until both are true: the adapter methods are real (offline-tested), and a live
`--node` run passed the macOS exit cell with the S2 artifact. The doc-comment contract
is explicit that promotion follows a live run and never precedes it
(`active_exit.rs:191-201`; adversarial review §2.1 `:51`). Until the flip, the stage
keeps its honest reported-skip → `Partial` posture (`:88-92`, artifacts `:188-189`).
The flip commit:

1. extends the predicate to `Macos`,
2. inverts the pinned test `runtime_implemented_linux_and_windows_not_macos` (`:310`)
   into the macOS-positive form, and
3. **A4 (folded): ordering + equality contract.** The flip commit lands committed and
   with a clean tree BEFORE the verifying run is launched; the run's appended row in
   `live_lab_node_run_matrix.csv` must name exactly that commit with a clean dirty state.
   The orchestrator attributes the deployed tree's provenance at run time, so row and
   change set cannot be one commit's contents — equality of the row's `git_commit` with
   the flip commit is the enforceable check (this replaces the earlier "same change set
   as the run-matrix row" wording, which is not literally enforceable). Pass/fail is
   read from the stage's own report artifact (status + data block), never from the
   matrix column alone. This will be the first predicate flip in the stage's history
   (git log on `active_exit.rs`: `b1c3989f`, `b4793800`, `8ec851a9` — none flip the
   predicate), so the row-equality check is mandatory, not borrowed from precedent.

No intermediate "implemented but unproven" state exists; that would silently convert
the reported skip into a live-shaped failure the ledger cannot distinguish from a real
attempt. This mirrors the sequencing already used for the Linux and Windows predicates.

## 7. Offline-testable core (module paths + test names)

Everything judgment-bearing is pure parsing/evaluation over captured fixtures, so the
predicate flip is the only part that must wait for the lab:

- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_exit_traffic.rs`
  - `parse_macos_pf_state_translation_line` — fixture-driven parser for the `pfctl -s
    state` translation record (original source / translated side); malformed line →
    parse error, never a guess.
  - `select_macos_client_nat_state` — identity selection over parsed states
    (expected mesh addr in `100.64.0.0/10`, translated side match), the Rust-side
    identity check.
  - `assert_exit_actively_serving_rejects_absent_anchor`,
    `..._rejects_forwarding_disabled`, `..._rejects_internal_prefix_drift` — the three
    snapshot-verdict branches over synthetic snapshot JSON.
- `egress` evaluator (same module or a sibling `macos_exit_egress.rs`):
  - `evaluate_macos_exit_egress_evidence_fails_closed_on_missing_artifact`,
    `..._on_partial_correlation`, `..._on_out_of_window_timestamps`,
    `..._on_dry_run_provenance`, `..._accepts_complete_sink_observation`,
    `..._accepts_two_phase_fallback_with_pf_state`.
- Two-phase lifecycle: reuse the daemon-side parsers' own tests
  (`macos_exit_nat_lifecycle.rs:327-345`) plus the CLI-side negative tests that already
  exist (`mod.rs:45482-45604`); add `macos_two_phase_stage_reports_skip_while_predicate_false`
  mirroring the `:310` pin so the rollout posture is itself tested. **(A2, folded)**
- **A2 (folded): evaluator unquarantine.** Removing `#[allow(dead_code)]` from
  `evaluate_macos_exit_nat_lifecycle_artifact` (`mod.rs:20075`) and
  `evaluate_macos_exit_killswitch_precedence_artifact` (`mod.rs:21266`) and re-wiring
  their call sites is in-scope implementation work, not a precondition assumed done —
  the existing negative tests (`mod.rs:45482-45604`, `:47199-47232`) re-activate with
  them.
- Sink-side capture format is defined in this design and versioned (`schema_version: 1`)
  so the evaluator can reject foreign payloads the same way the lifecycle artifact does.

## 8. Live proof and sequencing

**Dependencies (ordered, not parallel):**

1. **CP-1 first.** No traffic-facing cell greens while the macOS UTM guest
   (`192.168.65.0/24`, Shared-NAT) and the Debian bridge100 nodes
   (`192.168.64.0/24`) have no L3 path — triaged environmental
   (`CrossPlatformRoleParityRefresh_2026-07-23.md:294`, `:117-133`). The fix is the
   operator-authorized `prepare_lab_network` bridged re-attach of `macos-utm-1` onto
   the `192.168.64.0/24` segment — an explicit operator action, never an autonomous
   mutation (LiveLabVmConnectivityRulebook §13; summary row 8,
   `LiveLabStagePassLikelihood_Summary_2026-09-01.md:55`).
2. **macOS DNS fail-closed enforcement design** — owner-gated
   (`MacosDnsFailclosedEnforcementGap_2026-08-28.md`; macOS bucket §5 item 10,
   `LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md:195`). Without it the exit
   cell can prove NAT + egress but the overall macOS exit verdict stays red on
   `DnsFailclosed`; this design does not block on it for the adapter's own proof, only
   for an overall-green exit claim.
3. Then the adapter (offline-tested core first, §7), then the live run, then the
   predicate flip (§6).

**Run recipe** (after CP-1, and only after the §2 A1 role remap has landed — `alias:exit`
is valid election syntax today but deploys the `blind_exit` daemon posture until the
remap lands, so recipe and remap ship together): `--node` run with the macOS node elected `exit` —
`nodes=["macos-utm-1:exit", "<debian-client>:client", "<debian-anchor/relay>:…"]`,
Linux backbone unchanged, `rebuild_nodes` limited to newly patched aliases on re-verify.
Acceptance per column: `macos_stage_exit_handoff` and `cross_os_exit_path` first-ever
dispatch on macOS; the appended row in
`documents/operations/live_lab_node_run_matrix.csv` is confirmed to exist and be
attributed to the right commit, but the pass/fail claim is taken from the stage's own
report artifacts (stage `status` + the §4/§5 data blocks), never from the column alone
(AGENTS.md §12.3). Exit-NAT teardown ordering follows AGENTS.md §10.7 and
`SecurityMinimumBar.md:529-532`: forwarding + NAT down before the capability leaves
local state; the two-phase after-stop snapshot is the artifact that proves the residue
is gone.

## 9. Evidence artifacts produced by the cell

| Artifact | Producer | Consumer |
| --- | --- | --- |
| `active_exit.egress_evidence.json` (macOS-extended, §4) | stage | offline egress evaluator |
| merged two-phase lifecycle JSON (`during_run` + `after_stop`) | stage runs of `macos-exit-nat-lifecycle-snapshot` | `evaluate_macos_exit_nat_lifecycle_artifact` (`mod.rs:20076`) |
| `macos_exit_killswitch_precedence.json` (schema v1) | `macos-exit-killswitch-precedence-check` | `evaluate_macos_exit_killswitch_precedence_artifact` (`mod.rs:21267`) |
| `active_exit.reported_skips.json` / `reported_skips_egress.json` | stage, while predicate false | rollout honesty (§6) |
| run-matrix row | `--node` wrapper | ledger attribution check (AGENTS.md §10.9) |

## 10. Open questions (owner decisions / measurements needed)

1. **`pfctl -s state` output shape on the UTM macOS guest — UNVERIFIED.** Does the
   guest's pf expose per-connection translation records with an original source in the
   mesh range on the macOS version in the lab, and can the NAT-anchor translation be
   distinguished from unrelated state? A captured fixture is required before the §3
   parser can be trusted; until then the method fail-closes on parse failure.
2. **Sink placement.** Sink-observation (source address actually seen) vs the
   two-phase reachability fallback (§4): the fallback is weaker — it proves the anchor
   gates egress but attributes the translation only via pf state records. Which does
   the owner accept as "equivalent-strength" for G2? Default proposed: sink
   observation when a lab-local sink exists; fallback only with pf-state capture.
   **(A6, folded — RESOLVED):** sink observation, or the two-phase reachability
   fallback WITH pf-state capture — never the fallback without pf-state capture; the
   sink must sit on the post-CP-1 egress segment `192.168.64.0/24` (§4).
3. **Enforce-time ordering.** Is the `com.rustynet/nat` anchor guaranteed applied
   before `exit_handoff`/`active_exit` executes (role enforce earlier in the chain), so
   the assert-only `activate_exit_serving` never spuriously fails? If not, which
   daemon command (argv) is the legitimate refresh trigger — the orchestrator must not
   grow its own pf mutation path. **(RESOLVED by the adversarial review §2, folded):**
   enforcement happens in the daemon's role-apply path BEFORE any stage-level assert
   can succeed, so the assert-only method cannot spuriously fail on ordering; the
   legitimate refresh trigger is the daemon's own `verify_exit_nat_anchor`/teardown,
   never an orchestrator-side pf command.
4. **Precedence semantics while exit-serving.** During active exit serving the
   generation-numbered killswitch anchor carries a forwarding pass while the NAT anchor
   translates. Does PF-05 evaluation (`macos_exit_killswitch_precedence.rs:148`) pass
   in that posture, or does the terminal-block-reachable check need an
   exit-serving-aware expectation? Must be answered from the evaluator before the live
   run, not discovered live. **(RESOLVED by the adversarial review §4, folded):** PF-05
   CAN pass in exit posture — a narrowly-scoped quick pass (bounded `from`/`to`, e.g.
   `from 100.64.0.0/10`, the mesh CIDR the NAT builder emits) counts as NarrowAllow and
   satisfies "Presence is not precedence" while the terminal block stays reachable. The
   actual deployed rule shapes remain unverified until measured. Regardless, the check
   is mutating and must not run mid-serving — sequencing per §5 (A2).
5. **After-stop snapshot ownership.** Which stage/cleanup step runs the second
   `macos-exit-nat-lifecycle-snapshot` after daemon stop, and is the existing Linux
   `exit_nat_lifecycle` stage structure (`role_validation/exit_nat_lifecycle.rs`,
   Linux-only predicate per adversarial review §3.1 `:65`) the right template for a
   macOS port, or does the fold-in keep it inside `active_exit`?
6. **`cross_os_exit_path` generality.** The column also gates on Linux↔Windows exit
   paths (Windows exit is CP-3 hardware-blocked; summary `:109`). Does the owner accept
   a macOS-anchored pass writing this column while the Windows leg remains
   hardware-blocked, or should the column's verdict be annotated (not silently
   general) until CP-3 hardware exists?
7. **IPv6.** The macOS guest's v6 egress posture during exit serving is unmeasured
   (`macos_ipv6_leak` capture exists at `main.rs:457-459`, validator port is a separate
   quickest-win item, macOS bucket §5 item 8 `:193`). Does an active macOS exit
   introduce an IPv6 leak the killswitch anchors do not cover? Measure before claiming
   the cell "secure exit", independent of pass/fail.

## 11. References

- `LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md` §2 (`:49-61`), §10 (`:154-161`)
- `LiveLabStagePassLikelihood_Summary_2026-09-01.md` §2 row 13 (`:60`, `:72`, `:102-109`)
- `LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md` §1 (`:40-45`), §5 (`:188-196`), dead-column table (`:177`)
- `CrossPlatformRoleParityRefresh_2026-07-23.md` §6 S2 rule (`:389-398`), CP-1 (`:117-133`, `:294`), blind_exit pass (`:102`)
- `MacosDnsFailclosedEnforcementGap_2026-08-28.md` (owner-gated DNS design)
- `documents/SecurityMinimumBar.md:529-532`; AGENTS.md §10.7, §12.3, §13.1
- Code: `stage/active_exit.rs`, `adapter/node_adapter.rs`, `adapter/{linux,windows,macos}_traffic.rs`, `adapter/macos.rs`, `crates/rustynetd/src/macos_exit_nat{,_lifecycle}.rs`, `crates/rustynetd/src/macos_exit_killswitch_precedence.rs`, `crates/rustynetd/src/main.rs:445-459`, `crates/rustynet-cli/src/vm_lab/mod.rs:20076/:21267`
