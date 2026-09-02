# macOS Exit-Serving Adapter Wiring — Post-Merge Refute Review (2026-09-02)

Subject: the macOS exit-serving adapter wiring merged at `3f0be0c1`
(`Merge ai-edit/edit-1788367238…-87816-0`: design
`LiveLabMacosExitServingAdapterDesign_2026-09-02.md` + adversarial-review
amendment A2). This is a docs-only adversarial refute review of the six claims
the merge rests on. Every disposition cites file:line against the merge
result. No code was modified.

## Overall verdict: SOUND-WITH-FOLLOWUPS

All six claims are UPHELD. No security defect was found. Three follow-ups are
recorded (F1–F3 below), none release-blocking: a module-level dead-code
suppression that is broader than its justification, a stale-artifact claim in
a comment that the artifact schema cannot actually enforce, and a
documentation hazard around what the `active_exit` predicate does and does
not gate.

## Claim dispositions

### Claim 1 — ASSERT-NOT-ACTUATE: UPHELD

The CLI adapter never mutates the product firewall. The only `pfctl` invocation
in the adapter path is a read:

- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_exit_traffic.rs:846-855`
  — `sudo -n pfctl -s state`, built from `ValidatedArg` tokens. No `-f`, `-F`,
  `-a <anchor> -e/-d`, no `networksetup`, no `sysctl -w` anywhere in the
  module (grep over `macos_exit_traffic.rs` and `adapter/macos.rs`: `pfctl`
  appears only at :18 (doc), :851-853 (read); `sysctl` only in comments
  :46,:82-90; `networksetup` nowhere).
- Every mutation is the daemon's, and the adapter only runs the daemon's own
  verifier subcommands: `daemon_command` (`macos_exit_traffic.rs:587-600`)
  builds exactly `sudo -n <MACOS_RUSTYNETD_PATH> <subcommand> [extra…]`, used
  for `macos-exit-nat-lifecycle-snapshot` (:606-610) and
  `macos-exit-killswitch-precedence-check` (:642-650). The daemon-side
  subcommands exist (`crates/rustynetd/src/main.rs:451-456`) and the
  flush/tamper/restore mutation is performed inside the daemon
  (`crates/rustynetd/src/macos_exit_killswitch_precedence.rs:8-9`: "snapshot
  the active RustyNet pf anchor, flush it, prove the killswitch assertion
  fails, then restore the exact captured rules").
- Remaining remote commands are read-only or daemon-lifecycle:
  `cat` of the precedence artifact (:655-663), `route -n get default` +
  `ipconfig getifaddr <iface>` (:746-773). The CLI does issue daemon
  lifecycle mutations elsewhere (`launchctl bootout` at
  `role_validation/exit_nat_lifecycle.rs:77-87`, daemon start in the stage
  reactivation), but those are daemon-state, not product-firewall state, and
  the pf consequences are proven by snapshots, not assumed.

### Claim 2 — SEAM-ONLY: UPHELD

Every remote command with a runtime value goes through
`ssh::RemoteCommand::from_args` with `ValidatedArg` constructors:

- All six `ssh::run_remote` call sites in the new code pass a `script`
  obtained from `RemoteCommand::from_args` (`macos_exit_traffic.rs:611, 651,
  663, 755, 773, 865`) — each renders a quoted, space-joined argv. No
  `format!(...).as_str()` / `&format!(...)` reaches any `run_remote` sink;
  every `format!` in the module builds error/message strings only (e.g.
  :67, :71-96, :625, :666, :778, :894).
- Construction is the only way to make a `ValidatedArg`
  (`adapter/validated_args.rs:375-377`), and `cli_token` is a hard allowlist
  `[A-Za-z0-9._=/-]` rejecting whitespace and shell metacharacters
  (`validated_args.rs:292-307`), inert inside the single quotes `from_args`
  wraps tokens in.
- The single runtime value that joins a command line — the interface name
  parsed from `route -n get default` output — is validated at the seam
  before use (`macos_exit_traffic.rs:764`), and a crafted `interface:` line
  with any metacharacter is a hard error, not a command.
- The pre-existing `run_validator` path in `adapter/macos.rs:225-252`
  likewise validates every argv element (`build_validator_command`,
  `macos.rs:31-48`), pinned by
  `build_validator_command_rejects_empty_and_unsafe_argv`
  (`macos.rs:416-424`, rejects `"macos-key-custody-check; id"`).
- The role-validation stage dispatches through `RemoteShellHost::run_argv`
  (`role_validation/exit_nat_lifecycle.rs:55-66, 121-133`) — argv vectors,
  never shell strings.

### Claim 3 — KILLSWITCH-PRECEDENCE ORDERING (A2): UPHELD

`run_killswitch_precedence_baseline` is a mutating, root-required experiment
(`sudo -n <daemon> macos-exit-killswitch-precedence-check --output <path>`,
`macos_exit_traffic.rs:642-651`; root requirement inherited from the daemon
and declared in design A2) and it is issued ONLY from the pre-activation
baseline position:

- `MacosExitActivationSequence` (`macos_exit_traffic.rs:679-719`) enforces
  the order: `precedence_baseline` refuses with a named `AdapterError::Protocol`
  once `activation_attempted` is set (:697-704), and `activate` sets the flag
  before running the step (:716), so a FAILED activation also permanently
  disables the experiment (fail-closed: unknown posture ⇒ no further
  mutation). The only composition is baseline-then-activate
  (`activate_exit_serving`, :726-733).
- Pinned by three offline tests (`macos_exit_traffic.rs:1334-1395`):
  `precedence_baseline_runs_before_activation`,
  `precedence_check_cannot_be_issued_after_activation` (asserts the step
  closure never runs), `activation_failure_still_disables_precedence`.
- The restore is verified, not trusted: the baseline closes with a
  post-check lifecycle snapshot proving the daemon restored the exact anchor
  (`assert_exit_snapshot_serving(conn, "killswitch-precedence restore")`,
  :669-671), which fail-closes on absent anchor / disabled forwarding /
  prefix drift (:618-629 via `assess_exit_snapshot`, :62-106).
- Postural nuance (not a defect, recorded as note N1): the guarantee is
  positional (before the adapter's activation step), not postural. macOS
  exit NAT is enforce-time (`macos_exit_nat.rs`, design :123, :190), so when
  the sequence runs — including the stage reactivation path
  (`stage/exit_nat_lifecycle_validation.rs:97-111`) after `start_daemon` —
  the daemon may already have re-applied the anchor, and the experiment
  flushes exactly that enforced posture. Design A2 accepts precisely this
  ("baseline posture … or in an explicitly declared window with a post-check
  snapshot proving the restore",
  `LiveLabMacosExitServingAdapterDesignAdversarialReview_2026-09-02.md:76`);
  the restore is proven either way.

### Claim 4 — FAIL-CLOSED: UPHELD

- Missing/unparseable/foreign-schema artifacts are errors, never skips:
  `evaluate_macos_exit_nat_lifecycle_artifact`
  (`vm_lab/mod.rs:20376-20428`) rejects parse failure (:20380-20381),
  `schema_version != 1` (:20382-20390), missing fields via `require_json_*`,
  absent during-run anchor (:20398-20403), prefix drift (:20404-20409),
  non-Enabled forwarding (:20410-20411 via
  `require_forwarding_enabled_macos`, :21647-21656), leftover anchor
  (:20414-20418) and unrestored forwarding (:20419-20424) after stop.
  `evaluate_macos_exit_killswitch_precedence_artifact`
  (`mod.rs:21570-21602`) rejects parse failure, wrong schema, baseline
  not-ok (:21584-21586), tampered-ok (:21588-21590), zero tamper exit code
  (:21591-21594), empty reason (:21595-21598). The adapter maps evaluator
  rejection to `AdapterError::Protocol` (`macos_exit_traffic.rs:664-667`)
  and `cat` of a missing artifact is a non-zero remote exit ⇒
  `AdapterError::Command` (`adapter/ssh.rs:566-574` — `run_remote` fails
  closed on any non-zero exit, so a failing precedence check aborts the
  baseline before the artifact is ever read).
- Dry-run provenance can never pass:
  `evaluate_macos_exit_egress_evidence` rejects an empty `live_run_id`
  (`dry_run_provenance`, `macos_exit_traffic.rs:432-437`) and a mismatched
  one (`live_run_id_mismatch`, :438-443); the legacy dry-run stage path
  records `Skipped`, not Pass (`mod.rs:12030-12034`).
- The negative tests are compiled and active after the unquarantine. The
  merge removed `#[allow(dead_code)]` from both evaluators and made them
  `pub(crate)` (diff of `3f0be0c1` on `mod.rs`), and both keep full
  `#[cfg(test)]` negative sets: lifecycle at `mod.rs:45787-45916`
  (accepts/round-trip/rejects leftover anchor, prefix drift, unknown schema
  version, forwarding-not-restored) and precedence at `mod.rs:47504-47544`
  (accepts reviewed payload; rejects tampered success, zero exit code).
  None carry `#[ignore]`; the merge verified them under the full
  `rustynet-cli` suite (3372 tests, merge commit message). The unquarantine
  is what makes the evaluators *reachable*; the tests were never dropped.

### Claim 5 — PREDICATE ROLLOUT: UPHELD

- `active_exit_runtime_implemented` returns false for macOS:
  `stage/active_exit.rs:185-187` — `matches!(platform, Linux | Windows)`.
  It is a pure function of the platform with no mutable state, no setter,
  and no code path that flips it (grep: the only references are the gate at
  :88 and the tests).
- The reported-skip path is named, never silent: :88-93 writes
  `active_exit.reported_skips.json` (content pinned at :194-205) and returns
  `StageOutcome::Skipped`, so the run goes Partial rather than executing an
  unproven sequence.
- No pre-live-run activate→assert for macOS: the only callers of the three
  exit methods are `active_exit.rs:99,113,144` (behind the predicate) and
  `stage/exit_nat_lifecycle_validation.rs:102,107` — the latter is itself a
  live orchestrated stage (it is the macOS cell's live-evidence vehicle; see
  note N2). Offline tests drive the sequence only through closures and
  `MockShellHost` (`macos_exit_traffic.rs:1334-1395`;
  `role_validation/exit_nat_lifecycle.rs:230-298`).
- The pin test exercises the real adapter:
  `macos_two_phase_stage_reports_skip_while_predicate_false`
  (`active_exit.rs:322-401`) constructs a real
  `MacosNodeAdapter` (:340-343), asserts its platform is `Macos` (:343),
  executes the real stage, asserts `StageOutcome::Skipped` naming the
  platform (:381-389), and asserts the artifact names the alias and platform
  (:390-399). Not a stub.

### Claim 6 — NAT IDENTITY: UPHELD

- `is_mesh_cgnat_addr` (`macos_exit_traffic.rs:275-283`) accepts IPv4 with
  first octet 100 and second octet 64–127 — exactly `100.64.0.0/10`
  (`100.64.0.0`–`100.127.255.255`); IPv6 and non-mesh addresses are false.
- `select_macos_client_nat_state` (:301-337) binds BOTH ways: the record's
  `original_source` must equal `client_mesh_addr` exactly AND that address
  must be inside the mesh range (:306-311 — a non-mesh address is rejected
  even if a record matches), and `translated_source` must equal
  `exit_egress_addr`. An attacker-chosen source cannot satisfy it: the
  expected address comes from the run's own assignment
  (`active_exit.rs:138` via `ctx.mesh_ips`), the records come from a
  root-read `pfctl -s state` on the exit, and a spoofed 100.64/10 source
  would have to traverse the mesh to appear there. The no-known-address
  fallback (`select_macos_client_nat_state_by_range`, :809-823) matches only
  mesh-sourced sources translated to the exit's egress address and is
  honestly labelled the weaker claim (QH-25; `active_exit.rs:262-272`,
  tests :1399-1423).
- A malformed line is a parse error, never a false match:
  `parse_macos_pf_state_translation_line` (:229-270) requires the exact
  `<fam> <proto> <taddr> (<oaddr>) -> <daddr>` shape and `parse_addr_port_token`
  (:193-219) rejects ambiguous IPv6 spellings instead of guessing; the
  negative matrix is pinned at :1054-1081 (garbage, missing arrow,
  non-parenthesized source, bad protocol, bad address, port overflow,
  unparseable original). Non-translation lines in the global capture are
  skipped and counted, not fatal, and a capture that correlates nothing
  fails at selection time (:784-803, :858-898).

## Findings (ranked)

- **F1 (Low — lint hygiene):** `macos_exit_traffic.rs:23` carries
  `#![cfg_attr(not(test), allow(dead_code))]` at module level. The module IS
  reachable in production builds (imported by `adapter/macos.rs:7` and
  `role_validation/exit_nat_lifecycle.rs:23-24`), so the attribute also
  suppresses dead-code detection for the live wiring: if
  `activate_exit_serving` were ever disconnected, no warning would fire.
  Minimal fix: once the S2 egress-evidence stage lands and consumes
  `evaluate_macos_exit_egress_evidence`, delete the attribute (or narrow it
  to the genuinely test-only S2 items).
- **F2 (Low-Med — evidence freshness):** `run_killswitch_precedence_baseline`'s
  comment claims "a missing, stale, unparseable, or foreign-schema artifact
  is an error" (`macos_exit_traffic.rs:653-654`), but schema v1 carries no
  timestamp or run id (`MacosExitKillswitchPrecedenceReport`,
  `rustynetd/src/macos_exit_killswitch_precedence.rs:59-63`) and the
  evaluator checks shape only (`mod.rs:21570-21602`). A leftover valid-shape
  file at the fixed path
  (`MACOS_EXIT_KILLSWITCH_PRECEDENCE_ARTIFACT_PATH`, :571-572) from a
  previous run would pass if the daemon ever exited 0 without rewriting it.
  Mitigations today: the check command must exit 0 before the read
  (`ssh.rs:566-574`) and a missing file errors. Minimal fix: bind freshness —
  add `captured_at_unix` to the schema and assert recency in the evaluator,
  or have the daemon print the artifact verbatim on stdout so the adapter
  captures it fresh (the pattern already used for the lifecycle snapshot).
- **F3 (Info — documentation hazard, this review is the fix):** the
  `active_exit` predicate being false for macOS is easy to over-read as
  "the macOS adapter never runs the exit sequence". It does — live — via the
  `exit_nat_lifecycle_validation` reactivation
  (`stage/exit_nat_lifecycle_validation.rs:97-111`) whenever a macOS node
  holds the Exit role. That is the intended live-evidence vehicle for the
  predicate flip (design §6), not a bypass; recorded here so the next reader
  does not re-derive it as a defect.

### Considered, no defect

- `daemon_command` is the only command-construction path in the adapter
  module and is fully seam-validated (`macos_exit_traffic.rs:583-600`).
- `route -n get default` / `ipconfig getifaddr` runtime interface name is
  seam-validated before joining a command line (:764).
- The precedence experiment's root requirement is inherited from an existing
  daemon subcommand, not a new privileged surface (design review :106).
- IPv6 address/port ambiguity in pf state tokens fail-closes (:185-218).
- `100.64.0.0/10` octet arithmetic (:275-283) matches the /10 mask exactly.
- Empty pf capture fails closed at selection (:1419-1422); skipped
  non-translation lines are counted into the failure reason (:879-885).
- Bounded retry budget for the NAT-session convergence loop
  (:580-581, 10 × 1.5 s) and a bounded anchor-discovery budget daemon-side
  (`macos_exit_killswitch_precedence.rs:23-42`).
- Legacy stage call sites (`mod.rs:12068`, :12279) still gate on mesh-join
  and capture success before evaluating; dry-run records Skipped (:12030-12034).
- `RemoteCommand`'s `Debug` redacts content (`ssh.rs:516-521`) — no command
  text leaks to logs.
- `active_exit_runtime_implemented` test pin (`active_exit.rs:310-315`) and
  the macOS-specific skip-note content test (:403-410) both survive.

## Status

Review-only deliverable; no code changed. Follow-ups F1–F2 belong to the
macOS exit cell's live-lab iteration (`active_exit` predicate flip work),
not to this review.
