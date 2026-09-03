# macOS exit-cell `DnsFailclosed` — does the anchor-enumeration fix (`2c10f9d9`) change the outcome? — 2026-09-03

**VERDICT: MIXED.** The enum-fix plus the M1 SystemConfiguration enforcement (which landed the
same day the gap was dispositioned) **supersede the original 2026-08-28 rationale** — "the
enforcement posture is written to files the OS does not consult" no longer describes the code.
But the exit cell's `DnsFailclosed` red is **not flipped by the enum-fix**, because the exit cell
never reaches the check's subject matter: it fails closed **earlier**, at role/membership
alignment (`blind_exit` daemon posture vs an anchor-capability genesis membership), and that
blocker is a separate, still-open, owner-gated trust-state design. The disposition **stands**, in
the form its own 2026-08-31 role-split update already gave it — not in the original
enforcement-gap form.

Question asked: commit `2c10f9d9` makes `macos_dns_failclosed.rs::read_pf_dns_block_floor`
also enumerate nested `com.apple` sub-anchors, so the check can finally see the
`com.apple/rustynet_g{N}` pf DNS-block floor. The macOS **client** cell (full-tunnel →
`FullyProtected`) went green with it (`livelab-1788433705-bf4b1b1187c8`, 2026-09-03). Does the
macOS **exit** cell — also `FullyProtected` — therefore pass now, or is its red a genuinely
separate gap?

## 1) Does the macOS exit role install the same nested pf DNS-block floor? — YES, one shared path

The DNS posture is decided from the node's exit posture, **not** its lab role:

- `phase10.rs:794-807` — `macos_dns_posture(exit_mode, serve_exit_node)`: `serve_exit_node`
  (or `ExitMode::FullTunnel`) → `DnsPosture::FullyProtected`. Unit tests at
  `phase10.rs:822-827` pin `serve_exit_node=true → FullyProtected`.
- The daemon bootstrap computes it on macOS and applies in-place:
  `daemon.rs:8894-8898` (`applied_dns_posture = Some(macos_dns_posture(bootstrap_exit_mode,
  serve_exit_node))`), passed through `ApplyOptions { protected_dns: true, …,
  defer_scoped_dns_posture: false }` at `daemon.rs:8909-8918`; the reconcile path repeats the
  same decision at `daemon.rs:10634-10635`. The controller dispatches posture-aware at
  `phase10.rs:7442` → `apply_dns_protection_for_posture` (`phase10.rs:5237-5248`),
  where `FullyProtected => self.apply_dns_protection()` (`:5246`).

`MacosCommandSystem::apply_dns_protection` (`phase10.rs:5075-5227`) is therefore the SAME
sequence for client, anchor, and exit — there is no exit-specific branch, skip, or relocation:

1. `apply_pf_rules(false)` (`:5085`) — loads the pf ruleset whose killswitch spec carries the
   DNS-block anchor `com.apple/rustynet_g{generation}` (`macos_pf_load_spec.rs:186`; generation
   rotation prefix `MACOS_RUSTYNET_ANCHOR_PREFIX = "com.apple/rustynet_g"`,
   `macos_exit_killswitch_precedence.rs:21`).
2. `verify_live_pf_dns_floor()` (`:5093`, def `:4770`) — reads the anchor back BY FULL PATH
   (`pfctl -a com.apple/rustynet_g{N} -s rules`) before any SystemConfiguration mutation; a
   non-live floor fails the apply and rolls back.
3. M1 SystemConfiguration enforcement (`:5096-5224`, owner-approved per
   `MacosDnsFailclosedEnforcementGap_2026-08-28.md` §7 "2026-08-28 — DONE: M1 implemented"):
   per-service `networksetup -setdnsservers … 127.0.0.1` pins (`:5168-5181`), the fail-closed
   `/etc/resolv.conf` loopback write (`:5197-5204`), and the scoped-resolver write
   (`:5217-5224`), all wrapped in M2 all-or-nothing rollback.

The check-side half is exactly what `2c10f9d9` fixed: `read_pf_dns_block_floor`
(`macos_dns_failclosed.rs:511`) enumerates the top-level anchor set (required) **plus** the
nested `com.apple` sub-anchors (best-effort, `:521-525` — a missing nested query can only
narrow the scan, never make the check pass), and `block_rules_present` requires that SOME
enumerated anchor carries both labeled DNS block rules. Before the fix the top-level
`pfctl -s Anchors` never listed the nested anchor, so the check false-failed while the floor
was present. With the fix, a node that actually applied the `FullyProtected` posture — client
or exit — is checked against the real floor.

**Conclusion for (1)/(2):** the exit role installs and verifies the identical floor through the
identical path. Nothing about the enum-fix is exit-specific; it simply made the checker honest
for every `FullyProtected` node. The client cell's 2026-09-03 green is end-to-end proof of the
shared path, and a macos-as-**exit** run would be expected to pass `DnsFailclosed` the same way
— *if it ever reaches the apply*.

## 2) Why the exit cell still will not pass: it fails closed BEFORE the apply

The exit cell's last real failure (`livelab-1788164004680-17194-2`, commit `a80c4de3`,
2026-08-31, per `CrossPlatformRoleParityRefresh_2026-07-23.md` exit row) was root-caused the
same day — by the gap document's own role-split update
(`MacosDnsFailclosedEnforcementGap_2026-08-28.md` §7, "Update 2026-08-31 — role-split
follow-up") and `MacosExitDnsFailclosedRoleSplitInvestigation_2026-08-31.md` — as **NOT a
regression of the enforcement gap**:

- The lab maps a macOS exit to the `blind_exit` **daemon** posture:
  `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:158-160`
  (`NodeRole::Exit | NodeRole::BlindExit => Ok("blind_exit")` for `VmGuestPlatform::Macos`),
  still present at the current HEAD of this worktree.
- The genesis membership a macOS exit bootstrap receives still carries the **anchor**
  capability (issued by `rustynetd main.rs` genesis at `main.rs:4469-4479` per the design
  doc's citations; the macOS membership adapter
  `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs` initializes
  membership and adds only **non-exit** peers — `:111-113` — and contains **no**
  capability-rewrite step; the only membership ops it drives are `init-membership` /
  `e2e-membership-add`, `:225, :237`).
- `validate_node_role_membership_alignment` (`daemon.rs:2357`) hard-rejects that combination:
  `NodeRole::BlindExit if node.capabilities.contains(&RoleCapability::Anchor) => Err("blind_exit
  role cannot use membership carrying anchor capability")` (`daemon.rs:2396-2399`). The
  warn-and-continue exception at `:2378-2387` covers only *missing* capabilities, not the
  *forbidden* anchor capability.

So on a macos-as-exit run the daemon fails closed at alignment validation and
`apply_dns_protection` never runs — there is no floor to check, and `DnsFailclosed` reds (or
the stage never reaches a meaningful posture at all). That is a fail-closed trust-state
refusal working as designed, not a checker defect and not the old enforcement gap.

The fix is specified, adversarially reviewed, and **explicitly not implemented**:
`MacosExitMembershipRoleFixDesign_2026-08-31.md` — "DESIGN ONLY — trust-state change, requires
human security review + owner sign-off before implementation." Its chosen shape is a
post-genesis, owner-signed capability rewrite at the orchestrator membership adapter via the
existing hardened `ops e2e-membership-set-capabilities`, granting the macOS exit exactly
`{blind_exit, exit_server}`. No such rewrite exists in `macos_membership.rs` today, so the
blocker stands.

## 3) Disposition bookkeeping

- `MacosDnsFailclosedEnforcementGap_2026-08-28.md` header still reads "Status: DESIGN-ONLY,
  owner-gated. No code changed." That header is stale in one respect: M1 **was** implemented
  owner-approved the same day (§7 "2026-08-28 — DONE: M1 implemented"), plus the backup-baseline
  hardening, the legend-drift fix (2026-08-29), and the S1 periodic re-assert
  (`MacosDnsFailclosedS1S4FixDesign_2026-08-31.md` §2.2, `daemon.rs` `dns_posture_reassert_pending`).
  The enforcement gap as originally written is closed for every node that reaches the apply —
  proven live by the client cell. What remains owner-gated on that document is the §7
  role-split item: the macOS-exit membership/role alignment fix.
- The Refresh doc's exit row ("DnsFailclosed will stay red on the exit cell until that
  enforcement design lands (§5)") is likewise superseded in wording: the enforcement design it
  points at has landed; the exit cell now waits on `MacosExitMembershipRoleFixDesign_2026-08-31.md`
  instead.

## 4) Re-prove recipe (run ONLY after the membership/role fix lands)

Re-proving today would only re-demonstrate the alignment rejection — do not spend a lab run on
it until `MacosExitMembershipRoleFixDesign_2026-08-31.md` is implemented and its signed
capability rewrite is visible in `macos_membership.rs`. Then:

- Command (Rust `--node` engine; same election as the prior exit-cell run
  `livelab-1788164004680-17194-2` — confirm current aliases with `get_lab_topology` before
  launching):

  ```
  ai_lab_run(
    area = "macOS exit role cell re-prove: DnsFailclosed under enum-fix 2c10f9d9 + M1",
    nodes = ["macos-utm-1:exit", "<debian anchor alias>:anchor", "<debian client alias>:client"],
    skip_linux_live_suite = true,
  )
  ```

- Artifacts that decide pass/fail (take the claim from these, never from the matrix column
  alone — §12.3):
  - `validate_baseline_runtime` per-node `DnsFailclosed` report in the run's report dir: the
    `macos-dns-failclosed-check` JSON for macos-utm-1 must show `passed: true` with expected
    posture `fully_protected` (`dns_failclosed_validation.rs:78` threads
    `expected_dns_posture_for(&assignment.role, has_primary_exit)`; `:105` — exit-family nodes
    always expect the full posture — and the CLI itself defaults to `FullyProtected` and takes
    `--posture` only from the stage, `main.rs:2522-2556`).
  - The appended row in `documents/operations/live_lab_node_run_matrix.csv` attributed to the
    right commit and `macos-utm-1:exit`.
- Expected outcome if the analysis above holds: exit passes `DnsFailclosed` exactly as the
  client did — same floor, same checker, now unblocked at alignment.

## 5) Evidence index

- Enum-fix: `crates/rustynetd/src/macos_dns_failclosed.rs:491` (`merge_rustynet_anchor_names`),
  `:511-525` (`read_pf_dns_block_floor`, nested best-effort), `:512-519` (fix rationale comment).
- Posture decision: `crates/rustynetd/src/phase10.rs:794-807`; daemon call sites
  `daemon.rs:8894-8898`, `:10634-10635`; dispatch `phase10.rs:7442`, `:5237-5248`.
- Shared apply/verify path: `phase10.rs:5075-5227` (apply), `:5085` (pf load),
  `:5093`/`:4770` (`verify_live_pf_dns_floor`), anchor name `macos_pf_load_spec.rs:186`.
- Check evaluation: `macos_dns_failclosed.rs:646-678` (posture-aware evaluator), CLI
  `main.rs:2522-2556`.
- Exit-cell blocker: `role.rs:158-160`; `daemon.rs:2357`, `:2378-2387`, `:2396-2399`;
  `macos_membership.rs:111-113, :225, :237` (no rewrite); design
  `MacosExitMembershipRoleFixDesign_2026-08-31.md` §0 (owner-gated, unimplemented).
- Live evidence: client green `livelab-1788433705-bf4b1b1187c8` (`bf4b1b1187c8`, 2026-09-03);
  exit red `livelab-1788164004680-17194-2` (`a80c4de3`, 2026-08-31); role-split root cause
  `MacosExitDnsFailclosedRoleSplitInvestigation_2026-08-31.md`; dispositions in
  `MacosDnsFailclosedEnforcementGap_2026-08-28.md` §7 (M1 DONE + 2026-08-31 role-split update);
  rows in `CrossPlatformRoleParityRefresh_2026-07-23.md` (client, anchor, exit, blind_exit).
