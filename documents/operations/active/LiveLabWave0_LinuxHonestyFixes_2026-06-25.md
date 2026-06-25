# Live-Lab Wave 0 — Linux Honesty Fixes — Plan + Implementation Spec — 2026-06-25

Parent: `LiveLabCoverageAndHonestyAudit_2026-06-25.md` (§4 findings, §6 Wave 0).
Author: Iwan-Teague. **Code-only, NO live lab.** Every item here is on a Linux
code path that **compiles and unit-tests on this Linux dev host**, so each fix is
fully locally verifiable.

## 0. Why Wave 0 first
The honesty pass on 2026-06-24 fixed macOS/Windows leak/teardown captures but left
**Linux — the reference OS — with the same defects**. Before we port Linux depth to
mac/win (Wave 2/3), the Linux evidence itself must be trustworthy: today a Linux
exit-NAT teardown can report a false clean-teardown on a capture error (open-relay
risk), and the Linux DNS-leak proof passes on an empty pcap with no active probe.

## 1. Exemplar patterns to copy (already in-repo, proven)
- **Fail-closed capture interpret** (NAT teardown): `crates/rustynetd/src/macos_exit_nat_lifecycle.rs`
  `interpret_pf_anchor_capture(Err)⇒(true,_)` (:189) and `interpret_forwarding_capture(None)⇒"Unknown"` (:197);
  Windows `windows_exit_nat_lifecycle.rs` `interpret_netnat_capture(Err)⇒present`.
  A capture/query **error must read as "still present / not restored," never as torn-down/Disabled.**
- **Active-probe leak proof** (DNS / IPv6): `crates/rustynetd/src/macos_exit_dns_failclosed.rs`
  (off-tunnel `dig` mid-capture + `dns_block_probe.json`, validator requires
  `probe_attempted=true` AND no response) and `linux_ipv6_leak.rs` / `macos_ipv6_leak.rs`
  (`probe_attempted` guard: "a never-run probe must not count as fail-closed").
- **Behavioural functional proof**: `crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs`
  (real query + asserted answer + REFUSED negative + fail-closed adversarial guard).

## 2. Findings → fixes

### F0.1 — Linux exit-NAT table teardown is fail-open  (CRITICAL)
- File: `crates/rustynetd/src/linux_exit_nat_lifecycle.rs:78` (`capture_nft_nat_table(...).unwrap_or_default()`)
  + `:191-202` (`nft_nat_table_present`).
- Problem: an `nft` spawn/exec failure collapses to `""` ⇒ `nat_table_present=false`
  = "torn down" — the clean-teardown answer the validator wants
  (`vm_lab/mod.rs:14811,14884`). Residual exit NAT after stop/demotion is a
  release-blocking open relay, so "missing == clean" is worst-case.
- Fix: introduce `interpret_nft_nat_capture(Result<String,()>) -> (present, raw)`
  mirroring the macOS helper — a capture **Err ⇒ present=true** (cannot-confirm-absent).
  Only a *successful* `nft list table` that genuinely shows no table yields
  `present=false`. Thread the capture result (not `unwrap_or_default`) through.
- Test: unit test that a captured-error path yields `nat_table_present=true`; a
  real empty-but-successful capture yields `false`.

### F0.2 — Linux exit-NAT forwarding teardown is fail-open  (CRITICAL)
- File: `crates/rustynetd/src/linux_exit_nat_lifecycle.rs:181-189`
  (`capture_proc_forwarding` → `unwrap_or_else(|_|"0")`) + `:204-210` (`parse_proc_forwarding`).
- Problem: a failed `/proc/sys/net/ipv4|6/ip_forward` read defaults `"0"`→`"Disabled"`,
  read as "forwarding restored."
- Fix: a failed read must canonicalize to `"Unknown"` (a non-`Disabled`,
  non-`Enabled` sentinel), mirroring `interpret_forwarding_capture`. `forwarding_restored`
  stays false unless the read **succeeded and is literally Disabled**.
- Test: unit test failed-read ⇒ `"Unknown"` ⇒ not restored.

### F0.3 — Linux NAT-lifecycle shell merges default missing field to "Disabled"  (HIGH)
- Files: `scripts/e2e/capture_linux_exit_nat_lifecycle.sh:87-93`,
  `scripts/e2e/capture_linux_exit_demotion_residue.sh:92-97`
  (`(after.get("tunnel_forwarding") or "Disabled")`).
- Problem: a missing/empty/null forwarding field defaults to `"Disabled"` ⇒
  `forwarding_restored=true`. Identical to the macOS shell bug fixed on 06-24.
- Fix: default to `"Unknown"`; require the explicit literal `"Disabled"` for
  restored; default a missing after-stop `nat_table_present` to `true` (fail-closed).
  Mirror `scripts/e2e/capture_macos_exit_nat_lifecycle.sh` (already fixed).

### F0.4 — Linux exit DNS-leak proof is vacuous (no active probe)  (HIGH)
- Files: producer `crates/rustynetd/src/linux_exit_dns_failclosed.rs:106-120`
  (`capture_dns_pcap_text`, no probe); validator `vm_lab/mod.rs:15301`
  (`evaluate_linux_exit_dns_failclosed_artifact_dir`).
- Problem: empty pcap passes; nothing drives an off-tunnel DNS query, so an empty
  capture means "nothing tried," not "killswitch dropped it." This is the live twin
  of the just-fixed macOS bug.
- Fix: port the macOS pattern exactly — producer derives the LAN gateway
  (`ip route get` / default route), drives a real `dig` (UDP then TCP) at it
  mid-capture, and emits `dns_block_proof.json`/`dns_block_probe.json` recording
  `probe_attempted` + `udp_response_received`/`tcp_response_received` (a parsed
  `;; ->>HEADER<<-` of any rcode = response = open path). Validator: add the new
  artifact to the required-set + pull-list and require `probe_attempted=true` AND
  no UDP/TCP response. Reuse the macOS `dns_probe_response_received` /
  `build_*_dns_block_probe_report` shape (factor a shared helper if clean).
- Test: producer pure-builder unit tests (response-detected, fail-closed
  not-attempted/response-observed) + a validator fixture test rejecting a vacuous
  probe — mirror the macOS tests.

### F0.5 / F0.6 — `require_empty_dns_pcap` encodes the vacuity  (MED, shared root cause)
- File: `vm_lab/mod.rs:15646-15654`.
- Problem: treats empty / "0 packets captured" as PASS with no notion of an active
  probe. Root cause behind F0.4 and the latent Windows case.
- Fix: keep the helper but ensure **every caller pairs it with a `probe_attempted`
  assertion** (Linux via F0.4; macOS already does; Windows path stays Skipped until
  a producer exists — leave a doc-comment on the helper stating the invariant).
  Do **not** silently weaken; the helper plus the probe artifact together are the
  proof.

### F0.7 — Relay lifecycle records Pass from a `--dry-run` plan  (HIGH → honest-demote in Wave 0)
- Files: `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs`
  (lifecycle path) + `vm_lab/mod.rs:17594-17624` (`exercise_linux_relay_lifecycle_dry_run`).
- Problem: records **Pass** from `ops install-systemd-relay --dry-run` + `--uninstall
  --dry-run` without installing/running the relay or forwarding a frame.
- Wave-0 fix (honest demotion, NOT the full proof): a `--dry-run` plan must **not**
  record `Pass`. Make the dry-run path record a distinct non-Pass
  (`Skipped`/"contract-only — NOT live-proven", matching the Windows-contract demotion
  pattern from 06-24), and clearly label the real forwarded-frame proof as a Wave 4
  (cross-network/dataplane) deliverable. Keep any genuine non-dry-run lifecycle
  assertions that already run as real `Pass`.
- Note: the **real** proof (install + start + forward a frame client→relay→peer +
  prove ciphertext-only/zero-ingress + uninstall + no residue) is tracked for Wave 4,
  not built here.

### F0.8 — two-hop forwarding is asserted from status strings only  (HIGH)
- File: `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs:886,967-1021,1428`.
- Problem: "two-hop forwarding" asserted purely from `exit_node=…`,
  `serving_exit_node=true`, `state=ExitActive`, and `ip route get … dev rustynet0`
  config text. Zero data-plane probe.
- Fix: add an end-to-end data-plane probe to a target reachable **only past the
  final exit**, AND per-hop evidence — a TTL decrement of exactly 2, or a
  packet/counter on the entry node showing it relayed onward (whichever is cleanly
  observable through the existing `RemoteShellHost`/probe primitives). Keep the
  status-string checks as preconditions, add the behavioural assertion as the proof.
- Test: where a pure helper is added (e.g. TTL-delta parse), unit-test it.

### F0.9 — lan-toggle "blocked" satisfied by any ping failure  (LOW-MED)
- File: `crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs:907`
  (`wait_for_lan_probe_state`, "blocked" branch).
- Problem: any `ping` failure satisfies `desired_state=="blocked"` (mitigated by a
  positive control, so LOW-MED).
- Fix: the "blocked" state must also confirm an **enforced denial** — the killswitch
  drop rule present / the route absent — not merely a timeout. Add that enforcement
  check alongside the existing positive control.

### F0.10 — demotion-residue during-run guard omits internal_prefix  (LOW)
- Files: `vm_lab/mod.rs:14871` (during-run guard) + `scripts/e2e/capture_linux_exit_demotion_residue.sh:105`
  (omits `internal_prefix`).
- Problem: the "was actually serving exit" guard checks only `nat_table_present` +
  forwarding `Enabled`, never `internal_prefix == mesh_cidr` (unlike the lifecycle
  validator at `mod.rs:14801-14806`).
- Fix: capture `internal_prefix` during-run in the shell and assert
  `internal_prefix == mesh_cidr` in the validator, matching the lifecycle validator.

## 3. Agent assignment / file ownership (DISJOINT — no two agents touch the same file)
- **Agent W0-A — NAT teardown fail-closed (F0.1, F0.2, F0.3, + F0.10 capture side):**
  OWNS `crates/rustynetd/src/linux_exit_nat_lifecycle.rs`,
  `scripts/e2e/capture_linux_exit_nat_lifecycle.sh`,
  `scripts/e2e/capture_linux_exit_demotion_residue.sh`. (rustynetd + shells, NO mod.rs)
- **Agent W0-B — DNS active probe + mod.rs validators (F0.4, F0.5/6, F0.7 demote,
  F0.10 validator side):** OWNS `crates/rustynetd/src/linux_exit_dns_failclosed.rs`,
  `crates/rustynet-cli/src/vm_lab/mod.rs`,
  `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs`.
  (the only agent that edits mod.rs + the relay validator)
- **Agent W0-C — two-hop data-plane probe (F0.8):** OWNS
  `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs`.
- **Agent W0-D — lan-toggle enforced-denial (F0.9):** OWNS
  `crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs`.

Each agent runs in an isolated git worktree, implements only its owned files, runs
its gates, and reports its diff + test results. The reviewer (me) merges the four
disjoint diffs, runs the full workspace gate, fixes integration nits, and commits
per logical increment as Iwan-Teague (NO Co-Authored-By trailer), then pushes.

## 4. Shared contracts (so split work matches)
- **`dns_block_probe.json` (Linux)** — same schema as the macOS artifact:
  `{ schema_version:1, overall_ok, probe_attempted, probe_target, probe_query,
  udp_response_received, tcp_response_received, reason }`. Agent W0-B owns BOTH the
  producer field-emission and the validator that reads it (no split). Required-set
  + pull-list entries added in `vm_lab/mod.rs` (W0-B).
- **demotion-residue `internal_prefix`** — Agent W0-A adds `internal_prefix` to the
  during-run object in `capture_linux_exit_demotion_residue.sh`; Agent W0-B adds the
  `internal_prefix == mesh_cidr` assertion in the `mod.rs` validator. Field name:
  `internal_prefix` (string CIDR), matching the lifecycle artifact.

## 5. Gates each agent runs (before reporting)
- `cargo fmt --all -- --check` (after `cargo fmt --all`)
- `cargo check -p <owned crate(s)> --all-targets`
- `cargo clippy -p <owned crate(s)> --all-targets --all-features -- -D warnings`
- Scoped tests for the owned module(s) (`cargo test -p <crate> -- <module>`)
- Report: files changed, exact fix per finding, new tests + their pass output, any
  finding it could NOT complete and why. Do NOT commit to `main`; do NOT touch files
  outside the ownership map.

## 6. Definition of done (Wave 0)
- F0.1–F0.3: a capture/read error on the Linux NAT teardown path can no longer
  produce a clean-teardown verdict (unit-tested fail-closed).
- F0.4–F0.6: the Linux DNS-leak stage requires an active off-tunnel probe; an empty
  pcap with no probe fails closed (unit + fixture tested).
- F0.7: no relay-lifecycle stage records `Pass` from a `--dry-run` plan; the real
  frame proof is documented as Wave 4.
- F0.8: two-hop has a real data-plane + per-hop assertion, not status-string-only.
- F0.9: lan-toggle "blocked" confirms enforced denial, not just a timeout.
- F0.10: demotion-residue during-run guard asserts `internal_prefix == mesh_cidr`.
- All workspace gates green (fmt, clippy -D warnings, scoped tests), excluding the
  documented env-blocked sandbox tests. Committed as Iwan-Teague, pushed to `main`.
