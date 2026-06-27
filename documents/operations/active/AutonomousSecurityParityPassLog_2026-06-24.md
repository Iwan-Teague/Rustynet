# Autonomous Security + Parity Pass — Progress Log — 2026-06-24

Single-session, code-only pass (NO live lab; on `main`). All gates re-verified
green per increment (`cargo fmt --check`, `cargo clippy --workspace
--all-targets --all-features -D warnings`, scoped tests). Author: Iwan-Teague.

## TL;DR

Continued the pfctl privileged-boundary hardening (which was already landed),
**found and fixed a HIGH killswitch-bypass via a workflow adversarial review**,
knocked out a batch of code-fixable security findings (RSA-0008/0010/0014/0016/
0017/0026/0055/0058), authored the missing cross-OS role-switch design,
**re-audited every macOS/Windows parity cell against the stale §9 notes** and
landed the one genuine, Linux-verifiable parity code gap it surfaced (Windows
exit §10.7 self-heal). The remaining parity work is enumerated honestly in
ParityPlan §10.

## Commits (this pass, newest last)

1. `gate:` clear pre-existing clippy `-D warnings` lints in test/vendored code —
   the authoritative gate was **red on a clean tree**; established a green
   baseline (mechanical autofixes + a const_is_empty + a dead-assignment).
2. `control:` membership-gate signed-artifact issuance (**RSA-0008**).
3. `cli:` fail closed on durable-audit failure for sensitive role transitions
   (**RSA-0014**, owner decision resolved fail-closed).
4. `macos pf:` bound the mesh egress source CIDR — **closes the blind_exit
   killswitch bypass found by the pfctl-boundary adversarial review (HIGH)**.
5. `docs(security):` record RSA-0008/0014 + the blind_exit mesh-CIDR fix.
6. `audit:` remove phantom secret-type guards, extend scope, pin real redaction
   (**RSA-0026**).
7. `parity:` author `CrossOsRoleSwitchPlan_2026-06-24.md` + correct the §3 matrix
   (macOS blind_exit 🟡, Windows blind_exit 🚫 by-design).
8. `parity(matrix):` correct macOS blind_exit — the live stage exists (§9 stale).
9. `control:` fail-closed relay-token mint + constant-time break-glass + sqlite
   perms (**RSA-0010 / 0016 / 0017**).
10. `cli:` CSV formula-injection + repo-sync printf shell-injection
    (**RSA-0055 / 0058**).
11. `windows exit:` self-heal residual NAT + forwarding on crash-restart
    (**§10.7 parity** — the one genuine Linux-verifiable parity gap from the audit).
12. `docs:` fold the cross-OS code audit into ParityPlan §10 + mark applied RSAs.
13. `sysinfo:` fix off-by-one panics in the arp/tcp parsers (**RSA-0050** — pure
    fail-soft `parse_arp_n_row` + test; macOS guard fixes).
14. `cli:` confine report source-artifact paths against `..`/absolute traversal
    (**RSA-0054** — `confine_artifact_source` at all 3 read sites + test).
15. `windows anchor:` serve bundle-pull from the Windows reconcile loop — the
    genuine Windows-anchor runtime gap. Extracted the bind + accept/serve into two
    portable, Linux-unit-tested helpers shared by the Unix + Windows loops; the
    Windows loop now opens `127.0.0.1:51822`. (cfg(windows) call sites need a
    Windows builder/CI compile-check; a live serving stage also remains.)

## Live-lab honesty pass (no live run; code-only)

A read-only audit of "will the un-run live stages pass, and do they prove what
they claim?" surfaced false-passes, fail-open teardown proofs, and vacuous
captures. Fixes landed (all gates green; macOS/Windows runtime code is cfg-gated
so only the pure logic + non-target stubs compile-check here):

16. `rustynetd:` drive an ACTIVE off-tunnel DNS probe in the macOS exit leak
    proof. The proof passed on an EMPTY pcap with nothing generating DNS — a
    vacuous pass. Now a real UDP+TCP `dig` query is driven at the LAN gateway
    during capture; `dns_block_probe.json` records it ran and whether any DNS
    response leaked back (a parsed `dig` header of ANY rcode = open path =
    leak). Empty pcap is now meaningful (killswitch dropped real traffic).
    Also hardened `parse_pf_block_rule` so a label on a non-`block drop out`
    line cannot read as an enforced block.
17. `e2e:` fail-closed macOS exit NAT lifecycle merge — the shell python merge
    defaulted a missing forwarding field to `"Disabled"` (fail-open); now
    defaults to `"Unknown"` and a missing after-stop `pf_anchor_present` to
    `true`, mirroring the audited Rust RSA-0031 merge.
18. `live-lab:` honest stage statuses in the orchestrator —
    - `validate_windows_anchor_bundle_pull` and
      `validate_windows_relay_service_lifecycle` recorded a live **Pass** from
      an in-process plan-string check / a static `.ps1` lint that never touched
      the guest. Both now record **Skipped** ("contract-only (NOT
      live-proven)"); a contract violation is still **Fail**.
    - Windows-exit teardown live capture made fail-closed (RSA-0031 parity): a
      `Get-NetNat`/forwarding query error is treated as still-present /
      not-restored (`Test-NetNatAbsent`, literal `-eq 'Disabled'`), and the
      lifecycle artifact is ALWAYS emitted once the host was serving exit so a
      residual NAT (open relay) **Fails** instead of being masked as a Skip.
    - macOS exit DNS validator now requires `dns_block_probe.json`
      (probe ran + no response) + pull-list + required-set wiring, with
      vacuous-probe and probe-response rejection tests.

### Honestly-documented remaining gap (NOT a cheat — already fail-closed)

- **macOS exit client-egress NAT-session assertion.** `active_exit.rs:29-33`
  keeps the macOS adapter's fail-closed default for the activate→assert→nat-
  session shape, because macOS Exit maps to `blind_exit` whose pf NAT is applied
  at enforce-time (not via route-advertise) and whose anchor is hard-locked
  across cleanup. The macOS exit-NAT *lifecycle* (configured-to-serve during
  run + clean teardown) is proven; a live translated-client-session assertion
  through the macOS pf NAT remains a scoped follow-up. This is documented and
  fails closed (it does not claim a pass), so it is not a false-pass — it needs
  the two-node activate→assert path reworked for macOS's enforce-time pf model.

## Security research lessons applied (industry-grounded)

- **Versioned/self-describing framing** (Latacora): kept in mind for RSA-0001
  (deferred — see below).
- **ed25519 `verify_strict`** (RFC 8032 / WireGuard / ZeroTier): confirmed
  already applied repo-wide (RSA-0043/0077, commit `6e0d0f0`) — no plain
  `verify(` sites remain.
- **Constant-time secret compare** (subtle::ConstantTimeEq, mirroring the repo's
  own `admin.rs` CSRF compare): RSA-0016.
- **Default-deny at distribution** (innernet — withhold endpoint info unless
  authorized): RSA-0008 gates issuance so a bundle can't name a revoked/unknown
  node.
- **Fail-closed on entropy / no panics in production paths** (CLAUDE.md §10.2):
  RSA-0010.
- **OWASP CSV-injection neutralization** (apostrophe prefix): RSA-0055.
- **pf `quick` first-match semantics**: the HIGH finding — a `from 0.0.0.0/0`
  source in a `pass out quick` rule wins before the terminal `block drop`,
  defeating default-deny egress; the mesh source must be a bounded
  private/CGNAT/ULA range (RFC1918 / RFC6598 / RFC4193).

## The HIGH finding (pfctl boundary adversarial review)

A 4-lens workflow review of the landed `macos-pf-load` regeneration boundary
confirmed 1 HIGH: the daemon still chooses the `mesh_cidr` spec parameter, and a
compromised daemon sending `mesh_cidr=0.0.0.0/0` renders
`pass out quick on en0 inet from 0.0.0.0/0 to any` — which (pf `quick`) passes
all local-origin egress before the terminal `block drop out quick all`, silently
defeating the blind_exit killswitch. Neither the per-module `validate_cidr`
(prefix 0 accepted), the helper rule-shape assert, nor the self-referential
evaluator caught it. **Fixed** by `macos_pf_mesh_cidr::validate_mesh_egress_source_cidr`
(contained-within-private/CGNAT/ULA), wired into both the blind_exit and
exit-NAT config validators, with accept/reject tests at config-build, render,
and the `macos-pf-load` decode boundary.

## Code-complete vs blocked (parity — authoritative, see ParityPlan §10)

- **code-complete, live-run pending:** macOS admin, macOS anchor (bundle-pull),
  macOS exit, macOS blind_exit, Windows admin, Windows
  exit (now incl. §10.7 self-heal — WinNAT live still blocked).
- **NOW LIVE-PROVEN (2026-06-27):** macOS relay (lifecycle) — `validate_macos_relay_service_lifecycle` PASS, run `livelab-1782571161`.
- **genuinely unbuilt (Linux-authorable):** live cross-OS role transitions (a
  stage that flips a mac/win node + re-applies signed state); design now in
  `CrossOsRoleSwitchPlan_2026-06-24.md`.
- **genuinely unbuilt (cfg(windows)-build-blocked):** Windows anchor daemon
  bundle-pull listener wiring (the bind+accept lives only in the
  `#[cfg(not(windows))]` main loop) + its live stage.
- **HP-3-gated (all OSes):** relay live session forwarding.
- **out of scope by design:** Windows blind_exit (`main.rs:11833`).
- **missing on all mac/win stages:** a Linux-buildable contract test for the
  FAIL-LOUD gating decision matrix (small, addable by factoring the gate out of
  the live SSH call).

## Deferred / kept-as-is (with rationale)

- **RSA-0001** (envelope v0/v1 framing): **deferred** — high-blast-radius
  key-load change whose upgrade path can't be validated without a lab; AEAD
  preserves confidentiality meanwhile. Don't "fix" without a v0→v1 migration +
  back-compat for existing v1 blobs.
- **RSA-0003** (`with_exceptions` inverted guard): **keep as-is** — currently
  *protective* (denies ALL exceptions = strictest default-deny); "repairing" it
  would make it fail-open. Woven into `ga.rs` production, so not the clean
  tests-only deletion the ledger assumed.
- **RSA-0028/0034** (gossip) + **RSA-0035** (uPnP): dormant in the shipped daemon
  (zero current reachability) — forward-locking only; lower priority.
- **RSA-0002/0025/0039** (Windows key custody) + Windows anchor listener wiring:
  `cfg(windows)`-only code, not locally compile-verifiable (the Windows
  cross-build blocker) — needs a Windows builder / CI cross-check.

## Note on the gate state

The authoritative `cargo clippy --workspace --all-targets --all-features
-- -D warnings` was **red on a clean tree** at the start of this pass (test +
vendored lints) — fixed in commit 1. The full `cargo test` suite has ~21
**environment-blocked** failures in this sandbox (privileged-helper unix-socket
capture, netns/nft, STUN echo servers, SO_PEERCRED, root-owned symlink checks);
they fail identically on a clean tree and are not regressions. All
source-scanning meta-tests (e.g. `secret_log_audit`) and the new unit tests pass.
