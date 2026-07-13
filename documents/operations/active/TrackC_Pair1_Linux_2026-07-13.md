# Track-C Pair 1 — Linux 2-node (exit+client), 2026-07-13

First paired bash↔Rust functional-parity run scored against the §0.a G1–G8 gate.

- **Commit (both sides):** `982a6e2`, branch `main`, **clean tree** (G5 ✓).
- **Topology:** `debian-headless-2:exit` + `debian-headless-4:client`, same
  inventory, `utm-shared-192.168.64.0/24`.
- **Reports:** bash `state/pair2-bash-1783943058` (22 pass / 31 skip / 0 fail,
  `run_summary=pass`), Rust `state/pair2-rust-1783943058` (36 pass / 22 skip /
  0 fail). Both appended a matrix row.
- **Diff:** `state/parity-diff-linux-pair2.json` (`--mode functional`).

## Scorecard

| Gate | Result | Notes |
|---|---|---|
| G1 functional diff | **partial** | `overall_status_match=true` (both Partial — the TRACKC-FIX-1 registry fix resolved the first pair's false `Failed`), `node_count_match=true`. `pass=false` on ONE shared stage: `cross_network_preflight` (bash=skipped, Rust=passed). See Finding P1-1. |
| G2 role-cell equality | **pass** | From normalized parity inputs: both proved client; Rust proved exit via the full lifecycle (`exit_handoff`/`active_exit`/`exit_dns_failclosed`/`exit_nat_lifecycle`/`exit_demotion_residue` all pass) where bash proved exit only via `validate_baseline_runtime` + skipped `live_exit_handoff`. Rust proving MORE for a role is not a G2 failure (governed by G7). No role bash proved that Rust did not. |
| G3 cleanup + residue | **FAIL (follow-up)** | Both cleanups terminal `pass` and the Rust `assert_node_clean` passed, but the independent post-run probe found `table inet rustynet_boot` on BOTH guests. See Finding P1-2. |
| G4 evidence completeness | **pass** | Both artifacts present, both matrix rows well-formed, Rust finalize 0 errors. |
| G5 provenance | **pass** | Both `982a6e2`, `dirty_state=clean`, same inventory/topology. |
| G6 no cherry-picking | **pass** | Single lab-state window, chained bash→Rust, neither side re-run. |
| G7 Rust security floor | **pass** | ALL Rust security controls pass: security_audit, dns_failclosed, runtime_acls, service_hardening, key_custody, mesh_status, authenticode, ipv6_leak, exit_dns_failclosed, exit_nat_lifecycle, exit_demotion_residue, live_secrets_not_in_logs, live_key_custody. `blind_exit_dataplane` skipped — declared precondition (no blind_exit in topology). |
| G8 secrets + source | **pass** | `live_secrets_not_in_logs` pass; setup/stage manifests present; commit-clean tree (G5). |

**Verdict: NOT yet a full G1–G8 PASS.** Six of eight gates pass cleanly,
including the whole G7 security floor. Two items remain, both understood and
neither a Rust regression:

## Finding P1-1 — `cross_network_preflight` skipped(bash) vs passed(Rust)

The one shared-stage divergence. On a single-subnet 2-node topology the
cross-network suite has no real substrate; the Rust `cross_network_preflight`
passes (trivially) while the bash arm skips it. Benign, but it fails the strict
shared-stage-match. It lands squarely in the cross-network substrate being made
Rust-native (task: convert the netns probes) — resolve it there: either have the
Rust preflight Skip (not Pass) when no cross-network substrate is present
(matching bash and being more honest), or classify it as an intentional
suite-level difference in §0.a.3. Prefer the Skip fix.

## Finding P1-2 — `rustynet_boot` present after cleanup (residue) — HIGH — **RESOLVED 2026-07-13 (`20bca19`)**

**Root cause (both a fail-open AND a no-op cleanup, one bug):** the Linux
cleanup reset and the `assert_node_clean` probe both gate on `command -v nft`,
evaluated in the SSH **user's** PATH. On Debian a non-login SSH shell's PATH is
`/usr/local/bin:/usr/bin:/bin:/usr/games` — it OMITS `/usr/sbin`, where `nft`
lives. So `command -v nft` returned NOT-FOUND: the reset **skipped its entire
delete loop** (the boot killswitch table was never removed → residue every run),
and the clean probe reported `nft=-` → `assert_node_clean` **FAILED OPEN**,
passing a node that still carried a fail-closed killswitch table. The inner
`sudo -n nft` calls worked (root's PATH has `/usr/sbin`) — only the user-context
existence gate missed; `ip` is in `/usr/bin` so the iface dimension was fine
(that's why only nft was the residue). The RNQ-02 `assert_node_clean` control
was therefore not actually catching nft residue on this distro — a security-
relevant fail-open.

**Fix (`20bca19`, LIVE-PROVEN):** prepend `/usr/sbin:/sbin` to PATH in the
reset / iface-reset / clean-probe commands; make the probe FAIL CLOSED (nft/ip
present but unqueryable → `unknown` → dirty, never clean); same sbin-PATH
prefix defensively on the `wg` handshake probes. Proven end-to-end on
debian-headless-2: fake `rustynet_boot` table → fixed probe reports dirty →
fixed reset removes it → re-probe clean; both guests confirmed clean. This
un-blocks Pair 1's G3 on a re-run (the residue is now both detected and
removed).

### Original diagnosis (kept for the record)

The independent residue probe found `table inet rustynet_boot` on both guests
after pair2 completed (daemon inactive, tunnel iface absent, `ip_forward=0`, so
the dataplane IS down — only the boot killswitch table remains). The lab
cleanup (`linux_traffic.rs::clean_all_rustynet_nft_tables`) is DESIGNED to flush
every `rustynet*` table incl. `rustynet_boot`, with a documented
retry-until-clean loop because the boot table "can reappear after a single
delete pass". Yet the Rust cleanup stage + its `assert_node_clean` PASSED. So
either (a) `assert_node_clean`'s nft check has a gap and the table was there all
along, or (b) `rustynet_boot` reappeared AFTER `assert_node_clean` ran (the
product-side boot killswitch is intentionally kept alive across daemon teardown,
`linux_killswitch_boot.rs` — something may re-install it post-cleanup). This is
a genuine residue/cleanup question with a security dimension (a stranded
fail-closed boot killswitch is SECURE-but-not-pristine; a cleanup that can't
guarantee a clean node is a release-relevant gap). Needs root-cause before Pair
1 can score G3 pass. Track as a durability/residue follow-up (relates to RNQ-02).
