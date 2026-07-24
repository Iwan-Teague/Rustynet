# W5.6 Flip Dispositions (NodeEngineAcceptanceSpec §6.1) — 2026-07-24

**Named disposition ledger** for the W5.6 default-flip (bash → `--node`). Per
`NodeEngineAcceptanceSpec_2026-07-23.md` §6.1, a red/skipped in-scope cell may be
dispositioned out of the flip gate only under: (a) recorded in a named ledger
(this file), (b) owner sign-off per item with a stated reason, (c) an expiry /
re-review date, (d) T4-security items are NOT dispositionable below owner level,
and (e) the deferral is mirrored into the acceptance spec's list. Each item below
satisfies (a)–(e).

The flip is gated by **G1 (engine-adjudication trust)**, not G2 (parity
attainment) — §1. The unifying principle for every disposition here: the `--node`
engine **correctly adjudicated** each item (it reported the red/skip loudly and
truthfully — no false-green), which is exactly what G1 tests. None of these is an
engine-trust failure; each is a product/tooling gap the engine correctly surfaced.

## Flip evidence baseline (for context)

- Flip-candidate commit: `a414ceb` (clean tree, dirty-check fixes `65b9368`+`a414ceb`).
- §5.4 stability: **5-of-5** clean runs at `a414ceb` (`anchor_validation` 5-of-5,
  the flake-recorded stage; every other T0/T1 stage 5-of-5). Each run
  independently **A2-verified VALID** (§4.8). T0 (14 stages) + T1 (19 stages) all
  GREEN except the dispositioned items below.
- G3 enumeration-diff precondition: satisfied (`G3EnumerationDiff_2026-07-23.md`).

## Dispositions

### D1 — `live_two_hop_validation` (T1 client capability): validator-tooling gap
- **Status in the flip runs:** SKIPPED in the standard 5-node topology (correct,
  role-gated — needs an `entry` role + a second client, absent by design); FAILED
  in a dedicated two-hop topology (`exit/client/entry/aux/extra`) on a **tooling
  bug**, not the dataplane.
- **Root cause (verified):** `two_hop`'s known-hosts-file mode pre-check calls
  `ops check-local-file-mode`, which is `#[cfg(feature = "vm-lab")]`-gated. The
  helper `run_cargo_ops` (`crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs:755`)
  invokes `cargo run -p rustynet-cli` **without `--features vm-lab`**, so the
  subcommand is not compiled into the binary it runs → `unknown ops subcommand:
  check-local-file-mode`. The stage failed **before reaching any two-hop routing**.
- **Why it does not block the flip (G1):** the engine reported the failure loudly
  and correctly (a hard RED with a precise error) — no false-green. G1 tests
  whether the engine can be believed; a validator-scaffolding bug it *correctly
  surfaces* is orthogonal to engine trust. The client's *managed-tunnel* T1 path
  (traffic_test_matrix, live_managed_dns) is GREEN 5-of-5.
- **Owner sign-off:** APPROVED 2026-07-24 (owner chose "disposition two_hop, flip
  now" over a ~4h full re-prove).
- **UPDATE 2026-07-24 (tooling fixed → real root cause GROUNDED, and a prior
  mislabel corrected).** The `run_cargo_ops` `--features vm-lab` fix landed
  (`553f92d`, post-flip G2 item). With it, the two-hop topology re-run got *past*
  the pre-check and exercised the actual dataplane proof, which fails as
  `end_to_end_reachable=false per_hop_ttl_decrement=none`.
  - **CORRECTION:** an earlier draft of this update called it "the client↔client
    WireGuard-transport gap." That is **wrong**, grounded out as follows:
    - **Client↔client direct mesh reachability WORKS on the engine of record.**
      `traffic_test_matrix` (`stage/traffic_test_matrix.rs:101-160`) is a genuine
      full cross-node mesh probe (skips self L118; errors on any unreachable pair)
      and it **PASSED** in the two-hop run, which had **three clients**
      (debian-2 + fedora-aux + ubuntu-extra) — so every client↔client pair reached
      each other directly. The 2026-07-15 "client↔client 100% loss" finding is
      **stale / since-fixed**, not a current bug.
    - **Not a lab-no-internet artifact either:** the exit guest reaches `1.1.1.1`
      at baseline (0% loss, via the UTM Shared gateway `192.168.64.1`).
  - **Actual root cause (narrower):** the **two-hop EXIT-CHAIN internet route**
    (`client → entry(=client's exit) → final-exit → NAT → internet`) does not
    complete. The client reaches the *final exit's mesh IP* (two-hop TTL reply 64)
    but `1.1.1.1` via the chained NAT is unreachable, and the baseline (entry) TTL
    probe returned None. So this is a **two-hop exit-chaining / forwarding** gap
    (entry-as-intermediate forwarding to a second exit + chained NAT), a **product**
    gap of the same class as D3 `network_flap`. The engine adjudicates it correctly
    (loud, detailed RED, no false-green), so G1 engine-trust is unaffected.
- **Expiry / re-review:** root-cause and fix the two-hop exit-chain forwarding
  (needs live-mesh investigation of the entry-forward + final-exit chained NAT) and
  prove `two_hop` GREEN as a **G2/release** item. NOT a permanent exemption; NOT a
  flip blocker (G1 = engine-trust, satisfied).

### D2 — T5 negative controls `negative_control_planted_residue` + `negative_control_daemon_kill_mid_stage`: live proof deferred
- **Status:** built as opt-in T5 stages (A3a, `1b9e2c0`) with unit-tested pure
  adjudication logic, but `execute()` returns `Skipped` pending a live-guest fault
  injection (the deferred half of A3-finish per the CompletionBrief). The other
  two T5 fault classes — `negative_control_signed_bundle_rejection` and
  `negative_control_wrong_node_substitution` — are fully built, unit-tested, and
  exercised in-pipeline (see the T5 verification run recorded alongside this flip).
- **Why it does not block the flip (G1):** two of the four T5 fault classes are
  proven end-to-end (adjudicate RED-for-the-right-reason); the engine's ability to
  correctly report a real red is additionally demonstrated live by
  `live_network_flap_validation` correctly-RED across all 5 stability runs, each
  A2-verified VALID (exit-2 valid-non-pass, not INVALID). This is a **T5-tier**
  item, not T4-security, so it is dispositionable.
- **Owner sign-off:** APPROVED 2026-07-24 (part of the "flip now" decision).
- **Expiry / re-review:** implement the live residue/daemon-kill injection and
  prove RED-for-the-right-reason on a real guest as a G2 follow-on.

### D3 — `live_network_flap_validation` (T2 resilience): correctly-adjudicated-RED
- Already the acceptance spec's standing treatment (§6 / review B6): the daemon
  fails closed ~120 s after setup because nothing re-issues the signed
  traversal-authority bundle — a **real production self-sustenance gap** tracked in
  `TraversalSelfSustenancePlan_2026-07-23.md`. Correctly-RED satisfies G1; GREEN is
  required for G2. Restated here for completeness; the fix is the traversal track.

## What is NOT dispositioned (green on the engine of record)

T0 core (bootstrap, membership, distribute-{membership,assignments,traversal,dns},
enforce/validate baseline, traffic, cleanup) and T1 roles (anchor, admin, relay,
exit + its NAT/handoff/dns-failclosed/demotion-residue, blind_exit dataplane where
applicable, key-custody, service-hardening, runtime-acls, authenticode, ipv6-leak,
security-audit, mesh-status, managed-dns) are all GREEN 5-of-5, A2-verified. The
`--node` engine is trusted (G1) on this basis.

## Mirror

Mirrored into `NodeEngineAcceptanceSpec_2026-07-23.md` §6.1 (deferred-with-reason
list) per rule (e). These dispositions gate the W5.6 flip only; G2 (release) still
requires D1/D2 resolved and D3 green.
