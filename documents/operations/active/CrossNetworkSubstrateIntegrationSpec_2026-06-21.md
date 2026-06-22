# Cross-Network Substrate Integration Spec (2026-06-21)

**Status:** Active implementation spec. Resolves the one open design decision (substrate ↔ validator
mapping) and specifies the exact orchestrator wiring needed to make the cross-network live-lab stages
actually run. Companion to `RustynetDataplaneExecutionPlan_2026-05-18.md` §D5.1 — that plan is the *why*
and the acceptance criteria; this doc is the *how to wire it*.

**Precedence note:** Where this doc and §D5.1 disagree on mechanics, this doc wins for the integration
seam; §D5.1 still owns the NAT-profile vocabulary, the §4.1 failure-mode definitions, and the pass
criteria. Never weaken a security control to make a stage pass (see §10).

---

## 1. Problem statement

Everything cross-network is built **except the one thing that makes it run**: the orchestrator never
stands up a NAT substrate. The eight `live_linux_cross_network_*_test.sh` validators, the
`apply_nat_profile.sh` profile applier, the `netns_internet_sim.sh` Tier-A simulator, the classification
tooling, all the `cross_network_*` orchestrator stages, the `--cross-network-*` flags, and the Rust ops
(`validate-cross-network-nat-matrix`, `classify-cross-network-topology`, `write-cross-network-preflight-report`)
all exist. But nothing calls the substrate scripts, so the stages SSH to an unreachable subnet and die at
init (`assignment bundle missing exit node peer` after SSH timeout). Result: every `artifacts/phase10/`
cross-network report is `fail` at runtime init, and the only profile ever exercised is `baseline_lan`.

**Goal:** wire the existing substrate scripts into the orchestrator so a single invocation runs the §4.1
NAT-profile matrix to green-or-documented-expected-failure, with per-stage timing already auto-logged via
the `run_stage` hook (`live_lab_stage_timings.csv`).

---

## 2. What already exists (the ~80%)

| Layer | Artifact | Status |
| --- | --- | --- |
| NAT profile applier | `scripts/vm_lab/apply_nat_profile.sh` | **Production** (security-audited 2026-06-18). 5 profiles (`port_restricted_cone`, `full_cone`, `symmetric`, `double_nat_cgnat`, `baseline_lan`) + `--enable-upnp` / `--enable-v6` modifiers. Runs on a router guest (two NICs/ifaces), idempotent, records `/run/rustynet_nat_profile`. |
| Tier A substrate | `scripts/vm_lab/netns_internet_sim.sh` | **Validated 2026-06-11** on debian-headless-1 (SNAT, isolation, multi-site reachability). Builds wan-bridge + svc(STUN+relay) + N edge sites (`router-ns + endpoint-ns`) inside ONE guest. Supports `port_restricted_cone`/`full_cone`/`symmetric` + netem impairment. **Does NOT implement `double_nat_cgnat`** (refuses; needs a two-router chain). |
| Tier B substrate | `scripts/vm_lab/vxlan_tier_b.sh` | **Prototype** (not CI-gated). VXLAN VNIs over the flat 192.168.0.0/24 bridge give each leaf VM an isolated home LAN NAT'd by a router VM. Calls `apply_nat_profile.sh` per site. `double_nat_cgnat` + modifiers not wired. |
| Classification gates | `netns_nat_classify.sh`, `netns_nat_filter.sh`, `nat_probe.py`, `nat_filter_probe.py`, `stun_responder.py` | **Production tooling**. RFC-5780-style mapping/filtering classification; wire format matches `crates/rustynetd/src/stun_client.rs`. |
| e2e validators | `scripts/e2e/live_linux_cross_network_{direct_remote_exit,relay_remote_exit,failback_roaming,traversal_adversarial,remote_exit_dns,remote_exit_soak,controller_switch,node_network_switch}_test.sh` | **Production validators** — thin wrappers over `cargo run -p rustynet-cli -- ops …`. **SSH to separate client/exit/relay nodes on distinct network IDs.** Emit the canonical JSON report consumed by `validate-cross-network-nat-matrix`. |
| Orchestrator surface | `scripts/e2e/live_linux_lab_orchestrator.sh` | All `cross_network_*` stage functions + helpers + the per-profile loop (line 8294: `for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"`) + gating (`cross_network_stages_applicable` line 1033) exist. `--cross-network-nat-profiles` / `--cross-network-required-nat-profiles` / `--cross-network-impairment-profile` / `--cross-network-{client,exit,relay,probe}-underlay-ip` all parsed. |
| Rust ops | `crates/rustynet-cli/src/ops_cross_network_reports.rs` | `validate-cross-network-nat-matrix`, `classify-cross-network-topology`, `write-cross-network-preflight-report`, `read-cross-network-report-fields`, report generators — all implemented and report-schema-pinned. |

---

## 3. THE DESIGN DECISION (resolved): substrate ↔ validator mapping

The open question was: the SSH-based e2e validators expect **separate, SSH-able VMs on distinct subnets**,
but Tier A (netns) puts endpoints **inside namespaces in one guest** (not SSH hosts). Forcing the SSH
validators onto netns would require rewriting them to exec-into-namespace instead of SSH. **Resolution: do
not force-fit. Map each substrate to the validator family it naturally fits.**

- **Tier A (netns) = the deterministic NAT-matrix gate.** It runs the *classification* tooling
  (`netns_nat_classify.sh`, `netns_nat_filter.sh`) plus **one new in-guest daemon-path validator** (run
  `rustynetd` over kernel-WireGuard in the two endpoint namespaces; prove Direct on cone profiles and
  Relay-fallback on `symmetric` via tcpdump on the router WAN veth). It is fast, fully reproducible, needs
  no UTM network reconfig, and is the CI/regression gate for the §4.1 mapping/filtering matrix. **It does
  NOT run the SSH e2e validators.**
- **Tier B (vxlan) = the existing SSH e2e validator suite.** The eight validators run **unchanged**: SSH
  control stays on the management plane (192.168.0.x) while the *dataplane underlay IPs* become the overlay
  addresses (e.g. 172.16.10.2 / 172.16.20.2) behind `apply_nat_profile.sh` NAT. This is where the phase10
  e2e reports finally pass — they were only failing because nothing gave them a *routable-but-NAT'd*
  cross-network. Tier B provides separate-kernel / separate-conntrack fidelity.
- **Tier C (slirp) = cross-OS smoke only.** Windows/macOS behind slirp `Shared` NAT (type not selectable).
  Requires a UTM quit/relaunch (config-plist constraint); out of scope for the first cut, sequenced last.

**Consequence for stage selection:** the stage SET inside the per-profile loop depends on the substrate:
`netns` runs the matrix/daemon-path gate; `vxlan` runs the SSH e2e validators; `slirp` runs the cross-OS
smoke subset. The orchestrator dispatches on `--cross-network-substrate`.

**Recommended build order (each is an independently shippable win):** Tier A → Tier B → Tier C.
Tier A first because its substrate is already validated and it gives deterministic §4.1 matrix evidence
with zero VM-network reconfiguration.

---

## 4. Integration architecture (orchestrator wiring)

### 4.1 New selector flag
Add `--cross-network-substrate={netns,vxlan,slirp}` (default `netns`). Parse in
`crates/rustynet-cli/src/main.rs` alongside the existing `--cross-network-*` flags and forward as
`RUSTYNET_CROSS_NETWORK_SUBSTRATE` to the bash orchestrator (mirror how
`RUSTYNET_CROSS_NETWORK_NAT_PROFILES` is plumbed). Default `CROSS_NETWORK_SUBSTRATE="${RUSTYNET_CROSS_NETWORK_SUBSTRATE:-netns}"`.

### 4.2 Setup / teardown stages (the seam)
At `scripts/e2e/live_linux_lab_orchestrator.sh` **line 8291**, inside `if cross_network_stages_applicable; then`
and BEFORE the profile loop at line 8294, insert a setup stage; add a teardown stage after the loop:

```
if cross_network_stages_applicable; then
  run_setup_stage hard cross_network_substrate_setup \
    'stand up the requested cross-network NAT substrate (netns|vxlan|slirp)' \
    stage_run_cross_network_substrate_setup
  for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
    # existing per-profile stages, dispatched by substrate (see 4.3)
  done
  run_stage soft cross_network_substrate_teardown \
    'tear down the cross-network NAT substrate' \
    stage_run_cross_network_substrate_teardown
fi
```

`stage_run_cross_network_substrate_setup` dispatches on `$CROSS_NETWORK_SUBSTRATE`:
- **netns:** `live_lab_scp_to` the substrate scripts (`netns_internet_sim.sh`, `netns_nat_classify.sh`,
  `netns_nat_filter.sh`, `nat_probe.py`, `nat_filter_probe.py`, `stun_responder.py`,
  `apply_nat_profile.sh`) to one Debian guest (the **exit** node by convention) and `build` the topology
  with `--site A:<profile> --site B:<profile>`. No inventory IP changes (endpoints are netns).
- **vxlan:** scp `vxlan_tier_b.sh` + `apply_nat_profile.sh` to the participating VMs, `setup` the overlay,
  then **set the underlay IPs** the validators target. Wire them via the existing
  `CROSS_NETWORK_{CLIENT,EXIT,RELAY,PROBE}_UNDERLAY_IP` env (so no inventory mutation needed for the
  dataplane), OR `--update-inventory-live-ips` for live overlay IPs. SSH control stays on 192.168.0.x.
- **slirp:** out of scope first cut — return a documented SKIP with a clear "requires UTM relaunch" reason.

### 4.3 Per-profile dispatch
Inside the loop, the existing stage calls (`stage_run_cross_network_direct_remote_exit`, etc.) get a thin
substrate guard:
- **netns:** before the stage, re-point the netns sites at `$profile` (rebuild affected sites or
  `apply_nat_profile --profile $profile` inside the router ns); run the **matrix/daemon-path** validators
  (classification gates + the new daemon-in-netns reachability test). Skip the SSH e2e validators.
- **vxlan:** `apply_nat_profile.sh --profile $profile …` on each router VM, then run the existing SSH e2e
  validators with `--nat-profile $profile` (they already accept it). After, `apply_nat_profile --reset`.

The matrix validator (`validate-cross-network-nat-matrix`) is substrate-agnostic — it just checks the
required profiles have passing reports under `--artifact-dir`. It stays at the end of the loop unchanged.

### 4.4 Timing & evidence
- Per-stage durations auto-log to `documents/operations/live_lab_stage_timings.csv` (run_stage hook,
  already shipped) — `cross_network_substrate_setup`, each per-profile stage, and teardown all get rows.
- Artifacts land under `artifacts/cross_network/<commit>/<profile>/` per §D5.1.
- The standard matrix-row append (`ops append-orchestrator-run-to-matrix`) records the run; verify the row
  per the operating contract.

---

## 5. Phased implementation plan

### Phase X1 — Tier A netns matrix gate (FIRST; ~1–1.5 cycles)
1. Add `--cross-network-substrate` flag (main.rs + orchestrator env), default `netns`.
2. Add `stage_run_cross_network_substrate_setup` / `_teardown` (netns arm only) at the seam (line 8291).
3. Write the **new daemon-in-netns validator** (small): start `rustynetd` (kernel-WG) in each endpoint ns,
   establish the mesh through the NAT routers, assert Direct on `port_restricted_cone`/`full_cone`,
   Relay-fallback on `symmetric`; tcpdump on the router WAN veth is the path oracle; zero tunnel-CIDR leaks.
   Reuse `netns_internet_sim.sh exec <ns> -- …` for in-ns commands and the existing `stun_responder.py`.
4. Wire the per-profile loop (netns arm) to run the classification gates (`netns_nat_classify.sh`,
   `netns_nat_filter.sh`) + the new daemon-path validator for each requested profile.
5. **Acceptance:** `--cross-network-substrate netns --cross-network-nat-profiles port_restricted_cone,full_cone,symmetric`
   completes with every profile green-or-documented-expected-failure; matrix row present; timings logged.

#### X1 status & decomposition (2026-06-22)
- **X1 step 1-2 (substrate selector + classification gate): DONE + LIVE-VALIDATED** — commit
  `ae5c7ce` (on `main`). Added the `--cross-network-substrate {netns,vxlan,slirp}` selector +
  `RUSTYNET_CROSS_NETWORK_SUBSTRATE` env (default `netns`), the netns bypass in
  `cross_network_stages_applicable` (applicable when an exit guest exists, no distinct-prefix
  requirement), and `stage_run_cross_network_nat_classification` (HARD) which runs
  `netns_nat_classify.sh` + `netns_nat_filter.sh` on the exit guest; the netns dispatch branch records
  every SSH remote-exit stage as a documented skip ("run on substrate=vxlan"). Live run `crossnet1`
  (report `state/live-lab-crossnet1`): `cross_network_nat_classification` PASS — mapping **3/3**
  (cone→endpoint-independent, symmetric→endpoint-dependent) + filtering **9/9**. Trigger = standard
  orchestrate **without `--skip-cross-network`** (auto mode + netns default → gate runs; no separate
  VM prefixes needed). **NOTE:** the implementation landed as orchestrator-`.sh`-only (no `main.rs`
  `--cross-network-substrate` CLI flag yet — the flag lives in the orchestrator `.sh` + the env var;
  `rustynet-cli ops vm-lab-orchestrate-live-lab` has no `--cross-network-substrate` passthrough, so
  select non-default substrates via the env var until X2 adds the CLI flag).
- **X1 step 3 (daemon-path validator): DECOMPOSED into two increments** (the single-shot
  Direct+Relay+multi-profile validator is too large/iteration-prone for one cycle). NEXT:
  - **Increment 2 — netns single-pair Direct-path validator** (`port_restricted_cone`, 2 endpoints,
    **NO relay**). Stand up `rustynetd` (kernel-WG, namespace-pure) in `rnsim-ep-A`/`rnsim-ep-B`
    behind the cone NAT routers, STUN at `rnsim-svc` (`100.64.0.254:3478` via the existing
    `stun_responder.py`), establish the A↔B mesh, and prove `path_mode=direct_active` +
    `path_live_proven=true` with a fresh WG handshake; tcpdump on each router WAN veth shows WG UDP to
    the peer's reflexive endpoint (no relay) and **zero tunnel-CIDR cleartext leaks**.
    Feasibility unlocks: nftables is **netns-scoped** (the daemon's runtime nft + the host killswitch +
    the router NAT never collide — launch namespace-pure, **no** host killswitch boot-check); the
    daemon accepts a plaintext `--wg-private-key` (avoid the encrypted-key custody chain) and
    `--traversal-stun-servers 100.64.0.254:3478`. Largest new work = minting a **minimal 2-node signed
    state** (membership + A↔B assignments + traversal bundles) for the netns-local node identities via
    the existing `rustynet-cli ops` issuance commands, written to per-ns state dirs (iteration-prone —
    develop + validate `scripts/vm_lab/netns_daemon_path.sh` **standalone on a spare guest** with
    `rustynetd` built on it before the full orchestrate). New stage
    `stage_run_cross_network_daemon_path` mirrors the classification stage but runs at **`soft`/WARN
    tier** (novel timing-sensitive in-guest daemon bring-up; promote to HARD once stable). Bulletproof
    `trap cleanup EXIT` (kill rustynetd PIDs → `netns_internet_sim.sh teardown` → rm tmp state).
  - **Increment 3 — Relay-fallback** (`symmetric` + `full_cone`): layer a `rustynet-relay` service in
    `rnsim-svc` (argv-only, raw ed25519 verifier key, relay-fleet bundle) onto the proven
    daemon-in-netns harness; force relay via `symmetric` (endpoint-dependent mapping → hole-punch
    fails → fallback), assert `path_mode=relay_active` + `relay_session_state=live`, tcpdump shows
    relay forwarding + **no** direct WG to the peer. (Relay = the hardest dependency; isolated here.)
- Files for X1 step 3: NEW `scripts/vm_lab/netns_daemon_path.sh` (placed under `scripts/vm_lab/` like
  the other netns tools, not the `scripts/e2e/...daemon_path_test.sh` named in §7 — self-contained
  in-guest pattern); EDIT `scripts/e2e/live_linux_lab_orchestrator.sh` (new `soft` stage next to
  `stage_run_cross_network_nat_classification`, wired into the netns dispatch branch). Assertion
  targets = the daemon status line fields in `crates/rustynetd/src/daemon.rs` (`path_mode`,
  `path_live_proven`, `traversal_probe_result`, `relay_session_state`, `stun_candidate_local_addrs`).

### Phase X2 — Tier B vxlan + existing e2e suite (~1–1.5 cycles)
1. Harden `vxlan_tier_b.sh` for orchestrator use (robust remote teardown on failure; status check).
2. Add the vxlan arm to setup/teardown + the per-profile dispatch; wire `CROSS_NETWORK_*_UNDERLAY_IP`.
3. Root-cause + fix the phase10 init failure (it is *only* "no substrate" — Tier B provides routable-NAT'd
   cross-network; confirm the SSH validators then reach init and run).
4. Run the existing 8 e2e validators per profile on Tier B.
5. **Acceptance (the §D5.1 pass criterion):** one invocation with
   `--cross-network-substrate vxlan --cross-network-nat-profiles port_restricted_cone,full_cone,symmetric,double_nat_cgnat`
   completes with every stage green or documented-expected-failure, artifacts under
   `artifacts/cross_network/<commit>/<profile>/`, run-matrix row present.

### Phase X3 — the three §4.1 stages (with X1/X2)
Add `cross_network_cold_enroll` (§4.1.1), `cross_network_anchor_renumber` (§4.1.2),
`cross_network_double_nat_anchor` (§4.1.3) per §D5.1. Substrate mapping:
- `cold_enroll`: Tier A or B (`port_restricted_cone` anchor + cold enrollee; `+upnp_available`+`auto` must
  succeed end-to-end; `keepalive` must FAIL-with-correct-diagnosis, no hang/silent-retry).
- `anchor_renumber`: flip the anchor router's WAN address mid-session; expect documented lockout + correct
  peer diagnostics + stale-endpoint-ladder recovery.
- `double_nat_anchor`: needs `double_nat_cgnat` → **Tier B + `apply_nat_profile` (which implements it)**, OR
  extend `netns_internet_sim.sh` to build the two-router chain (currently refused). Pass = daemon *detects*
  CGNAT (uPnP-WAN vs STUN mismatch, or 100.64.0.0/10 WAN) and surfaces it; with `v6_native`, v4 path bypassed.

### Phase X4 — Tier C slirp cross-OS smoke (LAST)
Windows/macOS behind slirp Shared NAT (one UTM relaunch). Cross-OS traversal + relay-fallback smoke only.

---

## 6. Acceptance criteria (from §D5.1, restated)

- **Per-stage validators:** tcpdump on the router WAN interface is the path oracle (direct vs relay vs
  none); **zero tunnel-CIDR leaks** on every underlay; every run appends + verifies its
  `live_lab_run_matrix.csv` row.
- **`cross_network_cold_enroll`:** `keepalive` → passes only if the failure is diagnosed correctly (explicit
  cold-contact warning, no hang, no silent retry loop). `upnp_available`+`auto` → enrollment succeeds.
- **`cross_network_anchor_renumber`:** documented lockout + correct peer diagnostics + automatic recovery
  via the stale-endpoint ladder.
- **`cross_network_double_nat_anchor`:** daemon detects + surfaces CGNAT; with `v6_native` traffic bypasses
  v4 entirely.
- **Phase pass:** one orchestrator invocation across the requested NAT profiles completes with every stage
  green or in a documented-expected-failure state matching §4/§4.1, artifacts under
  `artifacts/cross_network/<commit>/<profile>/`, run-matrix row present, and the phase10 init failure
  root-caused and fixed.

---

## 7. Files to change

| File | Change |
| --- | --- |
| `crates/rustynet-cli/src/main.rs` | parse `--cross-network-substrate`, forward `RUSTYNET_CROSS_NETWORK_SUBSTRATE` |
| `scripts/e2e/live_linux_lab_orchestrator.sh` | `CROSS_NETWORK_SUBSTRATE` default; `stage_run_cross_network_substrate_setup`/`_teardown`; per-profile substrate dispatch at the loop (line 8291/8294); three new §4.1 stages |
| `scripts/vm_lab/netns_internet_sim.sh` | (X3) optional: add `double_nat_cgnat` two-router chain |
| `scripts/vm_lab/vxlan_tier_b.sh` | (X2) robust remote teardown; orchestrator-friendly status; wire modifiers |
| `scripts/e2e/live_linux_cross_network_daemon_path_test.sh` (NEW) | (X1) the netns daemon-path validator |
| `documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md` | substrate selector + per-tier prereqs |
| `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` | mark D5.1 substrate seam resolved; link this spec |

---

## 8. Open questions / gaps to fill

1. **`double_nat_cgnat` on Tier A** — `netns_internet_sim.sh` refuses it (needs a two-router chain). Either
   route `double_nat_anchor` to Tier B (`apply_nat_profile` implements double-NAT via a nested ns on the
   router VM), or extend the netns sim. **Recommendation:** Tier B for double-NAT first; netns extension later.
2. **uPnP / IPv6 modifiers on Tier B** — `apply_nat_profile.sh` supports `--enable-upnp`/`--enable-v6` but
   `vxlan_tier_b.sh` does not yet pass them. Needed for `cold_enroll`(+upnp) and `double_nat_anchor`(+v6).
3. **Underlay-IP wiring contract** — confirm the e2e validators honor `CROSS_NETWORK_*_UNDERLAY_IP` for the
   *dataplane* while SSH control uses the management plane; if not, prefer `--update-inventory-live-ips`.
4. **§4.1 fix dependencies (D14.a–f)** — D5.1 tests the *failure modes*; the *fixes* (auto port-mapping,
   IPv6-first, STUN NAT discovery, gossip-punch) are D14 and partly gated (D14.e/f need user sign-off). The
   substrate work does NOT depend on the fixes — stages pass on "documented-expected-failure" until then.
5. **Anchor role surface (D11)** — `cold_enroll`/`double_nat_anchor` lean on anchor capabilities
   (port-mapping authority, enrollment endpoint). Confirm the anchor membership surface is present, or scope
   the first cut to what the current daemon exposes.

---

## 9. Why this is ready to start

The plan (§D5.1) is detailed; the substrate scripts are largely production-ready (Tier A validated, the
profile applier audited); the orchestrator stages/flags/Rust-ops already exist. The remaining work is
**integration glue + one new in-guest validator**, not invention. The single design decision (substrate ↔
validator mapping) is resolved in §3. Start with Phase X1 (Tier A) for a fast, deterministic, already-
validated first win, then Tier B reuses the existing e2e suite for fidelity.

---

## 10. Security invariants (non-negotiable)

- Never weaken a security/crypto/fail-closed/default-deny/signature/freshness/key-custody control to make a
  cross-network stage pass. An adversarial/cold-contact/renumber/CGNAT stage that *fails-closed correctly* is
  **passing** (it proved the failure mode) — record it as documented-expected-failure, don't paper over it.
- One hardened apply path only: `refresh_signed_state_with_reason → load_verified_{trust,membership,auto_tunnel}`.
  No second/fallback/downgrade path for cross-network state.
- Production defaults unchanged: `DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS=300` and the systemd unit's 300s/120s
  windows are production-correct; the lab's 86400 is a test-env launch-flag override only.
- Every new control (e.g. CGNAT detection, NAT-type classification surfacing) needs an enforcement point +
  a verification test.
- All NAT-router config is applied over argv-only invocations on the router guest (`apply_nat_profile.sh`
  is already argv-validated and audited); no shell construction from untrusted values.
