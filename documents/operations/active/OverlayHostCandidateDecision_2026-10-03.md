# Decision: do not advertise third-party overlay addresses as host candidates (2026-10-03)

**Status.** DECIDED 2026-10-03 by the suite manager session under ADR-027 and AQ-254(a) ("or gate behind an opt-in"), while the owner was away. Independent review: `charter/reviews/REVIEW-overlay-host-candidates-2026-10-03.md` (SOUND-WITH-FIXES, both fixes applied in the landed patch). It is a default-behaviour change in the daemon; the owner may reverse it by flipping the default of `advertise_cgnat_host_candidates` to true, and the opt-in flag `--advertise-cgnat-host-candidates true` restores the old behaviour per node without a rebuild.

**Who is affected.** Any node that also runs a third-party overlay (tailscale) and relied on its overlay address as a rustynet endpoint now needs the flag: katana, lenovo-bot, the Azure cloud node and ubuntu-server in the lab. The mesh's own 100.64.0.0/10 addresses are unaffected (they were already excluded as own addresses). The lab orchestrator does not pass the flag yet, so tailnet-ridden lab scenarios must set it explicitly.

---

# DECISION — rustynet-b80-overlay-host-candidates (b74 rework)

Lane: `rustynet-b80-cgnat-candidates-rework`
Supersedes: b74 patch (reviewed in `rustynet-a109-r-b74-review`)
Base: superproject `207d991cc` (b74 review was at `e1037320c`; HEAD has since moved, patch re-verified against the new HEAD)

## Decision

Host candidates that live in **overlay-assigned address space** are excluded from the
candidate set by default and are only advertised when the operator explicitly opts in
with `--advertise-cgnat-host-candidates <true|false>`.

This rework closes the review findings on the b74 patch:

- **R1 — IPv6 leak.** b74 gated only RFC 6598 v4 space (100.64/10). Tailscale-style
  IPv6 ULA `fd7a:115c:a1e0::/48` classifies as `Private` via `classify_ipv6`
  (fc00::/7) and therefore still leaked out as a v6 Host candidate. The gate now
  covers both: `is_overlay_assigned_addr` = `is_rfc6598_cgnat_v4` (v4, unchanged
  semantics) OR `is_tailscale_ula_v6` (v6 segments[0..3] == `[0xfd7a, 0x115c, 0xa1e0]`,
  i.e. exactly the tailscale /48 — not all of fc00::/7, not fd7a::/8 at large).
  Flag semantics are unchanged: flag on ⇒ **both v4 and v6** overlay addresses are
  advertised; flag off (default) ⇒ neither.
- **R2 — fmt churn.** b74 carried ~24 unrelated `cargo fmt` violations (import
  reorders in main.rs, test reflows in dataplane_candidates.rs) and claimed they were
  pre-existing. Pristine HEAD at both `e1037320c` and `207d991cc` is fmt-clean
  (`cargo fmt -p rustynetd -- --check` rc=0), so that claim was false. The final diff
  drops all of it; main.rs contains only the flag parse arm and the usage-text token.
- **M1 — usage text.** `--advertise-cgnat-host-candidates <true|false>` is now in the
  daemon usage string (before `--traversal-flap-breaker`).

## Naming

b74's "cgnat" naming was too narrow once v6 ULA joined the gate, per review. Renames:

- `is_rfc6598_cgnat` → `is_overlay_assigned_addr` (combined v4+v6 predicate)
- `cgnat_host_advertisable` → `overlay_host_advertisable`
- new: `is_tailscale_ula_v6`
- kept: `is_rfc6598_cgnat_v4` (v4 half)

The **CLI flag name is kept** as `--advertise-cgnat-host-candidates` (and the
`DaemonConfig`/`DaemonRuntime` field `advertise_cgnat_host_candidates`): it is the
operator-facing contract b74 already shipped in docs/tests, renaming it would be a
second breaking change with no functional gain. The struct field is documented as
covering overlay-assigned space in both families.

## Witness tests

New v6 witnesses fail on b74 code (gate lacked v6):

- `daemon::tests::build_candidate_set_excludes_overlay_addresses_by_default` —
  tailscale v4 `100.109.160.10` AND v6 `fd7a:115c:a1e0::5` (and mesh-own
  `100.64.0.7`) absent by default; ordinary LAN v4, ULA `fd00::1`, and global
  `2001:4860:4860::8888` unaffected.
- `daemon::tests::build_candidate_set_keeps_overlay_addresses_when_flag_set` —
  flag re-enables both families.
- `dataplane_candidates::tests::is_overlay_assigned_addr_boundaries` — v4 bounds,
  mapped-v6, /48 endpoints (incl. the sysinfo fixture `fd7a:115c:a1e0::5`),
  outside-=/48 negatives (`fd7a::1`, `fd7a:115c::7`, `fd00::1`).
- `dataplane_candidates::tests::overlay_host_advertisable_gates_by_default_and_flag_reenables`.

Reverse-applying the two gate hunks makes the default-exclusion witness fail
(rc=101); re-applying restores green.

## Operational note — lab hosts ride tailnets

Per `orchestrator_charter.md`, our own lab hosts (katana, lenovo-bot, the Azure
node) sit on tailscale-style tailnets, i.e. their interfaces carry exactly the
address families this gate now suppresses (100.64/10 v4 and fd7a:115c:a1e0::/48
v6). Consequences:

- A rustynetd node running **without** the flag on such a host will not advertise
  its tailnet interface as a Host candidate to peers — by design, same posture b74
  took for v4, now extended to v6.
- Lab deployments that **want** those addresses advertised (e.g. experiments that
  treat the tailnet as the underlay) must run with
  `--advertise-cgnat-host-candidates true`. The flag is per-daemon, opt-in, and
  documented in the usage text.
- Ordinary LAN/ULA/global addresses (192.168.0.0/16, fd00::/8 outside the tailscale
  /48, global v6) are unaffected in all configurations.

## Not in scope

- Renaming the CLI flag or config field (declined, see Naming).
- Any change beyond the defect fix; no fmt/churn hunks (R2).
