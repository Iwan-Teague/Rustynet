<!-- Drafted 2026-09-07 by a glm-5.3-flash grounded read-only agent at the owner's request (owner decision 2: lab AND product bundle-freshness fixes, TTL unchanged); reviewed and placed by the managing Claude session. Status: PLAN — the lab half is GLM-implementable, the product half touches trust-state and is owner/Claude-implemented. Line references are against main at 2a5c4e1d unless stated. -->

# Signed traversal + dns_zone bundle freshness — implementation plan

## Goal
Stop `relay_forwards_frame_validation` from failing on `traversal bundle is stale` / `dns_zone_bundle_is_stale` by (a) re-minting + redistributing bundles in the lab right before the stage, and (b) defining the product path where a live authority re-mints before expiry and clients pick the bundle up — same TTL, replay/epoch monotonicity intact.

## Existing state (verified)
- Failure evidence: `state/edit-worktrees/edit-1788742681528-17771-0/state/live-lab-linux-relay-fwd8e-20260907-020008/logs/relay_forwards_frame_validation.log` — sender `debian-headless-2-bootstrap`: `state=FailClosed … restriction_mode=Permanent bootstrap_error=reconcile failure threshold exceeded: 97 … last_reconcile_error=traversal authority rejected reconcile apply: traversal authority requires valid signed traversal state: traversal bundle is stale`, `traversal_preexpiry_refresh_events=21`, `traversal_stale_rejections=138`, `dns_preexpiry_refresh_events=4`, `dns_stale_rejections=14`; receiver fedora-utm-1: 93/133. Run: 4 nodes, 66 stages, `fail`.
- Stage order: `stage/mod.rs:192-193` (`distribute_traversal`/`distribute_dns_zone` @ Setup/T0Core), `stage/mod.rs:252` (`live_reboot_recovery_validation` @ Live/T2Resilience); `plan.rs:806-827` — 66-stage default plan, 67-stage relay-forwarding plan places `RelayForwardsFrameValidation` "after relay_validation … still last before cleanup" (Disruptive tier, `stage/mod.rs:126-129`). Setup-minted bundles are hours old by the Live/Disruptive tail.
- Minting: `build_bundle_env` (`vm_lab/orchestrator/stage/distribute_assignments.rs:56`) → `distribute_bundle_kind` issues on the exit adapter via `issue_bundles_to_dir` (`adapter/linux_traffic.rs:1012`) and runs a verifier-key barrier before any bundle install (same file, `run_verifier_barrier`). Artifacts minted by `issue_traversal_bundle_artifacts` (`crates/rustynet-cli/src/ops_e2e.rs:3949`) through `ControlPlaneCore::signed_endpoint_hint_bundle` with `generated_at_unix = unix_now()`, `nonce = traversal_nonce(generated_at,0)` (3961-3993), TTL from `TRAVERSAL_TTL_SECS`, **default 120 when absent** (`ops_e2e.rs:3570-3575`), **ephemeral per-run signing secret** (`ops_e2e.rs:3578`), verifier key `rn-traversal.pub` (3602). Note: current HEAD `distribute_assignments.rs:127` pins `TRAVERSAL_TTL_SECS=86400`, but the failing run's staleness is consistent with the 120 default reaching the minter (worktree source not inspectable) — the default is a live footgun either way.
- Daemon refresh: `maybe_preexpiry_refresh_traversal` (`rustynetd/src/daemon.rs:6212`) → `refresh_signed_state_with_reason` (6022) → `state_fetcher.fetch_trust()` (fetcher.rs:91; daemon.rs:751 — pull only when `trust_url` set). No URL ⇒ every refresh errors → `restrict_recoverable` (11077) → threshold → `restrict_permanent` (11118-11122). Margins/cooldowns: `MIN_TRAVERSAL_REFRESH_MARGIN_SECS=15`, `COOLDOWN=5`, `JITTER≤30` (620-623); DNS: 30/10/45 (617-619); DNS zone auto-install via tmp+rename exists (959-973). Authority rejection string: daemon.rs:8111-8115.
- Control plane: mint/verify APIs live in `rustynet-control/src/lib.rs` (`signed_endpoint_hint_bundle` used at ops_e2e.rs:3981; `signed_traversal_coordination_record` 3132 / verify 3294). Membership precedent: signature → epoch → replay watermark (`enrollment.rs:363-366`, `role_signing_subflow.rs:84-90`, incl. `StateRefresh` IPC re-read). "Traversal authority" enforcement is in rustynetd, not rustynet-control (no matches there).

## Design
**(a) LAB — re-mint before the stage (chosen), not reorder.** Reordering puts a Disruptive stage mid-plan, invalidating its "last before cleanup" rationale (`plan.rs:826-827`) and letting 120-s TTL resurface staleness at every later Live stage. Re-mint restores fresh state exactly where needed and mirrors the product refresh path.
- New stage `refresh_signed_bundles` in `stage/mod.rs` (one catalog row, `Disruptive / T2`, position immediately before `relay_forwards_frame_validation`); `execute()` calls `distribute_bundle_kind(ctx, BundleKind::Traversal, …)` then `(ctx, BundleKind::DnsZone, …)` (reuse `distribute_assignments.rs:169+` — verifier barrier handles the ephemeral-key rotation automatically). Dependency: `LiveRebootRecoveryValidation`.
- Touch the five gated sites per `plan.rs` header doc: `stage/mod.rs`, `stage/refresh_signed_bundles.rs`, `plan.rs` (67→68 pin, `build` match arm), `vm_lab/mod.rs` count assert, `live_lab_stage_registry.rs`, `rustynet-mcp` repo_context doc.
- Close the 120 default: `ops_e2e.rs:3574` `None => 120` → hard error (matches the fail-loud comment at 3568). Keep TTL as configured; do not lengthen it.

**(b) PRODUCT — trust-state is owner-implemented; proposed shape.**
- Authority (admin/anchor, `rustynet-control`): loop re-mints per-pair hint bundles at `generated_at + ttl − MIN_TRAVERSAL_REFRESH_MARGIN_SECS` (same 15 s margin as clients, `daemon.rs:620`) with strictly increasing `generated_at_unix` and fresh nonce; **same long-term signing key** (the lab's `generate_ephemeral_signing_secret` is lab-only). DNS zone re-mint rides the same schedule (`parse_signed_dns_zone_bundle_wire`, `daemon.rs:154-155`).
- Pickup: point the daemon's existing B1 pull at the authority HTTPS endpoint (`trust_url`, daemon.rs:751) so the already-present pre-expiry schedulers (`daemon.rs:6212`, `5775`) succeed; publish event also triggers `StateRefresh` IPC (precedent `role_signing_subflow.rs:88-90`) for push pickup. One apply path only: verify signature against pinned verifier key → freshness → **new monotonicity watermark: reject `generated_at_unix ≤ last_accepted` even if still unexpired** (the traversal hint apply path around `daemon.rs:6120-6158`/6022 currently lacks the membership-style replay cache — owner must add it; counters `traversal_replay_rejections` already exist) → atomic tmp+rename install (DNS precedent 959-973) → clear `traversal_hint_error`. TTL unchanged; refresh failure keeps `restrict_recoverable` → Permanent.

## (b) PRODUCT — corrected grounding (2026-09-07, managing session)

The pull shape proposed above does not survive the code. `rustynetd` refuses every remote
state URL in its hardened path: `daemon.rs:13104` returns `InvalidConfig("remote network
state fetch is disabled in hardened daemon paths; use pinned local signed artifacts")` when
`trust_url`, `traversal_url`, `assignment_url` or `dns_zone_url` is set, so
`refresh_signed_state_with_reason` (`daemon.rs:6022`) always sees `FetchDecision::Skipped`
from the fetcher and re-loads the **pinned local artifacts** (`load_verified_trust`,
`load_verified_membership`, `refresh_traversal_hint_state`). The pre-expiry scheduler
(`maybe_preexpiry_refresh_traversal`, `daemon.rs:6212`) therefore only helps when something
has already replaced the local traversal bundle set; nothing in product does today. The
D2.5 peer gossip (`peer_gossip::GossipBundle`, `ingest_inbound_gossip_bundle`) carries peer
candidate sets, not the authority-signed `SignedEndpointHintBundle` / dns_zone artifacts,
so it does not close the gap either.

Product design to implement (trust-state, owner/Claude-implemented — never a delegated
edit):

1. Authority side (`rustynet-control` + the admin/anchor daemon): a re-mint loop that
   re-issues each node's traversal bundle set and the dns_zone bundle at
   `generated_at + ttl − MIN_TRAVERSAL_REFRESH_MARGIN_SECS` with a strictly increasing
   `generated_at_unix` (the existing watermark) and a fresh nonce, signed by the same
   pinned signer; no TTL extension, no re-signing of stale content.
2. Channel: the existing D2.5 gossip transport gains an authority-signed
   **artifact-refresh frame** type (verified against the already-pinned traversal / dns_zone
   verifier keys, not the gossip peer key) that a node persists through the SAME staged
   write + `load_traversal_bundle_set` watermark barrier the fetcher uses
   (`daemon.rs:803-840`), then triggers `SignedStateRefreshReason::PreExpiry`. Zero-ingress
   preserved: nothing listens on a new port and no URL is introduced.
3. Fail-closed unchanged: a missing or unrefreshed bundle still reaches `Permanent` on
   expiry; a frame that fails signature, watermark, or age is dropped and counted, never
   applied.
4. Tests: watermark-monotonic rejection over the frame path; refresh applies and clears
   the hint error; refresh failure keeps `Permanent`; authority re-mint has strictly newer
   `generated_at_unix`; frame with the wrong key (gossip peer key) is rejected.

Estimated 5–8 days. Until it lands the lab's `refresh_signed_bundles` stage (half (a)) is
the only freshness path and every product deployment must keep TTLs long enough to cover
the intended uptime, which is exactly the posture the plan set out to remove.

## Security analysis
Fail-closed preserved: no path extends a stale bundle; Permanent-on-unrefreshed-expiry unchanged. No new trust boundary: bundles are authenticated by signature against a pre-distributed pinned verifier key (existing barrier), the pull endpoint adds availability only, not authorization. Risks: replay of an older-but-valid bundle (closed by the watermark); lab re-mint doubles issuance traffic (bounded, fanout once); misconfigured `trust_url` must fail loudly, not silently skip refresh.

## Tests
Unit: monotonic-watermark rejection test; pre-expiry refresh with stub fetch applies + clears hint error; Permanent preserved on refresh failure (extend `daemon.rs:36420`, `36446`); missing-`TRAVERSAL_TTL_SECS` errors (`ops_e2e.rs`); second mint has strictly newer `generated_at`. Live-lab: `refresh_signed_bundles` stage proves (a) — `relay_forwards_frame_validation` then passes; acceptance target for (b): same stage passing with the lab re-mint stage **absent**, pickup via authority URL + StateRefresh (validated alongside `gossip_convergence_validation`/`live_managed_dns_validation`).

## Effort
(a) ~0.5–1 day (one stage struct + five gated touchpoints + tests). (b) trust-state owner: ~3–5 days daemon-side (fetch wiring, watermark, tests) + ~2–3 days authority re-mint loop + live validation.

## Open questions
- Which source revision the failing worktree ran (86400 vs the 120 default) — worktree checkout not inspectable from here.
- Exact daemon CLI flag name for `trust_url` (field confirmed at daemon.rs:751-752; flag not located).
- Whether the DNS-zone `auto_bundle` source (`daemon.rs:5775`, 940) already has a live authority producer in product, or lab-only.
- Production signing-key/verifier rotation ownership (trust-state owner).
