# Phase 6 Cross-Network And Shared-Transport Checklist

## Objective
Close the remaining code-side truth gaps for canonical cross-network and extended-soak evidence, then record the real non-code blockers that still prevent honest signoff at current `HEAD`.

## Current Status
- Code-side hardening in this phase: **implemented**
- Canonical cross-network evidence at current `HEAD`: **not yet regenerated**
- Canonical extended soak evidence at current `HEAD`: **not yet regenerated**
- Release-ready claim: **still blocked**

## What This Phase Hardened
- Pass reports now require per-suite SSH trust proof:
  - pinned host-key coverage for every target
  - `sudo -n` verification for every target
  - no silent UTM sudo-verification skip
- Pass reports now require measured shared-transport proof from daemon status:
  - `transport_socket_identity_state=authoritative_backend_shared_transport`
  - `transport_socket_identity_error=none`
  - non-empty backend identity label
  - non-empty backend local address
- Cross-network soak evidence now records and validates:
  - direct vs relay vs fail-closed vs other path samples
  - path transitions
  - status/route/endpoint mismatches
  - DNS alarm failures
  - shared-transport identity failures
  - endpoint-change counters
  - explicit reason for the first non-direct sample
- Authoritative direct-path soak pass now fails closed unless the soak stayed direct for the full duration with zero fallback/drift samples.

## Blocker Matrix

### Code Defects
- Closed in this phase:
  - UTM transport no longer bypasses passwordless-sudo verification in the shared helper path.
  - Canonical cross-network suites no longer rely on implicit SSH trust state; they emit suite-local trust summaries.
  - Canonical pass reports no longer accept under-specified path evidence; shared-transport identity must be authoritative.
  - Extended-soak evidence no longer allows fallback/drift to hide behind coarse aggregate counters.
- Remaining code-side blocker to prove live:
  - A real canonical pass still requires the runtime/backend path to emit `authoritative_backend_shared_transport` on the participating hosts during the real cross-network run.

### Topology / Inventory Defects
- Remaining:
  - The five local UTM guests remain on the same underlay and cannot by themselves satisfy the repo’s canonical cross-network proof contract.
  - `debian-lan-11` is still the only distinct-underlay inventory target.
  - Authoritative runs remain blocked until the operator’s pinned `known_hosts` file contains trusted host-key coverage for `debian-lan-11` / `192.168.0.11`.

### Evidence-Generation Defects
- Remaining:
  - The six canonical cross-network reports under `artifacts/phase10/` have not yet been regenerated on a clean current commit after this hardening.
  - The canonical cross-network soak report has not yet been regenerated on a clean current commit after this hardening.
  - Reduced/local-gate evidence must not be described as canonical cross-network release evidence.

## Phase Checklist
- [x] Common SSH/UTM helper enforces pinned host-key handling and `sudo -n` verification without the prior UTM skip.
- [x] Canonical cross-network suite wrappers emit suite-local SSH trust summary artifacts.
- [x] Canonical pass reports fail closed unless path evidence shows authoritative backend-owned shared transport.
- [x] Canonical soak reports fail closed unless the full soak remained direct with zero fallback/drift counters.
- [x] Operator-facing docs record the new trust, transport, and soak evidence contract.
- [ ] Trusted pinned host-key entry for `debian-lan-11` is present in the operator `known_hosts` file used for authoritative runs.
- [ ] Canonical cross-network reports regenerated for current clean `HEAD`.
- [ ] Canonical cross-network soak report regenerated for current clean `HEAD`.

## Operator Checklist For Canonical Cross-Network Completion
1. Work from a clean commit and keep the tree clean for the authoritative run.
2. Ensure the authoritative pinned `known_hosts` file contains trusted entries for every participating host, including `debian-lan-11` / `192.168.0.11`.
3. Confirm `vm_lab_inventory.json` still reflects the intended topology and that the chosen client/exit/relay/probe hosts are on distinct underlays where required.
4. Confirm `sudo -n` succeeds on every participating host before the cross-network suites begin.
5. Run the canonical cross-network suites using the pinned `known_hosts` file that will be cited for signoff.
6. Validate the resulting reports with the repo validator; do not accept file existence alone.
7. Accept signoff only if the generated reports are current-commit, pass, and include the new trust/transport/soak evidence.

## Evidence Checklist For Canonical Cross-Network Signoff
- [ ] `artifacts/phase10/cross_network_direct_remote_exit_report.json`
- [ ] `artifacts/phase10/cross_network_relay_remote_exit_report.json`
- [ ] `artifacts/phase10/cross_network_failback_roaming_report.json`
- [ ] `artifacts/phase10/cross_network_traversal_adversarial_report.json`
- [ ] `artifacts/phase10/cross_network_remote_exit_dns_report.json`
- [ ] `artifacts/phase10/cross_network_remote_exit_soak_report.json`
- [ ] Each pass report stamped with the current clean `git_commit`
- [ ] Each pass report contains its suite-local `*_ssh_trust_summary.txt` artifact with:
  - `all_targets_pinned=true`
  - `all_targets_passwordless_sudo=true`
  - per-target `host_key_status=pass`
  - per-target `passwordless_sudo_status=pass`
- [ ] Each pass report that carries path evidence shows:
  - `transport_socket_identity_state=authoritative_backend_shared_transport`
  - `transport_socket_identity_error=none`
- [ ] The soak pass artifact contains a summary with:
  - `direct_samples == samples`
  - `relay_samples == 0`
  - `fail_closed_samples == 0`
  - `other_path_samples == 0`
  - `path_transition_count == 0`
  - `status_mismatch_samples == 0`
  - `route_mismatch_samples == 0`
  - `endpoint_mismatch_samples == 0`
  - `dns_alarm_bad_samples == 0`
  - `transport_identity_failures == 0`

## Notes
- This phase intentionally strengthens truthfulness even when that makes the canonical run harder to pass.
- Missing trust material, missing distinct-underlay topology, or missing authoritative shared-transport proof remain hard blockers, not warnings.
