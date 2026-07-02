# Focused Live Lab Role Gap Analysis - 2026-07-02

Scope: static repo analysis only. No live lab was run. This document focuses on the three near-term role cells requested: Linux `blind_exit`, macOS `admin`, and Windows `anchor`. Long soak, chaos, gossip-fuzz, and other broad stages are intentionally out of scope here.

Security posture: do not weaken live stages to get green. The target is stricter proof: fail closed, verify-before-apply, signed capability checks, OS-secure key or token custody, no secret logging, and no dry-run/contract pass standing in for a live pass.

## Sources Reviewed

- `documents/Requirements.md`
- `documents/SecurityMinimumBar.md`
- `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md`
- `documents/operations/active/CrossPlatformRoleParityRoadmap_2026-06-22.md`
- `documents/operations/active/LiveLabCoverageAndHonestyAudit_2026-06-25.md`
- `documents/operations/active/LinuxBlindExitDataplane_2026-06-25.md`
- `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`
- `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
- `documents/operations/active/CrossOsRoleSwitchPlan_2026-06-24.md`
- `documents/operations/active/ParallelAgentWorkPlan_2026-07-01.md`
- `documents/operations/live_lab_run_matrix.csv`
- Relevant code in `crates/rustynet-cli/src/vm_lab/mod.rs`, `crates/rustynetd/src/daemon.rs`, `crates/rustynetd/src/linux_blind_exit.rs`, `crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/privileged_helper.rs`, and `scripts/bootstrap/windows/Install-RustyNetWindowsAnchorService.ps1`.

## Current High-Level Finding

The project now has credible implementation pieces for all three focus areas, but the remaining risk is uneven:

- Linux `blind_exit`: dataplane code exists and is unit-tested, but the live lab still needs to prove real `nft` application and real leak resistance.
- macOS `admin`: current live proof can mint and issue locally, but it is not yet a full admin-distribution proof against a real peer and adversarial bundle cases.
- Windows `anchor`: daemon and helper code for bundle-pull exist, and the live stage is fail-loud, but latest recorded failures stop during Windows deploy/execution before proving the listener.

## Linux `blind_exit`

### What The Stage Must Demand

A Linux `blind_exit` node must act as a hardened final-hop exit for mesh traffic while refusing the regular Linux exit behavior.

Required live behavior:

- The node receives a signed `blind_exit` role/capability through the normal signed-state path.
- The daemon applies kill-switch posture before enabling forwarding.
- Forwarded mesh egress is allowed only when source IP is inside the signed mesh CIDR.
- No NAT translation is present: no `masquerade`, `snat`, or `dnat`.
- Local-origin egress remains tunnel-only.
- DNS is fail-closed. No leak to ambient host DNS.
- Forward policy is terminal default-deny.
- Teardown or rollback cannot silently convert the node into a regular NAT exit.
- Role reversal out of `blind_exit` is denied except for explicit factory reset semantics.

Expected node interaction:

- At least one mesh peer sends egress through the Linux `blind_exit` node.
- Positive probe: signed mesh-CIDR traffic can egress through the intended path.
- Negative probe: non-mesh source, local-origin egress, direct DNS, and generic forward traffic are blocked.
- The lab captures and validates the live `nft list ruleset` from the guest, not only a generated rule plan.

### What Exists Now

Implementation exists in `crates/rustynetd/src/linux_blind_exit.rs`:

- Validates interface names and mesh CIDR.
- Builds `nft` commands for a mesh-scoped forward allow.
- Refuses unrestricted forwarding and NAT translation in the evaluator.
- Has an explicit posture-retention model: only factory reset should remove the blind-exit posture.

Integration exists in `crates/rustynetd/src/phase10.rs`:

- `apply_nat_forwarding` branches to `apply_linux_blind_exit_locked` when `blind_exit` is configured.
- The blind-exit path sets forwarding only after the hard-lock table exists.
- It deletes pre-existing NAT table state, reauthors the forward chain, and restores IPv4 forwarding on command failure.
- Rollback re-applies hard-lock posture for blind-exit instead of dropping into regular exit behavior.

Helper restrictions exist in `crates/rustynetd/src/privileged_helper.rs`:

- The nft allowlist permits the specific blind-exit rule shapes rather than arbitrary shell execution.

### Most Likely Remaining Failure

The likely failure is not missing builder logic. The likely failure is insufficient live proof.

`LinuxBlindExitDataplane_2026-06-25.md` records the critical state: the old Linux `blind_exit` failed open by running the regular NATing exit path. The replacement code landed, but the follow-up is explicitly `LIVE-RUN-PENDING`: prove actual `nft` apply and evaluate the live ruleset captured from the guest.

The current lab stage family still appears to include reversal/immutability checks, but that is not enough. A green result must prove the live dataplane, not just that role reversal is denied.

Secondary risk: the document also records a separate helper-test infrastructure problem around `PrivilegedCommandClient` framing versus older line-delimited helper tests. That can mask helper-path regressions unless cleaned up.

### Work Needed To Pass Strongly

1. Add or extend a Linux blind-exit live stage that actually starts a Linux node in `blind_exit` mode and captures `nft list ruleset`.
2. Run the captured ruleset through `evaluate_linux_blind_exit_ruleset`.
3. Add active probes:
   - signed mesh source egress allowed;
   - non-mesh source blocked;
   - NAT absent;
   - local-origin ambient egress blocked;
   - DNS leak blocked.
4. Verify rollback/failure behavior:
   - failed rule apply leaves default-deny posture;
   - normal service restart preserves blind-exit posture;
   - role reversal remains denied.
5. Fix the stale helper test protocol mismatch so helper-level negative tests can catch allowlist regressions.
6. Record live evidence in `live_lab_run_matrix.csv` only after the guest-applied rules and active probes pass.

Security bar: do not accept generated nft plans, empty packet captures, or reversal-only checks as a pass.

## macOS `admin`

### What The Stage Must Demand

A macOS `admin` node must prove it can act as the trust-operating node without bypassing the signed-state model.

Required live behavior:

- Admin signing material is created or loaded through OS-secure custody.
- The admin can issue a signed assignment or membership bundle for a peer.
- The peer ingests that bundle through the normal verify-before-apply path.
- The peer refuses stale, forged, downgraded, or unauthorized bundles.
- Audit output shows what was issued without leaking secrets.
- The admin role does not imply arbitrary local bypass of capability checks.

Expected node interaction:

- macOS admin signs a bundle for another node, preferably a Linux peer already in the live lab topology.
- The peer applies the bundle and exposes a verifiable post-state: node id, capability set, signer, counter/watermark, and accepted generation.
- A stale or tampered bundle is replayed and must be rejected.

### What Exists Now

The macOS orchestration in `crates/rustynet-cli/src/vm_lab/mod.rs` has `validate_macos_admin_issue` and `exercise_macos_admin_issue_live`.

The current live exercise:

- SSHes into the macOS guest.
- Creates a root-owned work directory.
- Runs `/usr/local/bin/rustynet assignment init-signing-secret`.
- Builds a node map and allowlist from the macOS node id and WireGuard public key.
- Runs `rustynet assignment issue`.
- Requires non-empty bundle output and verifier public key output.
- Deletes the temporary work directory.

Project docs record macOS admin as live-proven for the current narrow stage.

### Most Likely Remaining Failure

The current stage is likely to keep passing its current criteria, but it is narrow. It proves local mint/issue on the macOS guest. It does not yet prove the more important distributed admin property: another node accepting the signed state through the same runtime path used in production, and rejecting adversarial variants.

That means the likely gap is not "macOS cannot issue". The likely gap is "macOS admin has not proven end-to-end signed-state administration of another node under attack conditions."

This matters because an admin role that can create artifacts locally is not enough for the security model. RustyNet needs proof that peers enforce signature, authorization, generation, and rollback rules.

### Work Needed To Pass Strongly

1. Keep `validate_macos_admin_issue` as the base smoke proof, but add a stricter stage such as `validate_macos_admin_peer_ingest`.
2. In that stage:
   - generate admin signing material on macOS using the intended secure custody path;
   - issue a signed bundle for a real peer in the lab;
   - transfer it to the peer through the lab orchestration path;
   - apply it using the same daemon/CLI verify-before-apply path production uses.
3. Add negative tests:
   - stale generation rejected;
   - forged signature rejected;
   - unauthorized capability escalation rejected;
   - revoked admin or wrong verifier rejected if the trust model supports that case.
4. Verify no secrets in logs:
   - no signing secret;
   - no token;
   - no full private key material.
5. Record peer post-state and rejection evidence in the matrix.

Security bar: do not mark this stronger stage green from local bundle generation alone. The peer must apply a valid signed state and reject invalid signed states.

## Windows `anchor`

### What The Stage Must Demand

An anchor is more than a normal admin node. The anchor role is Primary Admin plus the anchor capability set described in `AnchorNodeRoleDesign_2026-05-21.md` and `NodeRoleTaxonomy_2026-05-21.md`:

- `anchor.gossip_seed`
- `anchor.bundle_pull`
- `anchor.enrollment_endpoint`
- `anchor.relay_colocation`
- `anchor.port_mapping_authoritative`

The current near-term Windows stage focuses on `anchor.bundle_pull`.

Required live behavior for `anchor.bundle_pull`:

- Windows node has a signed membership snapshot granting `anchor.bundle_pull` to its node id.
- Service starts `rustynetd` with a loopback-only bundle-pull listener.
- Bundle-pull token exists with Windows ACLs restricted to SYSTEM and Administrators.
- Valid loopback token returns the exact membership snapshot.
- Invalid token is denied.
- LAN bind is refused when `allow_lan=false`.
- Response headers and body do not leak the token.
- If capability is missing or revoked, listener refuses service.

Expected node interaction:

- The Windows guest runs the real service.
- The lab pulls from `127.0.0.1:51822` inside the guest with the valid token.
- The lab tries invalid token and LAN-bind variants.
- Later full-anchor stages should add peer pull, gossip seed, enrollment, colocated relay, and port-mapping authority checks.

### What Exists Now

Daemon support exists in `crates/rustynetd/src/daemon.rs`:

- `validate_anchor_bundle_pull_addr` enforces loopback-only unless LAN serving is explicitly allowed.
- Token loading uses file input, not argv exposure.
- Token comparison is constant-time.
- The listener checks that the local node has `anchor.bundle_pull` in the signed snapshot before serving.
- The listener can bind and poll on Windows in the main daemon loop.

Windows installer support exists in `scripts/bootstrap/windows/Install-RustyNetWindowsAnchorService.ps1`:

- Validates install paths and service existence.
- Mints a self-contained membership snapshot for the target node so bundle-pull capability exists for the proof.
- Seeds a token if absent.
- Locks token ACLs to SYSTEM and Administrators.
- Rewrites daemon args to use:
  - `--anchor-bundle-pull-addr 127.0.0.1:51822`
  - `--anchor-bundle-pull-token-path C:\ProgramData\RustyNet\config\anchor-bundle-pull.token`
  - `--anchor-bundle-pull-allow-lan false`
- Verifies the config before service restart.
- Restarts the Windows service and waits for a loopback listener.
- Emits a structured JSON report.

Live orchestration exists in `crates/rustynet-cli/src/vm_lab/mod.rs`:

- `validate_windows_anchor_bundle_pull` is fail-loud.
- Dry-run plan contracts are informational only and do not produce a pass.
- `deploy_windows_anchor_service` stages the PowerShell installer.
- `exercise_windows_anchor_bundle_pull_live` verifies valid loopback pull, invalid token denial, LAN bind refusal, and token non-disclosure.

### Current Recorded Failure

Latest `live_lab_run_matrix.csv` entries still fail at `validate_windows_anchor_bundle_pull`.

Observed failure text from recorded logs:

```text
Windows anchor bundle-pull live proof FAILED for windows-utm-1: Windows anchor deploy on windows-utm-1 failed: remote command exited with status 255: exec request failed on channel 0
```

The failure happens during deploy/execution, before the bundle-pull listener is proven. It is not yet evidence that the daemon listener or token checks are wrong.

### Most Likely Remaining Failure

Most likely: Windows remote execution transport for the anchor installer is still unreliable for this guest/stage.

The code already tries to avoid large inline `EncodedCommand` execution by staging `Install-RustyNetWindowsAnchorService.ps1` and invoking a short `-File` command. The logs still show SSH channel failure. The inventory entry for `windows-utm-1` has a local UTM controller and staging directory, so this stage should prefer the existing UTM result-file execution path for access-establishment work. If SSH is still being used for the installer or exercise at the wrong phase, the lab can fail before RustyNet is tested.

Secondary scope gap: passing `anchor.bundle_pull` is not full Windows anchor parity. It proves one anchor capability. Full anchor role proof still needs gossip seed, enrollment endpoint, colocated relay, and authoritative port mapping.

### Work Needed To Pass Strongly

1. Keep the stage fail-loud. Do not convert Windows anchor live failure to Skip or contract Pass.
2. Fix deploy transport:
   - force local-UTM result-file execution for `windows-utm-1` access-establishment commands when the inventory has `controller.type=local_utm`;
   - surface UTM errors directly instead of falling back to SSH for this phase;
   - record the staged script path and JSON report path.
3. Add a tiny Windows preflight through the same transport before installer execution:
   - `whoami`;
   - `Get-Service RustyNet`;
   - `Test-Path 'C:\Program Files\RustyNet\rustynetd.exe'`;
   - `Test-Path 'C:\ProgramData\RustyNet\config'`;
   - current listener state for port `51822`.
4. After deploy succeeds, keep the existing live checks:
   - exact body digest equals membership snapshot;
   - wrong token denied;
   - LAN bind refused with `allow_lan=false`;
   - token absent from served headers/body.
5. Add capability-negative proof if not already covered by the helper:
   - remove or revoke `anchor.bundle_pull`;
   - verify the listener refuses service or stops serving.
6. After bundle-pull is green, add separate full-anchor sub-stages:
   - gossip seed reachable and authenticated;
   - enrollment endpoint token-gated and loopback/LAN policy correct;
   - relay service colocated and not silently open;
   - port mapping authority single-owner behavior and teardown.

Security bar: do not make the listener LAN-wide, do not put the token in argv/logs, do not bypass signed capability checks, and do not accept an in-process plan contract as live proof.

## Suggested Execution Order

1. Windows `anchor.bundle_pull` transport repair first.
   - It is the currently recorded hard failure.
   - The daemon and helper code are already close enough that a transport fix may expose the next real bug quickly.
2. Linux `blind_exit` live dataplane proof second.
   - The code exists, but the missing proof covers a high-risk leak surface.
3. macOS `admin` peer-ingest hardening third.
   - Current narrow stage is already green, but the stronger proof is needed for real security confidence.

## Definition Of Done For These Three Cells

- The stage result is based on live guest behavior, not generated plans.
- Every pass has captured evidence from the guest.
- Every security-negative case has an explicit fail-closed assertion.
- Secrets are never printed.
- Role/capability checks use signed state.
- `documents/operations/live_lab_run_matrix.csv` records the exact run id and stage status.
- Any remaining dry-run/contract check is only advisory and cannot turn red into green.
