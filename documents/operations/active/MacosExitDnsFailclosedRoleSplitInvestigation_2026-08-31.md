# macOS Exit vs Anchor `DnsFailclosed` Role-Split Investigation (2026-08-31)

Status: investigation complete; verdict is an orchestrator membership/role-mapping
integration defect, not a DNS-enforcement gap and not a validator-expectation bug.
**Update 2026-09-05:** the fix is designed (`MacosExitMembershipRoleFixDesign_2026-08-31.md`,
owner-approved as an INTERIM fix after independent review, F1 limitation disclosed,
Option D ledgered as QH-66) and IMPLEMENTED in the macOS membership adapter +
`membership_init` stage (post-genesis owner-signed capability rewrite to exactly
`{blind_exit, exit_server}`, fail-loud stage assertion, `owner_signing_key_present=`
evidence line). Live re-proof of the exit cell on the landing commit is pending.
Every claim below cites file:line from the tree at investigation time.

## a) Run evidence and the role split

Two live-lab runs, same guest `macos-utm-1`, opposite baseline
`validate_baseline_runtime` outcome for the `DnsFailclosed` daemon probe:

| Run (report dir under `state/`) | macOS bootstrap_role | topology | macos DnsFailclosed |
| --- | --- | --- | --- |
| `deepseek-lab-labrun-1788165016205-17194-3` | anchor | macos=anchor, debian-headless-4=exit, debian-headless-2=client | `passed: true` |
| `deepseek-lab-labrun-1788164004680-17194-2` | exit | macos=exit, debian-headless-4=entry, debian-headless-2=client | `passed: false`, summary `validator reported not passed` |

Both runs' `validator_results.json` carry the same per-node op list
(`RuntimeAcls, ServiceHardening, KeyCustody, Authenticode, MeshStatus,
DnsFailclosed`); in the exit run every op on every node passes except
`macos-utm-1/DnsFailclosed`. The exit run's `failure_digest.json` confirms
`bootstrap_role=exit`. The stage log gives no reason — only
`macos-utm-1/DnsFailclosed: validation not passed`.

The decisive artifact is the exit run's own daemon failure marker, collected in
`diagnostics/rust-native-failure/summary.json`:

> `macos-utm-1`: `reconcile fail-closed: membership reconcile failed: membership
> role mismatch: blind_exit role cannot use membership carrying anchor capability`

The anchor run's diagnostics record no such failure. That one line is the root
cause; the rest of this document traces it through the code.

## b) What the `DnsFailclosed` baseline validator checks

- Dispatch: `crates/rustynet-cli/src/vm_lab/mod.rs` `DaemonProbeOp::DnsFailclosed`
  (:10119) is served by the platform adapter `MacosDaemonProbe`, which shells the
  guest daemon subcommand `macos-dns-failclosed-check --no-fail-on-drift`
  (:10266). `daemon_probe_for()` (:10318) picks by platform only — the baseline
  probe is role-agnostic (no role parameter, no per-role expectation flags).
- Check implementation: `crates/rustynetd/src/macos_dns_failclosed.rs`.
  `evaluate_macos_dns_failclosed` semantics: the system resolver posture must be
  loopback-only — `/etc/resolv.conf` nameservers (`parse_resolv_conf`, :110) and
  the `scutil --dns` primary resolver (`parse_scutil`, :145;
  `loopback_resolver_advertised_from_scutil`, :184) must both resolve via
  127.0.0.1; external/malformed/link-local/ipv4-mapped resolvers are drift.
  `build_macos_dns_failclosed_report` (:251) sets `overall_ok` = drift_reasons
  empty (:255).

So the baseline check asks: "does this macOS node's OS-level DNS point at the
loopback fail-closed resolver?" That expectation is correct for every macOS role
including exit — the dedicated exit-focused capture path
(`validate_macos_exit_dns_failclosed`, vm_lab/mod.rs:12146, artifact
`dns_leak_proof/macos_dns_failclosed_check.json` :13086) demands the same
loopback posture via `evaluate_macos_dns_failclosed_report` (:21296). The
validator is not conflating anchor posture with exit posture.

## c) Apply-path gating: anchor vs exit on macOS

The M1 enforcement landed per
`MacosDnsFailclosedEnforcementGap_2026-08-28.md` §7 is intact:

- `crates/rustynetd/src/phase10.rs` `MacosCommandSystem::apply_dns_protection`
  (:4557) sets `dns_protected=true`, renders the pf DNS floor (:4559), then does
  the system-configuration pin: enumerate `networksetup` services (:4581),
  capture a loopback-free backup baseline (:4584-4620), write it (:4626), pin
  each service to 127.0.0.1 (:4631-4641), best-effort `resolv.conf` and
  `/etc/resolver/rustynet` writes (:4656-4683). `assert_dns_protection`
  (:4687) verifies pf rules + per-service loopback.
- The generic generation apply calls it whenever `options.protected_dns` is set
  (`apply_generation_stages`, phase10.rs:6766-6770), and the daemon bootstrap
  always sets `protected_dns: true` (`apply_dataplane_generation` call at
  `crates/rustynetd/src/daemon.rs:8767-8793`).
- The macOS exit-NAT path additionally calls it inline for a *regular* NATing
  exit (`apply_nat_forwarding`, phase10.rs:4501-4508); the blind-exit branch
  (:4476-4491) installs only the blind-exit pf anchor and returns without the
  inline call — but the generic protected_dns stage above still covers it.

None of this gating ever executes on the failing node, because the daemon never
reaches a healthy apply at all. The chain:

1. **Daemon role mapping is platform-split.**
   `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`
   `daemon_node_role_for_platform` maps the lab `NodeRole::Exit` to daemon role
   `admin` on Linux/Windows (:136) but to `blind_exit` on macOS (:159-160),
   with the macOS product capability grant `{BlindExit, ExitServer}`
   (:186-189).

2. **Membership genesis for the exit node is anchor-carrying on every
   platform.** `crates/rustynetd/src/main.rs` `run_membership_init` builds the
   genesis membership with the exit/genesis node's own entry hard-wired to the
   full anchor capability set + Client/ExitServer/RelayHost (:4448-4479) —
   deliberate bootstrap behavior, documented in the comment at :4451-4458.

3. **The orchestrator never corrects the exit's own entry.** Both membership
   adapters skip the exit peer when adding nodes:
   `adapter/macos_membership.rs:248-251` and `adapter/linux_membership.rs:76-77`
   (`if peer.role == NodeRole::Exit { continue; }`), so the platform capability
   grant from step 1 is computed (`stage/membership_init.rs:108-111`) but never
   applied to the exit's own membership record. The exit keeps the anchor
   genesis caps.

4. **The daemon enforces the mismatch, fail-closed.**
   `crates/rustynetd/src/daemon.rs` `validate_node_role_membership_alignment`
   (:2262) warns-and-continues when a blind_exit node is *missing* required
   capabilities (:2277-2296) but hard-rejects when a blind_exit node's
   membership *carries* the anchor capability (:2302-2304):
   `blind_exit role cannot use membership carrying anchor capability`. Called
   from membership bootstrap replay at :5308 (`RoleMismatch`), surfaced as the
   reconcile fail-closed marker captured in the exit run's diagnostics.

5. **Consequence for DNS.** The daemon sits in restricted safe mode; the
   bootstrap dataplane apply (daemon.rs:8767) never completes, so
   `apply_dns_protection` (phase10.rs:4557) never pins the system resolver.
   macOS keeps advertising the LAN/DHCP resolvers, the baseline
   `macos-dns-failclosed-check` sees non-loopback nameservers, `overall_ok`
   is false, and `validate_baseline_runtime` fails.

The anchor run passes because anchor maps to daemon `admin` (role.rs:162),
whose membership requirement is exactly the anchor capability the genesis (and,
for the anchor role, the `e2e-membership-add` grant, role.rs:296-302) provides —
alignment succeeds, the apply runs, M1 pins loopback, the check passes. Linux
exits pass for the mirrored reason: daemon role `admin` (role.rs:136) + anchor
genesis membership align by construction.

## d) Verdict and confidence

**Verdict (c): neither of the two suspected bugs.** The macOS DNS enforcement
chain (§7 M1) is correctly implemented, and the baseline validator's loopback
expectation is correct for a macOS exit. The defect is an **orchestrator
membership/role-mapping integration defect** at the role split introduced when
macOS exits were mapped onto the `blind_exit` daemon posture:

- macOS lab exit → daemon `blind_exit` (role.rs:160), whose trust contract
  forbids anchor-carrying membership (daemon.rs:2302-2304);
- but the lab membership genesis universally grants the exit node anchor
  capabilities (rustynetd main.rs:4469-4479) and both membership adapters skip
  rewriting the exit's own entry (macos_membership.rs:248-251,
  linux_membership.rs:76-77).

The daemon's fail-closed rejection is the security control working as designed;
the `DnsFailclosed` failure is a downstream symptom (unprotected resolver
posture in restricted mode). The old "unimplemented macOS DNS gap" excuse is
confirmed dead — the check fails here because protection never gets a chance to
apply, not because it cannot.

Confidence: **high**. Every link in the chain is file:line-cited, the exit run's
own diagnostics name the exact mismatch, and the same topology passes on Linux
where the daemon-role mapping is `admin`.

## e) Fix location and classification

Fix (description only — not applied here): make the macOS exit's membership
entry consistent with its `blind_exit` daemon posture. Concretely, in
`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`
(`init_membership_snapshot`), stop skipping the exit peer and (re)write the
exit's own membership record with the platform capability grant
`{blind_exit, exit_server}` from
`NodeRole::product_capabilities_for_platform` (role.rs:186-189) — mirroring how
every non-exit peer is added via `ops e2e-membership-add --capabilities`
(:197-204). Because the genesis entry comes from `rustynetd membership init`
(rustynetd main.rs:4469-4479) and `execute_ops_init_membership`
(crates/rustynet-cli/src/main.rs:13781) forwards no capability override, this
needs either an explicit exit-peer rewrite stage after genesis, or a
capability-override flag threaded through `ops init-membership` /
`rustynetd membership init`. Do **not** weaken daemon.rs:2302-2304 — the
blind-exit/anchor-exclusivity check is the trust invariant doing its job; and do
not "fix" it by mapping macOS exits back to daemon `admin` without a posture
review — that reverses the deliberate macOS exit→blind_exit posture decision
recorded at role.rs:159-160 and its capability grant at :186-189.

Classification: **lab-tooling/orchestrator code with a trust-plane surface.**
The immediate edit site is lab bootstrap tooling (vm_lab orchestrator adapter),
which is normally a safe scoped fix — but the alternative fix path touches
`rustynetd membership init` / `ops init-membership` capability semantics, i.e.
signed-membership provisioning, which is product security-sensitive. Any fix
that changes which capabilities a signed membership carries must go through the
design+review path for trust-state mutation (SecurityMinimumBar: signed state
verified before apply; capability sets are trust state), and must add a
negative test pinning "macOS exit membership carries exactly
{blind_exit, exit_server}, never anchor". Until fixed, the macOS exit cell will
keep failing `validate_baseline_runtime` at `DnsFailclosed` with this same
signature.
