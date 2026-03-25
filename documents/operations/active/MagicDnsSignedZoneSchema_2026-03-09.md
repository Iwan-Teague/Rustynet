# Rustynet Signed Magic DNS Zone Schema

Date: 2026-03-09
Status: design
Scope: secure schema and runtime contract for Magic DNS-like naming

## AI Implementation Prompt

```text
You are the implementation agent for the remaining work in this document.
Repository root: /Users/iwanteague/Desktop/Rustynet

Mission:
Complete the remaining in-scope work in this file in one uninterrupted execution if feasible. Security is the top priority. Do not stop at planning if you can still write, test, and verify code safely.

Mandatory reading order:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. This document
7. Directly linked scope/design docs and the code you will touch

Non-negotiables:
- one hardened execution path for each security-sensitive workflow
- fail closed on missing, stale, invalid, replayed, or unauthorized state
- no insecure compatibility paths, no legacy fallback branches, and no weakening of tests to make results pass
- no TODO/FIXME/placeholders for in-scope deliverables
- do not mark work complete until code, tests, and evidence exist

Execution workflow:
1. Read this document fully and convert every unchecked, open, pending, partial, or blocked item into a concrete checklist.
2. Execute the remaining work in the ordered sequence listed below.
3. Implement in small, verifiable increments, but continue until the remaining in-scope slice is complete or a real external blocker stops you.
4. After every material code change:
   - run targeted unit and integration tests for touched crates and modules
   - run smoke tests, dry runs, or CLI/service validators for the exact workflow you changed
   - rerun the most relevant gate before moving on
5. After every completed item:
   - update this document immediately instead of maintaining a separate private checklist
   - mark checkboxes and status blocks complete only after verification
   - append concise evidence: files changed, tests run, artifacts produced, residual risk, and blocker state if any
   - keep any existing session log, evidence table, acceptance checklist, or status summary current
6. Before claiming completion:
   - run repository-standard gates when the scope is substantial:
     cargo fmt --all -- --check
     cargo clippy --workspace --all-targets --all-features -- -D warnings
     cargo check --workspace --all-targets --all-features
     cargo test --workspace --all-targets --all-features
     cargo audit --deny warnings
     cargo deny check bans licenses sources advisories
   - run the scope-specific validations listed below
   - if live or lab validation is available, run it; if it is not available, do not fake success and record the blocker precisely
7. If a test or gate fails, fix the root cause. Never weaken the check, bypass the security control, or mark a synthetic path as good enough.

Document-specific execution order:
1. Preserve the current hardened baseline and verify every already-implemented item before extending behavior.
2. Then implement per-node filtered bundle issuance policy enforcement in operator workflows.
3. Then complete OS DNS integration so managed-zone queries reach the loopback authoritative resolver without introducing /etc/hosts mutation or insecure fallback resolution.
4. Then add adversarial E2E coverage for stale, forged, replayed, tampered, and policy-invalid managed-zone bundles on live or semi-live nodes.
5. Update examples, CLI help, and operational notes only after the hardened path is real.

Scope-specific validation for this document:
- Targeted rustynetd DNS resolver and bundle-validation tests.
- Targeted rustynet-cli DNS issue and verify command tests.
- ./scripts/ci/phase10_gates.sh
- Managed-DNS smoke or live validation path if available in scripts/e2e or Rust ops commands.

Definition of done for this document:
The next secure slice in Section 18 is complete, managed names remain fail-closed, and there is still only one signed authoritative naming path.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- The hardened baseline is in place; the remaining work is the next secure slice only.
- Open items are per-node filtered issuance policy enforcement, OS DNS integration to the loopback authoritative resolver, and adversarial live or semi-live E2E testing.

`Do first`
- Verify the already-implemented baseline before extending behavior.
- Then enforce per-node filtered issuance in operator workflows before changing host-level DNS integration.

`Completion proof`
- Managed names resolve only through the signed authoritative path, stale or forged bundles fail closed, and managed-zone routing to the loopback resolver works without weakening protected DNS.
- Adversarial tests exist for stale, forged, replayed, tampered, and policy-invalid bundles.

`Do not do`
- Do not add /etc/hosts editing, unsigned local record mutation, or alternate local resolver paths.
- Do not treat usability shortcuts as acceptable if they bypass signed DNS state.

`Clarity note`
- When in doubt, prefer a narrower signed feature set over a broader DNS feature set with weaker trust guarantees.

## 0) Purpose

Define a single hardened design for Rustynet Magic DNS so node names and admin-assigned aliases are distributed as signed control-plane state, enforced fail-closed, and resolved only through trusted local DNS handling.

This document is a schema and runtime contract. It is not a relaxed UX sketch.

## 1) Precedence and Constraints

- [Requirements.md](../../Requirements.md) is normative.
- [SecurityMinimumBar.md](../../SecurityMinimumBar.md) is release-blocking.
- [Phase4.md](../../Phase4.md) and [phase10.md](../../phase10.md) define functional and runtime expectations.
- If this document conflicts with a higher-precedence source, the stricter security interpretation wins.

Non-negotiable constraints for this design:

- one hardened path for DNS record mutation and distribution
- default deny for record visibility
- fail closed when signed DNS state is missing, invalid, stale, replayed, or mismatched
- no unsigned local hostname overrides
- no public-domain interception by default
- no raw shell fallback in runtime DNS control paths

## 2) Security Goals

The design must prevent these failure classes:

1. Unsigned local spoofing
- a node must not be able to invent or persist its own name-to-IP mappings

2. Replay and rollback
- old zone bundles must not be re-applied after newer zone state exists

3. Record-to-rogue-IP injection
- a signed record must not be able to point at arbitrary underlay or internet IPs unless policy explicitly allows a future service-IP mode

4. Topology overexposure
- a client should not automatically learn every node and alias in the network if policy does not require it

5. DNS leak/fail-open behavior
- protected DNS mode must not silently fall back to insecure external resolution for managed Rustynet names

6. Alias collision ambiguity
- duplicate or conflicting labels must resolve deterministically before runtime

## 3) Design Position

Rustynet Magic DNS should be implemented as:

- a centrally issued signed DNS zone artifact
- optionally filtered per target node for least-knowledge visibility
- resolved against signed node identity and signed assignment state
- served locally by a trusted authoritative resolver only for the managed Rustynet zone

It should not be implemented as:

- a local mutable `/etc/hosts`-style database
- per-node self-registration
- arbitrary public-domain override
- unsigned CLI hostname mutation

## 4) Naming Scope

Version 1 scope:

- one private zone suffix only, for example `rustynet`
- records only for Rustynet-managed names under that suffix
- supported record types: `A` and `AAAA`
- alias support allowed only as additional labels under the same managed zone

Version 1 exclusions:

- `CNAME`
- wildcard records
- `TXT`, `SRV`, `MX`, `NS`
- public-domain interception such as `github.com`
- unsigned local alias files

These exclusions are deliberate. They keep the first secure implementation small and auditable.

## 5) Artifact Model

The recommended artifact is a per-target-node signed bundle:

- one bundle is issued for one consuming node
- the bundle contains only the records that node is authorized to learn

This is preferred over one global zone file because:

- it reduces topology leakage
- it fits the project's existing signed-assignment pattern
- it keeps least-privilege visibility aligned with the control plane

Recommended files:

- bundle: `/var/lib/rustynet/rustynetd.dns-zone`
- verifier key: `/etc/rustynet/dns-zone.pub`
- watermark: `/var/lib/rustynet/rustynetd.dns-zone.watermark`

Recommended custody:

- bundle: `0640 root:<daemon-group>`
- verifier key: `0644 root:root`
- watermark: `0640 root:<daemon-group>`

## 6) Bundle Schema

Top-level artifact:

```json
{
  "schema_version": 1,
  "artifact_type": "signed_dns_zone_bundle",
  "zone_name": "rustynet",
  "subject_node_id": "client-1",
  "generated_at_unix": 1773000000,
  "expires_at_unix": 1773000300,
  "membership_epoch": 5,
  "assignment_generation": 42,
  "dns_policy_generation": 7,
  "nonce_hex": "6f9e8f4c...",
  "records": [
    {
      "label": "nas",
      "fqdn": "nas.rustynet",
      "rr_type": "A",
      "ttl_secs": 60,
      "target_node_id": "node-nas-1",
      "target_addr_kind": "mesh_ipv4",
      "expected_ip": "100.100.10.10",
      "aliases": ["storage", "backup"]
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "key_id": "dns-zone-root-2026q1",
    "signature_hex": "ab12..."
  }
}
```

### 6.1 Top-Level Fields

- `schema_version`
  - integer
  - required
  - must equal `1` for the first implementation

- `artifact_type`
  - string
  - required
  - must equal `signed_dns_zone_bundle`

- `zone_name`
  - string
  - required
  - lower-case DNS suffix
  - must match the configured managed zone exactly

- `subject_node_id`
  - string
  - required
  - node that is authorized to consume this bundle
  - runtime must reject bundles for a different local node

- `generated_at_unix`
  - integer
  - required
  - signing time

- `expires_at_unix`
  - integer
  - required
  - hard expiration
  - runtime must reject expired bundles

- `membership_epoch`
  - integer
  - required
  - binds DNS state to a signed membership view

- `assignment_generation`
  - integer
  - required
  - binds DNS resolution to the signed assignment generation used to validate node address ownership

- `dns_policy_generation`
  - integer
  - required
  - monotonically increasing zone-policy/version counter

- `nonce_hex`
  - string
  - required
  - anti-replay nonce

- `records`
  - array
  - required
  - bounded size

- `signature`
  - object
  - required
  - detached or embedded signature payload metadata

### 6.2 Record Fields

- `label`
  - relative label under `zone_name`
  - lower-case canonical form only
  - no wildcard
  - each label component must be 1-63 chars

- `fqdn`
  - canonical fully-qualified name
  - must exactly equal `label + "." + zone_name`
  - runtime should re-derive and compare, not trust blindly

- `rr_type`
  - enum
  - allowed in v1: `A`, `AAAA`

- `ttl_secs`
  - integer
  - required
  - bounded, recommended range `30..=300`
  - default recommendation `60`

- `target_node_id`
  - required
  - binds record to Rustynet node identity

- `target_addr_kind`
  - enum
  - v1 allowed values:
    - `mesh_ipv4`
    - `mesh_ipv6`

- `expected_ip`
  - required
  - must match the target node's signed assignment-derived mesh address for the selected address kind
  - runtime must reject mismatch

- `aliases`
  - optional array
  - alias labels under the same zone only
  - each alias is subject to the same label restrictions as `label`

## 7) Canonical Validation Rules

Runtime must validate all of these before loading the bundle:

1. schema and artifact type are known
2. signature verifies against the pinned verifier key
3. artifact is fresh and unexpired
4. watermark/nonce is not replayed or rolled back
5. `subject_node_id` matches the local node
6. `zone_name` matches configured managed zone
7. every `fqdn` canonicalizes exactly from `label`
8. every `target_node_id` exists in current signed membership
9. every `target_node_id` is not revoked
10. every `expected_ip` matches current signed assignment state for that node
11. no record points outside authorized Rustynet address space
12. no duplicate `fqdn`
13. no alias collides with another primary label or alias
14. record count, alias count, and label lengths stay within hard bounds

If any validation fails:

- do not partially load
- preserve the last known valid zone if still fresh
- otherwise fail closed for managed zone resolution

## 8) Hard Bounds

Recommended initial bounds:

- max bundle size: `256 KiB`
- max records per bundle: `1024`
- max aliases per record: `8`
- max total labels including aliases: `2048`
- max TTL: `300`
- min TTL: `30`
- max zone name length: `64`

The goal is to prevent memory abuse, parser abuse, and oversized signed artifacts.

## 9) Watermark and Replay Protection

DNS should use the same strict watermark philosophy already used elsewhere in Rustynet.

Recommended watermark file fields:

```text
version=2
generation=7
payload_digest_hex=<sha256 of canonical bundle bytes>
generated_at_unix=1773000000
```

Rules:

- lower generation than current watermark is rejected
- equal generation with different digest is rejected
- equal generation with same digest is allowed
- legacy watermark versions are rejected fail-closed

This prevents stale-bundle replay and same-generation tampering.

## 10) Resolver Runtime Contract

The runtime resolver should behave as follows.

For names inside the managed zone:

- if bundle is valid and loaded:
  - answer authoritatively from signed records
- if bundle is missing, stale, invalid, or mismatched:
  - return `SERVFAIL` for managed names
  - do not forward the query to external DNS

For names outside the managed zone:

- forward only through the protected upstream DNS path
- keep existing DNS fail-closed behavior from protected mode

This distinction matters:

- `SERVFAIL` for managed-zone state failure preserves fail-closed semantics
- forwarding managed-zone misses externally would create namespace leakage and trust confusion

## 11) Authorization Model

Record visibility must be least-knowledge.

Preferred model:

- control plane computes visible DNS names for each target node
- zone bundle is filtered to only those records

Minimum authorization rules for v1:

- a node may see its own record
- a node may see records for peers it is authorized to communicate with under signed assignment/policy state
- a node may see exit-node names it is authorized to select
- a node must not automatically see unrelated aliases or nodes outside its allowed graph

This is stricter than many consumer VPNs. That is intentional.

## 12) Collision Handling

Collisions must be resolved centrally, not at daemon runtime.

Recommended issuer behavior:

- normalize labels to lower-case LDH form
- assign first claimant the base label
- assign later collisions deterministic suffixes:
  - `nas`
  - `nas-2`
  - `nas-3`

Runtime should still validate uniqueness, but it should not invent new labels locally.

Why:

- central deterministic issuance is auditable
- local renaming would create inconsistent views across nodes

## 13) Why Raw Hostname-to-IP Overrides Are Not Acceptable

A naive design would let an admin or node submit:

- `custom_url -> raw_ip`

That is not the right default in Rustynet.

Problems:

- raw IPs can point at rogue underlay or internet endpoints
- names become detached from signed node identity
- stale records survive assignment changes
- local operators can accidentally create unsafe split-brain behavior

The secure design is:

- `custom label -> target_node_id -> signed assignment-derived address`

That keeps naming bound to trust state.

## 14) Future Extension Points

These can be added later, but should not be in v1:

- service-scoped virtual IP records
- signed `SRV` records for service discovery
- policy-gated public-zone override for verified-owned domains
- DoH/DoT upstream transport
- DNSSEC-style authenticated negative responses inside the managed zone

Each of these expands trust surface and should be staged separately.

## 15) Recommended CLI Surface

Not for immediate implementation, but this is the right shape:

```bash
rustynet dns zone issue \
  --zone rustynet \
  --subject-node-id client-1 \
  --records-file /path/to/zone.records.json \
  --signing-secret /etc/rustynet/dns-zone.signing.secret \
  --signing-secret-passphrase-file /run/credentials/.../dns_zone_signing_passphrase \
  --output /tmp/client-1.dns-zone \
  --verifier-key-output /tmp/dns-zone.pub

rustynet dns zone verify \
  --bundle /var/lib/rustynet/rustynetd.dns-zone \
  --verifier-key /etc/rustynet/dns-zone.pub

rustynet dns inspect
```

Mutation should remain signer-backed and centrally issued. There should be no local unsigned `dns set` command.

## 16) Enforcement Points

Recommended enforcement mapping:

- `rustynet-control`
  - canonical schema types
  - signing and verification
  - collision validation

- `rustynet-cli`
  - issuance and verification commands
  - no local unsigned mutation path

- `rustynetd`
  - secure bundle loading
  - watermark enforcement
  - resolver runtime
  - `dns inspect`

- dataplane/DNS manager
  - managed-zone authoritative answers
  - protected upstream forwarding for non-managed names
  - fail-closed behavior when DNS state is invalid

## 17) Required Tests

Unit tests:

- canonical label normalization
- deterministic collision handling
- invalid label rejection
- duplicate alias rejection
- record-to-assignment IP mismatch rejection
- replay/rollback rejection
- subject-node mismatch rejection

Integration tests:

- node resolves authorized peer name through local authoritative resolver
- node cannot resolve unauthorized peer name
- managed-zone query returns `SERVFAIL` when bundle is stale or invalid
- external DNS remains protected and fail-closed on tunnel/DNS failure
- signed zone update rotates records without stale-cache confusion

Adversarial tests:

- forged signature
- same-generation different-digest tamper
- alias collision injection
- record pointing to underlay IP
- revoked-node record retention

## 18) Implementation Status and Next Slice

Current hardened baseline implemented:

1. shared `SignedDnsZoneBundle` schema/parser logic
2. watermark handling and `dns inspect`
3. signed bundle state replacing the in-memory-only placeholder path
4. CLI `dns zone issue` and `dns zone verify` commands
5. local authoritative resolver for the managed zone, bound to loopback only

Next secure slice:

1. per-node filtered bundle issuance policy enforcement in operator workflows
2. OS DNS integration that points managed-zone queries at the local loopback resolver without weakening protected-DNS routing
3. adversarial E2E tests for stale/forged/replayed managed-zone bundles on live nodes

Do not add dynamic local resolver mutation or OS `/etc/hosts` editing as an alternate naming path.

## 19) Bottom Line

The correct Rustynet Magic DNS schema is:

- signed
- per-target-node
- node-identity-bound
- assignment-cross-checked
- replay-protected
- private-zone-only
- fail-closed for managed names

That keeps naming inside the same security model as the rest of Rustynet instead of introducing a weaker side channel.
## Agent Update Rules

Use these rules every time you modify this document during implementation work.

1. Update the document immediately after each materially completed slice.
- Do not keep a private checklist that diverges from this file.
- This document must remain the public execution record.

2. Mark completion conservatively.
- Use `[x]` only after the code is implemented and verified.
- Use `Status: partial` when some hardening landed but real work remains.
- Use `Status: blocked` only for real external blockers; name the blocker precisely.

3. Record evidence under the section you touched, or in the existing session log/evidence table if the document already has one.
- Minimum evidence fields:
  - `Changed files:` exact paths
  - `Verification:` exact commands, tests, smoke runs, dry runs, gates
  - `Artifacts:` exact generated paths, if any
  - `Residual risk:` what still remains, if anything
  - `Blocker / prerequisite:` only when applicable

4. Use exact timestamps and commit references where possible.
- Prefer UTC timestamps in ISO-8601 format.
- If commits exist, record the commit SHA that contains the work.

5. Do not delete historical context that still matters.
- Correct stale claims when they are inaccurate.
- Do not erase previous findings, checklist items, or session history just to make the document look cleaner.

6. Keep security claims evidence-backed.
- Never write that a path is secure, complete, hardened, or production-ready without code and verification proof.
- If live validation is unavailable, state that explicitly and record the missing prerequisite.

7. If tests fail, record the failure honestly and fix the root cause.
- Do not weaken gates, remove checks, or relabel failures as acceptable.
- If a fix is incomplete, mark the item partial instead of complete.

