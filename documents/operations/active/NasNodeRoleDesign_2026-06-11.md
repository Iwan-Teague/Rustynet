# Rustynet NAS Node Role Design

- Date: 2026-06-11
- Status: active (design source-of-truth for the `nas` node role)
- Owner: Rustynet
- Parent doc: [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) — `nas` is one of the two new service-hosting presets defined there. This document is the deep dive for the `nas` preset specifically and inherits the secure-exposure model from the parent §5 and the security-control category from the parent §8.
- Sibling doc: [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md).

---

## 0) Purpose of this document

Define the **NAS node** role end-to-end: what it is, what it is not, the new Rust sibling service that backs it (`rustynet-nas`), exactly how it exposes storage over the mesh without ever exposing it off-mesh, the node-side interface contract the future **RustyBackup** client app will speak, the per-platform story, the security controls with enforcement + verification, and the build plan.

The NAS node is the dedicated storage device for a Rustynet home mesh. Users back up media (photos, video) and other files to it. The defining property — and the reason it is a Rustynet role and not "just plug in a Synology" — is that **it is reachable only by signed-authorised mesh peers over the encrypted tunnel, default-deny, with no off-mesh surface**. A NAS exposed the normal way (SMB/NFS on the LAN, or worse, port-forwarded) is one of the most-attacked surfaces in a home network. A NAS exposed as a Rustynet role has no LAN/public listener at all.

If a later document or commit conflicts with this design, this document is the source of truth for the `nas` role until explicitly superseded.

---

## 1) Why "nas" and what it deliberately is not

| It IS | It is NOT |
|---|---|
| A `rustynetd` peer with `serves_nas` advertised in signed membership, co-running `rustynet-nas`. | A new trust authority. It verifies signatures like any peer; it grants nobody. |
| A tunnel-only storage/backup endpoint, default-deny per signed policy. | A LAN file share. There is no SMB/NFS/AFP listener on the LAN or public interface by this role. (An operator may run those separately, but that is outside the role and outside its security guarantees.) |
| A thin Rust service wrapping a storage engine behind a process boundary. | A reimplementation of a filesystem or block store. No custom storage crypto, no custom replication protocol. |
| A consumer of the existing tunnel for confidentiality + peer auth. | A terminator of its own TLS for mesh peers. The tunnel is the secure channel. |
| Orthogonal to `NodeRole` (it is `NodeRole::Admin` + `serves_nas`). | A new `NodeRole` primary. |

The role's whole value is the **secure, signed, default-deny exposure** of storage to the mesh. The storage itself is commodity; the access model is the product.

---

## 2) Role definition

A **NAS node** is a `rustynetd` instance whose signed membership entry carries `Capability::ServesNas` (`serves_nas`). When that capability is present and verified, the daemon:

1. Deploys/ensures the `rustynet-nas` sibling service is running and healthy (deploy-before-advertise — the bundle never advertises `serves_nas` for a host where the service is not up).
2. Binds the NAS API listener to the **mesh tunnel address only** (parent §5 rule 1).
3. Admits a peer's session only if `ContextualPolicySet::evaluate_with_membership` returns `Decision::Allow` for `(peer, TrafficContext::NasService)` against current signed policy — otherwise `Decision::Deny` (parent §5 rule 2, §8 control E2).
4. Tears the listener down and drops sessions **before** the capability can be revoked from local state (parent §8 control E3).

The capability is **independent** and **signed**. A node cannot self-promote into a NAS; the membership owner signs a bundle granting `serves_nas`, exactly as for `serves_exit` / `serves_relay`.

---

## 3) `rustynet-nas` — the sibling service

A new Rust crate, deployed as a sibling service alongside `rustynetd` (same pattern as `rustynet-relay` co-deploying with `anchor`/`relay`). It is intentionally a **thin, hardened wrapper** — the storage durability is delegated to the host filesystem; `rustynet-nas` owns the protocol, the authorisation handshake with the daemon, and the on-disk layout for backup objects.

### 3.1 Responsibilities

- Expose a **content-addressed backup/sync API** over the tunnel-bound listener: chunked upload, resumable transfer, dedup by content hash, per-peer namespaces, snapshot/version listing, restore/download, delete (soft-delete + retention).
- Enforce per-peer storage quotas and per-peer namespaces so one peer's backups cannot read or clobber another's, even when both are authorised to reach the NAS.
- Receive the **verified peer identity** from `rustynetd` (the daemon authenticated the tunnel + checked signed policy) and bind every object to that identity. The service never authenticates a peer by itself from scratch; it trusts the daemon's mediated identity, and additionally validates a short-lived node-issued service token (defence-in-depth, parent §5 rule 4).
- Encrypt-at-rest backup data with a key from OS-secure storage (Linux `LoadCredentialEncrypted` / macOS keychain / Windows DPAPI), with strict permissions + startup permission checks — reusing `rustynet-local-security` key-custody patterns. **No custom crypto**: use `rustynet-crypto` AEAD primitives.
- Report health to `rustynetd` so the fail-closed health gate (parent §5 rule 6) can drop the endpoint if storage is unmounted, full, or the process is wedged.

### 3.2 What it delegates / does not do

- It does **not** implement a filesystem, RAID, or block replication. Disks, redundancy, and SMART monitoring are the operator's host concern.
- It does **not** open any LAN/public listener.
- It does **not** sign or mint membership/policy. Authorisation is read from signed state the owner produced.
- It does **not** hold the membership-root key.

### 3.3 On-disk layout (sketch)

```
<data-root>/rustynet-nas/
  objects/<peer-id>/<content-hash>      # encrypted-at-rest chunks, per-peer namespace
  snapshots/<peer-id>/<snapshot-id>.json.sig  # signed snapshot manifests
  quota/<peer-id>.json                  # quota + usage accounting
  .keycheck                             # startup permission/version sentinel
```

`<data-root>` is operator-provided (the data disk). The service refuses to start if `<data-root>` permissions are world-accessible or the at-rest key is unavailable (fail-closed).

---

## 4) Secure exposure (NAS specifics over parent §5)

The parent §5 six-rule model applies verbatim. NAS-specific points:

- **Listener:** `rustynet-nas` binds `<tunnel-ip>:<nas-port>` (default e.g. `:51823`, configurable). A config requesting any non-tunnel bind is rejected at startup (parent §8 E1). There is no LAN-bind escape hatch — unlike anchor bundle-pull (which has a documented `--lan-bind`), the NAS has **no** LAN-bind option at all, because storage is a higher-value target than a bundle-pull endpoint.
- **MagicDNS name:** the node gets a stable overlay name (e.g. `vault.nas.<mesh>`) from the signed DNS zone ([`MagicDnsSignedZoneSchema_2026-03-09.md`](./MagicDnsSignedZoneSchema_2026-03-09.md)). RustyBackup targets the name; it resolves only inside the mesh.
- **Authorisation:** a peer reaches the NAS only if signed policy says `(peer → NasService) = Allow`. Default-deny: a brand-new NAS authorises **nobody** until the owner signs a policy adding peers/groups. The wizard makes this explicit ("your NAS is up but no device can reach it yet — authorise devices from your admin box").
- **Per-peer isolation:** authorisation to *reach* the NAS is separate from *namespace* — every authorised peer gets its own object namespace and quota; cross-peer read/write is denied inside `rustynet-nas` even among authorised peers.

---

## 5) RustyBackup interface contract (node-side only)

The future **RustyBackup** client app (desktop/mobile UI for backing up media + files) is out of scope to design here; this section pins the **contract the NAS node exposes** so RustyBackup can be built against a stable surface. RustyBackup is "just a client" of this contract, the way RustyAI is a client of the LLM node.

**Transport:** RustyBackup connects to `<nas-name>.<mesh>` over the Rustynet tunnel. It never connects off-mesh. If the device is not in the mesh, the first step is enrollment (existing flow), not a NAS-specific path.

**Identity & authorisation:** the connecting device is already a mesh peer with a verified identity. RustyBackup presents no separate password to establish trust; reachability is decided by signed policy on the NAS node. On first connect, RustyBackup obtains a short-lived service token from the node (scoped to that peer, that service), used for subsequent requests and re-validated against signed policy on each use (parent §8 E4).

**API surface (stable contract):**

| Operation | Shape | Notes |
|---|---|---|
| `hello` | peer → node | negotiate protocol version, receive service token + quota/namespace info |
| `put-chunk` | content-addressed, resumable | dedup by hash; idempotent |
| `commit-snapshot` | manifest of chunk hashes + metadata | node stores a signed snapshot manifest |
| `list-snapshots` | per-peer | only the caller's namespace |
| `get-chunk` / `restore` | content-addressed read | only the caller's namespace |
| `delete-snapshot` | soft-delete + retention | retention/GC owned by node |
| `usage` | quota + usage | per-peer accounting |

**Versioning:** the `hello` handshake carries a protocol version; the node refuses unknown major versions fail-closed. The wire format reuses the project's existing serialization-hardening posture ([`SerializationFormatHardeningPlan_2026-03-25.md`](./SerializationFormatHardeningPlan_2026-03-25.md)) — length-bounded, no unbounded allocation, deny on malformed.

**What RustyBackup must NOT assume:** it cannot assume reachability implies authorisation forever (policy can revoke), cannot bypass quotas, cannot read another peer's namespace, and cannot reach the NAS without the tunnel. The client is untrusted; the node enforces.

The RustyBackup app's own architecture (UI, scheduling, local file watching, media handling) will be specified in a separate future document when that app is built. This document only guarantees the node-side surface it will target.

---

## 6) Per-platform implementation

Same host/consume split as anchor: Linux primary host, macOS secondary, Windows gated, mobile consume-only.

### 6.1 Linux (primary host)

- `rustynet-nas` runs as a systemd sibling unit (`rustynet-nas.service`), co-deployed by the role-transition orchestrator when entering `nas` (extends the existing `ops install-systemd` Rust path used for relay co-deploy — **no new shell logic**).
- Tunnel-only bind uses the overlay interface address; nftables emitter (`crates/rustynetd/src/linux_runtime_nftables.rs`) adds a NAS table: accept on the NAS port **only** from the tunnel interface, default-deny elsewhere — belt-and-braces on top of the bind-address restriction.
- At-rest key via systemd `LoadCredentialEncrypted`; startup permission check refuses world-readable data-root or key.
- Data-root is operator-provided; service refuses to serve if it is not mounted (fail-closed health).

### 6.2 macOS (secondary host; pending cross-OS green run)

- `rustynet-nas` runs as a launchd sibling (`com.rustynet.nas.plist`), mirroring the relay launchd pattern ([`../MacosLaunchdServiceManagement.md`](../MacosLaunchdServiceManagement.md)).
- At-rest key in macOS keychain (`rustynet.nas_at_rest_key`), separate keychain item from the WireGuard passphrase.
- PF anchor prunes/scopes the NAS port to the tunnel. Marked `⛔ fail-closed` in the platform matrix until live evidence (same readiness discipline as relay/anchor on macOS).

### 6.3 Windows (gated on D7/D9 dataplane parity)

- `rustynet-nas.exe` as a separate Windows service via SCM; env in `C:\ProgramData\RustyNet\config\`.
- At-rest key as a DPAPI `.dpapi` blob under `C:\ProgramData\RustyNet\secrets\`, covered by the W4 ACL verifier.
- WFP scopes the NAS port to the tunnel (consistent with the WFP killswitch direction). Blocked in the wizard until Windows reaches role parity, fail-closed on `role set nas`.

### 6.4 iOS / Android (consume-only — RustyBackup client)

- Cannot host (OS lifecycle, no 24/7 availability, no stable bind, sandboxed storage). Mobile runs the **RustyBackup client** against a NAS node hosted elsewhere.
- `rustynet-mobile-core` carries the RustyBackup transport client (tunnel-scoped) mirroring §5; UI surfaces "Backup target: `vault.nas.<mesh>`" read-only.
- Mobile `role set` refuses anything but `client` (inherited mobile role lock, SecurityMinimumBar §6.D control 8).

---

## 7) Security controls (enforcement + verification)

Inherits all parent §8 controls (E1–E4) and the §6.D transition controls. NAS-specific enforcement:

| Control | Enforcement | Verification |
|---|---|---|
| `serves_nas` requires owner signature | `apply_signed_update` rejects unsigned/invalid bundles; capability is signed metadata | Unit test: tampered `serves_nas` flag invalidates signature → reducer rejects |
| Endpoint binds tunnel-only, no LAN escape | bind address derived from overlay iface; any non-tunnel bind config rejected at startup; **no** LAN-bind option exists | Negative test: LAN/public packet to NAS port → dropped; startup with `0.0.0.0` bind → refuse to start |
| Default-deny per-peer reach | `ContextualPolicySet::evaluate_with_membership` gates every session; empty/missing/stale ⇒ `Decision::Deny` | Truth table: fresh NAS (no policy) → all peers denied; add signed allow → that peer only; revoke → denied |
| Per-peer namespace isolation | `rustynet-nas` binds objects to the daemon-mediated peer identity; cross-namespace access denied in-service | Test: authorised peer A cannot read/write peer B's namespace |
| At-rest encryption + key custody | AEAD via `rustynet-crypto`; key from OS-secure store; startup permission check | Test: world-readable data-root/key → service refuses to start; at-rest blobs are ciphertext |
| Teardown precedes revocation | Listener closed + sessions dropped before `serves_nas` leaves local state | Integration test: revoke during active upload → session severed, new connect refused, then bundle drops flag |
| Service token ≤ signed policy | Node-issued token re-checked against signed policy each use | Test: revoke peer → token use denied before TTL expiry |
| No secret in logs | Access logged by peer-id + token thumbprint + bytes; never token, never file contents, never key | Redaction test extended to NAS surfaces ([`../SecretRedactionCoverage.md`](../SecretRedactionCoverage.md)) |
| Capability is not authority | `rustynet-control` verifiers never consult `serves_nas` before validating signatures | Code review: no `serves_nas` reference gates signature verification |
| Deploy-before-advertise | Orchestrator verifies `rustynet-nas` healthy before emitting the signed bundle | Integration test: deploy failure → no signed bundle; previous state preserved |

---

## 8) Build slices (maps to D13.c)

| Slice | Scope | Pass criterion |
|---|---|---|
| **D13.c.1** | `rustynet-nas` crate: protocol, per-peer namespace, quota, at-rest AEAD, health reporting | Unit + property tests green; at-rest blobs are ciphertext; malformed wire → deny |
| **D13.c.2** | Daemon integration: tunnel-only listener lifecycle, daemon-mediated peer identity handoff, `TrafficContext::NasService` gate, fail-closed health, teardown-before-revoke | Integration test: default-deny → signed-allow → revoke, with session severance |
| **D13.c.3** | `nas` preset wiring: `role set nas` deploy/verify/advertise; `role set admin` undeploy after revoke; eight-preset table/transition tests | `rustynet role set nas` then `set admin` round-trips cleanly on Debian 13 |
| **D13.c.4** | Linux service install + nftables NAS table; platform-matrix row; macOS launchd + Windows SCM scaffolds (gated) | Linux live evidence; macOS/Windows `⛔` until green run |

Standard workspace gates + `service_hosting_role_gates.sh` (NAS cases) + extended `role_taxonomy_gates.sh` (eight presets) + a new `nas_default_deny_gates.sh` (the §7 truth table).

---

## 9) Refactor inventory (NAS-specific delta)

| File | Change |
|---|---|
| `crates/rustynet-nas/` (new crate) | The sibling service |
| `crates/rustynet-control/src/role_presets.rs` | `ServesNas` capability, `nas` preset row, `requires_nas_binary`, transition flags |
| `crates/rustynet-control/src/roles.rs` | `RoleCapability::ServesNas` + parse/`as_str` + tests |
| `crates/rustynet-control/src/membership.rs` | `serves_nas` in `node_capabilities` canonical pre-image (append-only) |
| `crates/rustynet-policy/src/lib.rs` | `TrafficContext::NasService` + truth-table tests |
| `crates/rustynetd/src/daemon.rs` | NAS listener lifecycle + access gate + health gate + teardown-before-revoke |
| `crates/rustynet-cli/src/role_set.rs` | `nas` deploy/undeploy orchestration |
| `crates/rustynet-cli/src/ops_install_systemd.rs` | Optional `rustynet-nas.service` co-deploy |
| `crates/rustynet-operator/src/role.rs` | `nas` per-platform eligibility |
| `crates/rustynetd/src/linux_runtime_nftables.rs` | NAS-port tunnel-scoping table |
| `start.sh`, operator menu | `nas` wizard option + "no device authorised yet" guidance |
| `documents/operations/PlatformSupportMatrix.md` | `nas` row |
| `documents/operations/RustynetdServiceHardening.md` | NAS hardening section |
| `documents/operations/SecretRedactionCoverage.md` | NAS log surfaces |
| `documents/Requirements.md` §6.1 | `rustynet-nas` component |
| `documents/SecurityMinimumBar.md` §6.E | service-hosting controls (shared with LLM) |

Deliberately unchanged: `NodeRole` enum, WireGuard backend, signing root, trust verifiers, `rustynet-relay`.

---

## 10) Open questions

| Question | Default | Re-open trigger |
|---|---|---|
| Should the NAS also support live file-share semantics (mountable), not just backup/restore? | No — start with content-addressed backup/sync (safer, simpler, dedup-friendly). | If users demand a mountable share, add a tunnel-scoped read path with the same default-deny gate; never a LAN mount. |
| Per-peer at-rest keys, or one node key? | One node at-rest key in OS-secure storage initially; per-peer namespaces give isolation. | If per-peer cryptographic separation (peer holds its own key, node stores opaque ciphertext) becomes a requirement, add client-side encryption in RustyBackup with the node as zero-knowledge blob store. |
| Multi-NAS replication/redundancy? | No — single NAS per mesh initially; operator handles disk redundancy. | If multi-site backup is wanted, design a signed NAS-to-NAS sync as a follow-up (reuses tunnel + signed policy). |
| Should `client` peers see the NAS in `role list`/DNS? | Read-only yes (so they know the backup target exists); reach still default-deny. | n/a |

---

## 11) Definition of done

The `nas` role is "done" when:

- D13.c.1–4 land on `main` with passing gates.
- A clean Debian 13 install with a data disk runs `rustynet role set nas`, ending with `rustynet-nas` healthy, `serves_nas` advertised in signed membership, endpoint bound tunnel-only, **default-deny** (no peer reaches it yet).
- The owner signs a policy authorising one device; that device — running the RustyBackup client contract (§5) — backs up and restores a file over the tunnel; an un-authorised mesh peer is denied; an off-mesh attempt has no surface to hit.
- `rustynet role set admin` (owner signs revocation) severs sessions, tears down the listener, and undeploys `rustynet-nas` before the capability drops.
- At-rest blobs are verified ciphertext; logs contain no secrets.
- `PlatformSupportMatrix.md` `nas` row, `SecurityMinimumBar.md` §6.E, and `Requirements.md` §6.1 reflect reality.
- This document remains the source-of-truth for the role.

---

## 12) Cross-references

- [`NodeRoleTaxonomyExtension_2026-06-11.md`](./NodeRoleTaxonomyExtension_2026-06-11.md) — parent; secure-exposure model (§5) and §6.E controls.
- [`LlmNodeRoleDesign_2026-06-11.md`](./LlmNodeRoleDesign_2026-06-11.md) — sibling service-hosting role.
- [`NodeRoleTaxonomy_2026-05-21.md`](./NodeRoleTaxonomy_2026-05-21.md) — base taxonomy.
- [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) — co-deployed-sibling pattern template.
- [`MagicDnsSignedZoneSchema_2026-03-09.md`](./MagicDnsSignedZoneSchema_2026-03-09.md) — stable overlay name for the NAS.
- [`SerializationFormatHardeningPlan_2026-03-25.md`](./SerializationFormatHardeningPlan_2026-03-25.md) — wire-format hardening for the NAS protocol.
- [`RustynetDataplaneExecutionPlan_2026-05-18.md`](./RustynetDataplaneExecutionPlan_2026-05-18.md) — D13.c.
- [`../PlatformSupportMatrix.md`](../PlatformSupportMatrix.md) · [`../RustynetdServiceHardening.md`](../RustynetdServiceHardening.md) · [`../MacosLaunchdServiceManagement.md`](../MacosLaunchdServiceManagement.md) · [`../SecretRedactionCoverage.md`](../SecretRedactionCoverage.md)
- [`../../Requirements.md`](../../Requirements.md) §6.1 · [`../../SecurityMinimumBar.md`](../../SecurityMinimumBar.md) §6.E
