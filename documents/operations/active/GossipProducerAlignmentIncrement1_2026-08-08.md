# Gossip producer alignment — increment 1

**IMPLEMENTED AND LIVE-PROVEN 2026-08-09.** S1–S11 all landed. Revision 2 of the design
is preserved below unchanged, including the parts review corrected, because the record
of *which claim broke* is the transferable part.

**Status of each step:**

| Step | State |
| --- | --- |
| S1–S7, S11 | Landed `f2d0e795` / `a696992e`; two blockers fixed in `43c1e03b` / `f9b86aa5` |
| S8, S9 | Landed `f3b89f01` — stage `gossip_convergence_validation`, Live suite / T0Core |
| **S8b** | **Deliberately not done.** The stage is `state_machine_only`, i.e. `--node` only, matching `mesh_status_validation` and every other rust-native validator. The bash dialect keeps its own per-check validators. I-6's "both dialects" is hereby narrowed rather than left ambiguous. |
| S10 | Proven twice — see below |

**Live proof.** Run `gossip-convergence-stage-20260809` at `f3b89f01`: 59 stages,
**37 passed, 0 failed**, `linux_stage_gossip_peer_convergence = pass` in the ledger.
Earlier, by hand at `43c1e03b`: the joiner's published `node_pubkey_hex` is byte-identical
to its own `show-gossip-key` output, and the exit node logs
`gossip_accept source=ba6c9bd6…` with accepts climbing 0→3→5 and zero
`gossip_reject_unknown_source` since daemon start — where before it rejected
continuously at `peers=0`.

**Two bugs got past this reviewed plan.** Neither was caught by review, and one was
caused *by* the plan:

1. **The plan's own advice was wrong.** It told the implementer not to use
   `systemctl is-active --quiet`, reasoning that `--quiet` would suppress the failure
   marker. The marker is a separate `echo` on the failure branch and fires regardless.
   Without `--quiet`, `is-active` prints `active` onto the same stdout the key is parsed
   from, and every node failed with `got 71`. **The unit test asserted the plan's wrong
   rule and passed, pinning the bug.** Found only by a live run.
2. **`macos_membership.rs` branched on the wrong axis.** It published every peer's
   WireGuard key unconditionally. That producer runs on a macOS *exit* node but writes
   membership for **every** peer, so any `--exit-platform macos` run silently
   republished Linux nodes' real gossip identities as WireGuard keys, under a flag
   named `unaligned-wireguard`. **The correct axis is the SUBJECT peer, not the
   producer's platform** — and both earlier review rounds counted callers by producer
   platform, so neither could see it.

---

**REVIEWED DESIGN, REVISION 2 (as written 2026-08-08 against HEAD `2afcd57d`).**

Revision 1 was adversarially reviewed twice: once as a design (four lenses + a
verifying judge, five blockers) and once as a written document (three lenses + a judge,
**five further blockers and six majors**). Revision 2 folds in all of it. **Revision 1
was not implementable** — three of its defects sat in the ordered steps an implementer
follows literally. The corrections are kept inline rather than silently applied,
because on this document family the transferable lesson has always been *which* claim
broke.

Scope: the *producer* half of
[GossipMembershipIdentityAlignment_2026-08-05.md](./GossipMembershipIdentityAlignment_2026-08-05.md).
Read its §1 first. This document corrects three of its claims (§1.2).

---

## 0. Why now, and what the evidence actually is

The parent design says fixing producers is impossible until a primitive exists to print
the gossip verifying key. That prerequisite shipped: `a0c0f914` (`key show-gossip-key`),
`26b6a78b` (genesis publishes its derived key), `07170612` (macOS product installer
mints).

**Measured 2026-08-07** on the two-node Debian lab. **Provenance, stated precisely:
these four values are live `ssh` reads taken by hand while run
`livelab-1786126778-adeea15e5125` was in flight. They are NOT in that run's report
artifacts, and nothing in the repository records them except this document.** The run
row itself is real (`live_lab_node_run_matrix.csv`), and the base64→hex identity below
is arithmetic anyone can recheck.

- genesis `debian-headless-2-bootstrap` published `d0f0cc07f25c2524…`, byte-identical
  to its own `show-gossip-key` output and to `gossip_mint source=` in its journal.
  P1 is fixed and proven.
- joiner `debian-headless-4-bootstrap` published
  `6d3065239a604d314b4bc3f1709bacaa2111aa321681e9f13eca6e44bae37c25`, which decodes
  exactly from its WireGuard key `bTBlI5pgTTFLS8PxcJusqiERqjIWgenxPspuRLrjfCU=`. Its
  real gossip key is `f26296b554fabfa0…`.
- the **exit** node logged `gossip_reject_unknown_source source=f26296b554fabfa0
  sender=100.124.191.164:51821` continuously and sat at `peers=0`. (The joiner reported
  `peers=1`; the count is not a health signal — see §9.)

It fails **closed**. Functional defect, not a vulnerability.

---

## 1. What review changed

### 1.1 Blockers against revision 1

| # | Blocker | Correction |
| --- | --- | --- |
| B1 | `e2e-membership-add` has **six** callers; the draft migrated three. | §4 S4 migrates all six. |
| B2 | The new stage wired only one dialect. | §4 S8 + S8b wire both. |
| B3 | The passphrase source was assumed. | **Probed. PASSES** — §8. |
| B4 | "Canonical-Ed25519-validated" sold as a control. | §1.3 — it is not. |
| B5 | The kill switch was an env var that cannot cross `ssh`+`sudo`. | **Dropped entirely** — §2 I-2. |
| **BL-1** | The sixth caller is the **shell orchestrator, which is Linux** — yet D-7 deferred it while I-2 hard-rejects the legacy flag. Both cannot hold. I-5's "four deferred-platform callers" was also wrong: only **three** non-Linux callers exist. | Shell migrated in S4; removed from D-7; count corrected to three. |
| **BL-2** | The Windows `--node` producer uses a **different binary and verb** — `rustynetd membership add-peer --node-pubkey-hex` (`windows_membership.rs:306-307`, wired `windows.rs:146`, dispatched `rustynetd/main.rs:3787`). It has no `--client-pubkey-hex`, so I-5's containment cannot reach it. | New **D-9**; I-5's greppability guarantee explicitly does **not** cover it. |
| **BL-3** | S9's "the joiner's own key is in the registered set" is **unobservable**. Only a count is published (`daemon.rs:5788`, fed by `node.peers.len()` at `:5777`); `register_peer` logs nothing (`gossip_runtime.rs:308-321`). | S9 rewritten around `gossip_accept source=…` on the exit node. |
| **BL-4** | S7's "absence is an `Err`" bricks every mixed-OS run: `collect_pubkeys.rs:19` `applies_to_roles → &[]` (all nodes) and `:94-97` turns any error into `StageOutcome::Failed`. | S6/S7 state the discriminator explicitly. |
| **BL-5** | S2 named a helper that cannot express `-u`: `ops_e2e.rs:6210-6218` builds `ssh` → `sudo -S -p` → `env` → program, with no uid switch. | S2 spells it concretely. |

### 1.2 Corrections to the parent design

1. **§4.3(b) "macOS never mints one" is stale — but only for the *product* path.**
   `install/live_macos.rs:301` runs `key init-gossip`, reachable solely from
   `install/mod.rs:235` (`OsFamily::Macos => live_macos::install(…)`). The **lab** macOS
   path (`adapter/macos_install.rs:34,36`) never mints. See §3 — this is narrower than
   revision 1 claimed.
2. **§4.3(a) still holds.** `daemon.rs:11592` refuses a configured gossip secret on
   non-unix: *"the gossip transport is unix-only"*.
3. **§4's 33-byte HKDF trap is closed by construction.** Both loaders call one shared
   `append_key_terminator` (`key_material.rs:540`, `:587`, defined `:600`). §4.1's
   *vacuous test* finding still stands (D-8).

### 1.3 The validation claim, corrected

The aligned flag is **not** a control that distinguishes a gossip key from a WireGuard
key. `VerifyingKey::from_bytes` decompresses with no canonicity and no low-order check
— the high-bit mask is `curve25519-dalek-4.1.3/src/backend/serial/fiat_u64/field.rs:213`
(`temp[31] &= 127u8;`), not the `verifying.rs` lines revision 1 cited. Measured against
RFC 8032 vectors: `"ff"×32`, `"00"×32`, `"01"×32`, `"03"×32`, `"11"×32` succeed;
`"02"×32`, `"ab"×32` fail; **the measured joiner value `6d3065…7c25` fails**; 20 000
random 32-byte strings pass at **0.5054**.

(Revision 1's table said `"ff".repeat(64)` — 64 bytes, unusable as a fixture and
rejected by S1's own length rule before decode. Corrected to `×32`.)

**So the only thing separating aligned from unaligned is the flag's spelling.** Fixtures
must use the measured joiner value, never `"ff"×32`.

---

## 2. Scope

### In

| ID | Change |
| --- | --- |
| I-1 | Linux collector: `show-gossip-key` on the joiner **as the `rustynetd` uid**, validated, no fallback. |
| I-2 | `ops e2e-membership-add`: aligned `--client-gossip-pubkey-hex`; explicit `--client-pubkey-hex-unaligned-wireguard`; hard rejection of legacy `--client-pubkey-hex`. **No `--require-gossip-identity`** — a flag parsed on the *guest* cannot gate a collector that runs on the *orchestrator host*; that is B5's defect in a new costume. Enforcement lives host-side in the collector (§5). |
| I-3 | Caller A — `ops_e2e.rs:4070`. |
| I-4 | Caller B — orchestrator Linux chain. |
| I-5 | The **three** non-Linux callers routed through the explicit unaligned flag. **This does not cover D-9.** |
| I-6 | New stage `validate_linux_gossip_peer_convergence`, wired into **both** dialects (S8 and S8b). |

### Out

| # | Deferred | Why |
| --- | --- | --- |
| D-1 | `ops init-membership` genesis passes no gossip flags. | Invisible on Linux **only by coincidence** — `linux_membership.rs:63-64` invokes it every run and is saved solely by the two-file `&&` short-circuit at `main.rs:13971`, whose fallback is deliberately fail-open (`rustynetd/main.rs:4204-4207`). Relocate or clean either file and genesis silently reverts `26b6a78b`. **No test pins this.** |
| D-2 | macOS producer. | Blocked on Keychain-passphrase reachability for a non-daemon caller (`key_material.rs:95-104`). |
| D-3 | Windows producer (the `e2e-membership-add` path). | Needs a decision and a mint that does not exist. |
| **D-9** | **Windows `--node` producer — `rustynetd membership add-peer --node-pubkey-hex`.** | Different verb, different binary; not reachable by I-5's flag rename. Filed so the gap is not silently uncovered. |
| D-4 | Enrollment `admit`/`consume`. | Carries a revocation-bypass consequence deserving its own review. |
| D-5 | Chokepoint validation. | Makes every unaligned producer fail closed at once — therefore **last**. |
| D-6 | Migration of published wrong keys. | Mixed fleet degrades gracefully. |
| D-7 | Operator-facing producers P2/P3/P3b/P10, netns. | (**Shell orchestrator removed — it is migrated in S4.**) |
| D-8 | Re-fixture `build_gossip_node_derives_gossip_only_subkey_from_encrypted_secret`. | Orthogonal, cheap; this increment raises its cost of being wrong. |

---

## 3. Platform answer

The **product** macOS installer mints; the **lab** macOS path does not. So in the
environment this increment measures, macOS and Windows both lack a gossip identity, and
the D4 gap is **both**, not Windows only.

**Revision 1 claimed a lab macOS node is "inert … checked rather than assumed". Retracted.**
`Install-RustyNetMacosService.sh:269` gates the plist fragment on
`if [[ -f "${STATE_ROOT}/keys/gossip.signing.secret" ]]` — **file existence, not who
minted it**. Lab guests are long-lived UTM images; a secret surviving any prior
`rustynet install` would make that node mint under a real key while I-5 publishes its
WireGuard key, producing reject lines on every Linux peer and failing S9 red for an
unrelated reason.

**Required probe before S9 is trusted:** on every lab macOS guest,
`test -f /usr/local/var/rustynet/keys/gossip.signing.secret`.

This increment adds **no** platform filter to `gossip_peer_registrations_from_membership`
(`gossip_runtime.rs:845-870` — no platform or capability term). It routes deferred
platforms through an explicitly-spelled flag so the gap is greppable, and defers the
policy to D-3/D-9.

---

## 4. Ordered steps

**S1** — pure parser `parse_gossip_verifying_key_hex` beside `collect_wireguard_public_key`
(`linux_traffic.rs:207-220`): trim, len 64, lowercase hex, decode, `from_bytes`.

**S2** — the remote command, with the uid switch spelled out. The existing helper
(`ops_e2e.rs:6210-6218`) builds `ssh` → `sudo -S -p` → `env` → program and has **no
`-u`**. Either nest (`program = "sudo"`, `args = ["-u", "rustynetd", RUSTYNET_D, …]`)
under the existing sudo, or change `run_remote_program` explicitly. The full argv is:

```
sudo -n -u rustynetd /usr/local/bin/rustynetd key show-gossip-key \
  --gossip-signing-secret /var/lib/rustynet/keys/gossip.signing.secret \
  --passphrase-file /run/credentials/rustynetd.service/wg_key_passphrase
```

`--gossip-signing-secret` is required (`rustynetd/main.rs:628`); the path is
`install/live_linux.rs:117`. Precede it with a readiness check emitting a **literal
marker** (`systemctl is-active rustynetd || { echo RN_GOSSIP_DAEMON_INACTIVE; exit 64; }`
— not `--quiet`, which suppresses the only text), and retry to a ~40 s deadline for the
reason `collect_node_id`'s own comment gives (`linux_traffic.rs:226-231`).

**S3** — the flag contract. Beyond the callers, the edit set is: `main.rs:1499`
(variant), `:5747` (parse arm), `:9479` (dispatch), `:20586` (help),
`:25966-25977` (test argv), `ops_e2e.rs:1908-1912` (signature), and `ops_e2e.rs:1921`
`ensure_hex_32("client-pubkey-hex", …)` — a user-facing label no compiler will flag.
Also `documents/operations/CrossNetworkSimulationRunbook.md:220`. Detecting the legacy
flag is a one-liner: `OptionParser` stores the literal token as key (`main.rs:16930`),
so `values.get("--client-pubkey-hex").is_some()`. **Do not touch**
`e2e-issue-assignments` — its `ensure_hex_32` is a genuine WireGuard sink.

**S4** — migrate **all six** callers. They are **four distinct shapes**, not two:
`vm_lab/mod.rs:13847` interpolates `--capabilities {capabilities}` *unquoted*;
`:24609` hardcodes `--capabilities client`; `linux_membership.rs:84-92` single-quotes
and pre-validates via `hex_32_safe_arg`; `macos_membership.rs:76-80` uses
`MACOS_RUSTYNET_PATH` and bare `sudo`. Plus `scripts/e2e/live_linux_lab_orchestrator.sh:3584`
(**Linux — migrate to the aligned flag**; it is selectable via
`vm_lab/mod.rs:1254 legacy_bash_orchestrator`). Extract the two `vm_lab/mod.rs` strings
into testable builders — they have none, which is why no revision-1 test caught B1.

**S5** — `GossipIdentity` enum, **no `Default`**; `Published` holds a validated newtype
(the value is remote stdout interpolated into a root shell, so `hex_32_safe_arg` must
not be lost). Context gains the map, keeps `#[serde(default)]`, and bumps
`ORCHESTRATION_CONTEXT_SCHEMA_VERSION` 3 → 4. **Operational cost the implementer must
know:** `context.rs:291-297` hard-rejects a mismatched version, so this invalidates
every persisted context — the setup/run split's single-stage re-run cannot cross this
change. Loud, not silent, but it will bite mid-iteration.

**S6** — adapter trait method, **no default impl**. Implementors: five production
(`macos.rs:45`, `windows.rs:46`, `ios.rs:49`, `linux.rs:40`, `android.rs:51`) plus
`FakeAdapter` (`diagnostics.rs:748`, `#[cfg(test)]`). Ios/Android are never
constructible in a real run (`factory.rs:59-66` returns `UnsupportedPlatform`).

**S7 — the discriminator, which BL-4 showed revision 1 omitted.** `CollectPubkeys`
applies to **all** nodes (`collect_pubkeys.rs:19`) and fails the stage on any error
(`:94-97`). So: deferred-platform adapters return `GossipIdentity::DeferredPlatform`,
which `CollectPubkeys` **accepts**; a node whose role is Linux returning absence is an
`Err`. Without this distinction every mixed-OS run dies at `CollectPubkeys`.
`build_membership_peers` errors only on a missing entry for a Linux node.
**`NODES_SPEC` must keep using the WireGuard map** (`distribute_assignments.rs:60-87`)
— pointing it at the gossip map gives green tests and dead tunnels.

**S8 — `--node` wiring.** More than a triple: `pub mod <name>;` in `stage/mod.rs`, the
`define_stage_catalog!` row *with its suite and tier tokens*, the `OrchestrationStage`
impl, the `PlanBuilder` arm, and `dependencies()` / `applies_to_roles()` / `fanout()`.
**Suite choice is not clerical** — `StageSuite::Live` is dropped by
`--skip-linux-live-suite`, the fast inner loop this work will be iterated in. Registry
spec uses **`direct_platform: Some(("linux", "gossip_peer_convergence"))`**, matching
`live_lab_stage_registry.rs:1615`; `logical` is reserved for shared stages
(`:381-382`). Add the `DEFAULT_MATRIX_COLUMNS` entry; the CSV header is **not** a
separate edit (`ensure_matrix_schema` auto-upgrades it, `live_lab_run_matrix.rs:1036-1057`).

**S8b — bash dialect.** I-6 promises both dialects and revision 1 had no bash step at
all (B2's correction over-rotated). Wire the stage into the legacy path too, or state
explicitly that it is `--node`-only and change I-6.

**S9 — verdict evaluator, per criterion naming the node it is read from.**

| # | Criterion | Read from |
| --- | --- | --- |
| 1 | `gossip_identity_mismatch == "false"` — **literal equality**; three paths return `"unknown"` for a broken node (`daemon.rs:5699-5711`), so `!= "true"` passes it | both nodes |
| 2 | `gossip_peers_registered >= 1` | **exit** node |
| 3 | `gossip_accept source=<joiner short_id>` present (`gossip_runtime.rs:~659`) — this replaces revision 1's unobservable "joiner's key in the registered set" | **exit** node journal |
| 4 | zero `gossip_reject_unknown_source` since daemon start — the mismatch warn latches once per process (`daemon.rs:5568-5581`), so grep from start, never tail | **exit** node journal |

Absent or unparseable → **fail**, never skip. Bound "since daemon start" by the unit's
`ActiveEnterTimestamp`, not by wall clock.

**S10** — live proof, then the ledger row, then §7's qualifier.

**S11 — docs sync (CLAUDE.md §6).** Register this document in `documents/README.md` and
`documents/operations/active/README.md`. Currently zero occurrences of either. Revision
1 had no docs step at all.

Each step's discriminating test and its proving mutation live in the design verdict
(workflow `wf_b872303e-660`) and are reproduced in the implementation commits.

---

## 5. Fail-closed posture

**Revision 1 opened with "a node with no gossip identity gets no membership entry, so it
cannot join." That is false and contradicted §3 in the same document. Deleted.** Deferred
platforms *do* get membership entries (I-5), and those entries still enter the
registration scan on every Linux node, because `gossip_peer_registrations_from_membership`
has no platform term.

The correct statement: **for a Linux node**, if the secret is absent, the passphrase is
unreadable, custody uid/mode drifts (`rustynet-crypto/src/lib.rs:1770-1778`, no root
exemption), the daemon is not running so the credential directory does not exist, or the
export is not 64 lowercase hex decoding to a point, then the collector returns `Err`
after its retry deadline and the run stops at **`CollectPubkeys`** (not `MembershipInit`
— revision 1 named the wrong stage). No `unwrap_or`, no `.ok()`, no fallback to
`collected_pubkeys`. That is strictly stricter than today.

The only capability increase is the intended one — a correctly-identified node's signed
gossip becomes acceptable. **That increase activates a pre-existing peer-removal gap,
which must be filed in the security ledger BEFORE this lands:** sync is additive-only
and documents itself as such (`daemon.rs:5507-5511`, "Peers absent from membership are
NOT unregistered"); `register_peer` is a plain `insert` (`gossip_runtime.rs:314`);
`unregister_peer` keys on the id (`:329-330`). So a key change W→G leaves W registered
for the process lifetime, and a later revocation removes only G.

Related, pre-existing, and **D-4 not this increment**: `enrollment admit` validates only
base64 and length (`rustynet-cli/src/main.rs:8414-8423`, sink at `:8456`/`:8458`) while
`consume` rejects a non-point.

---

## 6. Remaining risk

Revision 1 called the overlay-address join "the single riskiest assumption". **Probe 2
retired it in one direction** (§8) — but the enumeration was incomplete.

The registration path has **three** gates, not two. Above the loop's two skips
(`gossip_runtime.rs:858-860` key, `:861-863` overlay address) sits
`daemon.rs:5587 if let Some(bundle) = auto_tunnel {`, and the seam documents itself: a
member without a proven overlay address "is omitted this tick, never guessed"
(`:5507-5508`), and without a bundle the seam "only applied the revocation/seed updates
above" (`:5586`).

Probe 2 inspected the **exit** node's bundle and found the joiner as `peer.0` with a
`/32`. Registration is directional: **the joiner needs its own verified bundle to
register the exit**. That half is unprobed. The node observed at `peers=0` was the
**exit** node, which is the direction probe 2 covers — so the increment is very likely
sufficient, but S9 criterion 2 should be read on the exit node precisely because the
reverse direction is not yet established.

---

## 7. What a green stage will and will not prove

Every producer this increment fixes is `vm-lab`-gated: the module compiles
(`main.rs:35-36`) but all three wiring points are gated (`:1497` variant, `:5747` parse,
`:9477` dispatch), so the verb is unreachable in a release binary. A green stage proves
the lab path converges. It proves nothing about `enrollment admit` (`main.rs:8376`,
sink `:8456`/`:8458`), which is not feature-gated and is untouched. That qualifier
belongs in the stage report and the ledger entry.

---

## 8. S0 gating probes — COMPLETE, both pass

Captured 2026-08-08 on `debian-headless-2` **during a live run**, daemon active — the
state the collector will run in.

**Probe 1 — passphrase reachability. PASS.**
```
/run/credentials/rustynetd.service                    root:root 550
/run/credentials/rustynetd.service/wg_key_passphrase  root:root 440
sudo -n -u rustynetd permitted by sudoers:            YES
export exit=0  value=bd81fa4685670b898baa216ddc210221800ce55f8d9a2354e27ecb6db3256d42
```
B3 answered: the credential **is** readable by a host-namespace `sudo -n -u rustynetd`
process, `PrivateTmp` / `ProtectSystem=strict` notwithstanding. I-1 needs no alternative
design.

**Probe 2 — overlay join. PASS (exit-node direction only, see §6).**
```
peer.0.node_id=debian-headless-4-bootstrap
peer.0.allowed_ips=100.124.191.164/32
```
Exactly what `overlay_addresses_from_bundle_peers` (`daemon.rs:15896-15908`) keys on and
accepts, so `gossip_runtime.rs:861-863` will succeed on the exit node.

**Timing note:** the daemon is `disabled`, does not start on boot, and cannot be started
by hand on a cold-booted or post-cleanup node. Probe by polling `systemctl is-active
rustynetd` **while a run is in flight**.

### 8.1 Found on the way — filed separately, and one claim retracted

On a cold-booted guest, `rustynetd.service` restart-loops until systemd gives up, and
the loudest journal line is `ops disconnect-cleanup` reporting *"inspect route table
51820 failed: Error: ipv4: FIB table does not exist"*.

**Revision 1 called that the cause. Retracted — it cannot be.** That command runs as
`ExecStopPost=-` (`scripts/systemd/rustynetd.service:91`), and the unit's own comment at
`:84-86` records that the leading `-` makes systemd ignore its exit code, so it cannot
drive `Restart=on-failure` (`:92`). It is a symptom. **The real cause is unknown**; the
unit comment at `:88-90` names a likelier candidate (the L8 boot-time killswitch check
and split kernel state). This matters because S2 converts an undiagnosed cold-boot start
failure into a hard run-stop. Filed as its own defect; not part of this increment.
