# Gossip provisioning — Phase 1: make it run on a Linux lab node

**Status:** PLAN, not implemented, pending adversarial review.
**Scope:** provision the gossip signing secret so `build_gossip_node` returns
`Some` on a Linux lab node, and prove gossip actually exchanges bundles. Nothing
else.

**Explicitly out of scope** (deferred to Phase 2, deliberately):
enforcement that membership's `node_pubkey_hex` equals the gossip verifying key;
node-id admission validation; a recovery verb; macOS and Windows provisioning.

**Grounded personally, not agent-reported.** Every claim below was read from the
code during this session. Two workflow attempts at this plan died (a laptop-lid
close stalled the agents), so this was produced by direct verification instead.

---

## 1. What the daemon actually requires

`build_gossip_node` (`crates/rustynetd/src/daemon.rs`, grep the fn):

| Config state | Result |
| --- | --- |
| neither path set | `Ok(None)` — gossip dormant, today's default |
| exactly one set | **hard `InvalidConfig` error** |
| both set | `decrypt_private_key` → `derive_gossip_signing_key` → `GossipNode::new` |

**The error path is a fleet-brick mechanism, and it is deliberate.** The call site
is `gossip_node: build_gossip_node(config)?` — the `?` propagates out of
`DaemonRuntime::new`, so a configured-but-unloadable secret means **the daemon
refuses to start**, not that gossip is off. The doc comment states this as
intended: "the daemon refuses to run rather than silently running without gossip
and masking the fault."

That is correct fail-closed behaviour and Phase 1 must not weaken it. It is also
exactly why the earlier design's unconditional `Environment=` default in the
shipped unit would have taken down every existing node.

## 2. The right template is the assignment signing secret, not enrollment

An earlier note proposed copying the **enrollment** secret's provisioning. That is
the wrong sibling: the enrollment secret is 32 raw bytes read directly, while the
gossip secret goes through the **key-custody layer**. `build_gossip_node`'s own doc
says so — "Key custody mirrors the **relay-session signing secret path exactly**".

The working precedent is therefore `RUSTYNET_ASSIGNMENT_SIGNING_SECRET`, which is
already provisioned live:

- secret path `/etc/rustynet/assignment.signing.secret`
  (`ops_e2e.rs:7050`, `main.rs:9787`)
- passphrase via a **systemd credential** —
  `/run/credentials/<service>.service/signing_key_passphrase` (`ops_e2e.rs:7058`)

That is the shape to copy.

## 3. Two traps that make the obvious implementation wrong

### 3.1 The configured secret path is a decoy — it is never opened

`decrypt_private_key(secret_path, passphrase_path)` uses `secret_path` only to
derive:
- the custody **directory** = its parent, and
- a **key id** = `wg-private-` + first 8 bytes of `SHA-256(path string)`, hex
  (`key_custody_key_id`, `key_material.rs`).

The bytes then come from the OS store (`secret-tool` on Linux) or from
`<parent>/wg-private-<16hex>.enc`. So:

- provisioning must write through `encrypt_private_key_with_passphrase` with the
  **same** `secret_path`, or the derived key id will not match;
- **any "is it provisioned?" check against the configured path tests a decoy** and
  can read true while the artifact the daemon needs is absent. Given §1, that
  yields a node that will not start.

### 3.2 The passphrase argument is ignored on Linux

`read_passphrase_file` → `resolve_passphrase_source` consults, in order:
1. `RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH`
2. `CREDENTIALS_DIRECTORY` + the default credential name
3. otherwise **hard error** — falling back to the configured path is explicitly
   *disallowed* ("direct fallback to `<path>` is disallowed").

The `passphrase_path` we pass therefore never opens a file; it only appears in an
error message.

**Consequence, and it settles a pending operator decision:** the passphrase source
is **process-global**, so the gossip secret and the WireGuard private key are
necessarily decrypted with the **same passphrase**. Passphrase separation is *not
achievable in Phase 1* without changing `resolve_passphrase_source` itself. The
mitigating property is real but partial: `derive_gossip_signing_key` is a one-way
HKDF (`rustynet-control/src/lib.rs:3565-3579`) that zeroizes its input, so a later
daemon compromise cannot recover the identity secret *from the gossip path* — but
one passphrase recovery still unwraps both stored blobs.

## 4. Fleet safety — the non-negotiable constraint

Every node in the field today has **no** gossip key. Therefore:

- **No unconditional `Environment=RUSTYNET_GOSSIP_SIGNING_SECRET=…` in the shipped
  unit**, and **no `ExecStartPre` file test**. Either would fail startup fleet-wide
  via §1.
- Emit the two env vars **only as a pair, and only when the secret was actually
  provisioned**. One without the other is a hard error by §1.
- Note the env var names carry **no `_PATH` suffix** despite the Rust constants
  being named `..._PATH_ENV`. Setting the identifier-shaped name silently does
  nothing.
- An **empty** flag value sets the field to `None` — silently disabling gossip
  rather than erroring. Never emit an empty value.

## 5. Steps

1. **Mint helper**, modelled on the assignment-secret path: generate the secret,
   store it via `encrypt_private_key_with_passphrase` keyed on the chosen
   `secret_path`, set the custody directory to exactly `0700` and the blob to
   exactly `0600` owned by the daemon uid (the checks are **equality, not masks**).
2. **Wire the passphrase** as a systemd credential, matching the assignment
   service's `LoadCredential` shape, so `CREDENTIALS_DIRECTORY` resolves.
3. **Conditional pair-emit** of the two env vars into the daemon's environment,
   never into the shipped unit as a default. *Establish first whether the installer
   rewrites the env file wholesale or merges* — if wholesale, a conditional emit
   that omits the pair on an existing node could delete other settings.
4. **Lab-first**: apply via a per-node systemd drop-in on the lab guests before
   touching the shipped installer at all.

## 6. Acceptance — what actually proves gossip runs

`gossip_state=active` is **not sufficient**: it means the transport *bound*, not
that any bundle was exchanged. A single node with no peers would also mint and
never accept.

The proof needs **two lab guests in one mesh**, and on each:

- `gossip_state=active`
- `gossip_minted_total` **increasing** across two samples ≥35 s apart
  (`GOSSIP_REMINT_INTERVAL_SECS` is 30)
- `gossip_accepted_total` **> 0** — this is the one that proves an actual peer
  exchange rather than a lone node talking to itself
- `gossip_transport_error=none` and `gossip_reject_reasons=none`

Per CLAUDE.md §12.3, read these from the stage's own report artifact, never from a
run-matrix column.

## 7. Open question for the operator

**Passphrase separation** (§3.2). Phase 1 necessarily shares the WireGuard
passphrase. Accept for now with the residual recorded, or fund a change to
`resolve_passphrase_source` to support a per-secret credential first? Phase 1 is
implementable either way; only the residual changes.
