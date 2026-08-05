# Gossip provisioning — Phase 1: make it run on a Linux lab node

**Status:** **PARTIALLY IMPLEMENTED** — `37be86af` plus follow-up fixes. Revision 2
of the plan; revision 1 was refuted with four ship-blockers and its central
architectural claim inverted, and the implementation was then refuted again with
two more. Read §10 before continuing: two blockers remain open, and the
implementation **deviated from this plan's own §5 item 4** without recording it at
the time.

**Deviation, stated plainly.** §5 item 4 said "land mint + publish + read-back with
enforcement OFF first, and prove it on two guests via a per-node systemd drop-in,
**not the shipped unit**." The implementation went straight to the production
installer and the `install-systemd` env writer. The consequence was exactly what
lab-first would have caught: the mint was placed in `rustynet install`, which lab
guests do not use — they bootstrap through `ops e2e-bootstrap-host` — so gossip
would have stayed dormant on every machine the project can actually prove it on.
Fixed by minting in the e2e bootstrap path too, but the plan was right and
ignoring it cost a round.

**Scope:** provision the gossip signing secret so `build_gossip_node` returns
`Some` on a Linux lab node, and prove gossip does something real.

**The scope split from revision 1 does not survive** — see §7. What was deferred
to "Phase 2 enforcement" turns out to be a functional prerequisite for the
acceptance criteria, not a policy choice.

---

## 0. Two wrong templates, and why the mistake repeated

This plan has now named the wrong precedent **twice**, by the same method both
times: grepping a name and attributing another consumer's mechanics to it.

1. **Enrollment secret** (rejected in revision 1) — 32 raw bytes read directly,
   not the custody layer.
2. **`RUSTYNET_ASSIGNMENT_SIGNING_SECRET`** (revision 1's answer, now refuted) —
   that env var is read by **two unrelated consumers**:
   - the CLI `ops refresh-assignment` → `load_assignment_signing_secret`
     (`rustynet-cli/src/secret_material.rs:97`) → `load_encrypted_secret_material`
     (`:70-95`), which **opens the configured path directly** — no
     `decrypt_private_key`, no key-id derivation, no OS store, no
     `resolve_passphrase_source`;
   - the daemon's `relay_session_signing_secret_path` (`daemon.rs:1834`), which
     **does** use `decrypt_private_key` (`daemon.rs:4007`).

   Revision 1 cited the CLI sites (`ops_e2e.rs:7050`, `main.rs:9787`) and
   attributed the daemon's mechanics to them. The doc comment it trusted
   ("mirrors the relay-session signing secret path exactly", `daemon.rs:4022`) is
   *accurate* — it just refers to the other consumer.

   The two are **mutually exclusive**, not merely different:
   `encrypted_secret_permission_policy` requires `/etc/rustynet` at `0750`
   (`secret_material.rs:24-38`), while `decrypt_private_key` uses the default
   custody policy of `0700`/`0600` compared with `!=`, not a mask
   (`key_material.rs:590-595`; `rustynet-crypto/src/lib.rs:1725-1732`, `:1770-1773`).
   **A secret minted the assignment way is structurally unloadable by the gossip
   loader.**

3. **The relay-session path has never run.**
   `RUSTYNET_RELAY_SESSION_LOCAL_TOKEN_ISSUER` (`daemon.rs:227`) appears in no
   unit, script, env writer or lab code; without it both `validate_daemon_config`
   and `build_relay_client` hard-error, so `decrypt_private_key` at `daemon.rs:4007`
   is **unreachable in every current deployment**. And the *production* installer
   never emits the assignment signing pair either (`ops_install_systemd.rs:1721-1790`),
   so `ops refresh-assignment` fails on a production install — only lab writers
   emit it.

**The correct template is the WireGuard encrypted private key** — the one secret
actually read through `decrypt_private_key` by the non-root daemon today:
`/var/lib/rustynet/keys/wireguard.key.enc` (`scripts/systemd/rustynetd.service:50`),
decrypted at startup by `prepare_runtime_wireguard_key_material`
(`daemon.rs:11173-11194`).

## 1. What the daemon requires  `[verified]`

`build_gossip_node` (`daemon.rs:4036-4066`): neither path set → `Ok(None)`;
exactly one → hard `InvalidConfig`; both → `decrypt_private_key` →
`derive_gossip_signing_key` → `GossipNode::new`.

**Fleet-brick mechanism, deliberate:** the call site is
`gossip_node: build_gossip_node(config)?` (`daemon.rs:4313`) and a
`DaemonRuntime::new` failure is terminal (`daemon.rs:10324-10330`). A
configured-but-unloadable secret means **the daemon refuses to start**. The doc
comment states this as intended. Phase 1 must not weaken it.

## 2. Location — `/var/lib/rustynet/keys`, never `/etc/rustynet`

Revision 1 would have put the secret in `/etc/rustynet`. That bricks a node twice:

- `write_encrypted_key_file` **unconditionally chmods the parent directory** to the
  policy mode (`rustynet-crypto/src/lib.rs:1544-1548`), i.e. `0700`. `/etc/rustynet`
  is `root:rustynetd 0750` by design (`ops_install_systemd.rs:112-117`) and holds
  the daemon-readable `*.pub` files. Dropping group-execute stops the non-root
  daemon traversing it.
- `decrypt_private_key` requires `directory_uid == Uid::effective()` **and**
  `file_uid == effective` (`rustynet-crypto/src/lib.rs:1749-1780`). `/etc/rustynet`
  is root-owned; the daemon runs `User=rustynetd`
  (`scripts/systemd/rustynetd.service:116`). → `PermissionDenied` → §1 → won't start.

`/var/lib/rustynet/keys` is already chowned to the daemon uid by
`ops install-systemd` (`:504-514`, `:674-685`), and its sweeper
`set_owner_mode_on_key_custody_artifacts` (`:2185-2254`) already matches
`wg-private-*.enc` (`:2250-2254`) — **exactly the shape `key_custody_key_id`
emits** (`key_material.rs:779-788`). A gossip secret placed there inherits the
ownership repair for free.

## 3. Traps that make the obvious implementation wrong

### 3.1 The configured path is a naming input, not a file to read  `[verified]`
`decrypt_private_key` derives the custody dir from the **parent** and a key id
`wg-private-<8 bytes of SHA-256(path string)>` (`key_material.rs:521-542`,
`:779-788`), then loads from the OS store or `<parent>/<key_id>.enc`.

Nuance revision 1 got wrong: `encrypt_private_key_with_passphrase` **also
materialises the configured path deliberately** — "Keep the configured
encrypted-key path materialized on disk for service prechecks and deterministic
bootstrap" (`key_material.rs:567-579`). So an existence check there is a valid
*necessary* condition after a correct mint; it is only misleading if something
else wrote it. Keep the check, and pair it with one on the key-id artifact.

### 3.2 The passphrase resolver, and how separation is actually achieved
`read_passphrase_file` → `resolve_passphrase_source` reads a **process-global**
source (`RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH`, else `CREDENTIALS_DIRECTORY`)
and explicitly refuses direct fallback (`key_material.rs:709-772`). The unit pins
branch 1 (`rustynetd.service:52`).

**Revision 1's conclusion was half right and its remedy was wrong.** Gossip and
WireGuard do share a passphrase *as things stand* — but separation does **not**
require changing the resolver. `read_passphrase_file_explicit`
(`key_material.rs:95-104`) already bypasses it and is already used by
`rustynetd key init` (`rustynetd/src/main.rs:2640`) and the assignment reader.
Per-secret separation is a change to **`build_gossip_node`'s reader**
(`daemon.rs:4056`) — a much smaller change than revision 1's §7 implied.

### 3.3 Minting requires an explicit passphrase and the right uid order
A root mint has neither `CREDENTIALS_DIRECTORY` nor the credential-path env, so
`encrypt_private_key_with_passphrase(…, None)` hard-errors
(`key_material.rs:768-770`). It **must** pass `Some(<plaintext passphrase file>)`
(`:556-561`), exactly as `rustynetd key init` does.

Ownership is validated at **write** time against `Uid::effective()`
(`rustynet-crypto/src/lib.rs:1555`), so the WG precedent's two-step ordering is
mandatory: root mints into a then-root-owned dir
(`rustynet-cli/src/install/live_linux.rs:117`, `:130-145`), then
`ops install-systemd` chowns dir + artifacts. And the plaintext must be
byte-identical to what is sealed in
`/etc/rustynet/credentials/wg_key_passphrase.cred`, which the daemon reads
(`rustynetd.service:52`, `:65-66`).

### 3.4 An empty env value is a fleet brick, not a silent disable  `[corrected]`
Revision 1 said empty → `None` → silently off. **True for the CLI flag**
(`rustynetd/src/main.rs:2978-2995`), **false for env vars**, which is the mechanism
here: `std::env::var_os(…).map(PathBuf::from)` (`daemon.rs:1750-1756`) yields
`Some(PathBuf::from(""))`, and `validate_daemon_config` hard-errors "must not be
empty" (`daemon.rs:11505-11519`) *before* `DaemonRuntime::new`. Emitting
`RUSTYNET_GOSSIP_SIGNING_SECRET=` takes the node down.

### 3.5 The env file is rewritten WHOLESALE — and the risk is the inverse  `[settled]`
`/etc/default/rustynetd` is built from a fixed `env_entries` vec
(`ops_install_systemd.rs:874`, rendered `:1076-1084`) and published whole (`:1085`),
reading the prior file only as a per-key fallback (`:94`). **Unknown keys are
dropped.**

So revision 1's worry — that a conditional emit might delete other settings —
cannot happen. The real consequence is the opposite: **a gossip pair written there
outside `env_entries` is destroyed by the next `ops install-systemd`**, which runs
on every bootstrap/enforce (`ops_e2e.rs:671`, `:785`) and every
`ops write-daemon-env` (`ops_write_daemon_env.rs:185`). Gossip silently reverts to
`unconfigured` with no error — the worst outcome for an evidence run.

A `/etc/systemd/system/rustynetd.service.d/` drop-in does survive (nothing in the
repo writes there), but that is a **new mechanism**, not established practice, and
must be stated as such.

## 4. Fleet safety rules  `[unchanged, verified]`
No unconditional `Environment=` default and no `ExecStartPre` file test in the
shipped unit; emit the two env vars **only as a pair**, only when the secret was
actually provisioned, and **never empty** (§3.4). The env var names carry **no
`_PATH` suffix** despite the constants being named `..._PATH_ENV`
(`daemon.rs:272`, `:275-276`).

## 5. Preconditions the acceptance depends on  `[new]`
Ordering is mandatory and revision 1 omitted it entirely:

secret provisioned → daemon starts → **verified membership committed**
(`sync_gossip_data_plane` returns early without it, `daemon.rs:5514-5519`) →
transport binds (`:5529-5547`) → **verified assignment bundle carrying both guests'
overlay addresses** (peer registration needs it, `:5584-5601`) → peers registered →
mint/accept. Minting additionally needs the epoch (`gossip_runtime.rs:425-427`).

A node missing any of these sits at `attached_pending_transport` with `minted=0`
and looks like a provisioning bug. Also note a bind collision is a **retryable**
`gossip_transport_error`, not a startup failure (`daemon.rs:5539-5546`).

## 6. Acceptance — and why revision 1's version was unreachable

**`gossip_state=active` is not sufficient** — it means the transport bound. A lone
node cannot accept its own re-push (self-origin is rejected first,
`gossip_runtime.rs:573-576`), and `minted_count` increments on the timer with zero
peers (`:453`, before the broadcast loop at `:458`), so mint alone proves little.
`GOSSIP_REMINT_INTERVAL_SECS = 30` (`:72`).

But **`gossip_accepted_total > 0` cannot be reached within revision 1's scope** —
see §7. Phase 1 therefore proves **mint-and-bind only**:

- `gossip_state=active`, `gossip_transport_error=none`
- `gossip_minted_total` increasing across two samples ≥35 s apart
- `gossip_peers_registered` > 0 *if* §7 is resolved; otherwise expect `0`
- `gossip_identity_mismatch` — **record its value; it is the measurement §7 needs**

Per §12.3, read these from the stage's own report artifact, never a run-matrix
column. Note also that accepting a bundle proves it was validly signed by a
*registered peer*, not that it came directly from that peer — epidemic re-push
(`gossip_runtime.rs:520-548`) means it may have arrived via a third node.

## 7. The scope split is refuted — identity alignment is a prerequisite

Revision 1 deferred "membership `node_pubkey_hex` must equal the gossip verifying
key" to Phase 2 as an enforcement policy. It is not policy; it is **how peer
registration works**. `node_pubkey_hex` is used as **both the peer id and the
Ed25519 verifying key** (`gossip_runtime.rs:852-868`).

Every provisioning path in the repo puts a **non-gossip** value there:

| Path | What lands in `node_pubkey_hex` |
| --- | --- |
| e2e / orchestrator | the **WireGuard** public key (`ops_e2e.rs:1926-1927`, `:3440`; `vm_lab/mod.rs:13716-13730`, `:13851`) |
| membership genesis | raw CSPRNG bytes, not a public key at all (`rustynetd/src/main.rs:4002-4012`) |
| netns harness | `rand_hex_32` (`scripts/vm_lab/netns_daemon_path.sh:219`) |

So either the X25519 bytes fail `VerifyingKey::from_bytes` and the peer is
**skipped** (`gossip_runtime.rs:858-860`) → `gossip_peers_registered=0`; or they
decompress and every inbound bundle fails signature verification (`:594-609`) →
`gossip_reject_reasons` non-`none`, `accepted_count` never advances. The daemon
already anticipates exactly this (`daemon.rs:5576-5581`).

**Decision required.** Either (a) accept that Phase 1 proves mint-and-bind only,
and use `gossip_identity_mismatch` to measure the fleet before choosing a
migration; or (b) bring `node_pubkey_hex` into line with the gossip verifying key
as part of Phase 1, which is a genesis + enrollment + orchestrator change and much
larger.

Option (a) is recommended: it is honest about what it proves, and it produces the
measurement option (b) would otherwise be designed blind.

## 8. Recorded, not fixed: turning gossip on opens a live surface
The gossip socket is wildcard-bound (`daemon.rs:4315-4317`) and neither the daemon
nft table nor the boot table declares an `input` chain, so **inbound UDP 51821 is
unfiltered on the underlay** — documented at `daemon.rs:5628-5637`. Provisioning is
the moment that surface goes live. Ed25519 still gates acceptance, so this is not a
trust bypass, but a provisioning plan must say it.

## 9. Cross-OS: the pair must never reach a shared env writer
Windows rejects a configured gossip pair outright (`daemon.rs:11539-11547`); macOS
`read_passphrase_file` hard-errors without `PASSPHRASE_KEYCHAIN_ACCOUNT_ENV`
(`key_material.rs:80-83`, `:722-732`). Both are daemon-won't-start.


## 10. Post-implementation review — what shipped, what did not

Implemented in `37be86af` and follow-ups:

- `rustynetd key init-gossip` — mints 32 CSPRNG bytes through
  `encrypt_private_key_with_passphrase`, scrubs on every path including the
  entropy-failure branch.
- Minted in **both** installers: `install/live_linux.rs` (product) and
  `ops_e2e.rs` (lab bootstrap). The second was missing initially and is what makes
  the change provable at all.
- `ops install-systemd` emits the env pair conditionally, using the **daemon's own
  constants** (`GOSSIP_SIGNING_SECRET_PATH_ENV`, `..._PASSPHRASE_PATH_ENV`, now
  `pub`) rather than restated literals, so the `_PATH`-suffix drift class is
  removed by construction rather than tested for.

### 10.1 Corrected during review

- **The HKDF input is 33 bytes, not 32.** `decrypt_private_key` appends a trailing
  newline if absent, so the daemon derives from `<32 minted bytes> || b"\n"`.
  Harmless for the daemon (deterministic, so identity is stable across restarts)
  but a **silent identity fork** for any independent deriver — which is precisely
  what §7's follow-on work introduces. Documented at the constant.
- **A tautological test.** `gossip_env_var_names_have_no_path_suffix` asserted a
  property of two string literals declared inside the test, so the exact mistake it
  named — emitting the `_PATH`-suffixed identifier name — would still have passed.
  Replaced, and the underlying class removed by using the daemon constants.
- **An untested load-bearing invariant.** The ownership sweep only covers the
  gossip blob while it shares the WireGuard key's directory; nothing pinned that.
  Now tested.

### 10.2 STILL OPEN — do not treat Phase 1 as finished

1. **No provisioning path for an existing node.** The mint lives inside
   `setup_key_custody`, which only succeeds on a virgin node: once
   `ops install-systemd` has chowned `/var/lib/rustynet/keys` to the daemon uid, a
   root re-run of `rustynet install` fails `directory_uid == Uid::effective()` at
   `key init` — before reaching `key init-gossip`. There is no migration verb and no
   documented manual procedure. Every already-installed node stays dormant.
2. **The gossip path is hardcoded; the WireGuard path it piggybacks on is not.**
   Every ownership repair is keyed off `RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY`, which is
   operator-overridable. Override it and the gossip blob stays root-owned while the
   env pair is **still** emitted (the existence check uses the hardcoded path) —
   which is a daemon that refuses to start.
3. **`rustynetd-anchor.service` shares the env file but has no credential source.**
   It loads `/etc/default/rustynetd` and runs `rustynetd daemon`, but declares no
   `LoadCredentialEncrypted`, so the passphrase resolver hard-errors. Nothing
   installs that unit today and it likely already fails on the WireGuard key for the
   same reason — but this change makes it strictly worse.
4. **Silent-dormant is relocated, not prevented.** Deleting the marker file makes the
   next `ops install-systemd` drop the pair with no warning or log line.
5. **`--force` is unconditional in both callers**, so a re-run silently rotates the
   gossip identity. Symmetric with `key init`, but the consequences are not: a
   rotated WireGuard identity fails loudly, a rotated gossip identity fails silently
   because nothing publishes the gossip verifying key anywhere.
6. **`key init-gossip` has no tests** — not the arg parser, the `--force` guard, the
   secret length, or the absolute-path checks. And nothing pins that the mint and the
   daemon derive the same key id, which the commit itself calls load-bearing.
