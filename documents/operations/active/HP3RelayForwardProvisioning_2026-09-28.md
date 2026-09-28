# HP-3 relay forwarding: what the lab must provision — DRAFT FOR OWNER DECISION (2026-09-28)

**Status.** A proposal, not a plan of record. Nothing here is implemented. Six owner decisions are listed at the end. Until they are made, runs should leave `--enable-relay-forwarding-validation` off: the stage cannot pass, and it only burns a run.

**Sources.** Design lane b42 (GLM) and its adversarial review a73 (GLM, SOUND WITH CORRECTIONS). The manager checked the load-bearing claims against the code. This record folds in a73's corrections; where the two disagreed, it follows a73. An independent confirmation review of this record (SOUND WITH CORRECTIONS) found four more corrections, all applied; one of them (the wait budget, section 5) supersedes both b42 and a73. The review is in charter/reviews/REVIEW-hp3-relay-forward-provisioning-2026-09-28.md. Code references are to the reviewed lab stack (suite `20774f851` plus the staged patches).

## Why HP-3 has never passed

`relay_forwards_frame_validation` (HP-3) proves that a relay forwards frames between two peers whose direct path is blocked. It has never passed on any host: the node ledger holds only skip, not_proven and fail rows for it. The latest run, katana-u18, got past the health pre-flight and timed out waiting for a relay-routed session.

Four independent gaps each make a relay-routed session impossible:

| | gap | where |
|---|---|---|
| B1 | **No relay client on the peers.** The daemon builds one only when a relay session token source is configured: a preissued token spool (`RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR`) or a local token issuer. Nothing in the harness sets either, so both peers report `relay_session_configured=false`. | `crates/rustynetd/src/daemon.rs` `load_relay_client` (~5125) |
| B2 | **No relay candidate in any lab traversal bundle.** The issuer mints only Host and server-reflexive candidates; a test asserts that no bundle carries `type=relay`. Without a Relay candidate the daemon never selects a relay. | `crates/rustynet-cli/src/ops_e2e.rs` (~3934-3952, test ~8427); daemon `select_runtime_relay_candidate_with_verified_fleet` |
| B3 | **Relay candidates on private or CGNAT IPv4 are rejected**, at bundle parse (which rejects the whole bundle) and again at runtime. Every lab guest address is private. | daemon.rs `validate_traversal_candidate_ip` (~16985), `validate_runtime_relay_candidate_endpoint` (~17160) |
| B4 | **The kernel `linux-wireguard` backend exposes no authoritative transport**, and relay session setup needs one. The daemon reports `transport_socket_identity_state=blocked_backend_opaque_socket` and skips relay resolution. The userspace-shared backend provides it. | daemon.rs ~8191 and ~8235; `crates/rustynet-backend-wireguard/src/linux_command.rs` |

The stage today provisions only the relay service. It never touches the peers' relay configuration (B1), the bundles (B2) or the relay's address (B3), and runs have used the kernel backend (B4).

## Proposal

### 1. Token source: preissued spool only (B1)

The two peers get `RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR` in their daemon environment, pointing at a directory under /var/lib/rustynet owned by the daemon user (`rustynetd`), mode 0700, with token files 0600. The daemon checks modes, not ownership, and must be able to delete files to consume them. Tokens are minted outside the peers and delivered into the spool. The daemon-local issuer stays off in every lab profile. It is gated to reviewed deployments, and the lab should not normalise it.

Facts that shape this (a73, checked):
- **Token lifetime is capped at 120 s** (`MAX_RELAY_SESSION_TOKEN_TTL_SECS`, `crates/rustynet-control/src/lib.rs:1739`). Issuance refuses more, and so does the relay's verifier. The client refreshes about 15 s before expiry, and each refresh consumes a spool file (one use each). A token's 120 s runs from minting, so a spool filled once covers only about 120 s. An expired matching token is not skipped: it blocks issuance until removed. So the minter must top up each peer's spool with fresh tokens, each bound to the exact (node, peer, relay id) triple, at least every ~100 s, and purge expired ones. Over the stage about ⌈(stage budget + cleanup) / 105⌉ + 1 tokens are consumed per direction, plus headroom for failed session setups (a token is consumed before the relay hello). Never more than 128 files at once.
- The relay enforces lifetime and keeps a durable replay store, so a leaked token is good for one session within at most 120 s.

### 2. Who mints, and custody

The minting key is the lab's assignment signing secret, and issuing needs its passphrase file too. Today every lab guest's assignment-refresh environment points at the secret and the passphrase credential, and in a `--node` run the bundle refresh mints through the **exit guest's** adapter. So the claim that the key stays off the peers is not true in the lab today, and this record does not make it. The proposal is:
- mint relay tokens on the exit guest through the same adapter path that already issues assignment and traversal bundles, with the passphrase file, so custody stays exactly where issuance already lives;
- this is new code: nothing issues relay session tokens today outside `issue_relay_session_token` in `crates/rustynet-control/src/lib.rs` (~3109) and its tests. It needs a CLI token-issue command wrapping it, an adapter path for that command, and daemon environment plumbing for the spool variable;
- add a pre-flight that compares the relay's installed verifier key with the public key that signed the peers' bundles and tokens, and fails the stage on a mismatch. It must never re-issue under another key to make the check pass.

Taking the signing secret off non-issuing lab guests is a separate hardening question. It is out of scope here.

### 3. The relay's address (B3)

Proposal: give the relay a dedicated host-only network in 198.18.0.0/15 (the RFC 2544 benchmarking range), bind the relay there, and mint the relay candidate with that same address. That range is not private or CGNAT, so it passes both checks with no code change.

What this does and does not prove (a73 F3): the tree's own `is_global_unicast_ipv4` counts 198.18.0.0/15 as not globally addressable. A lab pass therefore proves candidate plumbing, relay selection, session setup and ciphertext-only forwarding. It does **not** prove that the relay is globally reachable, and the stage report must say so. The report must also pin the endpoint inside 198.18.0.0/15, so the pass cannot be misread.

Also required (a73 F4):
- **Both peers** (and the relay) must be able to reach that network, either by giving all three a NIC on it or through host routing. A NIC on the relay alone is unreachable from the peers.
- The relay's bind address and the minted candidate's endpoint must come from **one value**. Today the stage hardcodes the bind to the relay's SSH address (`crates/rustynet-cli/src/vm_lab/mod.rs` ~14700). The relay id is the relay's configured label (`relay-local`, at most 16 bytes).

Rejected: a lab-only flag that relaxes the private-address check. It would fork a trust check, and a lab pass would then prove a code path production never runs.

### 4. Backend: required, fail closed (B4)

HP-3 requires the userspace-shared backend on both peers (`--linux-backend linux-wireguard-userspace-shared`). At stage start, both peers must report `transport_socket_identity_state=authoritative_backend_shared_transport`. If either does not, the stage fails with the observed state. An elected disruptive stage never skips.

### 5. Wait budget

b42 and a73 both modelled a switch to relay after three failed direct probes. The live path does not use that counter: `relay_switch_after_failures` feeds only `on_direct_probe_timeout` (`crates/rustynetd/src/traversal.rs`), which only tests call. The daemon's ICE race (`crates/rustynetd/src/phase10.rs`, `execute_ice_pair_race`) selects the relay after one exhausted race (three rounds, 80 ms apart) once a relay endpoint is armed. So the switch should land within one reconcile after the restart, plus one 30 s reprobe interval for each failed arming. Proposal: derive the budget as restart-to-ready + N × 30 s (allowed failed armings) + session setup + capture, log the derivation in the stage report, and use 240 s as a conservative ceiling until a live run measures it. The 90 s wait is not the reason HP-3 fails today (B1-B4 are), but the derivation should replace the constant. The token spool (section 1) is sized from the same budget.

### 6. Dependencies and crypto (ADR-027)

No new dependency, no third-party or cloud service, no C crypto. Token issuance and verification use the existing in-tree ed25519 path (ed25519-dalek, pure Rust). The trust root is unchanged: the lab's assignment key signs the bundles and the tokens, and the peers and the relay verify with its public half.

## Staged patches, each with its own live evidence

1. **Key-pairing pre-flight.** The stage still times out as now, but its report carries the pairing check.
2. **Backend gate plus pinning the backend on the two peers.** On kernel-backed peers the stage fails fast at the gate; on userspace-shared peers it reaches the wait and no longer reports a blocked socket.
3. **Token issuance and spool** (sections 1 and 2: the new token-issue command, the adapter path, spool top-up). Both peers report `relay_session_configured=true`, and spool files are consumed as sessions refresh. The stage still times out, because there is no candidate yet.
4. **Relay candidate plus the 198.18 address, in one patch** (sections 2 and 3). Bundle shape and address can only be evidenced together. This is the patch that can pass: the relay-routed session forms, the relay's forwarded-frame counters rise, and the capture shows only ciphertext.
5. **Derived wait budget** (section 5).

Each patch gets an independent review before it lands. The lab host network change in patch 4 is host configuration on katana (and lenovo-bot if wanted), which the owner approves.

## Owner decisions

1. **Token source:** preissued spool only, with the daemon-local issuer never enabled in the lab. Recommended: yes.
2. **Relay address:** a 198.18.0.0/15 host-only network, with the stage report stating that global reachability is not proven, and no lab relaxation of the private-address check. Recommended: yes. The alternative is to leave HP-3 unproven in the lab.
3. **Backend:** HP-3 hard-requires `linux-wireguard-userspace-shared` on its two peers and fails closed otherwise. Recommended: yes, at this stage only for now.
4. **Lifetime and budget:** token lifetime stays at the product maximum of 120 s with a multi-token spool, and the wait budget is derived as in section 5 (240 s ceiling). Recommended: yes. Raising the product cap for the lab is not recommended.
5. **Custody:** mint on the exit guest through the existing adapter, with the passphrase file. Recommended: yes. Removing the signing secret from non-issuing lab guests is a separate question.
6. **Host network change:** approve adding the 198.18.0.0/15 host-only network on katana (and optionally lenovo-bot), attached to the relay and both peers.
