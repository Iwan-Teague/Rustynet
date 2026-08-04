# blind_exit under seizure — what a taken appliance reveals about the mesh

**Status:** **INVESTIGATION + DESIGN, NOT APPROVED, NOT IMPLEMENTED.** A 13-agent
read-only workflow enumerated the exposure, produced three mitigation designs from
different angles, judged them, then attacked the winner from three lenses. **All
three lenses returned NEEDS_CHANGES**, several with ship-blockers. Nothing here
should be built until §5's doctrine gap is closed and §4's blockers are answered.

**Provenance.** Agent-produced with file:line citations, recovered from workflow
`wf_0e3cd4ab-096` after the run was interrupted by a laptop-lid close — all 13
agents had completed and their results were cached. **Treat every claim below as
agent-reported and re-verify before acting**; this repo has repeatedly produced
confident, well-cited claims that were wrong, including one design ranked first
that would have bricked every node.

**Threat model, fixed for the exercise.** A `blind_exit` appliance sits in a
location the operator does not control. It is seized: unlimited offline access to
storage, RAM imaging if powered, and a possibly-compelled operator. The
appliance's own compromise is assumed. The question is **what it gives up about
everyone else**.

---

## 1. The finding that comes before any design

**There is no requirement to anchor this work to.** Verified by all three design
agents independently: `documents/SecurityMinimumBar.md` contains **no
physical-compromise requirement at all** — grepping physical / seiz / forensic /
tamper returns only tamper-evident audit-logging and key-publication lines. And
`documents/Requirements.md:204-207` lists exactly three threat considerations:
compromised node, stolen pre-auth key, and replay/MITM during bootstrap. **Seizure
of a physical appliance is not among them.**

So any hardening shipped here decays silently: a future change that persists a
roster onto a blind_exit violates no written requirement. **A seizure clause naming
a normative persistent-artifact allow-list is cheaper than any of the three designs
and is a precondition for all of them.** That is the first thing to do.

## 2. The cheapest high-value step, independent of which design wins

Four edits. No crypto, no wire-format change, no boot-time network dependency, no
availability cost, and no dependence on the outcome of §3.

1. **`PeerPriorStore::in_memory()` for the blind_exit role**, selected at the
   construction site (`daemon.rs:4209-4213`). `peer_traversal_priors.v1` is the
   closest thing on the appliance to **a history of what transited** — peer node
   id, NAT candidate class, last-contact time — persisted unconditionally on every
   traversal race (`daemon.rs:6755-6760`) with **no pruning path anywhere in the
   module**. Its own doc comment bounds the cost of removal
   (`peer_traversal_prior.rs:7-15`): it "only ever REORDERS an already-valid,
   still-authenticated candidate list", is "fail-open by construction", and a
   missing store "reproduces today's cold-ICE behavior exactly". The price is one
   wasted probe ordering.

   **It must be done explicitly.** Its path derives from `traversal_watermark_path`,
   and watermarks stay persistent by design — so it will **not** follow a state-root
   relocation. Any design that moves the state root and forgets this leaves the most
   transit-history-like artifact on the seized disk *while believing it removed it*.

2. **Process-memory hardening, which does not exist at all today.** Verified: zero
   grep hits across `crates/` and `scripts/` for
   `mlockall|memlock|LimitCORE|MADV_DONTDUMP|MemorySwapMax`. So today **a single
   core dump or swap page writes the whole roster back to flash** and voids every
   design in §3.

3. **macOS enrollment-secret parity.** `Bootstrap-RustyNetMacos.sh:1302,1314` calls
   `provision_enrollment_secret` **unconditionally on both install paths**, despite
   `DAEMON_NODE_ROLE` being validated earlier in the same script. Linux already
   withholds it from non-admin nodes, and the justification is already written
   verbatim at `ops_install_systemd.rs:824-829`. A blind_exit appliance should not
   be carrying an enrollment HMAC secret at all.

4. **journald `Storage=volatile`, plus the plaintext log sites.** A peer-node-id +
   real-IP `eprintln!` sits at `daemon.rs:6829-6833`, and **41 `eprintln!` sites in
   `daemon.rs` bypass the `RUST_LOG` filter entirely** — so a log-level change would
   not have helped. journald otherwise re-leaks in plaintext, on the same disk,
   exactly what every design below hides.

**Do NOT lead with a volatile state root, a vault, or an unlock protocol.** Each is
a larger change landing a conditional benefit, and steps 1–4 shrink the payload all
of them would later be protecting.

## 3. The three designs, and why the winner is not shippable

Ranked **blind-the-data > store-less > protect-at-rest**. All three lenses returned
NEEDS_CHANGES against the winner. The ship-blockers, worth recording because each
is a trap for the next attempt:

- **Endpoint elision makes the appliance structurally unreachable.** The headline
  move — drop `peer.N.endpoint` and let WireGuard roaming relearn it from the
  authenticated handshake — requires an inbound handshake to arrive *first*. An
  appliance locked behind a constrained topology never gets one.
- **Scrub-or-refuse-to-start converts a privacy control into a permanent brick.**
  The sketch refuses to start if any of eight artifacts survives, via a helper that
  returns `Err` on any stat failure.
- **Per-(subject, epoch) handles cannot be bound to the assignment.** Peer handles
  live in the assignment bundle; peer status lives in the blinded membership
  projection; **the assignment payload has no epoch field at all**. Any skew
  resolves every peer to Unknown → default-deny → total forwarding denial.
- **The scrub list deletes `rustynetd.relay-fleet`**, which is the only allow-list
  constraining relay candidates. Presented as surplus state; it is an enforcement
  point.
- **The blinding is specified on one field but the payload names every peer twice** —
  `peer.N.node_id` is blinded, `route.N.via_node` is not.
- **The appliance already bricks on any reboot >300 s after its last assignment**
  (bundle refused as Stale past `max_age`, unit sets 300 s), and the design removes
  the recovery path while claiming no availability cost.

## 4. What cannot be fixed in software

1. **RAM capture of a powered appliance.** Irreducible, because it is what
   forwarding *is*: a WireGuard responder must hold every peer's public key in
   memory to match the encrypted static field in handshake msg1, and each learned
   endpoint to route the return path. Software narrows the margin (§2.2); closing
   it needs a tamper switch wired to power-cut and RAM zeroize, with stored energy
   to finish the wipe.
2. **The unattended-boot oracle.** A logical ceiling, not an implementation gap: a
   device that can obtain its own secrets with no human present will do so for
   whoever is holding it. Escaping it needs hardware that refuses to release the key
   when the platform is modified or relocated. **The planned board has neither, and
   deliberately** — `BlindExitPcbHardwarePlan_2026-07-22.md:167-171` specifies
   mainline U-Boot with no vendor secure boot for stated anti-traceability reasons.
   That is a defensible trade for a different goal, but **the plan should record
   that it forecloses the only defence against this oracle.**
3. **WireGuard private-key recovery, hence node impersonation.** All four
   `systemd-creds encrypt` sites silently degrade without `--with-key=tpm2`;
   `live_linux.rs:121-152` compounds it by covering the WG key **and both credential
   blobs with one `random_hex_32()`**, so one recovery is a total custody failure.
   Impersonating the node back into the mesh is arguably worse than roster
   disclosure, and no amount of minimisation or blinding touches it.
4. **Forensic residue on flash.** Every design is forward-only; under wear-levelling
   an unlink is not an erase. Only devices provisioned clean from first boot are
   clean.
5. **On-path observation at the seizure site — a design property, not a defect.**
   blind_exit installs no NAT masquerade by design (`linux_blind_exit.rs:19-22`), so
   forwarded packets keep mesh source addresses and anyone with a tap on that LAN
   sees mesh source IPs regardless of disk or RAM. Document as accepted.

**And one that is neither software nor hardware:** unlinkability is bounded by the
weakest node in the mesh, not by the appliance. Every non-blind_exit node stores the
full plaintext roster (`membership.rs:1055-1121`, hex-encoded at mode 0600, no
encryption), so **one seized laptop re-links every handle**. Any ledger entry must
say this in those words, or a future reader will read "roster not on the appliance"
as "roster not obtainable".

## 5. Grafts worth keeping whatever ships

- **Watermarks stay persistent, and that asymmetry is the sharpest insight here.**
  `membership.watermark`'s payload is exactly `version=1\nepoch=<n>\nstate_root=<hex>`
  (`membership.rs:1558-1560`) and `TraversalWatermark` is
  generated_at/nonce/payload_digest (`daemon.rs:2118-2124`) — **no watermark names a
  node.** So anti-rollback can survive a reboot that the roster does not, and moving
  watermarks to tmpfs would open a replay hole on every power cycle.
- **Keyed address derivation.** `deterministic_offset_for_node_id` is unkeyed
  SHA-256 in public source (`lib.rs:3422-3427`), so any surviving
  `peer.N.allowed_ips` set is **an offline verifiable commitment to the node_ids
  behind it, at one hash per guess**. `hmac` + `sha2` are already workspace deps,
  two call sites, zero callers outside `rustynet-control`.
- **Gate it or it decays.** A minimisation property with no CI enforcement and no
  live-lab stage is a comment. Per §12.3, read a stage's pass/fail from its own
  report artifact, never from the run-matrix column.
