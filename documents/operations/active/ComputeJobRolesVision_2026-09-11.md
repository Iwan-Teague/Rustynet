# Compute / Job Roles Vision — composable "worker" roles on the mesh (2026-09-11)

**Status:** owner vision, recorded verbatim so it is not lost. Not yet scoped,
not yet scheduled. It extends the two-axis role model
(`NodeRoleTaxonomy_2026-05-21.md`, `NodeRoleTaxonomyExtension_2026-06-11.md`)
and the service-hosting programme (`ServiceHostingRolesRoadmap_2026-06-11.md`,
`LlmNodeRoleDesign_2026-06-11.md`). When this is picked up, it becomes a design
doc + a delta plan in the same shape as the `nas`/`llm` roles; until then this
page is the source of the intent.

## 1) Owner statement (verbatim, 2026-09-11)

> I want to have lots of different roles in rustynet, so nodes can have multiple
> roles if those roles can be compatible with others. For example if a node is
> used for processing audio to text, a whisper model being run on a device, ready
> to convert. I want that to be a role (for example). But maybe the user also
> wants this node to be a relay server. I want a node to be able to use this
> extra processing. Maybe it's also an admin role (if that's possible?), but it
> wouldn't be able to also be an anchor. It would have to be a relay or an
> anchor, but an anchor could also do the whisper model. I would also want it so
> that if a node has these roles, these kind of more job like roles, it should be
> easy for any user on the rustynet to send an audio file to that node, over the
> rustynet and have it converted to text. They can essentially have some "home"
> rusty enviroment whenre they can use these features and use the compute on
> different machines easily. This would play in with rustyAI, where a user might
> convert a lecture audio to text, to then get an AI to sort that script and
> audio into their school modules file.

## 2) How this maps onto what already exists

The mesh already has the right shape for this. Roles are two-axis
(`crates/rustynet-control/src/role_presets.rs`):

- **Axis 1 — primary role** (`RolePreset`): `client`, `admin`, `exit`,
  `blind_exit`, `relay`, `anchor`, `nas`, `llm`, `blind_relay`. One per node.
- **Axis 2 — composable capabilities** (`Capability`), signed into the
  membership bundle: `serves_exit`, `serves_relay`, `serves_nas`, `serves_llm`,
  `serves_dns`, the `anchor.*` flags, `blind_relay`. Several per node.
  Capabilities are operational metadata; they never gate signature verification.

A "job-like" role (whisper transcription, and later any other worker) is an
**Axis 2 capability**, not a new Axis 1 primary. That is exactly how `nas` and
`llm` were added: a sibling service co-deployed on the host, bound to the mesh
tunnel address only, reached by peers under a signed default-deny
service-access policy. So the whisper example becomes something like
`serves_transcribe` (name to be decided, §5) carried by a node whose primary
role is `relay`, `anchor`, `client`, or `exit`.

The owner's compatibility statements against the current model:

| Owner statement | Current model | Note |
| --- | --- | --- |
| whisper node can also be a relay | ✅ `relay` primary + a `serves_*` capability | same shape as `llm` co-hosting |
| anchor can also do whisper | ✅ `anchor` primary + the capability | anchor already composes `serves_relay` via `anchor.relay_colocation`; the added capability is just another sibling service |
| a node is relay **or** anchor, never both | ⚠️ today `anchor` composes relay colocation | owner decision needed: either keep the existing anchor-hosts-relay composition or add an exclusion (§6) |
| maybe also admin | ⚠️ `admin` is an Axis 1 primary today | `admin` + a worker capability needs admin to become an authority flag orthogonal to the primary role, or an `admin` primary that may carry `serves_*` capabilities (§6) |
| `blind_exit` + anything | ❌ | `blind_exit` is irreversible and capability-exclusive by design; keep it that way (a blind exit runs nothing else) |

## 3) The user-facing shape: "send a file over the mesh, get text back"

The invocation model the owner wants is the same one `rustynet-llm-gateway`
already defines (identity-from-tunnel, no API key, tunnel-only bind, signed
service-access policy). A worker service generalises it:

1. **Discovery.** A client learns which nodes carry `serves_transcribe` (and the
   job kinds they accept) from the signed membership bundle it already holds. No
   central registry; capabilities ride the existing gossip/bundle path.
2. **Submission.** The client streams the input (an audio file) to the worker's
   mesh tunnel address over the WireGuard tunnel. Identity is the tunnel source
   address + the peer's signed node identity; the worker's default-deny policy
   decides whether this peer may submit this job kind.
3. **Job handle.** The worker returns a job id; the client polls or streams the
   result (text, timestamps). Results are ephemeral on the worker unless the
   client asks for them to be stored on a `nas` node the client is allowed to
   use.
4. **"Home" environment.** The client-side experience the owner describes (a
   home rusty environment where a user reaches their own compute on other
   machines) is RustyAI + the worker capabilities + `nas` for durable storage.
   RustyAI is the orchestrating client: transcribe the lecture on the whisper
   node, then sort the transcript into the user's school-module files on the NAS.
   The mesh contributes identity, reachability, policy, and transport; RustyAI
   contributes the workflow.

## 4) Constraints this must keep (non-negotiable, inherited)

- **Tunnel-only exposure.** The worker binds to the mesh tunnel address only,
  never to a LAN or public interface (same rule as `nas`/`llm`).
- **Default-deny service access.** No peer may submit a job unless a signed
  service-access policy names it. Empty/missing policy = deny.
- **Signed capability advertisement.** A node cannot claim `serves_transcribe`
  by itself; the capability is in the membership bundle, signed by the mesh
  authority, verified by every consumer. A rogue "worker" is just a peer with no
  capability, and clients refuse to submit to it.
- **Model process isolation.** The inference process (whisper or anything else)
  runs as a separate, unprivileged sibling service with no internet egress of its
  own and no access to node key material. It is untrusted third-party code from
  the daemon's point of view.
- **Input hygiene.** Size caps, format validation, per-peer rate/queue limits,
  and a content hash recorded in the audit log. A malformed file must not be
  able to crash the daemon (the worker is a sibling process; a worker crash is a
  worker failure, not a mesh failure).
- **No secrets in logs.** Job inputs and outputs are user data; never log them.
- **Fail closed.** Missing policy, unverifiable bundle, or an unavailable worker
  ⇒ refuse the job, never fall back to another node silently.

## 5) Naming and generality (recommendation)

Do not add one capability per model. Add **one worker capability class** with a
declared job-kind list, e.g. `serves_compute` with kinds `transcribe.audio`,
`embed.text`, and so on, advertised in the bundle alongside the capability.
Whisper is an implementation of the `transcribe.audio` kind, not a role. This
keeps the `Capability` enum append-only (its ordering feeds canonical
serialisation) and lets a node advertise several job kinds without a new signed
variant each time. Presets: a user-facing `worker` preset is optional sugar;
the capability can be granted onto `relay`/`anchor`/`client` directly, exactly
as `serves_dns` is operator-granted today.

## 6) Owner decisions needed before design starts

1. **Relay vs anchor exclusivity.** Today an `anchor` co-hosts a relay. Keep that,
   or enforce the owner's "relay or anchor, never both" rule (which would remove
   `anchor.relay_colocation` from the anchor composition)?
2. **Admin composability.** Should `admin` stay a primary role, or become an
   authority flag so an admin machine can also carry worker capabilities?
3. **Which node kinds may carry workers.** Proposal: `client`, `relay`, `anchor`,
   `exit` yes; `blind_exit`, `blind_relay` never.
4. **Result storage.** Ephemeral-only on the worker, or worker-to-NAS handoff as
   a first-class step?
5. **First job kind.** `transcribe.audio` (whisper) is the stated first one.

## 7) Live-lab implications (tough policy applies)

Per `NodeEngineToughPolicy_2026-09-11.md`, a worker role ships with live stages
before it is called done, including negative controls: an unauthorised peer
submitting a job is refused (independent proof: no job row, no output file, no
CPU spike on the worker); an oversized/malformed input is refused without
daemon impact; the worker binds to the tunnel address only (ruleset + `ss` dump
over SSH); a forged `serves_compute` advertisement from an unsigned peer is
ignored by clients. Add these to the attack-coverage list when the role is
scheduled.

## 8) Cross-references

- `NodeRoleTaxonomy_2026-05-21.md`, `NodeRoleTaxonomyExtension_2026-06-11.md`
  — the two-axis model this extends.
- `LlmNodeRoleDesign_2026-06-11.md` — the identity-from-tunnel service pattern
  and the RustyAI client contract to reuse.
- `NasNodeRoleDesign_2026-06-11.md` — the durable-storage half of the "home"
  environment.
- `ServiceHostingRolesRoadmap_2026-06-11.md` — the programme this joins as a
  later milestone.
- `NodeEngineToughPolicy_2026-09-11.md` — the evidence standard for its stages.
