# Manager handover — 2026-09-08

You are taking over as the **manager** of this repository. You do not write most of the code; you
decompose work, dispatch GLM agents, verify what they produce, merge it, and keep the owner's
decisions in front of him. Read `CLAUDE.md` first — it is the law and it overrides anything here.

**Tree at handover:** `main` = `8c7a692d`, pushed, clean, gate green (13,262 tests).

---

## 1. First thing you must do

Give the owner the outstanding decisions in §7, each with pros and cons and your own
recommendation. He decides quickly when the options are laid out and is unable to act when they
are buried in a status report. Do not start work that depends on a §7 decision before he answers.

Second, arm a watchdog before you dispatch anything (§4). Agents fail silently far more often than
they fail loudly.

---

## 2. Provider rules — read before dispatching anything

**GLM only. DeepSeek and Kimi have NO credits — do not use them, do not "just try" them.** They
will burn a round trip and fail.

| Model string | When |
|---|---|
| `zai-coding/glm-5.3-flash` | default, everything |
| `zai-coding/glm-5.3` | heavy only: architecture, a design that decides a whole role |

Endpoints, measured 2026-09-08: `https://api.z.ai/api/coding/paas/v4/chat/completions` answers 200
and is what OpenCode uses. `https://api.z.ai/api/paas/v4/...` returns **429 insufficient balance** —
that is the pay-as-you-go API and it has no credit. `https://api.z.ai/api/anthropic` also answers
200 (that is the Claude-Code-compatible path; not needed for agent work).

Key lives in Keychain as `rustynet-glm-api-key`, read in-process by the MCP server. Never write it
anywhere.

---

## 3. How to dispatch a GLM agent

The MCP client's own `ai_edit_run` tool works, but the reliable path — and the one that survives a
client that has not reconnected — is the stdio driver:

```bash
S=<your scratchpad>
cp scripts/mcp/drive_ai_agent.py $S/drive.py
sed -i '' 's/default=600/default=1500/' $S/drive.py     # launches are slow; do NOT wrap in `timeout`
OPENCODE_DISABLE_MODELS_FETCH=1 python3 $S/drive.py \
  --bin /Users/iwan/Desktop/Rustynet/bin/rustynet-mcp-ai-agent \
  --tool ai_edit_run --args "$(cat $S/jobs/MYJOB.json)" --no-poll
```

`OPENCODE_DISABLE_MODELS_FETCH=1` is **mandatory**: OpenCode blocks at boot fetching models.dev and
the job sits in `launching` forever with a 0-message session.

Job JSON shape:
```json
{"task": "...", "mode": "full", "model": "zai-coding/glm-5.3-flash", "base_ref": "main"}
```

**The launch prints the job id but not in a shape a naive grep finds.** Recover it instead from
`ls -t state/deepseek-mcp-jobs/*.json | head -1`. Each record carries `job_id`, `state`,
`serve_pid`, `serve_port`.

**Orphaned serves block new launches.** This bit hard today: 18 leftover `opencode serve` processes
made every launch fail with a network error against `127.0.0.1:<port>/session`. When no live job
depends on one:
```bash
pkill -f 'opencode serve'
```
Check `ps -Ao command | grep -c 'opencode serve'` before and after. Stagger launches ~12–25s apart.

### Writing a brief that produces good work

Every brief this session that produced usable output had all of these. The ones that skipped them
produced work that had to be redone.

1. **Ground it.** Name the files and line numbers the agent should read. Give it the evidence you
   already have (a failing log line, a counter, a commit).
2. **Say what is already decided** so it implements rather than re-litigates.
3. **Demand fail-closed analysis** for every new field/flag/declaration: what happens when it is
   absent, malformed, stale, or written by the wrong party. A mechanism whose zero-effort path is
   permissive gets rejected — this repo cut a proposal for exactly that.
4. **Every test must fail if the fix is reverted**, and the agent must say which mutation each test
   catches. This repo has shipped tests that pass against their own assertion text.
5. **Give it permission to stop.** "If this is larger than the brief assumes, commit what is
   complete and write the remainder into the ledger. Do not half-land." Agents that lack this
   produce half-migrations.
6. **House rules block**: pinned toolchain and a dedicated `CARGO_TARGET_DIR`, gates that must exit
   0, no `unwrap`/`expect` in non-test code, touch only the named files, **never** a
   `Co-Authored-By` trailer (owner rule, has recurred).

### Review every branch before merging — this is not optional

Four blockers were caught this session by a second GLM agent reviewing the first one's work, and
**one of them was in code I wrote**. Reviews found: a fix that would have failed a Setup/T0Core
stage on every multi-node run; a one-character hex-case bypass; a capability that already existed
on another platform making the whole design unnecessary; and a `_ => false` catch-all that would
silently make a future operation quorum-sufficient.

Brief the reviewer as an **adversary**: "default to refuted when uncertain", "open the file and
quote the line, do not reason from names", "check the SIBLING callers — a defect here is usually a
divergence between two places that should agree", "disagreeing is a valid outcome; do not
manufacture findings to look thorough". For a *design* review, add: verify the problem statement
first, because a design built on a misread is worthless however good its reasoning.

Then **verify the reviewer yourself** on anything that changes a decision. Two of this session's
review claims were subtly wrong and I only caught them by reading the code (§6).

---

## 4. Watchdog

Agents go idle without telling you. Arm a `Monitor` per batch. The working pattern polls each job's
serve for `busy` and reports when a job has been quiet for 3 consecutive checks:

```bash
pending="A:edit-...-0 B:edit-...-0"; declare -A q
while [ -n "$pending" ]; do next=""
  for item in ${=pending}; do name=${item%%:*}; job=${item#*:}
    port=$(python3 -c "import json;print(json.load(open('state/deepseek-mcp-jobs/$job.json')).get('serve_port',''))")
    pid=$(python3 -c "import json;print(json.load(open('state/deepseek-mcp-jobs/$job.json')).get('serve_pid',''))")
    kill -0 "$pid" 2>/dev/null || { echo "SERVE-GONE $name"; continue; }
    st=$(curl -s -m6 "http://127.0.0.1:$port/session/status" 2>/dev/null || echo curlfail)
    [ "$st" = curlfail ] && { next="$next $item"; continue; }
    if echo "$st" | grep -q busy; then q[$name]=0; next="$next $item"
    else n=$(( ${q[$name]:-0} + 1 )); q[$name]=$n
      [ $n -ge 3 ] && echo "IDLE $name commits=$(git -C state/edit-worktrees/$job rev-list --count main..HEAD)" || next="$next $item"
    fi
  done; pending="${next# }"; [ -n "$pending" ] && sleep 60
done; echo "ALL-SETTLED"
```

Use `persistent: true`, `timeout_ms: 3600000`. Jobs have their own ~75-minute cap; a job that hits
it is checkpointed to its branch, so the work survives — resume with
`base_ref: "ai-edit/<job_id>"`.

**Never idle while a job or gate runs.** Work real ledger items in the gaps.

---

## 5. Gates, and the trap that will waste your afternoon

Definitions are in `CLAUDE.md` §7. Practical notes:

- **`syspolicyd` is why gates are slow.** macOS validates every freshly built unsigned binary on
  first exec. It had **158 minutes** of CPU today. Test binaries sit at 0% CPU with a stack of only
  `_dyld_start` — they never reach `main`. A 5-minute test stage becomes 50.
- **This produces PHANTOM FAILURES, not just slowness.** Two RNQ-09 signal tests failed at exactly
  their 30s handshake budget. Not a regression: the spawned harness was stuck in the linker. The
  same binaries passed alone on a quiet machine. **Re-running the whole suite reproduces it**,
  because it revalidates the same fresh binaries. `codesign -f -s -` does **not** clear it.
  Diagnose with `sample <pid>` before bisecting anything.
- **Stop the lab VMs before a full gate.** Measured: 128s clean vs 668s with VMs up.
- `cargo nextest` is fail-fast; one early failure leaves the rest unrun.
- **A test filter matching nothing exits 0.** Verify a new test ran by name with `--exact`, never by
  a filter's summary line.
- **Never raise a ratchet baseline to make it pass.** One tripped this session
  (raw sink-call sites 130→132); the fix was routing three commands through the validated seam,
  ending at 129.

---

## 6. Things that cost time this session — do not rediscover them

- **`git diff main..HEAD` in a worktree lies** once `main` moves: your newer commits show as the
  branch's deletions. Use `git merge-base main HEAD` and diff against that.
- **Two agents filed the same ledger number** (`QH-82` twice). On a doc conflict, keep both and
  renumber; do not drop one.
- **The path guard used to flag its own `allowlist.txt`** as a scope violation. Fixed on `main`; if
  you see `scope_violation` naming only that file on an older record, it is benign.
- **`vm-lab` is a default-off cargo feature.** Anything under it never ships, so grade its defects
  **ledger-integrity**, not product-security. H4 was relabelled for exactly this.
- **Verify a reviewer's premises.** One review said a host was DOWN — it had tested the *wrong host*
  (`ubuntu-kvm-1`, offline by owner decision, not `lenovo-bot`). Another mis-located a lab fix in
  the netns substrate when the stage runs on plain VMs of the flat `192.168.64.0/24` LAN.
- **UTM reassigns guest addresses on start order.** Refresh with
  `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips` before every run; never
  hand-edit the inventory. This churn is what broke the relay for a whole day.
- Commits are authored `Iwan-Teague` only. **No `Co-Authored-By` trailer, ever.**

---

## 7. Decisions the owner still needs to make

Present these to him with pros, cons and your recommendation. My views are below; form your own.

**D1 — Relay lab addressing (OD-1). Blocks the relay track; nothing else.**
The daemon rejects RFC 1918 for relay endpoints (`daemon.rs:16789`), so the lab relay needs an
address it will accept.
- *(a) Secondary TEST-NET-3 (203.0.113.0/24) address on the relay VM's own NIC*, with peer host
  routes on the flat lab LAN (or proxy ARP), the HP-3 provisioner binding it, a killswitch egress
  allowance for the range, and the candidate minted at that address. **No production check is
  weakened.** Needs the routing confirmed on the flat bridge.
  *(This is the corrected mechanism — an earlier write-up mis-located it in the netns substrate.)*
- *(b) A signed lab profile permitting a lab subnet.* Works anywhere, but changes a production
  validation path; only acceptable gated on the fleet signature, never an env var.
- *(c) A genuinely public address.* Honest, but adds cost and an external dependency.
- **Recommend (a)**, falling back to (b) only if (a) proves unroutable.

**D2 — QH-81 approach flip. Confirm before anyone builds it.**
The original design changes the mesh-status snapshot format. Review found the capability
**already exists on macOS** via the signed-membership snapshot; Linux and Windows simply never got
it (`macos_mesh_status.rs:162-208`; the other two have zero references).
- *Port the macOS mechanism* — less work, closes a parity gap, touches no snapshot format, asserts
  against **signed, replay-protected** state instead of an unkeyed SHA-256 digest, and avoids a
  restore-failure cliff that would put nodes into permanent restriction.
- *Original snapshot change* — matches what the live-handshake poll reads, but carries the cliff and
  a lab state migration.
- **Recommend the port.**

**D3 — Tombstones: build or accept?**
Membership identity-reuse is closed while a node is present in state, but a legitimately removed
node leaves no trace. Adding a tombstone changes `MembershipState`, therefore the canonical payload,
therefore **every signature and state root** — schema bump plus migration of deployed state.
- *Build* — closes the residual fully; expensive and touches signed state.
- *Accept and document* — cheap; the gap is already bounded because retiring a privileged node needs
  the owner.
- **Recommend deciding after §8 item 2 lands**; the review says establish precisely what the
  residual allows first.

**D4 — Cross-network proofs on `lenovo-bot`.** Ready now (repo cloned, both guests reachable, pinned
toolchain), needs no host networking changes and no password — unlike the CP-1 pf override. Owner
put it on hold. Restart when design work quietens, since it competes with gates for the machine.

**D5 — CP-1 launchd keeper.** Recommend **not** installing. It is lab scaffolding for a macOS-only
vmnet artifact; the durable answer is the second physical host (D4).

---

## 8. Build order

**1. Finish the verification layer** *(in flight: job `edit-1788895311405-2287-0`)*
Evidence-on-pass (QH-83) with its blocking correction: macro-generated stage families
(`cross_network.rs`, `chaos.rs`) need a compiler-enforced evidence declaration, or the promised
totality is discipline, not enforcement. H4's collision guard folds in. **First, because everything
below is proved by machinery we cannot currently trust** — 8 confirmed findings are defects in the
verification layer itself.

**2. H2 — the last outstanding High.** `WindowsHostWireguardRunner::run_capture`
(`rustynetd/src/daemon.rs:3753`) never reads `output.status`, so failed `wg`/`netsh` calls report
success and `remove_peer` drops a peer while the live tunnel may still serve it. One struct field
plus mirrored handling; **`netsh delete route` and `/uninstalltunnelservice` exit non-zero when the
object is already absent**, so those need explicit absent-is-success. Product code — do it
yourself, then have GLM review it.

**3. QH-78** — build-as-written, the only design that passed review clean.

**4. QH-82 completion** *(in flight: job `edit-1788895527187-2707-0`)* — three remaining sites plus
the `infer` root cause, with a CI tripwire; without the tripwire the migration is cosmetic, because
a caller can `unwrap_or` the unknown answer straight back to Linux.

**5. QH-81** — per D2.

**6. Relay** — per D1, then the lab fix (mint a Relay candidate + distribute fleet/session
material, bounded by the five minting rules in the design), then the production producer. Note the
producer gap is **release-blocking**: the relay role is unusable end-to-end today, and a green lab
stage must be annotated *lab-producer-only* so it is never read as a working feature.

**7. Tombstones** — per D3.

Designs and their reviews for every item are in `documents/operations/active/*_2026-09-08.md`;
`README.md` in that directory indexes them.

---

## 9. Standing context

- **Owner preference:** everything verified by a GLM 5.3 flash agent. He trusts that loop; honour it.
- **Never delegate to a GLM agent:** trust-state, validator verdicts, crypto, membership, killswitch,
  or `rustynetd` dataplane writes. Those are owner/manager-implemented, GLM-reviewed.
- The owner runs all `sudo` and host system changes himself.
- `ubuntu-kvm-1` is **offline by owner decision**; the Windows stream is parked with it.
- The repository is public. Run `scripts/ci/secrets_hygiene_gates.sh` before any push.
