# Adversarial Review — CrossPlatformRoleParityRefresh_2026-07-23.md

**Status: UNTRUSTED** — this is a docs-only adversarial review of
`documents/operations/active/CrossPlatformRoleParityRefresh_2026-07-23.md` (462 lines),
performed against the actual tree at commit `2b3422d3` (2026-09-05, "Merge
ai-edit/edit-1788563825461-26537-27: Windows collect_pubkeys code-trace"), branch
`ai-edit/edit-1788570682318-26537-30`, on 2026-09-05. Every SHA was checked with
`git cat-file`/`git show`, every file:line citation was re-read in the current tree,
and both ledger CSVs were re-parsed with a quote-aware reader (the columns carry
quoted comma-bearing fields; an `awk -F,` split reads the wrong column). No code was
changed. This review does not itself refresh the target document; §6 lists the exact
updates its owner should apply.

Scope note: one day before this review, the Windows bootstrap picture moved for the
first time — commit `1785a5877292` records the FIRST `--node`-engine
`bootstrap_hosts` PASS on a Windows guest, and commit `70e16a63` (2026-09-05, "fix
(windows): serve collect_pubkeys from daemon status, not a file read") landed the fix
for the stage that then blocked. A live-lab run attempting to carry a Windows client
past bootstrap is in flight at review time and is **not concluded**; nothing in this
review or in the recommended doc updates may claim it proven (§1.2, §6).

---

## 1. HIGH findings

### 1.1 — §0 ledger re-count is superseded (every number in the "as re-counted 2026-08-28" block has moved)

The doc's §0 and §9 anchor its whole reframe on "178 rows" (lines 41–45, 460):
178 ledger rows, 141 fail / 37 partial, zero overall pass; cross-OS
`live_mixed_topology_validation` "0-for-178" with "632 per-stage rows, every one
`skip`"; Windows bootstrap "n=5 fail … 173 `not_run`".

Re-parsed at `2b3422d3` (quote-aware): the `--node` run matrix now has **282 rows**
— **213 fail / 69 partial / 0 pass** (zero-overall-pass still holds, so the
headline reframe survives, but every count is stale). Windows
`windows_stage_bootstrap` is now **10 fail / 272 not_run** (doc: 5/173) — the five
new failures are the 2026-09-04 session (§1.2). `live_mixed_topology_validation` is
now **0-for-282**, still never green. The instruction embedded in the doc itself —
"The ledger is append-only — re-derive, do not cite" (line 42) — is correct and is
exactly why this is LOW-harm: but a reader who takes the printed 178/141/37/5/173
figures as current will under-count Windows bootstrap attempts by 2× and total
attempts by 58%. Severity HIGH only because these are the doc's headline numbers.

### 1.2 — §2 CP-4, the §3 Track W plan, and the §4 blocker table are superseded by the 2026-09-04/05 Windows bootstrap session

The doc states (lines 207–241, 282–287, 309) that Windows `--node` bootstrap "has
never succeeded", gates all Windows on CP-4, triaged 2026-08-28 as
`Bootstrap-RustyNetWindows.ps1:1130` (`winget configure`) code-primary plus a dead
`windows-utm-1` guest, and plans W-FIX-1 (make the WinGet precondition
explicit/self-healing) then W-FIX-4 (restore `windows-utm-1` SSH) on the
`debian-headless-2:exit + windows-utm-1:client` topology.

The tree and ledger show that path is no longer the operative one:

- The 2026-09-04 Windows session ran on **`windows-x86-1` @ `192.168.121.108`, a
  libvirt guest on `ubuntu-kvm-1` — not `windows-utm-1`**. Five runs recorded that
  day (`ba60c4eb5e` 19:53Z, `e75216093d` 20:51Z, `4412a109a9` 21:43Z,
  `1785a58772` 22:11Z, `9eca8a02d7` 22:28Z), each with `windows_present=pass` and
  `windows_stage_cross_network=pass` — the **first Windows stage-level passes ever
  recorded on the `--node` engine** (lifetime: `windows_present` 10 pass;
  `windows_stage_cross_network` 5 pass / 2 skip; `windows_stage_cleanup` 5 pass /
  5 fail).
- Run `run-2026-09-04-windows-5` (commit `1785a5877292`, "Windows bootstrap_hosts
  PASS milestone") achieved the **first `--node` `bootstrap_hosts` PASS on a
  Windows guest**: the apparmor build fix and the Windows key-custody fix are
  **live-proven** (build, key init/install, daemon healthy). That run then failed
  at `collect_pubkeys` on a `wireguard.pub` async-write race — fixed in
  `e1bdaeb8` ("require non-empty wireguard.pub in bootstrap readiness probe")
  with cleanup-race remedies in `9eca8a02d7d6`.
- Today, `70e16a63` (2026-09-05) replaced the racy file read with a daemon-status
  read for `collect_pubkeys`.

**Provenance discipline:** `bootstrap_hosts` passing is live-proven (matrix row at
`1785a58772`); the `collect_pubkeys` fixes are **merged but NOT live-proven** — the
matrix contains **no row at or after `70e16a63`**, the last Windows row is
`9eca8a02d7` (2026-09-04T22:28Z, `windows_stage_bootstrap=fail`), and the in-flight
run has not concluded. Neither this review nor any doc update may upgrade the
Windows client cell. The verdicts "Windows client ⬛ / bootstrap never green" in
the §1 matrix remain **correct as of HEAD**; what is stale is the *mechanism
narrative* (winget/`windows-utm-1`/W-FIX-1 as the critical path) and the absence of
any mention of the milestone. The doc needs a "fix merged, not yet live-proven"
caveat, not a verdict change (wording in §6).

### 1.3 — Dead citation: `userspace_shared_macos/tun.rs:1057` and the `route -n add -inet` claim (line 159)

The doc's CP-1 verdict cites "`userspace_shared_macos/tun.rs:1057` — mesh route
reconciliation programs `route -n add -inet`" and attributes the route work to
`third_party/rustynet-tun`. In the current tree, `third_party/rustynet-tun/src/lib.rs`
is **547 lines** (no line 1057), and the string `route -n add -inet` appears
**nowhere** under `crates/` or `third_party/` (word-tolerant substring search,
case-insensitive). Whatever the original citation pointed at has moved or the quote
is paraphrase mistaken for quotation; as written it is unverifiable and must be
re-derived before anyone acts on the CP-1 mechanism description. (The CP-1
*environmental* verdict itself is corroborated by the two-vmnet evidence in
MacosCrossNetworkTrafficBlocker_2026-09-03.md and is not challenged here — only the
code citation is dead.)

### 1.4 — CP-4 script citations are all stale: the cited lines and both named functions no longer exist

Lines 217–230 cite `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` at
`:1130` (the `winget configure` invocation), `:1132` (the throw), `:548-571`
(`Require-Winget`), and `:456-…` (`Get-WindowsBootstrapToolingState`), and assert
"nothing in the repository ever runs `winget configure --enable`". In the current
tree: `:1130` is now an `ssh-listener-not-ready` check and `:1132` is
`interactive_user_present`; `:548-571` are cargo checks and `:456` a quoting
helper; **the functions `Require-Winget` and `Get-WindowsBootstrapToolingState` no
longer exist anywhere in the script**, `Ensure-WingetConfigurationDependencies`
survives only inside a comment (`:465`), and the winget-related content that remains
is comment text at `:459-465` and `:1193`. The winget triage
(WindowsNodeBootstrapTriageVerdict_2026-08-28.md) was real and its commits check
out, but the script has since been restructured and the doc's line-anchored
narrative can no longer be followed by a reader. Superseded anyway by §1.2: the
operative Windows path is the libvirt guest, not this script's UTM flow.

---

## 2. MED findings

### 2.1 — `vm_lab/orchestrator/role.rs:68-70` → now `:75` (content matches)

Line 324 cites the Linux-only posture gate at `role.rs:68-70`. The function
`is_supported_for_platform` now sits at `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:75`
(~7-line drift; the doc also never states the full path). Content matches the
claim; the Linux-only-until-elected behavior described is intact.

### 2.2 — Stage-registry line block has drifted (`live_lab_stage_registry.rs`)

Line 108's block cite "`live_lab_stage_registry.rs:~1031-1369,1906`" and line 330's
"`:1151,1158,1168`" no longer land: those line numbers are now StageSpec
boilerplate. Current positions: `validate_macos_exit_nat_lifecycle` `:1161`,
`validate_macos_relay_service_lifecycle` `:1198`, `validate_macos_admin_issue`
`:1232`, `validate_windows_client_install` `:1400` with the windows trio names
through `:1473+`, and `live_mixed_topology_validation` at **`:2050`** (doc: 1906).
Two confirmations survived the drift: every stage name the doc claims exists does
exist, and HP-3's `relay_forwards_frame_validation` is present at `:2228` (the doc's
"stage exists, first live pass pending" stance is accurate).

### 2.3 — `phase10.rs:5075-5227` no longer brackets the macOS `apply_dns_protection` implementation

Line 101 (exit row) cites the shared apply path as `phase10.rs:5075-5227`. In the
current tree both endpoints are closing braces; the macOS implementation function
begins at **`:5121`** (other platform impls at `:1116`, `:3449`, `:6355`,
`:6855`). The load-bearing claim — one shared apply path, no exit-specific branch,
posture from `macos_dns_posture` at `phase10.rs:801` — is **verified exact**
(including `:801`), so this is drift, not error. The companion reassessment
(MacosExitDnsFailclosedEnumFixReassessment_2026-09-03.md) exists as cited.

### 2.4 — Harvest-caveat citations drifted (`ai_agent.rs:1864-1892`, `plan.rs:545-549`)

Lines 375–376 attribute the "61 → 19 stages" truncation to
`ai_agent.rs:1864-1892` plus `plan.rs:545-549`. In the current tree that
`ai_agent.rs` region is CSV header/rows collection, the `skip_linux_live_suite`
configuration now lives in `native.rs:46`/`:723` and `evidence.rs:161`, and
`plan.rs:545-549` shows `CrossNetworkRemoteExitDns` stage wiring —
`skip_linux_live_suite` does not appear in `plan.rs` at all. The *behavioral* claim
(skipping the Linux live suite drops the post-baseline mac/win suite) remains true
and is now enforced at the native.rs/evidence.rs sites; the cited anchors and the
61→19 figure are unverifiable as written.

### 2.5 — "Windows `blind_exit` — hard-excluded by design (`main.rs` hard-error)" (line 401) does not resolve

No blind_exit hard-error is locatable in `crates/rustynetd/src/main.rs`. The actual
enforcement is `is_blind_exit_supported_host` in
`crates/rustynet-operator/src/role.rs:90` (enforced at `:120`; Linux+macOS only;
negative test at `:245`). The design exclusion itself is real and correctly
reported as intended-divergence — only the file attribution is wrong. Relatedly,
the doc's own §7 line-drift note (line 434: Roadmap `11768` vs ParityPlan `11833`)
concerns the superseded historical docs and should be marked historical rather than
actionable.

### 2.6 — The §1 macOS admin 🟢 and relay-lifecycle 🟢 cells carry a known misattribution the doc does not yet acknowledge

`ParityStatusSnapshot_2026-09-03.md` (finding F1, quote-aware re-read of the
per-stage ledger) shows the 2026-07-19 runs behind both green cells had the macOS
node in the **anchor** role while `admin_issue`/`relay_validation` passed on
**Linux** nodes; the `macos_admin`/`macos_stage_*` roll-up columns are bash-dialect
aggregates. On that evidence both cells downgrade to never-proven-on-the-macOS-node.
This review did not re-adjudicate F1, but the Refresh doc — as the matrix of record
— must at minimum cross-reference the snapshot's correction instead of leaving
contradicting verdicts in two active documents.

---

## 3. LOW findings

1. **§2 CP-1 Linux anchor number superseded (line 121):** the doc's "`linux_stage_two_hop`
   is 35 pass including all four most recent runs" is now 62 pass / 35 fail in the
   column. The doc's own contamination caveat (column masks
   `live_two_hop_validation`) is correct and remains necessary: the per-stage tally
   is now 134 pass / 121 fail / 569 skip, consistent with the 2026-09-04 AGENTS.md
   update.
2. **Windows is no longer uniformly fail/not_run below bootstrap:** alongside §1.2's
   stage passes, `dns_failclosed_validation` shows 618 pass / 2 fail and
   `anchor_validation` 28 pass / 4 fail / 25 skip fleet-wide — context the §0
   "every one skip" sentence no longer describes.
3. **`windows_node_bootstrap_progress_2026-09-04.md` is referenced nowhere findable:**
   if the doc (or its siblings) intend to cite a progress record by that name, no
   such file exists under `documents/` at HEAD — either it was never committed or
   the name is wrong; flag to owner rather than cite.

---

## 4. Verified correct (attacked and survived)

- **Every SHA citation is real with a subject matching its use** (all checked via
  `git cat-file`): `34a9e6f8` (substrate acceptance, 2026-08-27), `db3ff1aaafe6`,
  `b7667cce46db`, `8ec851a9` (MAC-D1), `03619d0f` (MAC-D2), `5db953ad`,
  `a80c4de3`, `7bdcfe60`, `5b14669e`, `3aacdc2c`, `537e1901`, `11620a6`(=`11620a66`),
  `bf4b1b1187c8`, `2c10f9d9`, `e36a2295`, `e3297391`, `451f9730`, `a0851175`,
  `1278af04`, `7d6f5c98`, `001cc97`(=`001cc97e`), `e804723`(=`e8047233`),
  `a8c5ed7`/`ae678de`/`dff628d` (2026-07-22 nc-free), and
  `537e190`/`bbcb1f9`/`b519220` (2026-07-19 evidence). Zero fabricated or
  mis-subjected SHAs found.
- **`daemon.rs:2397-2398`** — the blind_exit-carries-anchor-capability refusal is
  verbatim at the cited lines (crates/rustynetd/src/daemon.rs).
- **`phase10.rs:801`** (`macos_dns_posture`) — exact.
- **`macos_dns_failclosed.rs`** — the nested `com.apple/rustynet_g{N}` sub-anchor
  enumeration from `2c10f9d9` is present (e.g. `:78`, `:487`, `:512`).
- **MAC-D2 path claims** — `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` is
  `/usr/local/etc/rustynet/membership.owner.key.pub`
  (crates/rustynetd/src/macos_install.rs:54-55; signing-key const `:45`): the doc's
  "seeded path correct, old read path wrong, fixed by `03619d0f`" narrative checks out.
- **All eight referenced ledger documents exist** under `documents/operations/active/`
  (WindowsNodeBootstrapTriageVerdict_2026-08-28, MacosDnsFailclosedEnforcementGap_2026-08-28,
  AnchorValidationMacosPostureGateInvestigation_2026-08-31,
  AnchorPlatformSelectorPropagationInvestigation_2026-08-31,
  MacosExitDnsFailclosedEnumFixReassessment_2026-09-03,
  MacosCrossNetworkTrafficBlocker_2026-09-03, NodeEngineAcceptanceSpec_2026-07-23,
  TraversalSelfSustenancePlan_2026-07-23). No dead document references.
- **§1 matrix verdicts as of HEAD:** Windows client/admin/relay/exit/bootstrap
  ⬛/🟠/🔒 verdicts remain correct (0 `windows_stage_bootstrap` passes in the
  ledger); macOS blind_exit 🟢 first-pass (`7bdcfe60` clean) matches; exit 🟡
  failing earlier at role/membership alignment matches the code; role-transition ⬛
  and cross-OS 0-for-N hold (now 0-for-282).
- **Self-awareness holds:** the doc's "re-derive, do not cite" ledger instruction
  and its bash-archive contamination caveat are both correct and were applied in
  this review.

---

## 5. Adversarial notes on method

- The counts in §1.1/§1.2 were taken with a quote-aware CSV parse at the reviewed
  commit; the matrix's own roll-up columns for mac/win stages are bash-dialect
  aggregates (§2.6), so Windows stage claims were read from per-run columns, not
  roll-ups.
- The in-flight Windows run was deliberately excluded: no verdict in this review
  depends on it, and the required doc caveat (§6) is written so it stays true
  whether that run passes or fails.
- Run-id attributions inside the §1 matrix (e.g. `livelab-1784501586`,
  `livelab-1784497253`) were not re-derived row-by-row in this pass; their commits
  are verified real and the snapshot (§2.6) is the doc that must carry any
  attribution correction.

## 6. Required updates to the target document (docs-only, owner to apply)

1. **Refresh §0/§9 counts** to the current ledger (or re-date them explicitly as
   "as of 2026-08-28" wherever they stand) — 282 rows / 213 fail / 69 partial /
   0 pass; Windows bootstrap 10 fail / 272 not_run; cross-OS 0-for-282.
2. **Add the CP-4/Track W caveat, preserving verdict discipline:** "2026-09-04:
   FIRST `--node` `bootstrap_hosts` PASS on a Windows guest (`windows-x86-1`,
   libvirt on `ubuntu-kvm-1`; run `run-2026-09-04-windows-5` @ `1785a58772`) —
   apparmor build fix + Windows key-custody fix live-proven. The run then failed
   `collect_pubkeys` (wireguard.pub async-write race); fixes `e1bdaeb8` and
   `70e16a63` are **merged but NOT live-proven** — no ledger row exists at or after
   `70e16a63`, the in-flight re-run is unconcluded, and the Windows client cell
   remains ⬛ until a ledger row proves `windows_stage_bootstrap=pass`." The
   winget/`windows-utm-1`/W-FIX-1 narrative should be demoted to the 2026-08-28
   triage history of the retired UTM path.
3. **Fix or drop the dead `tun.rs:1057` / `route -n add -inet` citation** (§1.3) —
   re-derive the actual route-programming site before the CP-1 mechanism text is
   relied on.
4. **Re-anchor the drifted code citations** (§1.4, §2.1–§2.5): role.rs `:75`,
   registry `:1161/:1198/:1232/:1400/:2050/:2228`, phase10 macOS impl `:5121`,
   harvest caveat → `native.rs:46`/`:723` + `evidence.rs:161`, blind_exit gate →
   `rustynet-operator/src/role.rs:90` (`:120`, test `:245`).
5. **Cross-reference ParityStatusSnapshot_2026-09-03 F1** from the §1 admin/relay
   rows so the two active documents cannot be read as disagreeing silently.

---

## 7. Self-verification

Re-checked after drafting, each against the tree at `2b3422d3`:

1. **`windows_stage_bootstrap` count** — re-parsed: 10 `fail`, 0 `pass`, 272
   `not_run`; the five 2026-09-04 rows name `windows-x86-1` — matches §1.1/§1.2.
2. **`70e16a63` provenance** — `git merge-base --is-ancestor 70e16a63 HEAD`
   succeeds; `git log -1 --format=%s 70e16a63` = "fix(windows): serve collect_pubkeys
   from daemon status, not a file read"; no matrix row with commit ≥ it — matches
   the "merged, not live-proven" framing.
3. **`tun.rs` dead cite** — `wc -l third_party/rustynet-tun/src/lib.rs` = 547;
   `grep -ri "route -n add -inet" crates third_party` = no matches — matches §1.3.
4. **`daemon.rs:2397-2398`** — re-read: the blind_exit anchor-capability refusal
   string is present verbatim at those lines — matches §4.

*End of review. This document is a point-in-time adversarial audit; per the
target's own rule, ledger counts must be re-derived, never cited, after today.*
