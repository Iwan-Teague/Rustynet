# Platform Infer Migration Design — QH-82 root cause (2026-09-08)

**Status:** IMPLEMENTED 2026-09-09 (commits `568d1aaf` tripwire, `a4475c53`
migration, `1ef841b2` tests; ledger: QH-82 in `QualityHardeningTodo_2026-07-25.md`).
Corrections from the review applied: true `.platform_profile()` counts are 34 raw lines
(32 in `vm_lab/mod.rs`, 1 each in `overnight/executor.rs` / `overnight/mod.rs`); the
"35 raw hits include the definition/impl" sentence in §1 was wrong (`.platform_profile()`
never matches the definition). The review's blocking CI-tripwire change landed as
`scripts/ci/check_platform_infer_tripwire.sh` + `crates/rustynet-cli/src/bin/check_platform_infer_tripwire.rs`,
wired into the gate-runner security set. §4's "no zero-effort path" claim is scoped to
the inference chain: direct `entry.platform.unwrap_or(Linux)` gates outside that chain
(the audit's gate list) were NOT touched by this migration. Line numbers below cite the
design tree (`702d9379`) and have drifted again on the implementation tree.
**Verified against:** worktree at commit `702d9379` (`ai-edit/edit-1788876485177-62192-0`). Every `mod.rs` line number below was read on this tree. The audit's own line numbers (`PlatformBranchingAudit_2026-09-08.md`) were measured at an earlier commit and have **drifted** — e.g. the audit's `mod.rs:3019` diagnose site is `mod.rs:3364` here, and its `13843`/`13918` relay filters are `14188`/`14263`. Cite audit rows by row number; cite this doc for current lines.
**Inputs:** QH-82 (`QualityHardeningTodo_2026-07-25.md:6869`), `PlatformBranchingAudit_2026-09-08.md`, and the six landed fail-closed sites of commit `f386b249`.

---

## 1. Decision

**Build the Option-returning `infer`, exactly as QH-82's shape note sketched, plus the Linux hint table — and convert the `platform_profile()` chain to `Result` so the compiler forces every one of its call sites to be individually reviewed.** Close the three remaining silent-Linux sites alongside it, each with a different treatment (§3). Do **not** add an `Unknown` variant; do **not** make `infer` return `Result`.

### Why Option and not the alternatives

- **`Option<Self>` (CHOSEN).** `infer` has exactly one failure kind ("no evidence"), so `Option` carries all the information. The conversion is 3 call sites + 1 chain (measured below), and it forces the failure to be *named at each resolution site* — which is the whole defect class. A caller that writes `infer(..).unwrap_or(Linux)` reintroduces the bug in one visible line, greppable as `VmGuestPlatform::Linux` (today's fallback is written `Self::Linux` at `mod.rs:2365` and is invisible to exactly that grep — audit row #1).
- **`Result<Self, E>` (REJECTED).** There is only one error case and no per-site error data to carry; the error text belongs to the *caller* (the audit's message template names the alias, which `infer` doesn't always have as a distinguishable failure). `Result` adds a variant nobody populates differently.
- **Explicit `Unknown` variant (REJECTED).** Three reasons, in order of weight:
  1. It makes every one of the ~180 behaviour-branch matches total **today**, which kills the compile-error property the audit is trying to *create* for future variants — a `_` wildcard arm would then absorb `Unknown` and any genuinely new OS in one arm, re-legitimizing exactly the wildcard-on-OS-axis pattern the audit names as the defect (audit §"Copy these shapes", `capability.rs` rule).
  2. It grows the serde surface of `VmGuestPlatform` (inventory/config files could then carry `"unknown"`), turning a compile-time discipline into a runtime value.
  3. It is a 180-site big-bang migration to get what `Option` gives at 4 sites.
- **Do nothing / per-site only (REJECTED).** The per-site fix is done (`f386b249`) and stopped at six sites; three silent sites remain (§3), and every future resolution site re-faces the same decision with a lying default available. The audit's own payoff note applies: *"`infer` coerces unknown OSes to Linux before they are consulted. Fixing it converts existing dead safety into live safety at no cost"* (audit line ~201: `default_platform_profile` and the filesystem tables are already exhaustive; their guarantee is unreachable only because `infer` pre-coerces to Linux).

### The load-bearing chain, verified on this tree

| Element | Today | Location |
| --- | --- | --- |
| `VmGuestPlatform` enum | `Linux, Macos, Windows, Ios, Android` | `mod.rs:2305-2313` |
| `parse` — exact-string table, **rejects** unknown with `Err` | includes `"linux" \| "debian" \| "ubuntu" \| "fedora" \| "mint"` | `mod.rs:2316-2327` |
| `infer` — explicit wins, else substring match on alias + os_name + utm_name, **unconditional `else { Self::Linux }`** | no Linux substrings checked at all — Linux is the *residue* | `mod.rs:2329-2367`; the fallback is `mod.rs:2364-2366` |
| `effective_platform_profile` — infallible, feeds `infer` | returns `VmPlatformProfile` | `mod.rs:2513-2535` |
| `VmInventoryEntry.platform: Option<VmGuestPlatform>` — `None` when the inventory key is absent | loader behaviour | field at `mod.rs:2661`; `None`-on-absence per QH-82/audit row 2 |
| `platform_profile()` — infallible | wraps `effective_platform_profile` | `mod.rs:2669-2679` |

**`infer` call sites — re-measured, confirmed 3** (QH-82's count stands):

1. `mod.rs:2522` — inside `effective_platform_profile` (the only path to `platform_profile()`).
2. `mod.rs:7502` — the unmatched-local-UTM discovery branch (`VmGuestPlatform::infer(None, None, utm_name, Some(utm_name))`), feeding `default_platform_profile` at `:7503`.
3. `topology.rs:229` — `platform_for_entry`, `#[allow(dead_code)]` W5.7 quarantine (`topology.rs:226`), returns `Option<TopologyPlatform>` already.

**`.platform_profile()` call sites — measured 34** in `crates/rustynet-cli/src/` (33 in `vm_lab/mod.rs`, 1 each in `overnight/executor.rs` and `overnight/mod.rs` — note 35 raw hits include the definition/impl). A handful fall inside test modules; the migration review covers all 34 regardless. Most are assertion-shaped (`if x.platform_profile().platform != Expected { bail }` — e.g. `mod.rs:11549, 14963, 15101, 16373, 16561, 19341`); the remainder build data (`mod.rs:30658, 31281, 31348`). The overnight-loop sites are at `overnight/mod.rs:97`-area and `overnight/executor.rs:492`-area (hits confirmed by grep; exact statement context **UNVERIFIED** — read during implementation).

---

## 2. The migration, concretely

### 2.1 `infer` → `Option<Self>` with Linux hints

```rust
fn infer(
    explicit: Option<Self>,
    os_name: Option<&str>,
    alias: &str,
    utm_name: Option<&str>,
) -> Option<Self> {
    if let Some(platform) = explicit {
        return Some(platform);
    }
    // haystacks built as today (mod.rs:2339-2345)
    if windows-substrings-match { Some(Self::Windows) }
    else if macos-substrings-match { Some(Self::Macos) }
    else if ios-substrings-match { Some(Self::Ios) }
    else if android-substrings-match { Some(Self::Android) }
    else if haystacks.iter().any(|v| v.contains("linux") || v.contains("debian")
        || v.contains("ubuntu") || v.contains("fedora") || v.contains("mint"))
    { Some(Self::Linux) }
    else { None }
}
```

**The Linux hint arm is mandatory, not decoration.** Without it, `debian-headless-4` — the workhorse lab alias — contains no non-Linux substring and no `linux` substring, so it would infer `None` and fail-closed every normal Linux guest. QH-82's shape note already flagged this; it is restated here because it is the single easiest way to ship this migration broken. The hint set **mirrors `parse`'s Linux arm** (`mod.rs:2318`) so a name `parse` cannot resolve cannot silently infer either. Match order stays Windows → macOS → iOS → Android → Linux (today's order, `mod.rs:2347-2363`) — precedence is observable behaviour and must not drift.

### 2.2 The chain becomes `Result`, and every consumer names its unknown

- `effective_platform_profile(...) -> Result<VmPlatformProfile, String>`: on `infer(...) == None`, return the audit template naming the alias:
  `'{alias}': platform could not be inferred from alias/os ('{os}'); refusing to assume Linux — set the inventory 'platform' field`.
- `VmInventoryEntry::platform_profile() -> Result<VmPlatformProfile, String>` (`mod.rs:2669`): propagates.
- The 34 call sites are then **compiler-forced** to be touched. Three disposition classes:
  1. **Assertion sites** (the majority): `let profile = entry.platform_profile()?;` — an un-inferable platform now fails the same named way a wrong platform already did. Mechanical.
  2. **Data-building sites** (`mod.rs:30658, 31281, 31348`, ...): `?`/`map_err` into the enclosing `Result`. Mechanical; each enclosing fn is `Result`-shaped (spot-verified at `:3343`-style sites; **verify each during implementation**).
  3. **The discovery else-branch (`mod.rs:7500-7503`)** — see §3, site 4. NOT an error: this branch runs for a local UTM VM **with no inventory entry at all**, so there is no alias record to fix and discovery's job is to enumerate, not to gate. Disposition: keep calling `infer`; on `Some` build the profile as today; on `None` synthesize the discovered entry with `platform: None` and **explicit `Unsupported`** `remote_shell`/`guest_exec_mode` (the variants exist: `mod.rs:2385`, `mod.rs:2413`) instead of `default_platform_profile`'s Linux defaults, plus a discovery note `platform-not-inferable-from-utm-name`. Every downstream exec path then refuses on its existing Unsupported handling rather than running bash against an unknown box. (Whether the surrounding discovery fn is `Result` — likely, but **UNVERIFIED** — does not matter; this branch never errors on an unknown platform.)
- `topology.rs:227-236` (`platform_for_entry`, quarantined dead code): `infer(...) -> Option` maps onto the function's existing `Option` return naturally — `let inferred = VmGuestPlatform::infer(..)?;` then `TopologyPlatform::try_from(inferred).ok()`. Its only consumer `select_alias_by_platform` (`topology.rs:255-263`) already turns `None` into "no match", and its documented contract turns that into a caller-side hard error (`topology.rs:249-253`). The G2 re-wire must preserve None→hard-error; note it in the quarantine comment.

### 2.3 Why converting `platform_profile()` is the point

The alternative — keep `platform_profile()` infallible and add a failable `try_platform_profile()` — would leave all 34 sites compiling untouched, the assertion sites still reading a value that can only be produced by inventing Linux, and the compiler never forcing anyone to look. The type-system-forced review **is** the migration. The 34-site touch is also why this is its own reviewable increment, not a rider (QH-82 already made this call; this doc confirms it with the per-site disposition classes filled in).

---

## 3. The three remaining silent-Linux sites — treatment each

The task's line numbers (`3019`, `13843`, `13918`) are the audit's; on this tree they are `3364`, `14188`, `14263`.

### Site 1 — `mod.rs:3364` (diagnose): FAIL CLOSED, explicit platform only

`execute_ops_vm_lab_diagnose` (`mod.rs:3343`, `-> Result<String, String>`) does `let platform = entry.platform.unwrap_or(VmGuestPlatform::Linux);` and feeds it to `node_adapter_for(...)` (`mod.rs:3381-3386`) — the platform *picks the adapter*, so a platform-less entry currently gets the Linux adapter and the diagnostic runs Linux-shaped probes (bash paths, systemctl-adjacent commands) against a box of unknown OS. The audit's row #18 adds the sharper tell: it bypasses `effective_platform_profile` entirely, so even an alias literally named `...windows...` gets the Linux adapter here.

**Fix:** replace the default with a hard error using the audit template:
`ok_or_else(|| format!("'{}': no platform recorded; refusing to assume Linux", entry.alias))?` — consistent with the six `f386b249` sites' message.

**Decision — explicit platform ONLY, no inference fallback in diagnose.** Strictest-secure-default (CLAUDE.md §2 rule): the alias-hint inference is exactly the mechanism being retired, and a diagnostic tool that guesses the OS can run wrong-OS probes against the one node the operator is already worried about. Cost to the operator: one inventory line. (Owner decision 2 below offers the softer option.)

### Sites 2+3 — `mod.rs:14188` and `mod.rs:14263` (relay-topology selection filters): EXCLUDE unknowns, ENRICH the resulting error — do not error inside the filter

Both `select_relay_forward_test_topology` (`mod.rs:14184-14239`) and `select_relay_forward_test_topology_for_run` (`mod.rs:14257+`) filter candidates with:

```rust
let is_linux = |e: &&VmInventoryEntry| {
    e.platform.unwrap_or(VmGuestPlatform::Linux) == VmGuestPlatform::Linux
};
```

A platform-less entry is therefore **silently selectable as a Linux node** — for the relay slot (which gets the relay service deployed to it) or as a sender/receiver peer.

**The failure mode the task warns about is real and the treatment must name it.** A selection filter that "fails closed" by hard-erroring on any unknown-platform entry would break every legitimate mixed topology: the standard 5-node lab contains Linux *plus* macOS/Windows guests, and the filter's contract is "pick the Linux ones", not "the inventory is all-Linux". Erroring inside the filter turns one Windows guest into a relay-proof abort — over-fail-closed, and it converts a diagnosable selection into an opaque refusal.

**Fix (both functions):**

1. Make the filter a **positive allowlist**: `matches!(e.platform, Some(VmGuestPlatform::Linux))`. A platform-less entry is excluded — it can never be minted into a Linux node. This is default-deny in the audit's own terms (§"Do not convert any gate into a negative test": only explicitly-Linux passes).
2. Collect the excluded-unknown aliases once (`unknown_platform: Vec<&str>`) and **append them to the pre-existing failure errors**: the relay-miss `ok_or_else` (`mod.rs:14195` / `:14270-14272`) and the peer-count error (`mod.rs:14213-14218`) gain `... ; excluded N entries with no recorded platform: [a, b]` when non-empty. Selection then fails through its *existing, already-tested* error paths — with the reason an operator can act on — instead of a new error class.

So the answer to "selection failing closed means selecting nothing" is: **yes — and that is correct here, because 'selecting nothing' lands in an explicit named error that already exists, while the enrichment makes the *cause* visible. The unacceptable outcome was never 'no selection'; it was 'a selection made from a guess'.**

---

## 4. Fail-closed analysis (mandatory)

For the new mechanism — Linux hints in `infer`, `Option`/`Result` propagation, the positive-allowlist filter:

| State | Behaviour after migration |
| --- | --- |
| **ABSENT** — no explicit `platform`, no hint-bearing name | `infer` → `None`. Every consumer then fails or excludes by its disposition class (§2.2/§3): resolution sites error with the named-alias template; the relay filter excludes; discovery degrades to `Unsupported` + note. **Zero-effort path is the refusing path.** The old zero-effort path (Linux) no longer exists as an expression shorter than the fix. |
| **MALFORMED** — e.g. `os = "Debina/Linux"` (typo) | Lowercased, contains no hint substring → `None` → fail closed. Today: silent Linux. This is a strict improvement: a typo that `parse` would reject if it were in the `platform` field can no longer sneak through the *name* channel. |
| **ABSENT but hint-bearing** — `debian-headless-4`, `ubuntu-24-04`, os `"Debian/Linux"` | `Some(Linux)` via the hint arm (§2.1). Deliberate: inference from an operator-chosen recorded name is evidence, not a default; the failure mode being fixed is the *residue* default, not inference itself. |
| **STALE** | The inference inputs (`alias`, `os`, `utm_name`) are inventory-static — nothing decays mid-run. A renamed guest with an explicit `platform` keeps it (explicit wins first, `mod.rs:2335-2337`). A renamed guest *without* a platform re-infers from the new name and, if now ambiguous, **fails closed**, forcing the operator to record the platform — the correct direction (stale name ⇒ loss of inference ⇒ refusal, never ⇒ Linux). |
| **UNAUTHORIZED SETTER** | The only write path into `explicit` is the inventory `platform` field, parsed by `parse()` (`mod.rs:2316-2327`), which rejects unknown strings with `Err` at load; the loader leaves an absent key as `None` (QH-82). No env/CLI override writes `entry.platform` (none found on this tree; the load path is the audited boundary per audit row 2). An unauthorized value therefore cannot enter as `Some` at all. |
| **Filter polarity regression** | `matches!(e.platform, Some(Linux))` is a positive allowlist — the audit's explicit warning against inverting gates to negative tests (`!matches!(platform, Ios \| Android)`) is followed; a new variant is *not* silently Linux-eligible. |

The one **permissive-by-default** temptation in this design is the discovery `Unsupported` degradation (§2.2 class 3) — it creates an entry that *looks* usable. It is bounded: `Unsupported` shell/exec modes make every command-construction path refuse, and the discovery note names the cause. If that is judged too soft, owner decision 3 covers the stricter alternatives.

---

## 5. What this does NOT solve

1. **Distro-level divergence.** `parse` folds `debian|ubuntu|fedora|mint` (and the hint arm folds `rocky`, `alma`, … only when hinted) into `Linux`; a Rocky guest is a Linux guest to every site. The audit's closing caveat (audit line ~286) stands: the Rocky `sudo secure_path` class of defect is invisible to this migration and needs distro-level capability data. Not solved, not started here.
2. **Wildcard arms on *resolved* platforms.** Once a platform is genuinely recorded (`Some(Windows)`), the R9 register sites still misbehave: `anchor.rs:515`'s skip-the-security-assertion, `relay.rs:262`'s inherited ports, `network_audit.rs`'s Linux parser, the `validate_linux_*` calls behind `Linux|Macos` gates, soak's `"linux"` token. Their input no longer *originates* from a guess — but their own `_`/`|` wildcards are untouched. That is the per-role probe work (R9), unaffected by this migration.
3. **Planning-side silent narrowing (R11).** `native.rs:733` `wants_*` bools, `executor.rs:552` hardcoded Linux exit+client, the mixed-topology gate: literals and bools, not inference. A platform-less node contributes to nothing there both before and after this fix (it is at least *excluded* from Linux selection now at the relay filter — but planning gates don't consult `infer`).
4. **The run-matrix ledger defects (QH-07's class).** Unrelated surface entirely.

---

## 6. Silent-wrong register accounting — does the root-cause fix pay for the table?

From the audit's register (25 silent-Linux groups of 52), classified **by mechanism** — which groups' silent-Linux *originates* in `infer`:

**Closes automatically (2 of the 25):**
- **Row #1** (`infer` itself) — closes by construction.
- **Row #18** (diagnose, audit `mod.rs:3019` / this tree `:3364`) — closes via §3 site 1.

**Closes on its None-path only (partial, 1):**
- **Row #5** (readiness `_ => true`, audit `mod.rs:30642`/`30566`) — a platform-less target can no longer arrive at the wildcard dressed as Linux (the resolve site errors first). But the wildcard itself remains for a *recorded* non-Linux/macOS platform — the fail-open arm still needs the R6 work.

**Also closed, from the audit's separate six-gate list (not counted in the 25):** the relay-forward filters (audit `mod.rs:13843`/`13918` / this tree `:14188`/`:14263`) via §3 sites 2+3.

**Everything else (~22 of 25) needs individual work and gets nothing automatic.** Their silent-Linux does not flow through `infer`: wildcard arms on already-resolved platforms (rows #4, #6, #7, #8, #10, #11, #24), hardcoded Linux literals (rows #14 `30966`/`31031`, #16 `executor.rs:552`), planning-side bools and gates (rows #22 `native.rs:733`, #23 `live_mixed_topology`), and None-polarity gates that read `entry.platform` directly rather than through inference (the audit's gate list: `mod.rs:3472`, `8096`, `34444`, `admin_issue.rs:4`, `backlog.rs:96`).

**The verdict the number forces:** the migration is **not** a substitute for the per-OS capability table — it auto-closes ~2/25 of the silent surface. It is nevertheless **sequenced before the table**, for a different reason than coverage: the R9 capability table's value is *evidence keyed by platform*, and evidence minted downstream of a lying `infer` is contaminated at the source. Land the 2-day inference fix first (it also removes the three remaining silent selection/resolution sites), then build the per-role probe table on a platform value that cannot lie.

---

## 7. Test plan — each test names the mutation it catches

The repo has shipped revert-passing tests; every test below observes behaviour that **fails when its specific mutation is applied**:

1. `infer_returns_none_when_no_platform_substring_matches` — input: alias `node-7`, os/utm `None`, expects `None`.
   **Catches:** re-adding `else { Self::Linux }` (or any `None → Linux` substitution inside `infer`).
2. `infer_still_yields_linux_for_hint_bearing_names` — inputs: `debian-headless-4`, `ubuntu-24-04`, alias `mint-box`, os `Debian/Linux`; expects `Some(Linux)` for each.
   **Catches:** the over-correction mutation (hint arm dropped → every plain-Linux guest fails closed; the exact breakage QH-82's shape note forbids).
3. `infer_platform_precedence_is_windows_macos_ios_android_linux` — a name containing both `macos` and `windows` infers `Windows`.
   **Catches:** hint-table reordering during the edit (precedence is observable behaviour).
4. `platform_profile_fails_closed_when_platform_is_uninferable` — entry with `platform: None`, alias `node-7`; `platform_profile()` must `Err` with the alias named.
   **Catches:** `unwrap_or`/`default_platform_profile(Linux)` reintroduced in `effective_platform_profile` or `platform_profile()`.
5. `discovery_unmatched_utm_without_inferable_platform_gets_unsupported_modes_and_a_note` — discovery else-branch with a hint-less `utm_name`; the synthesized entry carries `Unsupported` shell/exec and the note.
   **Catches:** the branch reverting to `default_platform_profile(inferred.unwrap_or(Linux))` (either the unwrap or the Linux default).
6. `select_relay_forward_test_topology_excludes_platform_unknown_entries_and_names_them` — two assertions in one test: (a) inventory whose only `relay_capable` entry lacks `platform` → `Err`, message names that alias in the excluded list; (b) inventory with 2 recorded-Linux peers + 1 unknown entry → `Ok`, selecting only the two.
   **Catches:** (a) the revert to `unwrap_or(Linux)` (unknown silently selected); (b) the over-correction mutation (hard error on any unknown-platform entry — the mixed-topology breakage §3 forbids).
7. Same pair for `select_relay_forward_test_topology_for_run` (`..._for_run_excludes_platform_unknown_entries_and_names_them`).
8. `diagnose_fails_closed_for_entry_without_recorded_platform` — platform-less entry → `Err` naming the alias; plus a positive case: `platform: Some(Windows)` builds the Windows adapter (guards a wrong-variant revert).
   **Catches:** `mod.rs:3364` reverting to `unwrap_or(VmGuestPlatform::Linux)`.

The six `f386b249` tests already pin the landed sites; no new meta-test is added beyond these behaviour tests.

---

## 8. Effort

| Part | Estimate | Content |
| --- | --- | --- |
| Mechanical | **~1.0 day** | `infer` signature + hint arm + precedence; `effective_platform_profile`/`platform_profile()` → `Result`; `topology.rs:227-236`; diagnose `:3364`; both relay filters + enrichment; discovery `Unsupported`+note; the `?`-conversion of the assertion-shaped majority of the 34 `.platform_profile()` sites. |
| Judgement | **~1.0–1.5 days** | Per-site review of all 34 callers (incl. the two overnight sites) with the §2.2 disposition classes; verifying each enclosing fn's `Result` shape; error-message consistency with the audit template; the test plan above; targeted gates (`cargo test -p rustynet-cli --lib --all-features --locked` + fmt/clippy per §13.1, with `--all-targets --all-features` on every scoped command); one `--node` live-lab re-verify. |

**Total: 2–2.5 days.** The mechanical share is genuinely mechanical *because* the type change forces the sites to surface — that is the design working.

---

## 9. Owner decisions

1. **`platform_profile()` signature — convert to `Result` (recommended) vs. add a failable sibling and keep the infallible one.** Converting forces the 34-site review (the migration's actual value); the sibling keeps churn low but the infallible path keeps producing Linux from nothing and the compiler never forces anyone to migrate off it. **Recommend convert.** Consequence of converting: ~34 files/lines touched, all mechanical; consequence of the sibling: silent sites can persist indefinitely behind the old API.
2. **Diagnose fallback — explicit platform only (as designed) vs. explicit-then-infer.** Explicit-only is the strictest default; cost is one inventory line on hint-bearing-name hosts that omit `platform`. Explicit-then-infer is more convenient but keeps a guessing path in a diagnostic tool. **Recommend explicit-only; owner may trade strictness for convenience.**
3. **Discovery unknown-UTM disposition — `Unsupported` + note (as designed) vs. omit the VM from discovery output vs. hard-error the whole discovery run.** `Unsupported`+note preserves operator visibility of a real VM while refusing every exec path. Omission hides a machine that exists; a hard error makes one weirdly-named UTM VM blind the entire discovery surface. **Recommend `Unsupported` + note.**

---

## 10. Sources

- QH-82, `documents/operations/active/QualityHardeningTodo_2026-07-25.md:6869-6941` (landed six sites, `f386b249`; shape sketch; 3-call-site/34-caller measurement — re-confirmed here).
- `documents/operations/active/PlatformBranchingAudit_2026-09-08.md` — register rows #1–#24, the six-gate list, the R6/R9/R11 remedy clusters, the wildcard thesis, and the distro caveat.
- This tree at `702d9379`: all `mod.rs`/`topology.rs` locations cited in §1–§3 were read directly; grep re-measured `infer` (3 sites) and `.platform_profile()` (34 sites).
