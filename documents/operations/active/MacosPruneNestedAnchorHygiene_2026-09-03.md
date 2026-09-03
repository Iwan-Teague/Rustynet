# macOS prune_owned_tables never flushes the nested generation anchors — hygiene latent bug

Date: 2026-09-03
Scope: `crates/rustynetd/src/phase10.rs` (MacosCommandSystem pf anchor lifecycle), `crates/rustynetd/src/macos_dns_failclosed.rs`, `crates/rustynetd/src/privileged_helper.rs`
Status: INVESTIGATION — docs only, no code changed. Every citation below is re-verifiable; the manager must re-check each before acting.
Proximity warning: this sits directly next to the just-closed macOS DNS floor work (enum-fix `2c10f9d9`, D2 fix `c4ef2583`, M3 latch). **Never propose flushing the current-generation floor.**

## VERDICT

**LATENT-BUG-NEEDS-CARE** — `MacosCommandSystem::prune_owned_tables` is a no-op for every nested `com.apple/rustynet_g{N}` anchor because `list_owned_anchors` enumerates with top-level-only `pfctl -s Anchors` (the exact blindness the enum-fix `2c10f9d9` corrected in the DNS check). Old-generation floors therefore accumulate un-flushed; the D2 comment at phase10.rs:4825 asserts a flush that never happens; the Linux prune's own test proves old-gen sweeping was the design intent. Fix is warranted but must carry an explicit current-generation + live-handle guard. The comment at :4825 is also stale (it reasons from a flush that does not occur), but the behavior is not "OK": it is a silent old-gen sweep failure, so this is not COMMENT-STALE-BEHAVIOR-OK.

## Q1 — Does `pfctl -s Anchors` ever list `com.apple/rustynet_g{N}`? (DECISIVE: no)

Evidence chain:

1. `phase10.rs:4091-4098` — `owned_anchor_names_from_output` keeps only lines `starts_with("com.apple/rustynet_g")`.
2. `phase10.rs:4100-4113` — `list_owned_anchors` runs `pfctl -s Anchors` (no `-a`) and feeds stdout to that filter. `pf not enabled` → empty list (4106-4107).
3. pfctl semantics (FreeBSD/macOS lineage; macOS ships FreeBSD-derived pf): `pfctl -s Anchors` iterates `DIOCGETRULESETS` **at the root anchor only** and prints the immediate children — on macOS that is `com.apple` (and `com.rustynet` when created). It is **not recursive**: a nested anchor `com.apple/rustynet_g{N}` is a child of `com.apple`, two levels deep, and can never appear in top-level output. Only `pfctl -a com.apple -s Anchors` lists `com.apple`'s sub-anchors.
4. This exact semantics was established **live** by the enum-fix `2c10f9d9` ("Fix macOS DnsFailclosed check: enumerate nested com.apple sub-anchors to find the pf floor"): its commit message states `pfctl -s Anchors` "lists only TOP-LEVEL anchor names (com.apple, com.rustynet) and never the nested com.apple/rustynet_g{N}", after live sampling showed `com.apple/rustynet_g1` present with 8-15 DNS-block rules while the top-level-only check scanned `[]`.
5. The corrected reader unions both queries — `macos_dns_failclosed.rs:511-542` (`read_pf_dns_block_floor`): `read_pfctl(&["-s","Anchors"])?` (526) + best-effort `read_pfctl(&["-a","com.apple","-s","Anchors"])` (527) merged at 528; comment 512-525 documents the blindness. Its regression test `floor_scan_unions_top_level_and_nested_com_apple_anchors` (~:1290-1325) models top-level output as `com.apple\ncom.rustynet\n` and nested output as full-path lines `com.apple/rustynet_g5`.
6. The floor anchor name is nested by construction: `phase10.rs:3880-3885` — `current_anchor_name() = format!("com.apple/rustynet_g{}", self.generation)`. A pf anchor name containing `/` **is** a nested path, so `com.apple/rustynet_g{N}` can never be a root child.

**Conclusion: `list_owned_anchors` returns `Vec::new()` on every real macOS system** (the unit test `owned_anchor_names_filters_only_rustynet_anchors`, phase10.rs:17501-17513, "passes" only because it feeds synthetic lines — `com.apple/rustynet_g1` among them — that real `pfctl -s Anchors` never emits; that test encodes the blind spot). The prune loop at `phase10.rs:4818-4823` therefore iterates zero times and flushes nothing nested.

## Q2 — Consequence A: do old-generation floors accumulate? (yes, with a bounded fast path)

Rotation mechanics:

- `phase10.rs:7115` — `let target_generation = self.generation.saturating_add(1);` and `:7121` `set_generation(target_generation)` — **every generation apply rotates the anchor name** (`prune_owned_tables` runs at `:7209`, after set_generation, before `apply_generation_stages`).
- `phase10.rs:4031-4041` (`apply_pf_rules`) flushes the **immediately-previous** anchor when the name changes (`Some(previous) if previous != &next_anchor && !is_macos_blind_exit_anchor(previous)` → `pfctl -a previous -F all`). So within one daemon lifetime, the previous generation is swept by the rotate-flush, not by prune.
- `MacosCommandSystem::new` initializes `generation: 0` (`:3778`), and the daemon only holds the **latest** anchor name in `self.anchor_name` (`:4064`).

Therefore:

- **Accumulation is real in two paths:**
  1. **Daemon restart** — the new process starts at gen 0→1 with `anchor_name = None`; the previous lifetime's `g1..gN` anchors are enumerated by nothing (prune no-op, rotate-flush has no handle). There is no startup stale-anchor reconcile for killswitch anchors (the only residue reconciles are exit-NAT + tandem-DNS, `reconcile_exit_nat_residue`, phase10.rs:4845-4898; grep for startup anchor cleanup finds none). Stale anchors persist **indefinitely across restarts**.
  2. **Same-lifetime history beyond one rotation** — only the single immediately-previous anchor gets the rotate-flush, so any anchor older than "previous" is orphaned exactly like a restart leftover (reachable via apply-failure/rollback sequences that swap handles; `flush_anchor` at `:4115-4126` likewise only ever flushes the one held handle, and `rollback_firewall` at `:4966-4971` is its caller).
- **The stale anchors are not inert.** macOS's main ruleset wildcard-references the com.apple family (`anchor "com.apple/*"` — the live ruleset carries `scrub-anchor "com.apple/*"` / `nat-anchor "com.apple/*"` per the parsers in `macos_ipv6_leak.rs:265` and `macos_exit_killswitch_precedence.rs:652-653`), and every generation anchor is loaded via the `MacosPfLoad` builtin (`phase10.rs:4055-4064`) with the **full killswitch render** (`killswitch_spec`, :3900-3919): `block drop out quick all`, pass rules for the tunnel interface, allow rules for SSH cidrs / traversal bootstrap / managed-peer endpoints, and — since the M3 latch (`:3911`, `dns_protected || has_live_loopback_dns_pins()`) — the labeled DNS-block floor in every render. Real effects of a stale `g{old}`:
  - **Stale ALLOW rules persist**: endpoints/cidrs an older configuration permitted keep being permitted after the policy tightens (security-relevant).
  - **Post-disable breakage**: `disable`/rollback flushes only the current handle (`flush_anchor`); a surviving old-gen anchor keeps `block drop out quick all` + DNS-floor rules evaluating with the tunnel interface gone — the node stays blocked after the killswitch is switched off (availability).
  - **pf rule bloat**: evaluated-rule count grows with each orphaned generation (duplicate, posture-equivalent blocks in the normal case — benign in themselves, last-match semantics, but they mask the two effects above).

Severity calibration: the common same-lifetime happy path is masked by the rotate-flush; the failure class is restart-with-accumulation and config-shrink. Fail-closed residue dominates (over-blocking), but stale-allow persistence is a genuine security-hygiene defect. Not benign; not urgent-urgent.

## Q3 — Consequence B: the :4825 comment premise is STALE

`phase10.rs:4825-4838` asserts: "the flush above just dropped a live DNS-block floor along with every other owned anchor". Given Q1, **the flush above drops nothing** — the loop body never executes. Consequently:

- The **current-generation nested floor SURVIVES prune** — it is never enumerated and never flushed. (prune's `self.anchor_name = None` at `:4824` only drops the in-memory handle; the kernel anchor lives on. The next `apply_pf_rules` re-establishes the handle at `:4064`.)
- The M3 re-render at `:4839-4841` (`has_live_loopback_dns_pins() → apply_pf_rules(false)`) is therefore **redundant-but-harmless** today: the floor it "re-establishes" was never dropped. The D2 fix `c4ef2583` ("Fix macOS DNS pin-without-floor half state after pf prune (D2)") correctly diagnosed the half-state class and correctly added the M3 latch + re-render, but its opening premise ("prune_owned_tables flushed every owned pf anchor") is false on real pfctl output — the half-state it observed in the field was produced by anchor **re-renders** that predated the M3 latch, not by prune's flush.
- The comment must be rewritten when this is fixed; the re-render itself should be **kept** (belt-and-braces; see Q5 reconciliation).

## Q4 — Latent bug or correct-by-design?

**Latent bug.** The design intent is unambiguous from the Linux twin: `LinuxCommandSystem::prune_owned_tables` (`:1026-1027`, test `prune_owned_tables_preserves_active_and_target_generation_tables`, `:13937-14004`) deletes stale generation tables (`nft delete table inet rustynet_g9`) while **preserving the active (previous) and target generations** — old-gen sweep, live-floor handoff preserved. The macOS comment at `:4846-4848` states the same intent ("prune_owned_tables only sweeps the generation-numbered `com.apple/rustynet_g*` killswitch anchors"). The macOS implementation intends to sweep old gens; it enumerates with the top-level-only query and sweeps nothing. The floor persisting through prune is *incidentally* the D2-desired outcome, but the sweep that should accompany it is silently dead. So: behavior-not-OK, comment-not-true, intent = Linux's preserve-active+target / delete-older.

## Q5 — The guarded fix (proposal only; NO code changed in this investigation)

Mirrors the enum-fix's union, plus the Linux prune's preserve-set, plus an explicit current-generation guard. Ordering matters: the guard is what makes this safe to land next to the green DNS floor.

1. **Privileged allowlist arm** — `privileged_helper.rs:3053-3078` `validate_pfctl_args` accepts only exact argv schemas; there is **no** arm for `["-a", anchor, "-s", "Anchors"]`. Add one, identical in trust shape to the existing read arms at `:3072-3075`:
   ```rust
   ["-a", anchor, "-s", "Anchors"] if is_anchor_name_token(anchor) => Ok(()),
   ```
   Read-only enumeration; the `-f <path>` ban (`:3064-3071`, audit major #5) is untouched. Add the negative test beside `validate_pfctl_args_permits_nat_anchor_show_and_flush_but_not_load` (`:6097`).
2. **Enumerate nested anchors in `list_owned_anchors`** (`phase10.rs:4100-4113`): keep the top-level `["-s","Anchors"]` query, add best-effort `["-a","com.apple","-s","Anchors"]`, union results filtered by the existing `com.apple/rustynet_g` prefix — **not** the broader `MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES` (`macos_dns_failclosed.rs:81-82`, which also admits `com.rustynet/…` e.g. `blind_exit`; the prune sweep must never touch the blind-exit anchor, matching the `is_macos_blind_exit_anchor` guards at `:4035`/`:4117`). Failure posture for the nested query: **best-effort** (a failed nested query degrades to today's no-op sweep, it must not fail the apply — mirrors the enum-fix's posture at `macos_dns_failclosed.rs:521-525` where a missing nested query can only *limit* what is swept, never loosen anything).
   - Naming uncertainty to resolve at implementation time: the repo's verified model of the nested dump is **full-path lines** (`com.apple/rustynet_g5`, `floor_scan_unions_top_level_and_nested_com_apple_anchors`). If the live `pfctl -a com.apple -s Anchors` ever emits bare child names (`rustynet_g5`), normalize by prefixing `com.apple/` before the prefix filter and the flush. Verify live once before merging; write the parser to accept both.
3. **The guard in `prune_owned_tables`** (`phase10.rs:4817-4843`) — capture the live handle BEFORE clearing it, and preserve exactly two anchors, mirroring Linux's active+target:
   ```rust
   let live_anchor = self.anchor_name.clone();          // previous generation, still enforcing
   let target = self.current_anchor_name();             // com.apple/rustynet_g{self.generation}
   for anchor in self.list_owned_anchors()? {
       if Some(&anchor) == live_anchor.as_ref() { continue; }   // active floor: never flush (D2)
       if anchor == target { continue; }                        // target gen: never flush (current-generation guard)
       self.run_allow_failure(Pfctl, &["-a", anchor.as_str(), "-F", "all"]);
   }
   self.anchor_name = None;
   ```
   Use **exact string compare against the two preserved names** rather than parsing `g{N}` numbers out of the path — immune to sub-anchor/mis-parse hazards (`is_rustynet_owned_pf_anchor` demonstrably admits names like `com.apple/rustynet_g10/sub`, macos_dns_failclosed.rs test ~:1270). With the prefix filter from (2), the sweep can only ever contain `com.apple/rustynet_g*` names, so the target-gen guard is fully deterministic.
4. **Keep the M3 re-render, rewrite the comment.** With the guards, prune can no longer drop a live floor, so `:4839-4841` becomes defense-in-depth. Replace the `:4825-4838` text: state that the sweep deletes **strictly older** generations (enumerate→guard→flush), that the live previous-generation anchor and the target-generation anchor are preserved by name, and that the re-render remains as the D2 belt-and-braces for the pins-persist case. Do **not** turn prune into flush-current-then-rerender — that would re-create the pin-without-floor half state and break the D2 no-half-states invariant (`c4ef2583`).
5. **Risk to the green DNS floor:** the live floor anchor is protected twice (live-handle compare + the fact that a fresh daemon's `list_owned_anchors` result never contains a name equal to a handle it doesn't hold — i.e., worst case across a weird handle loss, an old-gen flush drops a floor that the M3 re-render immediately re-establishes under pins, the exact D2 recovery path). Residual risks to gate: the new allowlist arm (read-only; negative test required), and the nested-output naming form (verify live once). The fix must be verified by a focused macOS live-lab cell (restart-accumulation scenario: apply gen 1, restart daemon, apply gen 2, assert `pfctl -a com.apple -s Anchors` no longer lists g1 and still lists g2 with both labeled DNS-block rules) before any claim of done.
6. **Unit tests** (all offline, no root):
   - Nested-enumeration parse: synthetic top-level `"com.apple\n"` + nested `"com.apple/rustynet_g1\ncom.apple/rustynet_g3\n"` → owned list `[g1, g3]`; top-level-only failure degrades to empty.
   - Prune preserves: `set_generation(3)`, live handle `com.apple/rustynet_g2`, owned list `[g1, g2, g3]` → assert flush commands for g1 only; **no** flush of g2 (live) or g3 (target/current-generation guard).
   - Empty enumeration → zero flush commands (today's no-op stays reachable, fail-safe).
   - Sweep never contains `com.rustynet/blind_exit` even when present in output.
   - pf-not-enabled (`stderr` contains `pf not enabled`) → empty, no error.
   - Allowlist: new `["-a","com.apple","-s","Anchors"]` arm accepted; `["-a",x,"-f",path]` still rejected.
   - Repair the stale synthetic test `owned_anchor_names_filters_only_rustynet_anchors` (`:17501-17513`): its input line `com.apple/rustynet_g1` cannot appear in real top-level output — keep it only as a parser-level test with that caveat, and add the union-level test that models real output shapes.

## Citations index

| Claim | Location |
| --- | --- |
| Filter keeps `com.apple/rustynet_g*` lines | phase10.rs:4091-4098 |
| Top-level-only enumeration | phase10.rs:4100-4113 |
| Prune loop + stale D2 comment + M3 re-render | phase10.rs:4817-4843 (comment 4825-4838) |
| Anchor name `com.apple/rustynet_g{generation}` | phase10.rs:3880-3885 |
| Generation rotates every apply | phase10.rs:7115, :7121 |
| Rotate-flush of immediately-previous anchor | phase10.rs:4031-4041 |
| Linux prune design: delete old, preserve active+target | phase10.rs:1026; test :13937-14004 |
| M3 latch puts floor in every render | phase10.rs:3911 (killswitch_spec 3900-3919) |
| pfctl top-level-only semantics established live | commit `2c10f9d9`; macos_dns_failclosed.rs:511-542, :81-82; union test ~:1290-1325 |
| D2 fix premise vs reality | commit `c4ef2583`; phase10.rs:4825-4838 |
| pfctl argv allowlist lacks nested-anchor-list arm | privileged_helper.rs:3053-3078; negative-test precedent :6097 |
| Blind-exit anchor never flushable | phase10.rs:4117, :4035; macos_blind_exit.rs:12 |
| Synthetic test encodes impossible top-level output | phase10.rs:17501-17513 |
| No startup stale-killswitch-anchor reconcile | grep across rustynetd (only exit-NAT/tdns: phase10.rs:4845-4898) |
