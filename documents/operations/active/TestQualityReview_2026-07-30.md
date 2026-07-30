# Test Quality Review — 2026-07-30

Companion to `TestInventory_2026-07-30.md`. That document says what exists. This
one asks whether it does what it claims, and says why not where it doesn't.

**No code was changed to produce this.** Nothing was run except read-only
inspection: `rg`, `grep`, `sed`, `git log`, `bash -n`. No gate, test, VM or e2e
script was executed.

---

## 1. Method, and how to read a verdict

Two independent passes, each fanned out across the repo and each followed by a
second agent whose instructions were to **refute** the first:

- **Pass 1 — inventory and critique.** 7 surfaces → 253 inventory entries →
  130 findings → adversarial verification of every finding.
- **Pass 2 — duplication and consolidation.** 4 areas → 50 proposed merges →
  adversarial verification of every merge.

| Verdict | Findings | Meaning |
| --- | --- | --- |
| **CONFIRMED** | 109 | verifier opened the file and reproduced the reasoning |
| **PLAUSIBLE** | 11 | real concern, could not be fully established |
| **REFUTED** | 9 | the reasoning did not survive; listed in §8 |

The refuted ones are published deliberately (§8). A review that reports only
what it found is not auditable.

Two findings in this document were additionally verified by hand before
publication, because they are the most consequential: the dead
`run_security_audit_and_deny` body (§4.1) and the `require_cargo_subcommands`
skip (§6). Both confirmed.

---

## 2. Headline

The Rust unit-test suite is, on the whole, **good** — better than its size would
lead you to expect, with several modules that are exemplary (§9). The problems
are concentrated somewhere else entirely:

> **The shell-gate and CI-wiring layer is where the testing story breaks down.**
> Of 51 gate scripts, 2 are wired into CI. Two more have been failing on every
> invocation for over a year and nobody noticed, because nothing invokes them.
> And the function that runs `cargo audit` and `cargo deny` returns `Ok(())`
> before reaching either command.

The single most useful sentence in this document: **on this repo, a green result
does not distinguish "the check passed" from "the check never ran".** That
pattern recurs at every layer, from a Rust `assert!` that matches its own source
text, to a leak capture that scores a dead `tcpdump` as clean, to a bash
orchestrator whose verdict ignores skips.

---

## 3. Systemic patterns

Individual findings are listed below, but they cluster into six recurring
shapes. Fixing the shape is worth more than fixing the instances.

### 3.1 Source-text pins that match their own source

The idiom is `include_str!("this_file.rs")` then `assert!(source.contains(needle))`.
Because `include_str!` includes the test module, and the needle is a string
literal *inside that test*, the assertion is true by construction.

Seven of these were confirmed across five files, guarding the killswitch boot
chain, membership file security, and anchor genesis capabilities.

The repo already knows the correct form: sibling pins in `rustynet-crypto`
(`lib.rs:2177`), `rustynet-relay` (`transport.rs:2947`) and `rustynetd`
(`daemon.rs:15854`) deliberately assemble the needle at runtime via
`concat!`/`format!` so it cannot appear literally in the file. **The fix is to
apply the existing convention consistently**, not to invent one.

### 3.2 "Could not measure" scored as "measured clean"

The most dangerous shape in the repo, because it inverts on exactly the runs
that matter.

- IPv6 leak capture treats a `tcpdump` that spawned and instantly died — no
  `CAP_NET_RAW`, exhausted `/dev/bpf*`, bad interface — as **zero leaked
  datagrams** (§5.6).
- `no_unexpected_bypass_routes` turns a failed route-table capture into `""` via
  `.unwrap_or_default()`, iterates zero lines, and reports PASS (§5.7).
- `probe_service_blocked_from_client` scores *any* command failure — SSH down,
  sudo denied, binary missing — as proof that traffic was blocked.

In each case the check reports its strongest result precisely when it learned
nothing.

### 3.3 Grep gates asserting constants the code emits unconditionally

`chaos_gates.sh` makes 20 JSON assertions. Every one is a hard-coded literal in
the report builder (`live_chaos_support/mod.rs:155`, `:164`, and the per-binary
`json!` blocks) — not a measured value. If the chaos suite regressed to
accepting a forged bundle, `"production_accepted": false` would still be printed
and all 20 greps would still pass. The gate asserts that nobody edited those
constants.

### 3.4 Conformance suites run only against doubles

`run_conformance_suite` — the TunnelBackend contract — lives in an integration
test binary, which **no other crate can import**. Its doc comment says "any
crate that ships a TunnelBackend implementation should run this full suite";
that is unenforceable by construction. Its only two callers are `ContractBackend`
(an inline mock in the same file) and a hand-copied duplicate of all 19
scenarios in `rustynet-backend-stub`, run against another in-memory double.

Zero production backends run it. `LinuxWireguardBackend`, `MacosWireguardBackend`,
`WindowsWireguardBackend`, `LinuxUserspaceSharedBackend`,
`MacosUserspaceSharedBackend` and `UserspaceBackend` could violate every contract
rule and the suite stays green.

### 3.5 Gates that pass by not running

- `windows_cross_compile_gate.sh` exits 0 with `SKIP` at six separate missing
  preconditions and has no "at least one leg ran" assertion — it prints PASS
  after compiling zero crates.
- Seven gate scripts run bare `cargo test <filter>`, which **exits 0 when the
  filter matches zero tests**. Six sibling gates use `run_required_test.sh`,
  which has a zero-match guard. The convention exists; it is applied
  inconsistently.
- Two gates run `cargo test -p rustynet-cli --bin rustynet-cli vm_lab::…`
  without `--features vm-lab`, so every filter matches zero tests and the gate
  passes having run nothing.

### 3.6 Coverage claimed by grepping for the existence of code

`cross_platform_role_gates.sh` makes 37 `rg -q` assertions that macOS and
Windows validator *functions exist in the source*. That is the only mechanical
thing standing behind the cross-platform claim. It checks for function names in
`.rs` files, not for observed behaviour — and the ledgers confirm the gap:
**50 evidence columns have never recorded a single pass in 646 logged runs**
(§5.8).

---

## 4. Critical

### 4.1 `cargo audit` and `cargo deny` never run from the gate that names them

`crates/rustynet-cli/src/ops_ci_release_perf.rs:1606-1612` — verified by hand:

```rust
fn run_security_audit_and_deny(
    _root_dir: &Path,
    _security: &SecurityCargoContext,
) -> Result<(), String> {
    println!("Skipping run_security_audit_and_deny on remote host (verified locally).");
    return Ok(());
    #[allow(unreachable_code)]
    let mut env_pairs_owned = Vec::new();
    …
```

The `return Ok(())` is **unconditional** — there is no `if remote {}` guard, and
the `#[allow(unreachable_code)]` suppresses the warning that would have exposed
it. The ~55 lines below, which build
`cargo audit --deny warnings --stale --no-fetch --db <db>` and
`cargo deny check bans licenses sources advisories`, never execute.

Four gate entry points call it and treat `Ok(())` as "security audit passed",
including `execute_ops_run_supply_chain_integrity_gates` — the function behind
`scripts/ci/supply_chain_integrity_gates.sh`, a script whose entire name is
supply-chain integrity.

The message reveals the intent: skip on a *remote* host because it was verified
locally. The implementation forgot the condition.

*Mitigating:* the macOS and Debian CI legs invoke `cargo audit` and `cargo deny`
directly in YAML, so the workspace is not unaudited. What is dead is the gate
path — the one the live-lab release flow depends on.

### 4.2 `anchor_downgrade_gates.sh` cannot pass — a regex mistake

`scripts/ci/anchor_downgrade_gates.sh:7`

```sh
rg -q 'epoch_new != state.epoch.saturating_add(1)' crates/rustynet-control/src/membership.rs
```

`rg` treats the argument as a regex, so `(1)` is a capture group and the pattern
requires the literal text `saturating_add1`. The source reads
`saturating_add(1)`. Verified read-only: the regex form returns rc=1, the `-F`
fixed-string form returns rc=0.

Under `set -euo pipefail` the script exits 1 at line 7 **every time**. Lines 8-16
never execute — two further pins and all six targeted tests the gate exists for,
including `replay_and_rollback_are_rejected`.

### 4.3 `anchor_secret_redaction_gates.sh` has been red for ~14 months

`scripts/ci/anchor_secret_redaction_gates.sh:12-15` greps for token/secret
context in anchor bundle-pull log lines. Running it read-only produces exactly
one hit — and it is a deliberate negative-test fixture:

```rust
// crates/rustynet-cli/src/bin/live_linux_anchor_test.rs:3511
let leaky = "Jul 01 anchor_bundle_pull: peer=relay-1 token=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
```

The grep has no test-file exclusion, so the failure branch is taken and the
script exits 1. The fixture landed in `835f0897` (2026-05-26), three days after
the gate (`63e49ac1`, 2026-05-23). Lines 17-25 — the real negative grep and all
four required redaction tests — have never run.

**4.2 and 4.3 together are the proof of §5.1**: two gates have been failing on
every invocation for over a year without anyone noticing, because nothing
invokes them.

### 4.4 A release tag cannot produce a release

`.github/workflows/release.yml:73` builds `rustynet-cli` for
`x86_64-pc-windows-msvc` with no `if:` guard, but `rustynet-cli` is
unconditionally Unix-only — `crates/rustynet-cli/src/main.rs:91-93` has three
unguarded `std::os::unix::*` imports and `Cargo.toml:117` depends on `nix`
unconditionally. Both `cross-platform-ci.yml:200-203` and
`windows_cross_compile_gate.sh:61` state the crate cannot build for Windows.

Pushing a `v*.*.*` tag fails that matrix leg. `fail-fast: false` lets the others
finish, but `manifest` has `needs: build`, so it is skipped: **no signed
manifest and no GitHub Release at all**. `release.yml` has no push/PR trigger, so
this is invisible until the first real tag.

---

## 5. High

### 5.1 49 of 51 gate scripts are wired into no workflow

`grep -rn 'scripts/ci/' .github/workflows/` returns two scripts:
`bootstrap_ci_tools.sh` and `lab_monitor_gates.sh`. Seventeen more run only
inside `live_linux_lab_orchestrator.sh:5176-5192`, itself guarded by
`has_five_node_release_gate_topology`. Two run as a side effect of `ops`
phase-artifact generation. The remaining **~32 — every anchor, role, NAS, LLM,
chaos, orchestrator and regression-coverage gate — execute only when a human or
agent explicitly asks.**

### 5.2 Seven source-text pins that cannot fail

| Test | File |
| --- | --- |
| `boot_killswitch_source_contains_traversal_endpoint_rule` | `rustynetd/src/linux_killswitch_boot.rs:1292` |
| `boot_killswitch_source_contains_wg_listen_port_rule` (2 of 4 asserts) | `linux_killswitch_boot.rs:1240` |
| `membership_init_genesis_includes_anchor_sub_caps` | `rustynetd/src/main.rs:5922` |
| membership file-security pin | `rustynet-control/src/membership.rs:5676` |
| `anchor_restore_uses_the_audited_helper_not_a_local_temp_file` | `macos_exit_killswitch_precedence.rs:497` |
| `trust_bundle_loaders_use_bounded_reader_only` | `rustynetd/src/daemon.rs:19452` |
| `ipc_read_failure_is_non_fatal_in_accept_loop` | `daemon.rs:16751` |

Each guards a documented regression. Delete the guarded code and the test still
reports pass. The genesis one is additionally a whole-file grep, not scoped to
`run_membership_init`.

### 5.3 `rustynet-control/src/admin.rs` — four "security" tests on a dead module

`policy_bootstrap_defaults`, `default_web_security_headers`,
`validate_privileged_command`, `command_preview` and `contains_shell_meta` are
all `#[cfg(test)]` — they do not exist in a shipped binary.
`policy_bootstrap_defaults_to_safe_values` inserts two literals and asserts the
same two come back out. `WebSecurityHeaders` is never constructed outside this
file. The privileged-command tests exercise a test-only validator; the real argv
allowlist lives in `rustynetd/src/privileged_helper.rs` and is untouched.

Three of these are named as **required gates** in
`crates/rustynet-cli/src/bin/phase6_gates.rs:66/72/78`.

### 5.4 Every secret-leak scanner is line-scoped

`rustynetd/src/secret_log_audit.rs:140-171` (and the same shape at 1971-2032,
plus the hex/base64/dbg scanners) requires the macro name and the format
placeholder to be on the **same physical line**. rustfmt routinely splits long
log calls across lines — `daemon.rs:551-553`, `608-610`, `680-682`, `743-745`,
`4611-4613` are exactly that shape, and there are ~100 such wrapped openings
across `daemon.rs`, `main.rs`, `gossip_runtime.rs` and `phase10.rs` alone.

Add a wrapped `eprintln!(\n "key={passphrase_bytes:?}"\n);` in an audited root
and all four workspace scanners still report zero offenders. All 20+ scanner
unit tests use single-line fixtures, so the blind spot is neither tested nor
documented.

### 5.5 The CI-gated e2e kill-switch check cannot fail

`crates/rustynet-cli/src/bin/real_wireguard_exitnode_e2e.rs:386-394` — this is
the **only** live scenario in CI.

```rust
run_ns_ok(&ns_client, ["ip", "link", "set", "wg0", "down"])?;
let _ = run_status(ns_command(&ns_client, ["ip", "route", "del", "default", "dev", "wg0"]));
if run_expect_failure_ns(&ns_client, ["ping", "-c", "1", "-W", …]) { … }
```

The test brings `wg0` down **and deletes the default route**, then asserts the
ping fails. With `dns_server_ip` outside the only remaining link route, the ping
returns `Network is unreachable` by routing-table arithmetic.
`run_expect_failure_ns` accepts any non-zero code.

No RustyNet kill-switch exists in that namespace — the binary never invokes
`rustynetd`, and the only nft rules are a hand-written literal installed in the
*exit* namespace. Delete RustyNet's kill-switch entirely and this check passes.

### 5.6 IPv6 leak capture: a dead `tcpdump` reads as "no leak"

`rustynetd/src/linux_ipv6_leak.rs:481-519`, identical at
`macos_ipv6_leak.rs:219-253`. `Command::spawn()` returns `Ok` as soon as the
child is forked; tcpdump then dies instantly without `CAP_NET_RAW`, on exhausted
`/dev/bpf*`, or on a bad interface. stderr goes to `/dev/null`, `kill()`/`wait()`
are `let _ =`, and the follow-up `tcpdump -r` failure is swallowed by
`.unwrap_or_default()` into an empty string. `count_pcap_datagrams("") == 0` →
`leaked_datagram_count=0`.

Meanwhile `probe_attempted = ping_status.is_ok()` is true for *any* exit status,
including a usage error. The validator then sees `probe_attempted=true,
leaked=0` and records a clean IPv6-leak proof.

### 5.7 `no_unexpected_bypass_routes` passes vacuously

`ops_live_lab_orchestrator.rs:2404-2426`. The producer uses
`.unwrap_or_default()`, so a failed capture becomes `""`; `"".lines()` yields
nothing; the loop never runs; the check reports PASS. Its two sibling checks use
`.contains(...)` and fail safe on an empty capture — only the loop-based one is
vacuous. It gates `CHECK_REMOTE_EXIT_SERVER_IP_BYPASS_IS_NARROW`, a canonical
cross-network pass criterion.

### 5.8 The bash orchestrator's verdict ignores skips

`live_linux_lab_orchestrator.sh:1381-1396`. `record_stage_skip` never calls
`update_overall_status`, and `update_overall_status` returns early for any
non-`fail` status. So `--skip-stages`, `--skip-to`, `--rerun-failed`,
`--skip-cross-network`, `--skip-soak`, `--skip-gates` and the default chaos-off
path all leave `OVERALL_STATUS=pass`.

A run driven with `--skip-to live_two_hop` that passes one stage writes
`overall_status: "pass"` and appends a `pass` row to
`live_lab_run_matrix.csv` — which this repo treats as parity evidence.

**The Rust engine gets this right**: `live_lab_evidence_verifier.rs:138-148`
classes `Skip` as `is_incomplete` and demotes a marker-claimed pass to
`partial`. Visible in the ledger: all 97 `--node` rows are fail or partial, zero
pass. The bash path, which produced the other 549 rows, does not.

### 5.9 Fifty evidence columns have never passed

Tallying both ledgers (646 rows), 50 stage/proof columns contain zero `pass`:
every macOS live stage except two-hop, every Windows live stage except
two-hop/hello-limiter, chaos on all three OSes, `cross_os_exit_path`,
`cross_os_lan_toggle`, `cross_os_anchor_enrollment`, `cross_os_role_switch`,
`macos_pf_killswitch`, `macos_keychain_key_custody`,
`linux_stage_mixed_topology`, and all three `*_blind_exit_dataplane_check`
columns.

### 5.10 Other high findings

| Finding | Location |
| --- | --- |
| TunnelBackend conformance never hits a real backend (§3.4) | `backend_contract.rs:205` |
| `phase1_backend_contract_perf_report` asserts nothing, times an inline mock | `backend_contract_perf.rs:234` |
| `minted_token_encoded_form_does_not_contain_raw_secret` cannot detect its leak — searches for raw 0xef bytes inside a base64 ASCII string | `rustynetd/tests/enrollment_token_audit.rs:29` |
| LLM gateway default-deny admission path (`admitted_peer`, `load_access_state`, key/bind validators) has zero tests | `rustynet-llm-gateway/src/main.rs:278` |
| 218 dependency packages in `gui/`, `lab-monitor` and `fuzz/` are seen by no `cargo audit`/`cargo deny` | `Cargo.toml:31`, `fuzz/Cargo.toml:38` |
| `chaos_gates.sh` asserts hard-coded literals (§3.3) | `chaos_gates.sh:56-62` |

---

## 6. Medium and low — grouped

**Cannot fail / vacuous** — `contract_exit_mode_off_is_default` asserts nothing;
`contract_configure_peer_replaces_existing` discards the result it needs;
`contract_routes_*` never read routes back; `userspace_backend_capabilities_struct_is_well_formed`
has no assertion on Linux; `backend_contract_ipv6_endpoint_accepted_if_supported`
discards the result it is named after; `check_ssh_reachable_fn_exists` is a
compile-time coercion; `role_transition_and_platform_support_agree` compares a
function to itself; `security_gates_are_unique_and_nonempty` asserts `len() >= 2`
on a 10-entry list; `assert_eq!(read_to_string(&utmctl_log).unwrap_or_default(), "")`
on a file nothing creates; the phase1 bench is a `#[test]` asserting a fixed
arithmetic identity.

**Self-referential** — netns-probe's STUN "wire-format pin" asserts the
encoder's own constant, not the RFC literal; `orchestrator_stages_doc_matches_the_rust_planbuilder`
never reads `StageId::ALL`; `platform_gate_matches_code` pins `repo_context`'s
own table; the signed-state chaos suite validates its manifest against the same
static table that generated it; HKDF "golden vectors" are hex values produced by
the implementation under test; `test_subtle_crate_is_used_for_constant_time_comparisons`
tests the `subtle` crate.

**Never runs** — the whole `rustynet-backend-wireguard` conformance file is
`#![cfg(feature = "test-harness")]`, a non-default feature; the Linux userspace
conformance suite is env-gated on a variable set nowhere in the repo; the
workspace's only doctest is run by neither nextest nor the documented gate;
`gui/node-map-tool`'s 7 tests are compiled by nothing; boringtun's 5 vendored
benches are excluded by `autobenches = false`; `observe_system_diagnostics_smoke`
is `#[ignore]`d; `rustynet-sysinfo`'s `#[cfg(target_os = "windows")]` tests never
compile because the crate is outside the Windows leg.

**Supply chain** — `require_cargo_subcommands()` hard-codes `audit` and `deny` to
`continue`, making the presence check a no-op (verified by hand);
`rustup default 1.85.0` is overridden by `rust-toolchain.toml`, so the MSRV pin
is never exercised; `cargo deny` runs without `--deny warnings` while `deny.toml`
sets `multiple-versions=warn` and `wildcards=allow`; the advisory DB has no
freshness check; macOS release codesign failure is swallowed by `|| true`; no
workflow has a `schedule:` trigger.

**Scope** — `regression_coverage_gates.sh` floors 22 of ~60 `rustynetd` modules
and seven floors sit 3-20 tests below actual, so whole groups can be deleted
silently; the deprecated-crypto lockfile scan covers only the root workspace; the
"no API-key mechanism" gate scans one crate.

---

## 7. Duplication and consolidation

50 candidate merges were proposed; each was checked by a second agent instructed
to mark it **UNSAFE** if merging would lose a distinct assertion, platform path,
privilege boundary, or failure message.

| Verdict | Count |
| --- | --- |
| SOUND — merge is safe | **24** |
| UNSAFE — would lose coverage | **17** |
| ALREADY-DISTINCT — do not actually overlap | **9** |

**52% of proposals were rejected.** Worth stating plainly: a naive dedup pass
over this repo would have removed real coverage.

### 7.1 The suite is much less duplicated than its size suggests

All 7,269 test bodies were normalised (comments stripped, literals collapsed) and
hashed. Only ~8% fall into any duplicate cluster. `vm_lab/mod.rs` — 56k lines,
663 tests — has just 88 in near-duplicate clusters. **It is genuinely distinct
coverage, not copy-paste.**

### 7.2 Worth merging (SOUND)

| What | Scale |
| --- | --- |
| 15 byte-identical copies of a 7-line `outcome_for` helper across stage files, each with its own 3 tests | 45 tests → ~3 |
| `help_text_advertises_*` in `rustynetd/main.rs` — one assertion, 28 literals | 28 → 1 table-driven |
| systemd-directive drift tests differing only in `(directive, bad value)` | 14 → 1 |
| `reported_skip_note` across 12 stage files | 12 → 1 |
| `evaluate_runtime_acl_rejects_*` SDDL cases | 13 → 1 table |
| deprecated-crypto import scanners differing only in crate name | 8 → 1 |
| `exit_ok` fixture copy-pasted into 13 role_validation modules | 13 → 1 shared fixture |
| identical frame codec + `CountingSink` in `rustynet-nas` and `rustynet-llm-gateway` | 1 shared module |
| four 95-line Rust gate binaries byte-identical except one string literal | 4 → 1 |
| `run_required_test()` bash helper pasted verbatim into six gate scripts | 6 → 1 source |
| `TunnelBackend` conformance suite copy-pasted between `backend-api` and `backend-stub` — **and already drifted** | 1 shared crate |

That last one is both a duplication and a correctness finding: the copies have
diverged, so the two crates now test slightly different contracts.

### 7.3 Do **not** merge (UNSAFE / ALREADY-DISTINCT)

Recorded so the same proposals aren't re-raised:

- `remote_shell_tests.rs`'s 64 byte-identical tests across the bin-support shim
  and the orchestrator. The duplication is real, but the two modules pin
  **different constructor signatures and different fail-closed error types**
  (`String` vs `AdapterError::UnsupportedPlatform`). Dedup the *production*
  helpers first; the tests then fold for free.
- 28 gate scripts byte-identical modulo one `--bin` name — verifier: keep them,
  the distinct names are the failure message.
- `capture_linux_*` vs `capture_macos_*` per-OS pairs — the platform-specific
  assertions are the point.
- direct vs relay remote-exit, and controller-switch vs node-network-switch —
  67% textual overlap, genuinely different legs.
- MAC/ARP helpers shared between `rustynet-cli` and `rustynet-mcp`.
- Chaos-bin argument-parser tests across four binaries.
- `scripts/vm_lab/` is already clean — only 18 redundant lines.

### 7.4 Duplication that is a defect, not just waste

- **`phase10` CI gates lost `-- -D warnings`** on clippy through copy-paste drift
  across five identical preambles. That gate has been passing on warnings it was
  written to reject.
- **`membership_gates.sh` re-runs clippy on a §7-covered scope with weaker
  flags** than the mandatory gate, so it can go green where the real gate fails.
- The phase-gate chain **re-runs the full workspace suite 7× per invocation**
  (phase10 → phase9 → … → phase4). Pure machine time.
- `lab_monitor_gates.sh` runs `cargo check` immediately after `cargo clippy` —
  the exact redundancy this repo's own gate documentation calls out.
- `test_validate_cross_network_remote_exit_reports.sh` is **dead** — bypassed
  entirely. A deletion candidate, not a merge candidate.

---

## 8. What did not survive verification

Nine findings were refuted. Published because a review that hides its
false positives cannot be trusted on its true ones.

| Claim | Why it failed |
| --- | --- |
| `signing_key_loader_accepts_owner_only_file` never round-trips the key | Literally true, but `rustynet-crypto/src/lib.rs:2483` already round-trips through the same path |
| STUN IPv6 response never parsed back | Code facts right, but `run_nat_classify` binds an AF_INET socket, so the v6 path is unreachable |
| `nas_args_help_text_snapshot` pins nothing | The sibling test immediately above drives the real parser with that exact flag |
| perf gate has no baseline | `load_perf_metrics` *does* fail on any metric with status `fail`/`not_measurable` |
| blocker-string tests are change-detectors | They fail on any change to the value, which is what their names declare |
| Windows DPAPI path compiled nowhere | `rustynetd` depends on it unconditionally and **is** in the Windows leg |
| `triple-des` banned only by an unrun script | Also enforced by `FORBIDDEN_DEPRECATED_CRYPTO_CRATES` in `secret_log_audit.rs:1515`, which runs in CI |
| Parallel stage with zero workers passes | `build_nodes_file` always records literal labels; the scope cannot match zero rows |
| Chaos negative control accepts any non-zero exit | The positive control ten lines above blocks the named exploit |

---

## 9. What is genuinely strong

Stated because the defect list above would otherwise misrepresent the repo.

- **`rustynet-policy` and `rustynet-crypto` are near-exemplary.** Explicit
  anti-vacuity controls, mutation-checked negative cases, and comments that
  honestly state where a test does *not* discriminate the fix.
- **The eight `*_audit.rs` self-audit modules** drive the real shipped evaluators
  through adversarial funnels, each with a deny-side case *and* an allow-side
  control. `policy_default_deny_audit` contains a deliberate **bite probe** that
  mislabels a case to prove the harness reports violations. That is the correct
  way to prove a test can fail, and it is already in this repo.
- **The membership model conformance test** is a real bounded 6³ model check with
  an anti-vacuity floor.
- **`live_lab_evidence_verifier.rs`** treats skips as incomplete and demotes
  marker-claimed passes to `partial` — a genuinely independent verdict authority.
  It is strictly better than the bash orchestrator it runs beside (§5.8), and the
  ledger shows it: zero false `pass` rows on the `--node` path.
- **The `run_required_test.sh` zero-match guard** and the runtime-assembled
  source pins are both correct patterns that already exist here. Most of §3.1
  and §3.5 is a matter of applying them consistently, not inventing anything.

---

## 10. Suggested order

Ordered by "how much does fixing this change what a green run means", not by
effort.

1. **§4.1** — remove the unconditional `return Ok(())`, or make it conditional as
   its own message intends. Everything else in supply chain is downstream of it.
2. **§4.2, §4.3** — two gates red for over a year. Also decide the general
   question they raise: a gate nothing runs is indistinguishable from a gate that
   does not exist.
3. **§5.1** — wire the gates to CI, or delete them. The current state is the
   worst of both: maintained but not run.
4. **§3.2** — the "could not measure = clean" class (§5.6, §5.7). These invert on
   exactly the runs that matter.
5. **§4.4** — before the next release tag, not after.
6. **§3.1, §3.5** — apply the conventions the repo already has.
7. **§7** — consolidation, once the above are settled. The 24 SOUND merges remove
   ~190 tests without losing an assertion.
