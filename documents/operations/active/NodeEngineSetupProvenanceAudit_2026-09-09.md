# Setup-stage distribution provenance audit — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W4: bundle distribution passes on transport exit 0 with no digest read-back (the verifier key HAS one — the asymmetry); label-derived node identity still minted at enforce time (QH-68 class); empty-scope vacuous passes; minter output trusted by listing. Feeds the SETUP batch edit job.

[glm/glm-5.3-flash | AGENT | budget=40 | briefed]

# Rust `--node` live-lab engine — setup-stage provenance audit

## (1) Findings

**F1 — HIGH (ledger integrity). `distribute_membership` / `distribute_assignments` / `distribute_traversal` / `distribute_dns_zone` / `refresh_signed_bundles`: `Passed` means "transport exited 0", not RECEIVED+VERIFIED+APPLIED.**
Input path: `distribute_bundle_kind_inner` (crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs:274-388) issues bundles on the exit adapter, then `run_verifier_barrier` (:392-427) distributes verifier keys to every node and only then installs bundles; `errors.is_empty() → Passed` (:383-384). Per node the bundle leg is: `bundle_path.exists()` on the host (:368-370) → `adapter.distribute_signed_bundle(...)` → Linux impl scp's to `/tmp/rn-*.bundle` then `sudo install` and returns `Ok(())` on exit 0 (adapter/linux_membership.rs:157-199); macOS identical pattern (adapter/macos_membership.rs:708-754); Windows scp + `Move-Item`, exit-code only (adapter/windows_membership.rs:135-186). **Content check location: none for bundles.** The asymmetry is proven by the sibling method: `distribute_verifier_key` *does* read back a remote sha256 and compares to the host digest — `test "$(sudo -n sha256sum '{dst}' | awk '{print $1}') = '{expected_sha256}'" (linux_membership.rs:226-228), `Get-FileHash … throw 'verifier key digest mismatch'` (windows_membership.rs:218-227), `sudo shasum -a 256` (macos_membership.rs:783-792). So the one small file the daemon trusts to verify bundles is digest-attested; the bundles themselves are not. The bundle is staged world-readable in `/tmp` owned by the SSH user until `sudo install` picks it up — a guest-local substitution/truncation between scp and install still yields `Passed`. VERIFIED/APPLIED are never asserted by the orchestrator: the daemon's signature check only surfaces indirectly and later (`enforce_baseline_runtime`), and `validate_baseline_runtime` runs the six generic posture validators (`validate_runtime.rs:110-117`), none of which asserts "the generation I minted is the generation applied". Compounding it: all four distribute rows plus `collect_pubkeys`, `enforce_baseline_runtime`, `validate_baseline_runtime` carry `StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }` (stage/mod.rs:294-306), and `verify_declared_evidence` passes `StageEvidence::None` through unchanged (runner.rs:301-302) — so the QH-83 demotion is a no-op for exactly the stages that establish the trust fabric. The 2026-09-09 run (`36c7017f`, 39 pass / 0 fail / 54 skip, report `state/…/run-2026-09-09-qh83-linux2e` per `lab_run_status`) recorded these passes with zero on-disk witnesses.

**F2 — HIGH (QH-68 class, still live on Linux). Label-derived node identity fallback in `install_daemon` and `enforce_daemon`.**
`adapter/linux_install.rs:62-66` and `:213-217`: `let node_id = ctx.node_ids.get(alias).cloned().unwrap_or_else(|| format!("{alias}-bootstrap"));` and `:55-61`/`:206-212`: `…unwrap_or(NodeRole::Client)`. Provenance: `ctx.node_ids` is daemon-reported (collect_pubkeys → `collect_node_id`, linux_traffic.rs:354+) and is what the signed membership snapshot is keyed by (membership_init.rs:206-276 fails closed on its absence). The `"{alias}-bootstrap"` string is the documented QH-68 mint (the macOS anchor ran as `macos-utm-1-bootstrap`). At *install* time minting is unavoidable (no daemon exists yet to ask). At *enforce* time it is not: `EnforceBaselineRuntime` is transitively downstream of `CollectPubkeys` (enforce_runtime.rs deps `DistributeDnsZone` → … → `MembershipInit` → `CollectPubkeys`, membership_init.rs:22-24), so reaching `enforce_daemon` with `node_ids` empty means a `--skip-stage`/reuse path bypassed collection — and the code silently invents a label-derived identity and passes it as `--node-id` to `e2e-enforce-host` (linux_install.rs:334-338), exactly the query-under-a-guessed-identity shape the macOS anchor stage now refuses ("never guesses", stage/macos_anchor_port_mapping_authority_validation.rs:16-21, 118-133). The `unwrap_or(NodeRole::Client)` role fallback is unreachable from the stage (it iterates `ctx.assignments`, enforce_runtime.rs:41) but is a silent-wrong-posture default for any direct adapter call.

**F3 — MEDIUM. Vacuous `Passed` pinned by tests.** `distribute_membership` with zero non-exit nodes returns `Passed` without contacting anything, and a test pins it (`stage/distribute_membership.rs:118-160` `no_non_exit_nodes_passes_trivially`). `collect_pubkeys` / `enforce_baseline_runtime` / `validate_baseline_runtime` each pass with empty `assignments` (their `empty_assignments_passes` tests). Contrast: the bundle family fails closed on a missing exit (`distribute_assignments.rs:283-286` "no Exit node in assignments"). Failing input: any run that reaches these stages with an empty scope — e.g. reuse/skip paths; I found no guard in plan.rs for my query patterns (unverified, see §6).

**F4 — LOW/MEDIUM. Minter output trusted by listing only.** `issue_bundles_to_dir` (adapter/linux_traffic.rs:1035-1150) runs the issuer, `ls -1` the issue dir (:1130-1134) and scp's back whatever exists (:1140-1144); a zero-file or partial mint returns `Ok(())`, deferring detection to per-node "bundle not found: {fname}" (distribute_assignments.rs:368-370) — a distribution-shaped error for an issuance failure.

Positive controls (verified, not to be broken): verifier-key-before-any-bundle barrier is genuinely two-phase (distribute_assignments.rs:392-427); host-side verifier-key digest validation fails closed (distribute_assignments.rs:344-351); bundle env content is built only from daemon-collected keys/ids and fails closed on any missing entry (distribute_assignments.rs:64-77); membership peers fail closed on missing gossip identity (membership_init.rs:248-264).

## (2) Patches + red tests

**F1a — digest read-back for bundles** (mirror the verifier-key tail; same style in all three adapters; Linux shown):
```rust
// linux_membership.rs, distribute_signed_bundle
let expected = crate::vm_lab::orchestrator::adapter::verifier_key::
    sha256_hex_of_file(bundle_path)?;   // new host-side helper, same crate as validated_verifier_key_sha256
…
"sudo -n install -m {mode} -o {owner} -g rustynetd '{remote_tmp}' '{install_dst}' && \
 sudo -n rm -f '{remote_tmp}'{log_init} && \
 test \"$(sudo -n sha256sum '{install_dst}' | awk '{{print $1}}')\" = '{expected}'"
```
(macOS: `sudo shasum -a 256`; Windows: `Get-FileHash … throw 'bundle digest mismatch'` — copy distribute_verifier_key's script verbatim.)

**F1b — witness + catalog flip (QH-83 mechanism, compile-forced).** In `distribute_bundle_kind_inner`, before returning `Passed`, write `ctx.report_dir.join("logs").join(format!("distribute_{kind}.bundle_evidence.json"))` containing per-alias `{alias, node_id, file, sha256, install_dst}` (any write error ⇒ `Failed`, not best-effort); flip stage/mod.rs:296/299/300/301 and the `RefreshSignedBundles` row to `StageEvidence::File("logs/distribute_<kind>.bundle_evidence.json")` (+ DistributeMembership). The exhaustive match forces the row change to compile; runner.rs:295-325 then demotes any unwitnessed `Passed` to `NotProven`.
Red tests: `bundle_digest_mismatch_fails_distribution` (mutation: delete the digest tail from the install script — fixture asserts the remote-digest command is present and that a mismatched sha errors, QH-86-style real-shaped negative); `distribute_pass_without_witness_is_demoted_to_not_proven` (mutation: revert the catalog row to `StageEvidence::None` — fake-adapter run through `StateMachineRunner` must produce `NotProven`).

**F2 — fail closed at enforce; name the mint at install:**
```rust
// enforce_daemon (linux_install.rs:213-217)
let node_id = ctx.node_ids.get(alias).map(String::as_str).ok_or_else(|| AdapterError::Protocol {
    message: format!(
        "{alias}: no daemon-reported node id recorded (collect_pubkeys must run first); \
         refusing to mint a '{alias}-bootstrap' identity for enforcement")
})?;
// install_daemon keeps the mint, made explicit:
fn mint_bootstrap_node_id(alias: &str) -> String { format!("{alias}-bootstrap") }
```
Red test: `enforce_daemon_refuses_to_mint_node_id_when_context_has_none` (mutation: restore `unwrap_or_else`).

**F3 — empty scope fails closed** in DistributeMembership (`if non_exit.is_empty() { Failed("no non-exit node in assignments") }`) and in the three PerNode setup stages (`if aliases.is_empty() { Failed("no assignments in scope") }`); update the pinning tests to expect `Failed`.
Red test: `distribute_membership_fails_closed_when_no_non_exit_nodes` (mutation: revert the guard).

**F4 — assert the mint is complete** after the scp-back loop in `issue_bundles_to_dir`: error naming each expected `rn-<prefix>-{node_id}.{ext}` absent from the listing ("issuer did not mint …"), instead of `Ok(())` on an empty/partial `ls`.
Red test: `issue_bundles_errors_when_minter_mints_a_subset` (mutation: drop the completeness check).

## (3) Gate that kills the class

Two source pins in the existing scanner style (`no_stage_spells_bundle_file_names_inline`, refresh_signed_bundles.rs:161-193): (a) every `distribute_signed_bundle` implementation slice must contain a remote-digest assertion (`sha256sum|shasum -a 256|Get-FileHash`) — "no exit-code-only install"; (b) the literal `-bootstrap` mint and `unwrap_or(NodeRole::` appear only in the allowlisted install sites. Plus a catalog test forbidding `PHASE1_EVIDENCE_PENDING` on any stage whose id is in the setup trust-fabric set, so the witness column cannot regress to `None`.

## (4) Effort

F1 = M (three adapter tails + evidence write + catalog flip + tests). F2, F3, F4 = S each.

## (5) Could not verify

- Daemon-side behavior of `e2e-enforce-host` (whether its internal restart poll actually fails non-zero on bundle rejection) — not read; `enforce_daemon`'s assertiveness on Linux rests on that remote script.
- Whether the plan builder guarantees non-empty assignments (my plan.rs grep patterns found no guard; resolved_plan.rs/native.rs not read), which conditions F3's live reachability.
- The per-stage rows of run `livelab-1788919346` / `run-2026-09-09-qh83-linux2e` (report dir lives on the lab host; `lab_run_detail` could not resolve it locally), so "the distribute stages passed unwitnessed in that run" is inferred from the catalog rows + stage code, not read from its stages.tsv.
- Windows/macOS `install` scripts were verified digest-free via grep context, not full-file reads.

## Tools used (53 call(s); step budget of 40 reached)
