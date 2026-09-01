# Security-audit catalog references paths that no longer exist (RSA-0049 class)

**Status:** RESOLVED 2026-09-01 (see [Resolution](#resolution-2026-09-01) below).
Raised 2026-07-28, verified against `b285685e`.

## What is wrong

`crates/rustynet-cli/src/security_audit_catalog.rs` names repository paths in its
`affected_files` arrays and in check `argv` lists. The catalog feeds an
operator-facing security-audit / ops report, so every path it names reads as an
audited enforcement point.

Two of the 11 repo-path strings in that file do not exist on disk.

### 1. `:279` — `crates/rustynetd/src/dataplane.rs` (deleted)

In the `affected_files` of the `server_ip_bypass` `ValidationSpec`:

```rust
affected_files: &[
    "crates/rustynetd/src/phase10.rs",
    "crates/rustynetd/src/dataplane.rs",     // <- deleted 2026-06-26
    "crates/rustynet-backend-wireguard/src/lib.rs",
],
```

Deleted by `a39a70aa` (2026-06-26), *"security: retire dead dataplane.rs, point
phase-4 assurance at the live path (RN-02)"*.

That same commit already handled the sibling case — the comment at `:415` records
the removal for the `phase4_fail_closed` comparative spec. This occurrence was
missed, so one spec was updated and the other was not.

`crates/rustynetd/src/phase10.rs` is already listed immediately above at `:278`
and is the live path, so the stale line most likely just needs deleting rather
than replacing.

### 2. `:693` — `documents/operations/SecurityHardeningBacklog_2026-03-09.md` (moved)

This one is NOT in an `affected_files` list — it is an argument to a check that
actually runs:

```rust
argv: &[
    "rg", "-n",
    "constant-time auth/token checks",
    "documents/operations/SecurityHardeningBacklog_2026-03-09.md",
],
```

The file was relocated by `1d471846` ("Harden daemon state handling and
reorganize operations docs") and now lives at
`documents/operations/done/SecurityHardeningBacklog_2026-03-09.md`. A separate,
newer `documents/operations/active/SecurityHardeningBacklog_2026-06-01.md` also
exists, so part of the fix is deciding WHICH document this check is supposed to
interrogate — the archived 2026-03-09 one it was written against, or the current
active backlog.

**Open question worth answering first:** what does the harness do when `rg`
targets a missing file? `rg` exits 2 with an error, but if the runner treats any
non-zero exit as "pattern not found" then a moved file silently becomes a
*passing* check. If so this is not merely a stale path — it is a check that
reports success while inspecting nothing, which is materially worse than the
`affected_files` case and should be graded accordingly.

## Why it matters

This is the assurance-over-claim class the audit ledger tracks as **RSA-0049**
(`documents/operations/active/SecurityAuditLedger_2026-06-18.md`): a report that
names an enforcement point which does not exist. A reader of the audit output
reasonably concludes those files were examined.

It is also the same shape as several defects found on 2026-07-27 — presence
cited as proof of enforcement. A path in a catalog looks like coverage; a symbol
in a file looks like a control; a green check looks like a verified property.
In each case the artifact and its description agree with each other while nothing
inspects the runtime.

## Fix

1. Delete the `crates/rustynetd/src/dataplane.rs` entry at `:279` (`phase10.rs`
   already covers the live path).
2. Decide which `SecurityHardeningBacklog` the `:693` check should read, and
   point it there. Answer the `rg`-exit-code question above first, because it
   determines whether this is a stale reference or a silently-passing check.
3. **Add a test that every repo path named in the catalog exists.** This is the
   part that closes the class rather than the two instances. A scan of the file
   for quoted strings matching `^(crates|scripts|documents|third_party|\.github)/`
   found 11 candidates, of which these 2 are missing — so the test is cheap and
   the current violation count is small.

   Mutation-verify it: reintroduce a bogus path and confirm the test fails. A
   test that cannot fail is worse than no test, and this catalog is exactly the
   kind of data-driven table where a "test" that iterates nothing looks green
   forever.

4. Run the normal gates afterwards: `cargo fmt --all -- --check`;
   `cargo build -p rustynet-cli`; `cargo check -p rustynet-cli --bin rustynet-cli`;
   `cargo check --workspace --all-targets --all-features`;
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
   `cargo test --workspace --all-targets --all-features`.

   Read real exit codes, not a wrapper's. A test filter that matches nothing
   prints `ok. 0 passed; N filtered out` — read the COUNT, never the word "ok".

## Verification already done

Confirmed against `b285685e` on 2026-07-28:

- `:279` does still list `crates/rustynetd/src/dataplane.rs`; the file is absent
  from disk; `a39a70aa` (2026-06-26) is the commit that removed it.
- `:693`'s target is absent from that path and present at
  `documents/operations/done/`.
- 11 repo-path strings referenced by the catalog, 2 missing.
- No existing test asserts that catalog-referenced paths exist.

## Resolution 2026-09-01

1. **`:279` dataplane.rs — deleted.** The stale entry was removed from the
   `server_ip_bypass` `affected_files`; `crates/rustynetd/src/phase10.rs` already
   covered the live path, as predicted.
2. **`:693` backlog path — repointed to the archived doc.** The check now reads
   `documents/operations/done/SecurityHardeningBacklog_2026-03-09.md`, which is
   where the marker string ("constant-time auth/token checks", its line 141)
   actually lives. The active
   `documents/operations/active/SecurityHardeningBacklog_2026-06-01.md` does not
   contain the marker, and the comparative-coverage document
   (`RustynetComparativeVpnExploitCoverage_2026-03-14.md`, lines 202/361/651)
   records the original verification as having run against the archived copy —
   so the archived doc is the faithful target.
3. **rg-exit-code question answered — no silent-pass hazard.** The consumer,
   `run_comparative_commands` in
   `crates/rustynet-cli/src/ops_security_audit_workflows.rs` (the `rc`/`status`
   assignment), sets `status = rc == 0 ? "pass" : "fail"` from
   `output.status.code().unwrap_or(1)`. A missing file makes `rg` exit 2, which
   is reported as `fail` with the stderr captured in the report output — the
   harness never treats a non-zero exit as "pattern absent". The stale path was
   therefore a stale reference (a report that names something it cannot
   inspect), not a silently-passing check.
4. **Class-closing test added.**
   `security_audit_catalog::tests::catalog_repo_path_references_exist_on_disk`
   (in `crates/rustynet-cli/src/security_audit_catalog.rs`) asserts every
   catalog string matching `^(crates|scripts|documents|third_party|\.github)/` —
   across both `LIVE_VALIDATION_SPECS[].affected_files` and
   `COMPARATIVE_COMMAND_SPECS[].argv` — exists under the repo root
   (`CARGO_MANIFEST_DIR` two levels up). Mutation-verified: injecting
   `crates/rustynetd/src/nonexistent_mutation.rs` failed the test with the exact
   offending reference named; reverting restored green.

Verification on this fix (all exit codes read directly): test
`1 passed; 0 failed` against `--bin rustynet-cli`; `rustfmt --check` clean on the
edited file; `cargo clippy -p rustynet-cli --all-targets --all-features -- -D
warnings` clean. Note: repo-wide `cargo fmt --all -- --check` currently reports
pre-existing drift in unrelated files (`vm_lab/orchestrator/adapter/
windows_install.rs`, `rustynetd/src/anchor_tls.rs`, `rustynetd/src/daemon.rs`)
introduced outside this change and deliberately left untouched here.
