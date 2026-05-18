# Phase 2 Wrapper Provenance And Completeness Checklist

Prepared: 2026-04-12
Scope: `crates/rustynet-cli/src/vm_lab/mod.rs` and its in-file tests
Objective: make setup reuse provenance-bound and prevent subset runs from being reported as full release-gate success

## Checklist

- [x] Setup manifest struct and hashing helpers added
  Evidence:
  - code: `crates/rustynet-cli/src/vm_lab/mod.rs`
  - tests: `vm_lab::tests::validate_setup_manifest_rejects_mismatched_source_mode`

- [x] Setup path writes the manifest on success
  Evidence:
  - code: `crates/rustynet-cli/src/vm_lab/mod.rs`
  - artifact path: `state/setup_manifest.json`
  - tests: `vm_lab::tests::validate_setup_manifest_rejects_mismatched_source_mode`

- [x] Run path validates the manifest before auto-continue or explicit setup skip that reuses report state
  Evidence:
  - code: `crates/rustynet-cli/src/vm_lab/mod.rs`
  - tests: `vm_lab::tests::resolve_run_setup_reuse_allows_matching_auto_continue`
  - tests: `vm_lab::tests::resolve_run_setup_reuse_rejects_explicit_skip_setup_when_manifest_mismatches`

- [x] Release-gate completeness artifact is generated under `state/`
  Evidence:
  - code: `crates/rustynet-cli/src/vm_lab/mod.rs`
  - artifact path: `state/release_gate_completeness.json`
  - tests: `vm_lab::tests::write_release_gate_completeness_writes_incomplete_requested_artifact`

- [x] Full-gate mode fails when required stages are absent or not `pass`
  Evidence:
  - code: `crates/rustynet-cli/src/vm_lab/mod.rs`
  - tests: `vm_lab::tests::build_release_gate_completeness_report_marks_subset_runs_not_requested`
  - tests: `vm_lab::tests::write_release_gate_completeness_writes_incomplete_requested_artifact`
  - tests: `vm_lab::tests::build_release_gate_completeness_report_marks_complete_when_all_required_stages_pass`

- [x] Tests cover manifest mismatch handling and release-gate completeness logic
  Evidence:
  - tests: `vm_lab::tests::validate_setup_manifest_rejects_mismatched_source_mode`
  - tests: `vm_lab::tests::resolve_run_setup_reuse_allows_matching_auto_continue`
  - tests: `vm_lab::tests::resolve_run_setup_reuse_rejects_explicit_skip_setup_when_manifest_mismatches`
  - tests: `vm_lab::tests::build_release_gate_completeness_report_marks_subset_runs_not_requested`
  - tests: `vm_lab::tests::write_release_gate_completeness_writes_incomplete_requested_artifact`
  - tests: `vm_lab::tests::build_release_gate_completeness_report_marks_complete_when_all_required_stages_pass`

## Validation Evidence

- [x] `cargo fmt --all -- --check`
- [x] `cargo check -p rustynet-cli`
- [x] `cargo check --workspace --all-targets --all-features`
- [x] `cargo clippy -p rustynet-cli --all-targets -- -D warnings`
- [x] `cargo test -p rustynet-cli --bin rustynet-cli validate_setup_manifest_rejects_mismatched_source_mode`
- [x] `cargo test -p rustynet-cli --bin rustynet-cli resolve_run_setup_reuse`
- [x] `cargo test -p rustynet-cli --bin rustynet-cli release_gate_completeness`
- [x] `cargo test -p rustynet-cli --bin rustynet-cli transition_local_utm_vm_accepts_timeout_when_vm_reaches_stopped_state`
- [x] `cargo test --workspace --all-targets --all-features`
- [ ] `cargo audit --deny warnings`
  Reason: `cargo-audit` is not installed in this environment (`cargo audit` returned `no such command: audit`).
- [ ] `cargo deny check bans licenses sources advisories`
  Reason: `cargo-deny` is not installed in this environment (`cargo deny` returned `no such command: deny`).
