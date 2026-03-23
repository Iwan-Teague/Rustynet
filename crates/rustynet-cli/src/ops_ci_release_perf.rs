#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const DEFAULT_AUDIT_DB_RELATIVE_PATH: &str = ".cargo-audit-db";
const DEFAULT_AUDIT_HOME_RELATIVE_PATH: &str = ".ci-home";
const DEFAULT_CARGO_HOME_RELATIVE_PATH: &str = ".cargo-home";
const DEFAULT_CARGO_DENY_DB_NAME: &str = "advisory-db-3157b0e258782691";
const DEFAULT_SECURITY_TOOLCHAIN: &str = "1.88.0";
const DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS: &str = "2678400";
const DEFAULT_RELEASE_OUT_DIR: &str = "artifacts/release";
const DEFAULT_RELEASE_SBOM_PATH: &str = "artifacts/release/sbom.cargo-metadata.json";
const DEFAULT_RELEASE_SBOM_SHA256_PATH: &str = "artifacts/release/sbom.sha256";
const DEFAULT_RELEASE_ARTIFACT_PATH: &str = "target/release/rustynetd";
const DEFAULT_RELEASE_PROVENANCE_PATH: &str = "artifacts/release/rustynetd.provenance.json";
const DEFAULT_RELEASE_TRACK: &str = "beta";
const DEFAULT_PHASE3_REPORT_PATH: &str = "artifacts/perf/phase3/mesh_baseline.json";
const DEFAULT_PHASE1_PERF_SAMPLES_PATH: &str =
    "artifacts/perf/phase1/source/performance_samples.ndjson";
const DEFAULT_PHASE10_SOURCE_DIR: &str = "artifacts/phase10/source";
const DEFAULT_PHASE10_EVIDENCE_ENVIRONMENT: &str = "ci";
const DEFAULT_SIGNED_REPORT_PATH: &str = "artifacts/phase10/signed_state_tamper_e2e_report.json";
const DEFAULT_HIJACK_REPORT_PATH: &str = "artifacts/phase10/rogue_path_hijack_e2e_report.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareAdvisoryDbConfig {
    pub target_db: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateReleaseProvenanceConfig {
    pub artifact_path: PathBuf,
    pub track: String,
    pub output_json: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveNetworkSecurityGatesConfig {
    pub exit_host: String,
    pub client_host: String,
    pub ssh_allow_cidrs: String,
    pub ssh_user: String,
    pub ssh_port: String,
    pub ssh_identity: Option<String>,
    pub ssh_known_hosts_file: Option<String>,
    pub ssh_sudo_mode: String,
    pub sudo_password_file: Option<String>,
    pub signed_report_path: PathBuf,
    pub hijack_report_path: PathBuf,
    pub rogue_endpoint_ip: String,
    pub exit_node_id: Option<String>,
    pub client_node_id: Option<String>,
    pub network_id: Option<String>,
    pub remote_root: Option<String>,
    pub repo_ref: Option<String>,
    pub baseline_report_path: Option<String>,
    pub skip_apt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecurityCargoContext {
    audit_db: PathBuf,
    security_toolchain: String,
    effective_home: Option<PathBuf>,
    effective_cargo_home: PathBuf,
    effective_rustup_home: Option<PathBuf>,
    deny_disable_fetch: bool,
}

pub fn execute_ops_prepare_advisory_db(config: PrepareAdvisoryDbConfig) -> Result<String, String> {
    prepare_advisory_db(&config.target_db)?;
    Ok(format!(
        "prepared advisory db: {}",
        config.target_db.display()
    ))
}

pub fn execute_ops_run_phase1_ci_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let gate_threads = env_string_or_default("RUSTYNET_GATE_TEST_THREADS", "1")?;
    require_commands(&["cargo", "rustup", "rg"])?;
    require_cargo_subcommands(&["fmt", "clippy", "audit", "deny"])?;

    let security = prepare_security_cargo_context(&root_dir, default_security_toolchain()?)?;

    run_command_inherit(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;
    run_security_audit_and_deny(&root_dir, &security)?;

    run_script(
        &root_dir,
        "scripts/ci/check_backend_boundary_leakage.sh",
        &[],
    )?;
    run_self_op(
        &["ops", "check-no-unsafe-rust-sources"],
        Some(&root_dir),
        &[],
    )?;

    if rg_matches(
        &root_dir,
        r"\[\[UNRESOLVED\]\]|\{\{UNRESOLVED\}\}",
        &["crates", "documents"],
    )? {
        return Err("Documentation hygiene gate failed".to_string());
    }

    execute_ops_run_security_regression_gates()?;
    let phase1_samples_path = env_string_or_default(
        "RUSTYNET_PHASE1_PERF_SAMPLES_PATH",
        DEFAULT_PHASE1_PERF_SAMPLES_PATH,
    )?;
    run_self_op(
        &["ops", "run-phase1-baseline"],
        Some(&root_dir),
        &[(
            "RUSTYNET_PHASE1_PERF_SAMPLES_PATH",
            phase1_samples_path.as_str(),
        )],
    )?;

    Ok("Phase 1 CI gates: PASS".to_string())
}

pub fn execute_ops_run_phase9_ci_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let gate_threads = env_string_or_default("RUSTYNET_GATE_TEST_THREADS", "1")?;
    require_commands(&["cargo", "rg"])?;
    require_cargo_subcommands(&["fmt", "clippy", "audit", "deny"])?;

    run_command_inherit(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    run_script(&root_dir, "scripts/ci/phase8_gates.sh", &[])?;
    execute_ops_run_phase1_ci_gates()?;

    run_script(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &["rustynet-control", "ga::tests", "--all-features"],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "test",
            "-p",
            "rustynet-backend-wireguard",
            "--test",
            "conformance",
            "--all-features",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "test",
            "-p",
            "rustynet-backend-api",
            "--all-targets",
            "--all-features",
        ],
        Some(&root_dir),
        &[],
    )?;

    run_script(
        &root_dir,
        "scripts/operations/collect_phase9_raw_evidence.sh",
        &[],
    )?;
    let phase9_environment = env_string_or_default("RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT", "ci")?;
    run_script_with_env(
        &root_dir,
        "scripts/operations/generate_phase9_artifacts.sh",
        &[],
        &[(
            "RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT",
            phase9_environment.as_str(),
        )],
    )?;
    run_script(&root_dir, "scripts/ci/check_phase9_readiness.sh", &[])?;

    for path in [
        "documents/operations/CompatibilitySupportPolicy.md",
        "documents/operations/ProductionSLOAndIncidentReadiness.md",
        "documents/operations/ProductionRunbook.md",
        "documents/operations/DisasterRecoveryValidation.md",
        "documents/operations/BackendAgilityValidation.md",
        "documents/operations/CryptoDeprecationSchedule.md",
        "documents/operations/PostQuantumTransitionPlan.md",
        "documents/operations/FinalLaunchChecklist.md",
    ] {
        require_file(&root_dir.join(path), "phase9 operations artifact")?;
    }

    Ok("Phase 9 CI gates: PASS".to_string())
}

pub fn execute_ops_run_phase10_ci_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let gate_threads = env_string_or_default("RUSTYNET_GATE_TEST_THREADS", "1")?;
    require_commands(&["cargo", "rustup", "rg"])?;
    require_cargo_subcommands(&["fmt", "clippy", "audit", "deny"])?;

    run_script(
        &root_dir,
        "scripts/ci/test_check_fresh_install_os_matrix_readiness.sh",
        &[],
    )?;
    run_script(
        &root_dir,
        "scripts/ci/fresh_install_os_matrix_release_gate.sh",
        &[],
    )?;

    let security = prepare_security_cargo_context(&root_dir, default_security_toolchain()?)?;

    run_command_inherit(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;
    run_security_audit_and_deny(&root_dir, &security)?;

    execute_ops_run_phase9_ci_gates()?;
    run_script(
        &root_dir,
        "scripts/ci/check_backend_boundary_leakage.sh",
        &[],
    )?;

    if rg_matches(
        &root_dir,
        r#"BEGIN PRIVATE KEY|SECRET_KEY=|API_KEY=|TOKEN=.{8,}|password\s*=\s*"[^"]+""#,
        &["crates"],
    )? {
        return Err("Secret redaction gate failed".to_string());
    }

    run_script(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &["rustynetd", "phase10::tests", "--all-features"],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "test",
            "-p",
            "rustynet-backend-wireguard",
            "--all-targets",
            "--all-features",
        ],
        Some(&root_dir),
        &[],
    )?;
    execute_ops_run_phase10_hp2_gates()?;
    execute_ops_run_security_regression_gates()?;

    if env_truthy_with_default("RUSTYNET_PHASE10_GENERATE_ARTIFACTS", true)? {
        let environment = env_string_or_default(
            "RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT",
            DEFAULT_PHASE10_EVIDENCE_ENVIRONMENT,
        )?;
        run_self_op(
            &["ops", "generate-phase10-artifacts"],
            Some(&root_dir),
            &[(
                "RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT",
                environment.as_str(),
            )],
        )?;
    }

    if env_truthy_with_default("RUSTYNET_PHASE10_RUN_REAL_E2E", false)? {
        ensure_linux_for_gate("real phase10 e2e")?;
        if current_uid_is_root()? {
            run_script(&root_dir, "scripts/e2e/real_wireguard_exitnode_e2e.sh", &[])?;
        } else {
            run_command_inherit(
                "sudo",
                &["-E", "./scripts/e2e/real_wireguard_exitnode_e2e.sh"],
                Some(&root_dir),
                &[],
            )?;
        }
    }

    let artifact_dir = env_string_or_default(
        "RUSTYNET_PHASE10_ARTIFACT_DIR",
        &env_string_or_default("RUSTYNET_PHASE10_OUT_DIR", "artifacts/phase10")?,
    )?;
    let max_evidence_age_seconds = env_string_or_default(
        "RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS",
        DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS,
    )?;
    let shared_env = [
        ("RUSTYNET_PHASE10_ARTIFACT_DIR", artifact_dir.as_str()),
        (
            "RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS",
            max_evidence_age_seconds.as_str(),
        ),
    ];
    run_script_with_env(
        &root_dir,
        "scripts/ci/phase10_cross_network_exit_gates.sh",
        &[],
        &shared_env,
    )?;
    run_self_op(
        &["ops", "verify-phase10-provenance"],
        Some(&root_dir),
        &shared_env,
    )?;
    run_self_op(
        &["ops", "verify-phase10-readiness"],
        Some(&root_dir),
        &shared_env,
    )?;

    Ok("Phase 10 CI gates: PASS".to_string())
}

pub fn execute_ops_run_membership_ci_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let gate_threads = env_string_or_default("RUSTYNET_GATE_TEST_THREADS", "1")?;
    require_commands(&["cargo", "rustup", "rg"])?;
    require_cargo_subcommands(&["fmt", "clippy", "audit", "deny"])?;

    let security = prepare_security_cargo_context(&root_dir, default_security_toolchain()?)?;

    run_command_inherit(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[],
    )?;
    run_command_inherit(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;
    run_security_audit_and_deny(&root_dir, &security)?;

    execute_ops_run_phase9_ci_gates()?;
    execute_ops_run_phase10_ci_gates()?;

    run_script(
        &root_dir,
        "scripts/ci/check_backend_boundary_leakage.sh",
        &[],
    )?;
    run_script(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &["rustynet-control", "membership::tests", "--all-features"],
    )?;
    run_script(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &["rustynet-policy", "membership_aware", "--all-features"],
    )?;
    run_script(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &[
            "rustynetd",
            "daemon_runtime_denies_exit_selection_for_revoked_membership_node",
            "--all-features",
        ],
    )?;

    let mut membership_snapshot_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH",
        "/var/lib/rustynet/membership.snapshot",
    )?);
    let mut membership_log_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_MEMBERSHIP_LOG_PATH",
        "/var/lib/rustynet/membership.log",
    )?);
    let membership_environment =
        env_string_or_default("RUSTYNET_MEMBERSHIP_EVIDENCE_ENVIRONMENT", "ci")?;
    let membership_source_snapshot_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_MEMBERSHIP_SOURCE_SNAPSHOT_PATH",
        "artifacts/membership/source/membership.snapshot",
    )?);
    let membership_source_log_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_MEMBERSHIP_SOURCE_LOG_PATH",
        "artifacts/membership/source/membership.log",
    )?);
    let membership_bootstrap_state_dir = PathBuf::from(env_string_or_default(
        "RUSTYNET_MEMBERSHIP_BOOTSTRAP_STATE_DIR",
        "artifacts/membership/tmp_membership",
    )?);
    let mut membership_bootstrap_state = false;

    if !(membership_snapshot_path.is_file() && membership_log_path.is_file()) {
        if membership_source_snapshot_path.is_file() && membership_source_log_path.is_file() {
            fs::create_dir_all(&membership_bootstrap_state_dir).map_err(|err| {
                format!(
                    "failed to create membership bootstrap dir {}: {err}",
                    membership_bootstrap_state_dir.display()
                )
            })?;
            membership_snapshot_path = membership_bootstrap_state_dir.join("membership.snapshot");
            membership_log_path = membership_bootstrap_state_dir.join("membership.log");
            copy_file(&membership_source_snapshot_path, &membership_snapshot_path)?;
            copy_file(&membership_source_log_path, &membership_log_path)?;
            set_mode_owner_only(&membership_snapshot_path)?;
            set_mode_owner_only(&membership_log_path)?;
            membership_bootstrap_state = true;
        } else {
            return Err("membership state sources are missing; provide runtime paths via RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH/RUSTYNET_MEMBERSHIP_LOG_PATH or seed files under artifacts/membership/source".to_string());
        }
    }

    let artifacts_dir = root_dir.join("artifacts/membership");
    fs::create_dir_all(&artifacts_dir).map_err(|err| {
        format!(
            "failed to create membership artifact dir {}: {err}",
            artifacts_dir.display()
        )
    })?;

    let snapshot_value = membership_snapshot_path.to_str().ok_or_else(|| {
        format!(
            "membership snapshot path is not utf-8: {}",
            membership_snapshot_path.display()
        )
    })?;
    let log_value = membership_log_path.to_str().ok_or_else(|| {
        format!(
            "membership log path is not utf-8: {}",
            membership_log_path.display()
        )
    })?;
    let output_dir_value = artifacts_dir.to_str().ok_or_else(|| {
        format!(
            "membership artifact dir is not utf-8: {}",
            artifacts_dir.display()
        )
    })?;
    run_self_command(
        &[
            "membership",
            "generate-evidence",
            "--snapshot",
            snapshot_value,
            "--log",
            log_value,
            "--output-dir",
            output_dir_value,
            "--environment",
            membership_environment.as_str(),
        ],
        Some(&root_dir),
        &[],
    )?;

    let conformance = artifacts_dir.join("membership_conformance_report.json");
    let negative = artifacts_dir.join("membership_negative_tests_report.json");
    let recovery = artifacts_dir.join("membership_recovery_report.json");
    let audit_log = artifacts_dir.join("membership_audit_integrity.log");

    for artifact in [&conformance, &negative, &recovery, &audit_log] {
        require_file(artifact, "membership artifact")?;
    }

    let conformance_json = require_measured_pass_report(&conformance, true)?;
    require_measured_pass_report(&negative, false)?;
    require_measured_pass_report(&recovery, true)?;

    let audit_text = read_utf8_file(&audit_log)?;
    if !audit_text.contains("index=") {
        let entries = conformance_json
            .get("entries")
            .and_then(|value| value.as_u64())
            .unwrap_or(u64::MAX);
        if !membership_bootstrap_state || entries != 0 {
            return Err("membership audit integrity log missing chain entries".to_string());
        }
    }

    Ok("Membership CI gates: PASS".to_string())
}

pub fn execute_ops_run_supply_chain_integrity_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    require_commands(&["cargo", "rustup", "rustc"])?;
    require_cargo_subcommands(&["audit", "deny"])?;

    let host_triple = detect_host_triple()?;
    let security_toolchain = env_optional_string("RUSTYNET_SECURITY_TOOLCHAIN")?
        .unwrap_or_else(|| format!("{DEFAULT_SECURITY_TOOLCHAIN}-{host_triple}"));
    let security = prepare_security_cargo_context(&root_dir, security_toolchain)?;
    run_security_audit_and_deny(&root_dir, &security)?;

    run_command_inherit(
        "cargo",
        &["build", "--release", "-p", "rustynetd"],
        Some(&root_dir),
        &[],
    )?;
    generate_release_sbom_internal(&root_dir)?;

    let release_artifact_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_RELEASE_ARTIFACT_PATH",
        DEFAULT_RELEASE_ARTIFACT_PATH,
    )?);
    let release_track = env_string_or_default("RUSTYNET_RELEASE_TRACK", DEFAULT_RELEASE_TRACK)?;
    validate_release_track(&release_track)?;
    let release_provenance_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_RELEASE_PROVENANCE_PATH",
        DEFAULT_RELEASE_PROVENANCE_PATH,
    )?);
    let release_sbom_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_RELEASE_SBOM_PATH",
        DEFAULT_RELEASE_SBOM_PATH,
    )?);
    let release_sbom_sha256_path = PathBuf::from(env_string_or_default(
        "RUSTYNET_RELEASE_SBOM_SHA256_PATH",
        DEFAULT_RELEASE_SBOM_SHA256_PATH,
    )?);

    for required_file in [
        &release_artifact_path,
        &release_sbom_path,
        &release_sbom_sha256_path,
    ] {
        require_file(required_file, "supply-chain input")?;
    }

    let base_env = release_env_pairs(
        &release_artifact_path,
        &release_track,
        &release_provenance_path,
        &release_sbom_path,
        &release_sbom_sha256_path,
    )?;
    run_self_op(
        &["ops", "sign-release-artifact"],
        Some(&root_dir),
        &base_env,
    )?;
    run_self_op(
        &["ops", "verify-release-artifact"],
        Some(&root_dir),
        &base_env,
    )?;

    let tmp_dir = root_dir.join("artifacts/release/.supply-chain-tmp");
    fs::create_dir_all(&tmp_dir)
        .map_err(|err| format!("failed to create temp dir {}: {err}", tmp_dir.display()))?;
    let unique = unique_suffix();
    let unsigned_provenance_path = tmp_dir.join(format!("unsigned.{unique}.json"));
    let tampered_artifact_path = tmp_dir.join(format!("tampered-artifact.{unique}"));
    let tampered_provenance_path = tmp_dir.join(format!("tampered.{unique}.json"));
    let cleanup_paths = [
        unsigned_provenance_path.clone(),
        tampered_artifact_path.clone(),
        tampered_provenance_path.clone(),
    ];

    let unsigned_input = release_provenance_path.to_str().ok_or_else(|| {
        format!(
            "release provenance path is not utf-8: {}",
            release_provenance_path.display()
        )
    })?;
    let unsigned_output = unsigned_provenance_path.to_str().ok_or_else(|| {
        format!(
            "unsigned provenance path is not utf-8: {}",
            unsigned_provenance_path.display()
        )
    })?;
    if let Err(err) = run_self_op(
        &[
            "ops",
            "write-unsigned-release-provenance",
            "--input",
            unsigned_input,
            "--output",
            unsigned_output,
        ],
        Some(&root_dir),
        &[],
    ) {
        cleanup_files(&cleanup_paths);
        return Err(err);
    }

    let unsigned_env = release_env_pairs(
        &release_artifact_path,
        &release_track,
        &unsigned_provenance_path,
        &release_sbom_path,
        &release_sbom_sha256_path,
    )?;
    if run_self_op_allow_failure(
        &["ops", "verify-release-artifact"],
        Some(&root_dir),
        &unsigned_env,
    )?
    .success()
    {
        cleanup_files(&cleanup_paths);
        return Err("supply-chain gate failed: unsigned provenance was accepted".to_string());
    }

    if let Err(err) = copy_file(&release_artifact_path, &tampered_artifact_path) {
        cleanup_files(&cleanup_paths);
        return Err(err);
    }
    let tampered_env = match release_env_pairs(
        &tampered_artifact_path,
        &release_track,
        &tampered_provenance_path,
        &release_sbom_path,
        &release_sbom_sha256_path,
    ) {
        Ok(env) => env,
        Err(err) => {
            cleanup_files(&cleanup_paths);
            return Err(err);
        }
    };
    if let Err(err) = run_self_op(
        &["ops", "sign-release-artifact"],
        Some(&root_dir),
        &tampered_env,
    ) {
        cleanup_files(&cleanup_paths);
        return Err(err);
    }
    if let Err(err) = append_file(&tampered_artifact_path, b"tamper\n") {
        cleanup_files(&cleanup_paths);
        return Err(err);
    }
    if run_self_op_allow_failure(
        &["ops", "verify-release-artifact"],
        Some(&root_dir),
        &tampered_env,
    )?
    .success()
    {
        cleanup_files(&cleanup_paths);
        return Err("supply-chain gate failed: tampered artifact was accepted".to_string());
    }

    cleanup_files(&cleanup_paths);
    Ok("Supply-chain integrity gates: PASS".to_string())
}

pub fn execute_ops_run_security_regression_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let required_tests = [
        [
            "rustynetd",
            "daemon::tests::read_command_rejects_oversized_payload",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::read_command_rejects_null_byte_payload",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::node_role_command_matrix_is_fail_closed",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::artifact_limitgate_rejects_oversized_bundle_files",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::artifact_limitgate_rejects_count_overflow_for_assignment_and_traversal",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::artifact_limitgate_rejects_excessive_key_depth",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::artifact_fuzzgate_rejects_rollback_generations_fail_closed",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::artifact_fuzzgate_bundle_parsers_never_panic_and_fail_closed",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::load_auto_tunnel_bundle_rejects_equal_watermark_when_payload_digest_differs",
            "",
        ],
        [
            "rustynetd",
            "daemon::tests::load_trust_evidence_rejects_equal_watermark_when_payload_digest_differs",
            "",
        ],
        [
            "rustynetd",
            "privileged_helper::tests::validate_request_rejects_too_many_arguments",
            "",
        ],
        [
            "rustynetd",
            "privileged_helper::tests::validate_request_rejects_argument_over_max_bytes",
            "",
        ],
        [
            "rustynetd",
            "privileged_helper::tests::fuzzgate_read_request_rejects_oversized_payload",
            "",
        ],
        [
            "rustynetd",
            "privileged_helper::tests::fuzzgate_rejects_unknown_tokens_and_shell_metacharacters",
            "",
        ],
        [
            "rustynetd",
            "privileged_helper::tests::fuzzgate_malformed_inputs_never_panic",
            "",
        ],
        [
            "rustynet-cli",
            "ops_phase9::tests::read_json_object_rejects_oversized_source",
            "",
        ],
        [
            "rustynet-cli",
            "ops_phase9::tests::read_utf8_regular_file_with_max_bytes_rejects_oversized_source",
            "",
        ],
    ];
    for [package, filter, _] in required_tests {
        run_script(
            &root_dir,
            "scripts/ci/run_required_test.sh",
            &[package, filter],
        )?;
    }

    run_script(&root_dir, "scripts/ci/secrets_hygiene_gates.sh", &[])?;
    run_script(&root_dir, "scripts/ci/role_auth_matrix_gates.sh", &[])?;
    run_script(&root_dir, "scripts/ci/traversal_adversarial_gates.sh", &[])?;
    execute_ops_run_supply_chain_integrity_gates()?;

    let run_no_leak_gate_mode =
        env_string_or_default("RUSTYNET_SECURITY_RUN_NO_LEAK_GATE", "auto")?;
    let require_no_leak_gate = env_truthy_with_default(
        "RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE",
        env_truthy_with_default("CI", false)?,
    )?;
    if require_no_leak_gate && run_no_leak_gate_mode == "0" {
        return Err(
            "no-leak dataplane gate disable is forbidden when gate is required".to_string(),
        );
    }
    match run_no_leak_gate_mode.as_str() {
        "1" => run_script(&root_dir, "scripts/ci/no_leak_dataplane_gate.sh", &[])?,
        "auto" => {
            if host_is_linux()? && current_uid_is_root()? {
                run_script(&root_dir, "scripts/ci/no_leak_dataplane_gate.sh", &[])?;
            } else if require_no_leak_gate {
                return Err(
                    "no-leak dataplane gate is required but host is not eligible (requires root Linux)"
                        .to_string(),
                );
            } else {
                println!("No-leak dataplane gate skipped (requires root Linux).");
                println!(
                    "Set RUSTYNET_SECURITY_RUN_NO_LEAK_GATE=1 to run now or RUSTYNET_SECURITY_REQUIRE_NO_LEAK_GATE=1 to fail when unavailable."
                );
            }
        }
        "0" => {}
        _ => {
            return Err(format!(
                "invalid RUSTYNET_SECURITY_RUN_NO_LEAK_GATE value: {run_no_leak_gate_mode} (expected 0, 1, or auto)"
            ));
        }
    }

    if env_truthy_with_default("RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E", false)? {
        ensure_linux_for_gate("RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1")?;
        if !current_uid_is_root()? {
            return Err(
                "RUSTYNET_SECURITY_RUN_REAL_NETNS_E2E=1 requires root privileges".to_string(),
            );
        }
        run_script(&root_dir, "scripts/e2e/real_wireguard_exitnode_e2e.sh", &[])?;
    }

    let run_active_network_gates =
        env_truthy_with_default("RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES", false)?;
    let require_active_network_gates =
        env_truthy_with_default("RUSTYNET_SECURITY_REQUIRE_ACTIVE_NETWORK_GATES", false)?;
    if require_active_network_gates && !run_active_network_gates {
        return Err(
            "active network security gates are required but disabled; set RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES=1"
                .to_string(),
        );
    }
    if run_active_network_gates {
        let config = active_network_security_config_from_env()?;
        execute_ops_run_active_network_security_gates(config)?;
    } else if require_active_network_gates {
        return Err("active network security gates are required but did not execute".to_string());
    }

    Ok("Security regression gates: PASS".to_string())
}

pub fn execute_ops_run_active_network_security_gates(
    config: ActiveNetworkSecurityGatesConfig,
) -> Result<String, String> {
    let root_dir = repo_root()?;
    require_commands(&["cargo", "ssh"])?;

    let rogue_ip = config.rogue_endpoint_ip.clone();
    run_self_op(
        &["ops", "validate-ipv4-address", "--ip", rogue_ip.as_str()],
        Some(&root_dir),
        &[],
    )?;

    let mut common_args = vec![
        "--exit-host".to_string(),
        config.exit_host,
        "--client-host".to_string(),
        config.client_host,
        "--ssh-user".to_string(),
        config.ssh_user,
        "--ssh-port".to_string(),
        config.ssh_port,
        "--ssh-sudo".to_string(),
        config.ssh_sudo_mode,
        "--ssh-allow-cidrs".to_string(),
        config.ssh_allow_cidrs,
    ];
    push_optional_arg(&mut common_args, "--ssh-identity", config.ssh_identity);
    push_optional_arg(
        &mut common_args,
        "--ssh-known-hosts-file",
        config.ssh_known_hosts_file,
    );
    push_optional_arg(
        &mut common_args,
        "--sudo-password-file",
        config.sudo_password_file,
    );
    push_optional_arg(&mut common_args, "--exit-node-id", config.exit_node_id);
    push_optional_arg(&mut common_args, "--client-node-id", config.client_node_id);
    push_optional_arg(&mut common_args, "--network-id", config.network_id);
    push_optional_arg(&mut common_args, "--remote-root", config.remote_root);
    push_optional_arg(&mut common_args, "--repo-ref", config.repo_ref);
    push_optional_arg(
        &mut common_args,
        "--report-path",
        config.baseline_report_path,
    );
    if config.skip_apt {
        common_args.push("--skip-apt".to_string());
    }

    let signed_report_path = config.signed_report_path.to_string_lossy().to_string();
    let hijack_report_path = config.hijack_report_path.to_string_lossy().to_string();
    let rogue_endpoint_ip = config.rogue_endpoint_ip;

    let mut signed_args = common_args.clone();
    signed_args.push("--tamper-report-path".to_string());
    signed_args.push(signed_report_path);
    run_script_strings(
        &root_dir,
        "scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh",
        &signed_args,
        &[],
    )?;

    let mut hijack_args = common_args;
    hijack_args.push("--rogue-endpoint-ip".to_string());
    hijack_args.push(rogue_endpoint_ip);
    hijack_args.push("--hijack-report-path".to_string());
    hijack_args.push(hijack_report_path);
    run_script_strings(
        &root_dir,
        "scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh",
        &hijack_args,
        &[],
    )?;

    Ok("Active network security gates: PASS".to_string())
}

pub fn execute_ops_run_phase10_hp2_gates() -> Result<String, String> {
    let root_dir = repo_root()?;
    let source_dir = resolve_path_from_env_or_default(
        "RUSTYNET_PHASE10_SOURCE_DIR",
        DEFAULT_PHASE10_SOURCE_DIR,
    )?;
    let evidence_environment = env_string_or_default(
        "RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT",
        DEFAULT_PHASE10_EVIDENCE_ENVIRONMENT,
    )?;
    fs::create_dir_all(&source_dir).map_err(|err| {
        format!(
            "failed to create source dir {}: {err}",
            source_dir.display()
        )
    })?;

    let path_selection_log = source_dir.join("traversal_path_selection_tests.log");
    let probe_security_log = source_dir.join("traversal_probe_security_tests.log");
    truncate_file(&path_selection_log)?;
    truncate_file(&probe_security_log)?;

    let path_selection_tests = [
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_accepts_multi_peer_snapshot",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence",
        "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives",
        "phase10::tests::traversal_probe_falls_back_to_relay_when_handshake_does_not_advance",
        "phase10::tests::traversal_probe_promotes_direct_when_handshake_advances",
    ];
    for test_name in path_selection_tests {
        run_logged_test(
            &root_dir,
            &path_selection_log,
            &[
                "cargo",
                "test",
                "-p",
                "rustynetd",
                test_name,
                "--all-features",
                "--",
                "--exact",
                "--nocapture",
            ],
        )?;
    }

    let probe_security_tests = [
        (
            "rustynetd",
            "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
        ),
        (
            "rustynetd",
            "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
        ),
        (
            "rustynetd",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_requires_full_peer_coverage",
        ),
        (
            "rustynetd",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_rejects_unmanaged_peer_bundle",
        ),
        (
            "rustynetd",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_missing_peer_coverage",
        ),
        (
            "rustynetd",
            "traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback",
        ),
        (
            "rustynetd",
            "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
        ),
    ];
    for (package, test_name) in probe_security_tests {
        run_logged_test(
            &root_dir,
            &probe_security_log,
            &[
                "cargo",
                "test",
                "-p",
                package,
                test_name,
                "--all-features",
                "--",
                "--exact",
                "--nocapture",
            ],
        )?;
    }
    let backend_tests = [
        "tests::latest_handshake_parser_rejects_oversized_or_malformed_output",
        "tests::linux_backend_reads_latest_handshake_for_configured_peer",
    ];
    for test_name in backend_tests {
        run_logged_test(
            &root_dir,
            &probe_security_log,
            &[
                "cargo",
                "test",
                "-p",
                "rustynet-backend-wireguard",
                test_name,
                "--all-targets",
                "--all-features",
                "--",
                "--exact",
                "--nocapture",
            ],
        )?;
    }

    let source_dir_value = source_dir.to_string_lossy().to_string();
    let path_log_value = path_selection_log.to_string_lossy().to_string();
    let probe_log_value = probe_security_log.to_string_lossy().to_string();
    run_self_op(
        &[
            "ops",
            "write-phase10-hp2-traversal-reports",
            "--source-dir",
            source_dir_value.as_str(),
            "--environment",
            evidence_environment.as_str(),
            "--path-selection-log",
            path_log_value.as_str(),
            "--probe-security-log",
            probe_log_value.as_str(),
        ],
        Some(&root_dir),
        &[],
    )?;

    Ok("Phase 10 HP2 traversal gates: PASS".to_string())
}

pub fn execute_ops_generate_release_sbom() -> Result<String, String> {
    let root_dir = repo_root()?;
    generate_release_sbom_internal(&root_dir)?;
    Ok(format!(
        "SBOM generated:\n  - {}\n  - {}",
        root_dir.join(DEFAULT_RELEASE_SBOM_PATH).display(),
        root_dir.join(DEFAULT_RELEASE_SBOM_SHA256_PATH).display()
    ))
}

pub fn execute_ops_create_release_provenance(
    config: CreateReleaseProvenanceConfig,
) -> Result<String, String> {
    let root_dir = repo_root()?;
    validate_release_track(&config.track)?;
    require_file(&config.artifact_path, "artifact")?;

    let output_dir = config.output_json.parent().ok_or_else(|| {
        format!(
            "output path must have parent directory: {}",
            config.output_json.display()
        )
    })?;
    fs::create_dir_all(output_dir).map_err(|err| {
        format!(
            "failed to create output dir {}: {err}",
            output_dir.display()
        )
    })?;

    let sbom_json =
        resolve_path_from_env_or_default("RUSTYNET_RELEASE_SBOM_PATH", DEFAULT_RELEASE_SBOM_PATH)?;
    let sbom_digest = resolve_path_from_env_or_default(
        "RUSTYNET_RELEASE_SBOM_SHA256_PATH",
        DEFAULT_RELEASE_SBOM_SHA256_PATH,
    )?;
    require_file(&sbom_json, "sbom")?;
    require_file(&sbom_digest, "sbom digest")?;

    let env_pairs = release_env_pairs(
        &config.artifact_path,
        &config.track,
        &config.output_json,
        &sbom_json,
        &sbom_digest,
    )?;
    run_self_op(
        &["ops", "sign-release-artifact"],
        Some(&root_dir),
        &env_pairs,
    )?;
    Ok(format!(
        "release provenance written: {}",
        config.output_json.display()
    ))
}

pub fn execute_ops_run_phase3_baseline() -> Result<String, String> {
    let root_dir = repo_root()?;
    let phase3_report = root_dir.join(DEFAULT_PHASE3_REPORT_PATH);
    let phase3_report_env = phase3_report.to_string_lossy().to_string();
    run_script_with_env(
        &root_dir,
        "scripts/ci/run_required_test.sh",
        &["rustynetd", "phase3_three_node_mesh_succeeds"],
        &[("RUSTYNET_PHASE3_MESH_REPORT", phase3_report_env.as_str())],
    )?;
    require_file(&phase3_report, "phase3 report")?;
    let report_text = read_utf8_file(&phase3_report)?;
    for key in ["connected_nodes", "peer_sessions", "relay_sessions"] {
        if !report_text.contains(key) {
            return Err(format!("phase3 report missing required metric: {key}"));
        }
    }
    Ok(format!(
        "Phase 3 mesh baseline artifact generated:\n  - {}",
        phase3_report.display()
    ))
}

pub fn execute_ops_run_fuzz_smoke() -> Result<String, String> {
    let root_dir = repo_root()?;
    require_commands(&["cargo-fuzz", "rustup"])?;
    if !has_nightly_toolchain()? {
        run_command_inherit(
            "rustup",
            &["toolchain", "install", "nightly", "--profile", "minimal"],
            Some(&root_dir),
            &[],
        )?;
    }
    let fuzz_dir = root_dir.join("fuzz");
    for target in [
        "ipc_parse_command",
        "membership_decode_state",
        "membership_decode_signed_update",
    ] {
        run_command_inherit(
            "cargo",
            &[
                "+nightly",
                "fuzz",
                "run",
                target,
                "--",
                "-max_total_time=10",
            ],
            Some(&fuzz_dir),
            &[],
        )?;
        let _ = run_command_allow_failure(
            "cargo",
            &["+nightly", "fuzz", "cmin", target],
            Some(&fuzz_dir),
            &[],
        )?;
    }
    Ok("Fuzz smoke: PASS".to_string())
}

pub fn active_network_security_config_from_env() -> Result<ActiveNetworkSecurityGatesConfig, String>
{
    Ok(ActiveNetworkSecurityGatesConfig {
        exit_host: required_env_string("RUSTYNET_ACTIVE_NET_EXIT_HOST")?,
        client_host: required_env_string("RUSTYNET_ACTIVE_NET_CLIENT_HOST")?,
        ssh_allow_cidrs: required_env_string("RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS")?,
        ssh_user: env_string_or_default("RUSTYNET_ACTIVE_NET_SSH_USER", "root")?,
        ssh_port: env_string_or_default("RUSTYNET_ACTIVE_NET_SSH_PORT", "22")?,
        ssh_identity: env_optional_string("RUSTYNET_ACTIVE_NET_SSH_IDENTITY")?,
        ssh_known_hosts_file: env_optional_string("RUSTYNET_ACTIVE_NET_SSH_KNOWN_HOSTS_FILE")?,
        ssh_sudo_mode: env_string_or_default("RUSTYNET_ACTIVE_NET_SSH_SUDO_MODE", "auto")?,
        sudo_password_file: env_optional_string("RUSTYNET_ACTIVE_NET_SUDO_PASSWORD_FILE")?,
        signed_report_path: resolve_path_from_env_or_default(
            "RUSTYNET_ACTIVE_NET_SIGNED_TAMPER_REPORT_PATH",
            DEFAULT_SIGNED_REPORT_PATH,
        )?,
        hijack_report_path: resolve_path_from_env_or_default(
            "RUSTYNET_ACTIVE_NET_HIJACK_REPORT_PATH",
            DEFAULT_HIJACK_REPORT_PATH,
        )?,
        rogue_endpoint_ip: env_string_or_default(
            "RUSTYNET_ACTIVE_NET_ROGUE_ENDPOINT_IP",
            "203.0.113.250",
        )?,
        exit_node_id: env_optional_string("RUSTYNET_ACTIVE_NET_EXIT_NODE_ID")?,
        client_node_id: env_optional_string("RUSTYNET_ACTIVE_NET_CLIENT_NODE_ID")?,
        network_id: env_optional_string("RUSTYNET_ACTIVE_NET_NETWORK_ID")?,
        remote_root: env_optional_string("RUSTYNET_ACTIVE_NET_REMOTE_ROOT")?,
        repo_ref: env_optional_string("RUSTYNET_ACTIVE_NET_REPO_REF")?,
        baseline_report_path: env_optional_string("RUSTYNET_ACTIVE_NET_BASELINE_REPORT_PATH")?,
        skip_apt: env_truthy_with_default("RUSTYNET_ACTIVE_NET_SKIP_APT", false)?,
    })
}

fn prepare_security_cargo_context(
    root_dir: &Path,
    security_toolchain: String,
) -> Result<SecurityCargoContext, String> {
    let audit_db = resolve_env_path(
        "RUSTYNET_AUDIT_DB_PATH",
        root_dir.join(DEFAULT_AUDIT_DB_RELATIVE_PATH),
    )?;
    prepare_advisory_db(&audit_db)?;

    let source_cargo_home = PathBuf::from(
        env_optional_string("RUSTYNET_SOURCE_CARGO_HOME")?
            .or_else(|| env_optional_string("CARGO_HOME").ok().flatten())
            .unwrap_or_else(|| {
                format!(
                    "{}/.cargo",
                    env::var("HOME").unwrap_or_else(|_| ".".to_string())
                )
            }),
    );
    let audit_home = resolve_env_path(
        "RUSTYNET_AUDIT_HOME",
        root_dir.join(DEFAULT_AUDIT_HOME_RELATIVE_PATH),
    )?;
    let cargo_home_path = resolve_env_path(
        "RUSTYNET_CARGO_HOME_PATH",
        root_dir.join(DEFAULT_CARGO_HOME_RELATIVE_PATH),
    )?;

    let use_source_cargo_home = probe_writable_directory(&source_cargo_home)?;
    let deny_db_name =
        env_string_or_default("RUSTYNET_CARGO_DENY_DB_NAME", DEFAULT_CARGO_DENY_DB_NAME)?;

    let (effective_home, effective_cargo_home, deny_disable_fetch) = if use_source_cargo_home {
        (
            env_optional_string("HOME")?.map(PathBuf::from),
            source_cargo_home,
            false,
        )
    } else {
        fs::create_dir_all(&audit_home).map_err(|err| {
            format!(
                "failed to create audit home {}: {err}",
                audit_home.display()
            )
        })?;
        fs::create_dir_all(&cargo_home_path).map_err(|err| {
            format!(
                "failed to create cargo home path {}: {err}",
                cargo_home_path.display()
            )
        })?;
        if source_cargo_home != cargo_home_path {
            copy_dir_if_missing(
                &source_cargo_home.join("advisory-dbs"),
                &cargo_home_path.join("advisory-dbs"),
            )?;
            copy_dir_if_missing(
                &source_cargo_home.join("registry"),
                &cargo_home_path.join("registry"),
            )?;
            copy_dir_if_missing(&source_cargo_home.join("git"), &cargo_home_path.join("git"))?;
        }
        let deny_db_root = cargo_home_path.join("advisory-dbs");
        let deny_db_path = deny_db_root.join(deny_db_name);
        if !deny_db_path.is_dir() {
            fs::create_dir_all(&deny_db_root).map_err(|err| {
                format!(
                    "failed to create deny db root {}: {err}",
                    deny_db_root.display()
                )
            })?;
            copy_dir_recursive(&audit_db, &deny_db_path)?;
        }
        (Some(audit_home), cargo_home_path, true)
    };

    let effective_rustup_home = env_optional_string("RUSTUP_HOME")?
        .map(PathBuf::from)
        .or_else(|| {
            env_optional_string("HOME")
                .ok()
                .flatten()
                .map(|home| PathBuf::from(home).join(".rustup"))
        });

    ensure_security_toolchain_available(&security_toolchain)?;

    Ok(SecurityCargoContext {
        audit_db,
        security_toolchain,
        effective_home,
        effective_cargo_home,
        effective_rustup_home,
        deny_disable_fetch,
    })
}

fn run_security_audit_and_deny(
    root_dir: &Path,
    security: &SecurityCargoContext,
) -> Result<(), String> {
    let mut env_pairs_owned = Vec::new();
    env_pairs_owned.push((
        "CARGO_HOME".to_string(),
        security.effective_cargo_home.to_string_lossy().to_string(),
    ));
    if let Some(home) = &security.effective_home {
        env_pairs_owned.push(("HOME".to_string(), home.to_string_lossy().to_string()));
    }
    if let Some(rustup_home) = &security.effective_rustup_home {
        env_pairs_owned.push((
            "RUSTUP_HOME".to_string(),
            rustup_home.to_string_lossy().to_string(),
        ));
    }
    let env_pairs = env_pairs_owned
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let audit_db_value = security.audit_db.to_string_lossy().to_string();

    let audit_args = vec![
        "run",
        security.security_toolchain.as_str(),
        "cargo",
        "audit",
        "--deny",
        "warnings",
        "--stale",
        "--no-fetch",
        "--db",
        audit_db_value.as_str(),
    ];
    run_command_inherit("rustup", &audit_args, Some(root_dir), &env_pairs)?;

    let mut deny_args = vec![
        "run",
        security.security_toolchain.as_str(),
        "cargo",
        "deny",
        "check",
    ];
    if security.deny_disable_fetch {
        deny_args.push("--disable-fetch");
    }
    deny_args.extend(["bans", "licenses", "sources", "advisories"]);
    run_command_inherit("rustup", &deny_args, Some(root_dir), &env_pairs)?;
    Ok(())
}

fn prepare_advisory_db(target_db: &Path) -> Result<(), String> {
    validate_advisory_db_target(target_db)?;
    if is_valid_db_layout(target_db) {
        return Ok(());
    }

    let global_db = env_optional_string("HOME")?
        .map(|home| PathBuf::from(home).join(".cargo/advisory-db"))
        .unwrap_or_else(|| PathBuf::from(".cargo/advisory-db"));
    if copy_advisory_db_if_valid(&global_db, target_db)? {
        return Ok(());
    }

    if !env_truthy_with_default("RUSTYNET_AUDIT_DB_AUTO_FETCH", true)? {
        return Err(format!(
            "advisory db missing at {} and auto-fetch disabled (RUSTYNET_AUDIT_DB_AUTO_FETCH=0)",
            target_db.display()
        ));
    }
    require_commands(&["git"])?;

    let remote = env_string_or_default(
        "RUSTYNET_AUDIT_DB_REMOTE",
        "https://github.com/RustSec/advisory-db.git",
    )?;
    let parent = target_db.parent().ok_or_else(|| {
        format!(
            "advisory db target must have parent: {}",
            target_db.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create advisory db parent {}: {err}",
            parent.display()
        )
    })?;

    let tmp_db = PathBuf::from(format!(
        "{}.tmp.clone.{}",
        target_db.display(),
        std::process::id()
    ));
    remove_path_if_exists(&tmp_db)?;
    let clone_status = run_command_allow_failure(
        "git",
        &[
            "clone",
            "--depth",
            "1",
            remote.as_str(),
            tmp_db.to_string_lossy().as_ref(),
        ],
        None,
        &[],
    )?;
    if !clone_status.success() {
        remove_path_if_exists(&tmp_db)?;
        return Err(format!("failed to clone advisory db from {remote}"));
    }
    if !is_valid_db_layout(&tmp_db) {
        remove_path_if_exists(&tmp_db)?;
        return Err(format!(
            "downloaded advisory db is invalid: {}",
            tmp_db.display()
        ));
    }

    remove_path_if_exists(target_db)?;
    fs::rename(&tmp_db, target_db).map_err(|err| {
        format!(
            "failed to move advisory db {} into place {}: {err}",
            tmp_db.display(),
            target_db.display()
        )
    })?;

    if !is_valid_db_layout(target_db) {
        return Err(format!(
            "advisory db bootstrap produced invalid layout: {}",
            target_db.display()
        ));
    }
    Ok(())
}

fn generate_release_sbom_internal(root_dir: &Path) -> Result<(), String> {
    let out_dir = root_dir.join(DEFAULT_RELEASE_OUT_DIR);
    let sbom_json = root_dir.join(DEFAULT_RELEASE_SBOM_PATH);
    let sbom_digest = root_dir.join(DEFAULT_RELEASE_SBOM_SHA256_PATH);
    fs::create_dir_all(&out_dir).map_err(|err| {
        format!(
            "failed to create sbom output dir {}: {err}",
            out_dir.display()
        )
    })?;

    let metadata = run_command_capture(
        "cargo",
        &["metadata", "--format-version", "1"],
        Some(root_dir),
        &[],
    )?;
    fs::write(&sbom_json, metadata.stdout.as_bytes())
        .map_err(|err| format!("failed writing sbom {}: {err}", sbom_json.display()))?;
    let digest = sha256_file_hex(&sbom_json)?;
    fs::write(&sbom_digest, format!("{digest}\n")).map_err(|err| {
        format!(
            "failed writing sbom digest {}: {err}",
            sbom_digest.display()
        )
    })?;
    Ok(())
}

fn release_env_pairs<'a>(
    artifact_path: &'a Path,
    track: &'a str,
    provenance_path: &'a Path,
    sbom_path: &'a Path,
    sbom_sha256_path: &'a Path,
) -> Result<Vec<(&'static str, &'a str)>, String> {
    let artifact = path_as_utf8(artifact_path, "release artifact")?;
    let provenance = path_as_utf8(provenance_path, "release provenance")?;
    let sbom = path_as_utf8(sbom_path, "release sbom")?;
    let sbom_sha = path_as_utf8(sbom_sha256_path, "release sbom digest")?;
    Ok(vec![
        ("RUSTYNET_RELEASE_ARTIFACT_PATH", artifact),
        ("RUSTYNET_RELEASE_TRACK", track),
        ("RUSTYNET_RELEASE_PROVENANCE_PATH", provenance),
        ("RUSTYNET_RELEASE_SBOM_PATH", sbom),
        ("RUSTYNET_RELEASE_SBOM_SHA256_PATH", sbom_sha),
    ])
}

fn validate_release_track(track: &str) -> Result<(), String> {
    match track {
        "unstable" | "canary" | "stable" | "internal" | "beta" => Ok(()),
        _ => Err(format!("invalid release track: {track}")),
    }
}

fn default_security_toolchain() -> Result<String, String> {
    env_string_or_default("RUSTYNET_SECURITY_TOOLCHAIN", DEFAULT_SECURITY_TOOLCHAIN)
}

fn detect_host_triple() -> Result<String, String> {
    let output = run_command_capture("rustc", &["-vV"], None, &[])?;
    for line in output.stdout.lines() {
        if let Some(rest) = line.strip_prefix("host: ") {
            return Ok(rest.trim().to_string());
        }
    }
    Err("failed to determine rustc host triple".to_string())
}

fn ensure_security_toolchain_available(toolchain: &str) -> Result<(), String> {
    let status = run_command_allow_failure(
        "rustup",
        &["run", toolchain, "cargo", "--version"],
        None,
        &[],
    )?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "missing required pinned security toolchain: {toolchain}\ninstall with: rustup toolchain install {toolchain}"
    ))
}

fn require_commands(commands: &[&str]) -> Result<(), String> {
    for command in commands {
        let status = Command::new(command)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(_) => {}
            Err(_) => return Err(format!("missing required command: {command}")),
        }
    }
    Ok(())
}

fn require_cargo_subcommands(subcommands: &[&str]) -> Result<(), String> {
    for subcommand in subcommands {
        let status = Command::new("cargo")
            .arg(subcommand)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(status) if status.success() => {}
            _ => {
                return Err(format!(
                    "missing required cargo subcommand: cargo {subcommand}\ninstall toolchain components/tools and retry."
                ));
            }
        }
    }
    Ok(())
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), String> {
    run_script_with_env(root_dir, script, args, &[])
}

fn run_script_with_env(
    root_dir: &Path,
    script: &str,
    args: &[&str],
    env_pairs: &[(&str, &str)],
) -> Result<(), String> {
    let owned_args = args
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    run_script_strings(root_dir, script, owned_args.as_slice(), env_pairs)
}

fn run_script_strings(
    root_dir: &Path,
    script: &str,
    args: &[String],
    env_pairs: &[(&str, &str)],
) -> Result<(), String> {
    let script_path = root_dir.join(script);
    let mut command = Command::new(&script_path);
    command.current_dir(root_dir);
    command.args(args);
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    let status = command
        .status()
        .map_err(|err| format!("failed to execute script {}: {err}", script_path.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "script {} failed with status {status}",
            script_path.display()
        ))
    }
}

fn run_self_op(
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<(), String> {
    let status = run_self_op_allow_failure(args, cwd, env_pairs)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command {args:?} failed with status {status}"))
    }
}

fn run_self_op_allow_failure(
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<ExitStatus, String> {
    run_self_command_allow_failure(args, cwd, env_pairs)
}

fn run_self_command(
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<(), String> {
    let status = run_self_command_allow_failure(args, cwd, env_pairs)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command {args:?} failed with status {status}"))
    }
}

fn run_self_command_allow_failure(
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<ExitStatus, String> {
    let current_exe =
        env::current_exe().map_err(|err| format!("resolve current executable failed: {err}"))?;
    let mut command = Command::new(current_exe);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command.args(args);
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    command
        .status()
        .map_err(|err| format!("failed to execute {args:?}: {err}"))
}

fn run_command_inherit(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<(), String> {
    let status = run_command_allow_failure(program, args, cwd, env_pairs)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "command {program:?} {args:?} failed with status {status}"
        ))
    }
}

fn run_command_allow_failure(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<ExitStatus, String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    command
        .status()
        .map_err(|err| format!("failed to execute {program:?} {args:?}: {err}"))
}

fn run_command_capture(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<CapturedOutput, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to execute {program:?} {args:?}: {err}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("command {program:?} {args:?} produced non-utf8 stdout"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| format!("command {program:?} {args:?} produced non-utf8 stderr"))?;
    if !output.status.success() {
        return Err(format!(
            "command {program:?} {args:?} failed with status {}\n{}{}",
            output.status, stdout, stderr
        ));
    }
    Ok(CapturedOutput { stdout })
}

fn run_logged_test(root_dir: &Path, log_path: &Path, command: &[&str]) -> Result<(), String> {
    if command.is_empty() {
        return Err("logged test command must not be empty".to_string());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|err| format!("failed to open log {}: {err}", log_path.display()))?;
    let header = format!("[{}] RUN {}\n", timestamp_utc(), command.join(" "));
    file.write_all(header.as_bytes())
        .map_err(|err| format!("failed to write log header {}: {err}", log_path.display()))?;
    print!("{header}");

    let output = run_command_capture_allow_failure(command[0], &command[1..], Some(root_dir), &[])?;
    file.write_all(output.stdout.as_bytes())
        .and_then(|_| file.write_all(output.stderr.as_bytes()))
        .map_err(|err| format!("failed to append log {}: {err}", log_path.display()))?;
    print!("{}{}", output.stdout, output.stderr);
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "command {} failed with status {}",
            command.join(" "),
            output.status
        ))
    }
}

fn run_command_capture_allow_failure(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    env_pairs: &[(&str, &str)],
) -> Result<CapturedStatusOutput, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in env_pairs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to execute {program:?} {args:?}: {err}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("command {program:?} {args:?} produced non-utf8 stdout"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| format!("command {program:?} {args:?} produced non-utf8 stderr"))?;
    Ok(CapturedStatusOutput {
        status: output.status,
        stdout,
        stderr,
    })
}

fn rg_matches(root_dir: &Path, pattern: &str, paths: &[&str]) -> Result<bool, String> {
    let mut args = vec!["-n", pattern];
    args.extend(paths.iter().copied());
    let status = run_command_allow_failure("rg", &args, Some(root_dir), &[])?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!(
            "rg command failed while evaluating pattern: {pattern}"
        )),
    }
}

fn require_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("missing {label}: {} ({err})", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_utf8_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(contents)
}

fn require_measured_pass_report(
    path: &Path,
    allow_fail_status_absent: bool,
) -> Result<serde_json::Value, String> {
    let value: serde_json::Value = serde_json::from_str(&read_utf8_file(path)?)
        .map_err(|err| format!("failed parsing json {}: {err}", path.display()))?;
    if value.get("evidence_mode").and_then(|value| value.as_str()) != Some("measured") {
        return Err(format!(
            "artifact is not measured evidence: {}",
            path.display()
        ));
    }
    if value
        .get("captured_at_unix")
        .and_then(|value| value.as_u64())
        .is_none()
    {
        return Err(format!(
            "artifact missing captured_at_unix metadata: {}",
            path.display()
        ));
    }
    if value
        .get("environment")
        .and_then(|value| value.as_str())
        .is_none()
    {
        return Err(format!(
            "artifact missing environment metadata: {}",
            path.display()
        ));
    }
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("artifact missing status field: {}", path.display()))?;
    if status != "pass" {
        return Err(format!("artifact is not pass: {}", path.display()));
    }
    if !allow_fail_status_absent && contains_status_field(&value, "fail") {
        return Err(format!(
            "artifact contains failure status: {}",
            path.display()
        ));
    }
    Ok(value)
}

fn contains_status_field(value: &serde_json::Value, expected: &str) -> bool {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| contains_status_field(item, expected)),
        serde_json::Value::Object(map) => {
            map.get("status")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == expected)
                || map
                    .values()
                    .any(|item| contains_status_field(item, expected))
        }
        _ => false,
    }
}

fn resolve_env_path(key: &str, default: PathBuf) -> Result<PathBuf, String> {
    match env_optional_string(key)? {
        Some(value) => resolve_path(value.as_str()),
        None => Ok(default),
    }
}

fn resolve_path_from_env_or_default(key: &str, default: &str) -> Result<PathBuf, String> {
    match env_optional_string(key)? {
        Some(value) => resolve_path(value.as_str()),
        None => resolve_path(default),
    }
}

fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("path must not be empty".to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(repo_root()?.join(path))
    }
}

fn env_optional_string(key: &str) -> Result<Option<String>, String> {
    match env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} contains non-utf8 data"))
        }
    }
}

fn env_string_or_default(key: &str, default: &str) -> Result<String, String> {
    Ok(env_optional_string(key)?.unwrap_or_else(|| default.to_string()))
}

fn required_env_string(key: &str) -> Result<String, String> {
    env_optional_string(key)?.ok_or_else(|| format!("missing required environment variable: {key}"))
}

fn env_truthy_with_default(key: &str, default: bool) -> Result<bool, String> {
    Ok(match env_optional_string(key)? {
        Some(value) => parse_truthy(value.as_str())?,
        None => default,
    })
}

fn parse_truthy(value: &str) -> Result<bool, String> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
        other => Err(format!("invalid boolean value: {other}")),
    }
}

fn host_is_linux() -> Result<bool, String> {
    Ok(std::env::consts::OS == "linux")
}

fn ensure_linux_for_gate(label: &str) -> Result<(), String> {
    if !host_is_linux()? {
        return Err(format!("{label} requires a Linux host"));
    }
    Ok(())
}

fn current_uid_is_root() -> Result<bool, String> {
    let output = run_command_capture("id", &["-u"], None, &[])?;
    Ok(output.stdout.trim() == "0")
}

fn has_nightly_toolchain() -> Result<bool, String> {
    let output = run_command_capture("rustup", &["toolchain", "list"], None, &[])?;
    Ok(output
        .stdout
        .lines()
        .any(|line| line.starts_with("nightly")))
}

fn repo_root() -> Result<PathBuf, String> {
    env::current_dir().map_err(|err| format!("resolve current directory failed: {err}"))
}

fn validate_advisory_db_target(target_db: &Path) -> Result<(), String> {
    if target_db.as_os_str().is_empty()
        || target_db == Path::new(".")
        || target_db == Path::new("/")
    {
        return Err(format!(
            "invalid advisory db target path: '{}'",
            target_db.display()
        ));
    }
    Ok(())
}

fn is_valid_db_layout(path: &Path) -> bool {
    path.is_dir() && path.join("crates").is_dir() && path.join("support.toml").is_file()
}

fn copy_advisory_db_if_valid(source: &Path, target: &Path) -> Result<bool, String> {
    if !is_valid_db_layout(source) {
        return Ok(false);
    }
    copy_dir_recursive(source, target)?;
    Ok(true)
}

fn probe_writable_directory(path: &Path) -> Result<bool, String> {
    if !path.exists() && fs::create_dir_all(path).is_err() {
        return Ok(false);
    }
    let probe = path.join(format!(".rustynet-ci-write-test.{}", std::process::id()));
    match OpenOptions::new().create_new(true).write(true).open(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn copy_dir_if_missing(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() || !source.is_dir() {
        return Ok(());
    }
    copy_dir_recursive(source, destination)
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!("source directory missing: {}", source.display()));
    }
    remove_path_if_exists(destination)?;
    fs::create_dir_all(destination).map_err(|err| {
        format!(
            "failed to create directory {}: {err}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source)
        .map_err(|err| format!("failed to read directory {}: {err}", source.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read directory entry: {err}"))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = entry
            .metadata()
            .map_err(|err| format!("failed to read metadata {}: {err}", source_path.display()))?;
        if metadata.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            copy_file(&source_path, &destination_path)?;
        } else {
            return Err(format!(
                "unsupported advisory db entry: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create parent {}: {err}", parent.display()))?;
    }
    fs::copy(source, destination).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
            .map_err(|err| format!("failed to remove directory {}: {err}", path.display()))
    } else {
        fs::remove_file(path)
            .map_err(|err| format!("failed to remove file {}: {err}", path.display()))
    }
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(hex_encode(digest.as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(format!("{byte:02x}").as_str());
    }
    output
}

fn path_as_utf8<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("{label} path is not utf-8: {}", path.display()))
}

fn append_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open {} for append: {err}", path.display()))?;
    file.write_all(bytes)
        .map_err(|err| format!("failed to append {}: {err}", path.display()))
}

fn truncate_file(path: &Path) -> Result<(), String> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map(|_| ())
        .map_err(|err| format!("failed to truncate {}: {err}", path.display()))
}

fn timestamp_utc() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z\n".to_string())
            .trim()
            .to_string(),
        _ => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn push_optional_arg(args: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        args.push(flag.to_string());
        args.push(value);
    }
}

fn cleanup_files(paths: &[PathBuf]) {
    for path in paths {
        let _ = remove_path_if_exists(path);
    }
}

fn set_mode_owner_only(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|err| format!("failed to set mode 600 on {}: {err}", path.display()))?;
    }
    Ok(())
}

fn unique_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", std::process::id(), now)
}

struct CapturedOutput {
    stdout: String,
}

struct CapturedStatusOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_truthy_accepts_expected_values() {
        assert!(parse_truthy("1").unwrap());
        assert!(parse_truthy("true").unwrap());
        assert!(!parse_truthy("0").unwrap());
        assert!(!parse_truthy("false").unwrap());
    }

    #[test]
    fn validate_release_track_rejects_unknown_values() {
        assert!(validate_release_track("beta").is_ok());
        assert!(validate_release_track("preview").is_err());
    }

    #[test]
    fn advisory_db_layout_requires_expected_files() {
        let root = env::temp_dir().join(format!("rustynet-ci-db-{}", unique_suffix()));
        fs::create_dir_all(root.join("crates")).unwrap();
        fs::write(root.join("support.toml"), "[advisory]\n").unwrap();
        assert!(is_valid_db_layout(&root));
        let _ = fs::remove_dir_all(root);
    }
}
