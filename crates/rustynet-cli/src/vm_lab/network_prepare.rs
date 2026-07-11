//! VM-lab network prepare/restore transaction (rulebook Slice B).
//!
//! The ONLY sanctioned mutation path for VM network attachments. Everything
//! else in the lab (audit, preflight, MCP run functions) is verify-only.
//!
//! Design (rulebook §13/§15.6/§15.8 Slice B):
//! - A journal-driven step machine: every step is persisted before/after
//!   execution so an interrupted transaction is recoverable and restore is
//!   idempotent.
//! - An explicit authorization boundary: without `--approve-reconfigure` the
//!   command only prints the redacted dry-run plan. Nothing is touched.
//! - An atomic network lease refuses overlapping concurrent transactions and
//!   allows disjoint ones. Stale leases are recovered only after verifying
//!   process identity (pid + recorded command line), never pid liveness alone.
//! - Full prior UTM configurations are snapshotted to an owner-only rollback
//!   store (0700 dir / 0600 files) under `state/`, outside committed evidence.
//! - Any step failure rolls back every affected VM and verifies the restored
//!   configuration digests and power states before reporting.
//! - `en0` can never appear as a bridge target: rejected at profile parse,
//!   plan build, and render time.
//!
//! Side effects run through the [`NetworkMutationPort`] trait so the whole
//! transaction is fault-injectable in tests without a real VM.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::network_audit::parse_utm_nics_json;
use super::network_profile::{
    AttachmentMode, DEFAULT_NETWORK_PROFILE_DIR, ManagementAttachmentPolicy, NetworkProfile,
    NetworkProfileId, ScenarioSubstrate, UtmBackend, load_network_profile_dir,
};
use super::{VmController, VmInventoryEntry};

const DEFAULT_STATE_DIR: &str = "state";
const TXN_SUBDIR: &str = "vm_lab_network_txn";
const LEASE_SUBDIR: &str = "vm_lab_network_leases";
const LEASE_LOCK_FILE: &str = ".acquire.lock";
const LEASE_LOCK_STALE_SECS: u64 = 60;
const LEASE_LOCK_RETRIES: u32 = 20;
const LEASE_LOCK_RETRY_MS: u64 = 100;
// A guest just started in the apply step can be mid-boot when rollback needs
// it stopped again; the graceful window must outlast a slow ACPI shutdown, and
// stop_vm force-stops past this ceiling anyway.
const VM_POWER_POLL_TIMEOUT_SECS: u64 = 180;
const VM_POWER_POLL_INTERVAL_MS: u64 = 500;
// Generous ceiling: a Windows guest can take minutes from `utmctl start`
// to a DHCP lease + sshd answering on the new attachment.
const MANAGEMENT_READY_TIMEOUT_SECS: u64 = 420;
const MANAGEMENT_READY_POLL_MS: u64 = 3000;
const JOURNAL_SCHEMA_VERSION: u32 = 1;

// --- Transaction step vocabulary ---

/// Ordered mutation steps. The journal records each step's status so a crash
/// at any point is recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnStep {
    SnapshotConfigs,
    StopVms,
    ApplyConfigs,
    StartVms,
    WaitManagement,
    ConfigureGuests,
    PostAudit,
    WriteEvidence,
}

impl TxnStep {
    pub const ORDER: [TxnStep; 8] = [
        TxnStep::SnapshotConfigs,
        TxnStep::StopVms,
        TxnStep::ApplyConfigs,
        TxnStep::StartVms,
        TxnStep::WaitManagement,
        TxnStep::ConfigureGuests,
        TxnStep::PostAudit,
        TxnStep::WriteEvidence,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotConfigs => "snapshot_configs",
            Self::StopVms => "stop_vms",
            Self::ApplyConfigs => "apply_configs",
            Self::StartVms => "start_vms",
            Self::WaitManagement => "wait_management",
            Self::ConfigureGuests => "configure_guests",
            Self::PostAudit => "post_audit",
            Self::WriteEvidence => "write_evidence",
        }
    }
}

impl fmt::Display for TxnStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnOutcome {
    InProgress,
    Applied,
    RolledBackVerified,
    RollbackIncomplete,
    RestoredVerified,
}

impl TxnOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Applied => "applied",
            Self::RolledBackVerified => "rolled_back_verified",
            Self::RollbackIncomplete => "rollback_incomplete",
            Self::RestoredVerified => "restored_verified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    Started,
    Stopped,
    Other,
}

// --- Target model ---

/// One target adapter, rendered from the validated profile. `en0` is
/// structurally unrepresentable: construction rejects it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetNic {
    pub index: usize,
    pub mode: AttachmentMode,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_interface: Option<String>,
}

impl TargetNic {
    fn new(
        index: usize,
        mode: AttachmentMode,
        mac: String,
        hardware: Option<String>,
        bridge_interface: Option<String>,
    ) -> Result<Self, String> {
        if mode == AttachmentMode::Bridged {
            match bridge_interface.as_deref() {
                None => {
                    return Err(
                        "a bridged target adapter must pin an explicit host interface".to_owned(),
                    );
                }
                Some("en0") => {
                    return Err(
                        "bridging to en0 (the host's everyday LAN) is denied by policy".to_owned(),
                    );
                }
                Some(_) => {}
            }
        } else if bridge_interface.is_some() {
            return Err("only bridged adapters may name a host interface".to_owned());
        }
        Ok(Self {
            index,
            mode,
            mac,
            hardware,
            bridge_interface,
        })
    }

    fn utm_mode_str(&self, backend: UtmBackend) -> Result<&'static str, String> {
        match (self.mode, backend) {
            (AttachmentMode::Shared, _) => Ok("Shared"),
            (AttachmentMode::HostOnly, UtmBackend::Qemu) => Ok("Host"),
            (AttachmentMode::Bridged, _) => Ok("Bridged"),
            (mode, backend) => Err(format!(
                "attachment {} is not applicable on backend {}",
                mode.as_str(),
                backend.as_str()
            )),
        }
    }
}

/// Typed guest-side network plan. Values are validated types, never raw
/// strings, so no shell text can be constructed from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GuestNetworkPlan {
    /// `address/prefix` for the scenario NIC (validated CIDR host form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario_address_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario_gateway: Option<String>,
}

impl GuestNetworkPlan {
    pub fn is_empty(&self) -> bool {
        self.scenario_address_cidr.is_none() && self.scenario_gateway.is_none()
    }
}

/// Per-VM transaction record persisted in the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmTxnRecord {
    pub alias: String,
    pub utm_name: String,
    pub bundle_path: String,
    pub backend: String,
    pub management_host: String,
    pub original_power: PowerState,
    /// sha256 of the full original config.plist bytes.
    pub original_config_sha256: String,
    /// Rollback filename (relative to the transaction directory).
    pub rollback_file: String,
    pub target_nics: Vec<TargetNic>,
    /// Rendered UTM `Network` JSON for this backend.
    pub target_network_json: String,
    pub already_compliant: bool,
    pub guest_plan: GuestNetworkPlan,
    // Progress flags — updated as steps run so restore knows what to undo.
    pub snapshot_taken: bool,
    pub stopped_by_txn: bool,
    pub config_applied: bool,
    pub started_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub step: TxnStep,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTxnJournal {
    pub schema_version: u32,
    pub transaction_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub lease_id: String,
    pub created_at_epoch_secs: u64,
    pub vms: Vec<VmTxnRecord>,
    pub steps: Vec<StepRecord>,
    pub outcome: TxnOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

/// Redacted transaction evidence (safe fields + digests only; full configs
/// stay in the owner-only rollback store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionEvidence {
    pub schema_version: u32,
    pub transaction_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub vms: Vec<TransactionEvidenceVm>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionEvidenceVm {
    pub alias: String,
    pub utm_name: String,
    pub original_config_sha256: String,
    pub target_modes: Vec<String>,
    pub already_compliant: bool,
}

// --- Mutation port (all side effects go through here) ---

pub trait NetworkMutationPort {
    fn read_config(&mut self, utm_name: &str) -> Result<Vec<u8>, String>;
    /// The VM's backend plus its current rendered `Network` JSON.
    fn read_network_state(&mut self, utm_name: &str) -> Result<(UtmBackend, String), String>;
    fn power_state(&mut self, utm_name: &str) -> Result<PowerState, String>;
    fn stop_vm(&mut self, utm_name: &str) -> Result<(), String>;
    fn start_vm(&mut self, utm_name: &str) -> Result<(), String>;
    /// Apply the rendered `Network` JSON to a STOPPED VM's configuration.
    fn apply_network_config(&mut self, utm_name: &str, network_json: &str) -> Result<(), String>;
    /// Restore the full original configuration bytes (rollback path).
    fn restore_config_bytes(&mut self, utm_name: &str, original: &[u8]) -> Result<(), String>;
    /// Wait until the management plane answers (SSH TCP reachability).
    fn wait_management_ready(&mut self, utm_name: &str, host: &str) -> Result<(), String>;
    fn configure_guest(&mut self, utm_name: &str, plan: &GuestNetworkPlan) -> Result<(), String>;
    /// Re-read and semantically verify the applied adapters against targets.
    fn verify_applied(&mut self, utm_name: &str, expected: &[TargetNic]) -> Result<(), String>;
    fn write_evidence(&mut self, evidence: &TransactionEvidence) -> Result<PathBuf, String>;
}

// --- Owner-only storage (0700 dirs, 0600 files) ---

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|err| format!("create dir failed ({}): {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("set dir permissions failed ({}): {err}", path.display()))?;
    Ok(())
}

fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("path {} has no filename", path.display()))?;
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp"));
    fs::write(&tmp_path, contents)
        .map_err(|err| format!("write temp failed ({}): {err}", tmp_path.display()))?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        format!("set permissions failed ({}): {err}", tmp_path.display())
    })?;
    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        format!("rename failed ({}): {err}", path.display())
    })?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Journal + rollback storage for one transaction.
pub struct TransactionStore {
    txn_dir: PathBuf,
}

impl TransactionStore {
    pub fn create(state_dir: &Path, transaction_id: &str) -> Result<Self, String> {
        let txn_dir = state_dir.join(TXN_SUBDIR).join(transaction_id);
        if txn_dir.exists() {
            return Err(format!(
                "transaction directory {} already exists",
                txn_dir.display()
            ));
        }
        create_private_dir(&txn_dir)?;
        Ok(Self { txn_dir })
    }

    pub fn open(state_dir: &Path, transaction_id: &str) -> Result<Self, String> {
        validate_transaction_id(transaction_id)?;
        let txn_dir = state_dir.join(TXN_SUBDIR).join(transaction_id);
        if !txn_dir.is_dir() {
            return Err(format!(
                "transaction {transaction_id} not found under {}",
                state_dir.join(TXN_SUBDIR).display()
            ));
        }
        Ok(Self { txn_dir })
    }

    pub fn list(state_dir: &Path) -> Result<Vec<String>, String> {
        let root = state_dir.join(TXN_SUBDIR);
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for entry in
            fs::read_dir(&root).map_err(|err| format!("read {} failed: {err}", root.display()))?
        {
            let entry =
                entry.map_err(|err| format!("enumerate {} failed: {err}", root.display()))?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && let Some(name) = entry.file_name().to_str()
            {
                ids.push(name.to_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn dir(&self) -> &Path {
        &self.txn_dir
    }

    pub fn save_journal(&self, journal: &NetworkTxnJournal) -> Result<(), String> {
        let serialized = serde_json::to_vec_pretty(journal)
            .map_err(|err| format!("serialize journal failed: {err}"))?;
        write_private_atomic(&self.txn_dir.join("transaction.json"), &serialized)
    }

    pub fn load_journal(&self) -> Result<NetworkTxnJournal, String> {
        let path = self.txn_dir.join("transaction.json");
        let bytes =
            fs::read(&path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| format!("parse journal {} failed: {err}", path.display()))
    }

    pub fn save_rollback_config(&self, rollback_file: &str, bytes: &[u8]) -> Result<(), String> {
        validate_rollback_file_name(rollback_file)?;
        write_private_atomic(&self.txn_dir.join("rollback").join(rollback_file), bytes).or_else(
            |_| {
                create_private_dir(&self.txn_dir.join("rollback"))?;
                write_private_atomic(&self.txn_dir.join("rollback").join(rollback_file), bytes)
            },
        )
    }

    pub fn load_rollback_config(&self, rollback_file: &str) -> Result<Vec<u8>, String> {
        validate_rollback_file_name(rollback_file)?;
        let path = self.txn_dir.join("rollback").join(rollback_file);
        fs::read(&path).map_err(|err| format!("read rollback {} failed: {err}", path.display()))
    }
}

fn validate_transaction_id(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > 96
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("invalid transaction id {raw:?}"));
    }
    Ok(())
}

fn validate_rollback_file_name(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > 128
        || raw.contains('/')
        || raw.contains("..")
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("invalid rollback file name {raw:?}"));
    }
    Ok(())
}

// --- Atomic network lease (rulebook §15.6) ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLease {
    pub lease_id: String,
    pub transaction_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub vm_aliases: Vec<String>,
    pub utm_names: Vec<String>,
    pub owner_pid: u32,
    /// Full recorded owner command line. Stale-lease recovery requires the
    /// live process at `owner_pid` to match this exactly; pid liveness alone
    /// is never trusted (PID reuse).
    pub owner_command: String,
    pub created_at_epoch_secs: u64,
    /// Run-scoped owned resources beyond the VMs (namespaces, VXLAN ids,
    /// capture handles...). Empty in Slice B; populated by later slices.
    pub resources: Vec<String>,
}

/// Identity probe for stale-lease recovery. Injectable for tests.
pub trait ProcessProbe {
    /// The full command line of the process at `pid`, if it is alive.
    fn process_command(&self, pid: u32) -> Option<String>;
}

pub struct PsProcessProbe;

impl ProcessProbe for PsProcessProbe {
    fn process_command(&self, pid: u32) -> Option<String> {
        let output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let command = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if command.is_empty() {
            None
        } else {
            Some(command)
        }
    }
}

pub struct LeaseStore {
    lease_dir: PathBuf,
}

impl LeaseStore {
    pub fn new(state_dir: &Path) -> Result<Self, String> {
        let lease_dir = state_dir.join(LEASE_SUBDIR);
        create_private_dir(&lease_dir)?;
        Ok(Self { lease_dir })
    }

    fn lock_path(&self) -> PathBuf {
        self.lease_dir.join(LEASE_LOCK_FILE)
    }

    fn acquire_scan_lock(&self) -> Result<(), String> {
        for _ in 0..LEASE_LOCK_RETRIES {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.lock_path())
            {
                Ok(_) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Remove a stale lock (holder died mid-acquisition).
                    if let Ok(metadata) = fs::metadata(self.lock_path()) {
                        let stale = metadata
                            .modified()
                            .ok()
                            .and_then(|modified| modified.elapsed().ok())
                            .is_some_and(|age| age.as_secs() > LEASE_LOCK_STALE_SECS);
                        if stale {
                            let _ = fs::remove_file(self.lock_path());
                            continue;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(LEASE_LOCK_RETRY_MS));
                }
                Err(err) => return Err(format!("lease lock failed: {err}")),
            }
        }
        Err("could not acquire the lease-store lock; another transaction is acquiring".to_owned())
    }

    fn release_scan_lock(&self) {
        let _ = fs::remove_file(self.lock_path());
    }

    fn lease_path(&self, lease_id: &str) -> PathBuf {
        self.lease_dir.join(format!("{lease_id}.json"))
    }

    fn existing_leases(&self) -> Result<Vec<(PathBuf, NetworkLease)>, String> {
        let mut leases = Vec::new();
        for entry in
            fs::read_dir(&self.lease_dir).map_err(|err| format!("read lease dir failed: {err}"))?
        {
            let entry = entry.map_err(|err| format!("enumerate lease dir failed: {err}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|err| format!("read lease {} failed: {err}", path.display()))?;
            let lease: NetworkLease = serde_json::from_slice(&bytes)
                .map_err(|err| format!("parse lease {} failed: {err}", path.display()))?;
            leases.push((path, lease));
        }
        Ok(leases)
    }

    /// Acquire a lease. Overlapping live leases are refused; stale leases
    /// (owner process gone or command mismatch) are recovered first.
    pub fn acquire(&self, lease: &NetworkLease, probe: &dyn ProcessProbe) -> Result<(), String> {
        self.acquire_scan_lock()?;
        let result = self.acquire_locked(lease, probe);
        self.release_scan_lock();
        result
    }

    fn acquire_locked(&self, lease: &NetworkLease, probe: &dyn ProcessProbe) -> Result<(), String> {
        let requested_vms: BTreeSet<&str> = lease
            .vm_aliases
            .iter()
            .map(String::as_str)
            .chain(lease.utm_names.iter().map(String::as_str))
            .collect();
        for (path, existing) in self.existing_leases()? {
            let live = probe
                .process_command(existing.owner_pid)
                .is_some_and(|command| command == existing.owner_command);
            if !live {
                // Verified-stale: owner gone or a different process reused
                // the pid. Recover the lease file.
                fs::remove_file(&path).map_err(|err| {
                    format!("recover stale lease {} failed: {err}", path.display())
                })?;
                continue;
            }
            let existing_vms: BTreeSet<&str> = existing
                .vm_aliases
                .iter()
                .map(String::as_str)
                .chain(existing.utm_names.iter().map(String::as_str))
                .collect();
            let overlap: Vec<&&str> = requested_vms.intersection(&existing_vms).collect();
            if !overlap.is_empty() {
                return Err(format!(
                    "network lease refused: transaction {} (pid {}) already holds {}",
                    existing.transaction_id,
                    existing.owner_pid,
                    overlap
                        .iter()
                        .map(|s| (**s).to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        let serialized = serde_json::to_vec_pretty(lease)
            .map_err(|err| format!("serialize lease failed: {err}"))?;
        let path = self.lease_path(&lease.lease_id);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => {}
            Err(err) => return Err(format!("create lease {} failed: {err}", path.display())),
        }
        write_private_atomic(&path, &serialized)
    }

    /// Release a lease, verifying ownership by content first.
    pub fn release(&self, lease: &NetworkLease) -> Result<(), String> {
        let path = self.lease_path(&lease.lease_id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(format!("read lease {} failed: {err}", path.display())),
        };
        let on_disk: NetworkLease = serde_json::from_slice(&bytes)
            .map_err(|err| format!("parse lease {} failed: {err}", path.display()))?;
        if on_disk.owner_pid != lease.owner_pid || on_disk.transaction_id != lease.transaction_id {
            return Err(format!(
                "refusing to release lease {}: it is owned by transaction {} (pid {})",
                lease.lease_id, on_disk.transaction_id, on_disk.owner_pid
            ));
        }
        fs::remove_file(&path).map_err(|err| format!("remove lease failed: {err}"))
    }
}

// --- Plan derivation ---

fn deterministic_local_mac(utm_name: &str, index: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rustynet-vm-lab-scenario-nic");
    hasher.update(utm_name.as_bytes());
    hasher.update(index.to_le_bytes());
    let digest = hasher.finalize();
    let mut octets = [
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ];
    // Locally administered, unicast.
    octets[0] = (octets[0] & 0xfc) | 0x02;
    octets
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Derive the per-VM target adapters for a profile. Conservative Slice B
/// mapping:
/// - management: `Shared` (UTM Host Only stays pending the rulebook §15.9
///   owner decision 4 live capability probe, even where the policy would
///   allow it);
/// - scenario `vxlan`/`isolated_lan`: one additional Host Only adapter on
///   QEMU; refused on the Apple backend until multi-NIC is live-proven;
/// - scenario `netns`/`none`: no scenario adapter (netns rides inside a
///   guest);
/// - scenario `physical_interface`: bridged to the first allowlisted
///   interface (never `en0`);
/// - scenario `remote_physical`: cannot be produced by a local transaction.
pub fn derive_target_nics(
    profile: &NetworkProfile,
    backend: UtmBackend,
    utm_name: &str,
    current: &[super::network_audit::UtmNicObservation],
) -> Result<Vec<TargetNic>, String> {
    profile
        .backend_compatibility(backend)
        .map_err(|err| format!("profile {} cannot apply to {utm_name}: {err}", profile.id))?;
    let management_mode = match profile.management.attachment {
        ManagementAttachmentPolicy::Shared | ManagementAttachmentPolicy::HostOnlyOrShared => {
            AttachmentMode::Shared
        }
        ManagementAttachmentPolicy::HostOnly => AttachmentMode::HostOnly,
    };
    let default_hardware = match backend {
        UtmBackend::Qemu => Some("virtio-net-pci".to_owned()),
        UtmBackend::Apple => None,
    };
    let management_nic = current.first();
    let mut targets = vec![TargetNic::new(
        0,
        management_mode,
        management_nic
            .map(|nic| nic.mac.clone())
            .unwrap_or_else(|| deterministic_local_mac(utm_name, 0)),
        management_nic
            .and_then(|nic| nic.hardware.clone())
            .or(default_hardware.clone()),
        None,
    )?];
    match profile.scenario.substrate {
        ScenarioSubstrate::None | ScenarioSubstrate::Netns => {}
        ScenarioSubstrate::Vxlan | ScenarioSubstrate::IsolatedLan => {
            if backend == UtmBackend::Apple {
                return Err(format!(
                    "profile {} needs a scenario adapter but Apple-backend multi-NIC is not live-proven; refusing (fail closed)",
                    profile.id
                ));
            }
            let existing = current.get(1);
            targets.push(TargetNic::new(
                1,
                AttachmentMode::HostOnly,
                existing
                    .map(|nic| nic.mac.clone())
                    .unwrap_or_else(|| deterministic_local_mac(utm_name, 1)),
                existing
                    .and_then(|nic| nic.hardware.clone())
                    .or(default_hardware),
                None,
            )?);
        }
        ScenarioSubstrate::PhysicalInterface => {
            let interface = profile
                .scenario
                .physical
                .as_ref()
                .and_then(|physical| physical.allowed_host_interfaces.first())
                .ok_or_else(|| {
                    format!(
                        "profile {} has no allowlisted physical interface",
                        profile.id
                    )
                })?;
            let existing = current.get(1);
            targets.push(TargetNic::new(
                1,
                AttachmentMode::Bridged,
                existing
                    .map(|nic| nic.mac.clone())
                    .unwrap_or_else(|| deterministic_local_mac(utm_name, 1)),
                existing
                    .and_then(|nic| nic.hardware.clone())
                    .or(default_hardware),
                Some(interface.clone()),
            )?);
        }
        ScenarioSubstrate::RemotePhysical => {
            return Err(format!(
                "profile {} targets remote physical networks; a local UTM transaction cannot produce it",
                profile.id
            ));
        }
    }
    Ok(targets)
}

/// Render the UTM `Network` array JSON for a backend from target adapters.
pub fn render_network_json(backend: UtmBackend, targets: &[TargetNic]) -> Result<String, String> {
    let mut adapters = Vec::new();
    for target in targets {
        let mode = target.utm_mode_str(backend)?;
        let mut object = serde_json::Map::new();
        object.insert(
            "Mode".to_owned(),
            serde_json::Value::String(mode.to_owned()),
        );
        object.insert(
            "MacAddress".to_owned(),
            serde_json::Value::String(target.mac.clone()),
        );
        if let Some(interface) = &target.bridge_interface {
            if interface == "en0" {
                return Err("bridging to en0 is denied by policy".to_owned());
            }
            object.insert(
                "BridgeInterface".to_owned(),
                serde_json::Value::String(interface.clone()),
            );
        }
        if backend == UtmBackend::Qemu {
            if let Some(hardware) = &target.hardware {
                object.insert(
                    "Hardware".to_owned(),
                    serde_json::Value::String(hardware.clone()),
                );
            }
            object.insert("IsolateFromHost".to_owned(), serde_json::Value::Bool(false));
            object.insert(
                "PortForward".to_owned(),
                serde_json::Value::Array(Vec::new()),
            );
        }
        adapters.push(serde_json::Value::Object(object));
    }
    serde_json::to_string(&serde_json::Value::Array(adapters))
        .map_err(|err| format!("render network json failed: {err}"))
}

fn nics_match_targets(
    observed: &[super::network_audit::UtmNicObservation],
    targets: &[TargetNic],
) -> bool {
    if observed.len() != targets.len() {
        return false;
    }
    observed.iter().zip(targets.iter()).all(|(nic, target)| {
        nic.mode == target.mode
            && nic.mac == target.mac
            && nic.bridge_interface.as_deref() == target.bridge_interface.as_deref()
    })
}

// --- The transaction engine ---

pub struct NetworkTransactionEngine<'a, P: NetworkMutationPort> {
    port: &'a mut P,
    store: TransactionStore,
    lease_store: LeaseStore,
    lease: NetworkLease,
    journal: NetworkTxnJournal,
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn new_transaction_id() -> String {
    format!("txn-{}-{}", now_epoch_secs(), std::process::id())
}

impl<'a, P: NetworkMutationPort> NetworkTransactionEngine<'a, P> {
    /// Validate, plan, snapshot power/config digests, acquire the lease, and
    /// persist the initial journal. Nothing is mutated. Fails closed on any
    /// incompatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        port: &'a mut P,
        state_dir: &Path,
        probe: &dyn ProcessProbe,
        profile: &NetworkProfile,
        entries: &[(String, String, String, String)],
        owner_command: String,
        transaction_id: String,
    ) -> Result<Self, String> {
        validate_transaction_id(&transaction_id)?;
        if entries.is_empty() {
            return Err("no VMs selected for the network transaction".to_owned());
        }
        let mut vm_records = Vec::new();
        for (alias, utm_name, bundle_path, management_host) in entries {
            let config_bytes = port.read_config(utm_name)?;
            let (backend, current_network_json) = port.read_network_state(utm_name)?;
            let current = parse_utm_nics_json(backend, &current_network_json)?;
            let targets = derive_target_nics(profile, backend, utm_name, &current)?;
            let target_network_json = render_network_json(backend, &targets)?;
            let power = port.power_state(utm_name)?;
            vm_records.push(VmTxnRecord {
                alias: alias.clone(),
                utm_name: utm_name.clone(),
                bundle_path: bundle_path.clone(),
                backend: backend.as_str().to_owned(),
                management_host: management_host.clone(),
                original_power: power,
                original_config_sha256: sha256_hex(&config_bytes),
                rollback_file: format!("{}.config.plist", sanitize_file_stem(utm_name)),
                already_compliant: nics_match_targets(&current, &targets),
                target_nics: targets,
                target_network_json,
                guest_plan: GuestNetworkPlan::default(),
                snapshot_taken: false,
                stopped_by_txn: false,
                config_applied: false,
                started_back: false,
            });
        }
        let lease = NetworkLease {
            lease_id: transaction_id.clone(),
            transaction_id: transaction_id.clone(),
            profile_id: profile.id.as_str().to_owned(),
            profile_digest: profile.canonical_digest(),
            vm_aliases: vm_records.iter().map(|vm| vm.alias.clone()).collect(),
            utm_names: vm_records.iter().map(|vm| vm.utm_name.clone()).collect(),
            owner_pid: std::process::id(),
            owner_command,
            created_at_epoch_secs: now_epoch_secs(),
            resources: Vec::new(),
        };
        let lease_store = LeaseStore::new(state_dir)?;
        lease_store.acquire(&lease, probe)?;
        let store = match TransactionStore::create(state_dir, &transaction_id) {
            Ok(store) => store,
            Err(err) => {
                let _ = lease_store.release(&lease);
                return Err(err);
            }
        };
        let journal = NetworkTxnJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            transaction_id,
            profile_id: profile.id.as_str().to_owned(),
            profile_digest: profile.canonical_digest(),
            lease_id: lease.lease_id.clone(),
            created_at_epoch_secs: now_epoch_secs(),
            vms: vm_records,
            steps: Vec::new(),
            outcome: TxnOutcome::InProgress,
            failure: None,
        };
        store.save_journal(&journal)?;
        Ok(Self {
            port,
            store,
            lease_store,
            lease,
            journal,
        })
    }

    pub fn journal(&self) -> &NetworkTxnJournal {
        &self.journal
    }

    fn record_step(
        &mut self,
        step: TxnStep,
        status: &str,
        detail: Option<String>,
    ) -> Result<(), String> {
        self.journal.steps.push(StepRecord {
            step,
            status: status.to_owned(),
            detail,
        });
        self.store.save_journal(&self.journal)
    }

    /// Execute one step. The journal is persisted before and after so a crash
    /// between any two operations is recoverable via `run_restore`.
    pub fn execute_step(&mut self, step: TxnStep) -> Result<(), String> {
        self.record_step(step, "running", None)?;
        let result = self.execute_step_inner(step);
        match &result {
            Ok(()) => self.record_step(step, "done", None)?,
            Err(err) => self.record_step(step, "failed", Some(err.clone()))?,
        }
        result
    }

    fn execute_step_inner(&mut self, step: TxnStep) -> Result<(), String> {
        match step {
            TxnStep::SnapshotConfigs => {
                for index in 0..self.journal.vms.len() {
                    let utm_name = self.journal.vms[index].utm_name.clone();
                    let rollback_file = self.journal.vms[index].rollback_file.clone();
                    let bytes = self.port.read_config(&utm_name)?;
                    if sha256_hex(&bytes) != self.journal.vms[index].original_config_sha256 {
                        return Err(format!(
                            "configuration of {utm_name} changed between planning and snapshot; aborting"
                        ));
                    }
                    self.store.save_rollback_config(&rollback_file, &bytes)?;
                    self.journal.vms[index].snapshot_taken = true;
                    self.store.save_journal(&self.journal)?;
                }
                Ok(())
            }
            TxnStep::StopVms => {
                for index in 0..self.journal.vms.len() {
                    if self.journal.vms[index].already_compliant {
                        continue;
                    }
                    let utm_name = self.journal.vms[index].utm_name.clone();
                    if self.port.power_state(&utm_name)? == PowerState::Started {
                        self.port.stop_vm(&utm_name)?;
                        self.journal.vms[index].stopped_by_txn = true;
                        self.store.save_journal(&self.journal)?;
                    }
                    if self.port.power_state(&utm_name)? != PowerState::Stopped {
                        return Err(format!("{utm_name} did not reach the stopped state"));
                    }
                }
                Ok(())
            }
            TxnStep::ApplyConfigs => {
                for index in 0..self.journal.vms.len() {
                    if self.journal.vms[index].already_compliant {
                        continue;
                    }
                    let utm_name = self.journal.vms[index].utm_name.clone();
                    let network_json = self.journal.vms[index].target_network_json.clone();
                    self.port.apply_network_config(&utm_name, &network_json)?;
                    self.journal.vms[index].config_applied = true;
                    self.store.save_journal(&self.journal)?;
                }
                Ok(())
            }
            TxnStep::StartVms => {
                for index in 0..self.journal.vms.len() {
                    let record = &self.journal.vms[index];
                    if record.already_compliant || record.original_power != PowerState::Started {
                        continue;
                    }
                    let utm_name = record.utm_name.clone();
                    self.port.start_vm(&utm_name)?;
                    self.journal.vms[index].started_back = true;
                    self.store.save_journal(&self.journal)?;
                }
                Ok(())
            }
            TxnStep::WaitManagement => {
                for record in &self.journal.vms {
                    if record.already_compliant || record.original_power != PowerState::Started {
                        continue;
                    }
                    self.port
                        .wait_management_ready(&record.utm_name, &record.management_host)?;
                }
                Ok(())
            }
            TxnStep::ConfigureGuests => {
                for record in &self.journal.vms {
                    if record.already_compliant || record.guest_plan.is_empty() {
                        continue;
                    }
                    self.port
                        .configure_guest(&record.utm_name, &record.guest_plan)?;
                }
                Ok(())
            }
            TxnStep::PostAudit => {
                for record in &self.journal.vms {
                    self.port
                        .verify_applied(&record.utm_name, &record.target_nics)?;
                }
                Ok(())
            }
            TxnStep::WriteEvidence => {
                let evidence = TransactionEvidence {
                    schema_version: 1,
                    transaction_id: self.journal.transaction_id.clone(),
                    profile_id: self.journal.profile_id.clone(),
                    profile_digest: self.journal.profile_digest.clone(),
                    vms: self
                        .journal
                        .vms
                        .iter()
                        .map(|vm| TransactionEvidenceVm {
                            alias: vm.alias.clone(),
                            utm_name: vm.utm_name.clone(),
                            original_config_sha256: vm.original_config_sha256.clone(),
                            target_modes: vm
                                .target_nics
                                .iter()
                                .map(|nic| nic.mode.as_str().to_owned())
                                .collect(),
                            already_compliant: vm.already_compliant,
                        })
                        .collect(),
                };
                self.port.write_evidence(&evidence)?;
                Ok(())
            }
        }
    }

    /// Run all steps; on any failure, roll back everything and verify.
    /// A rollback failure is reported and leaves the lease held: the next
    /// overlapping transaction is blocked until `vm-lab-network-restore`
    /// completes a verified restore.
    pub fn run_all(mut self) -> Result<String, String> {
        for step in TxnStep::ORDER {
            if let Err(step_err) = self.execute_step(step) {
                let rollback = rollback_journal(&self.store, self.port, &mut self.journal);
                return match rollback {
                    Ok(()) => {
                        self.journal.outcome = TxnOutcome::RolledBackVerified;
                        self.journal.failure = Some(step_err.clone());
                        self.store.save_journal(&self.journal)?;
                        self.lease_store.release(&self.lease)?;
                        Err(format!(
                            "network transaction {} failed at step {step} and was fully rolled back (verified): {step_err}",
                            self.journal.transaction_id
                        ))
                    }
                    Err(rollback_err) => {
                        self.journal.outcome = TxnOutcome::RollbackIncomplete;
                        self.journal.failure =
                            Some(format!("{step_err}; rollback incomplete: {rollback_err}"));
                        self.store.save_journal(&self.journal)?;
                        // Lease is intentionally NOT released: the fleet state
                        // is unknown and overlapping work must stay blocked.
                        Err(format!(
                            "network transaction {} failed at step {step} AND rollback is incomplete ({rollback_err}); run `rustynet ops vm-lab-network-restore --transaction {}` before any overlapping work",
                            self.journal.transaction_id, self.journal.transaction_id
                        ))
                    }
                };
            }
        }
        self.journal.outcome = TxnOutcome::Applied;
        self.store.save_journal(&self.journal)?;
        self.lease_store.release(&self.lease)?;
        Ok(format!(
            "network transaction {} applied and verified for {} VM(s)",
            self.journal.transaction_id,
            self.journal.vms.len()
        ))
    }
}

fn sanitize_file_stem(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Restore every VM in a journal to its snapshotted configuration and power
/// state, verifying digests. Idempotent: safe to run repeatedly and after a
/// process interruption at any step.
pub fn rollback_journal<P: NetworkMutationPort>(
    store: &TransactionStore,
    port: &mut P,
    journal: &mut NetworkTxnJournal,
) -> Result<(), String> {
    let mut failures = Vec::new();
    for index in (0..journal.vms.len()).rev() {
        let record = journal.vms[index].clone();
        if record.already_compliant || !record.snapshot_taken {
            continue;
        }
        let restore_one = (|| -> Result<(), String> {
            let current = port.read_config(&record.utm_name)?;
            let config_intact = sha256_hex(&current) == record.original_config_sha256;
            if config_intact && !record.config_applied {
                // The configuration was never modified: do not rewrite an
                // untouched file; only undo a stop this transaction caused.
                if record.stopped_by_txn
                    && record.original_power == PowerState::Started
                    && port.power_state(&record.utm_name)? != PowerState::Started
                {
                    port.start_vm(&record.utm_name)?;
                }
                return Ok(());
            }
            let original = store.load_rollback_config(&record.rollback_file)?;
            if sha256_hex(&original) != record.original_config_sha256 {
                return Err(format!(
                    "rollback snapshot for {} does not match its recorded digest; refusing to restore corrupted state",
                    record.utm_name
                ));
            }
            // Configuration writes require a stopped VM.
            if port.power_state(&record.utm_name)? == PowerState::Started {
                port.stop_vm(&record.utm_name)?;
            }
            port.restore_config_bytes(&record.utm_name, &original)?;
            let now = port.read_config(&record.utm_name)?;
            if sha256_hex(&now) != record.original_config_sha256 {
                return Err(format!(
                    "restored configuration of {} does not verify against the original digest",
                    record.utm_name
                ));
            }
            if record.original_power == PowerState::Started {
                port.start_vm(&record.utm_name)?;
                if port.power_state(&record.utm_name)? != PowerState::Started {
                    return Err(format!(
                        "{} did not return to its original started state",
                        record.utm_name
                    ));
                }
            }
            Ok(())
        })();
        match restore_one {
            Ok(()) => {
                journal.vms[index].config_applied = false;
                store.save_journal(journal)?;
            }
            Err(err) => failures.push(err),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

// --- Live UTM port ---

/// SSH material for the management-readiness probe. The readiness check runs
/// the real `ssh` binary rather than a raw `TcpStream`: on macOS a raw TCP
/// socket to a LAN address opened from inside this process is silently blocked
/// by Local Network Privacy and false-negatives, whereas the `ssh` binary
/// reaches the guests fine (see CLAUDE.md §12.3.1). Restore never probes, so
/// this is optional.
#[derive(Debug, Clone)]
pub struct SshProbeConfig {
    pub identity_file: PathBuf,
    pub known_hosts: PathBuf,
    /// utm_name → ssh user.
    pub ssh_users: std::collections::BTreeMap<String, String>,
    /// utm_name → recorded ssh user@host fallback host (already split).
    pub default_user: String,
}

pub struct LiveUtmMutationPort {
    utmctl_path: PathBuf,
    /// utm_name → bundle config.plist path.
    config_paths: std::collections::BTreeMap<String, PathBuf>,
    evidence_dir: PathBuf,
    ssh_probe: Option<SshProbeConfig>,
}

impl LiveUtmMutationPort {
    pub fn new(
        utmctl_path: PathBuf,
        config_paths: std::collections::BTreeMap<String, PathBuf>,
        evidence_dir: PathBuf,
    ) -> Self {
        Self {
            utmctl_path,
            config_paths,
            evidence_dir,
            ssh_probe: None,
        }
    }

    /// Attach SSH material so `wait_management_ready` can probe via the `ssh`
    /// binary (required for a correct readiness verdict on macOS).
    pub fn with_ssh_probe(mut self, probe: SshProbeConfig) -> Self {
        self.ssh_probe = Some(probe);
        self
    }

    fn config_path(&self, utm_name: &str) -> Result<&PathBuf, String> {
        self.config_paths
            .get(utm_name)
            .ok_or_else(|| format!("no bundle path known for {utm_name}"))
    }

    /// Probe management-plane readiness with the real `ssh` binary (argv-only,
    /// no shell). Host-key pinning is preserved (`StrictHostKeyChecking=yes`
    /// against the pinned known_hosts); a host-key rejection still proves the
    /// transport reached sshd, which `classify_ssh_probe` treats as reachable.
    fn ssh_management_probe(&self, probe: &SshProbeConfig, user: &str, host: &str) -> SshReadiness {
        let destination = format!("{user}@{host}");
        let known_hosts_arg = format!("UserKnownHostsFile={}", probe.known_hosts.display());
        let output = Command::new("/usr/bin/ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                known_hosts_arg.as_str(),
                "-o",
                "ConnectTimeout=6",
                "-o",
                "IdentitiesOnly=yes",
                "-i",
            ])
            .arg(&probe.identity_file)
            .arg(&destination)
            .args(["--", "exit"])
            .output();
        match output {
            Ok(out) => {
                classify_ssh_probe(out.status.success(), &String::from_utf8_lossy(&out.stderr))
            }
            Err(_) => SshReadiness::NotReachable,
        }
    }

    fn utmctl(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new(&self.utmctl_path)
            .args(args)
            .output()
            .map_err(|err| format!("utmctl invocation failed: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "utmctl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn wait_power(&self, utm_name: &str, wanted: PowerState) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(VM_POWER_POLL_TIMEOUT_SECS);
        loop {
            let status = self.utmctl(&["status", utm_name])?;
            let state = parse_power_state(&status);
            if state == wanted {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{utm_name} did not reach {wanted:?} within {VM_POWER_POLL_TIMEOUT_SECS}s (last status {status:?})"
                ));
            }
            std::thread::sleep(Duration::from_millis(VM_POWER_POLL_INTERVAL_MS));
        }
    }
}

fn parse_power_state(raw: &str) -> PowerState {
    match raw.trim().to_ascii_lowercase().as_str() {
        "started" => PowerState::Started,
        "stopped" => PowerState::Stopped,
        _ => PowerState::Other,
    }
}

/// Resolve a guest's IPv4 from the host ARP table by (normalized) MAC.
/// macOS `arp -a` prints unpadded octets, so both sides are normalized to
/// lowercase zero-padded colon-hex before comparison.
fn arp_lookup_ipv4_by_mac(wanted_mac: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/arp").arg("-a").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // `? (192.168.64.9) at 3e:ae:a9:5a:61:82 on bridge100 ...`
        let Some(ip) = line
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(ip, _)| ip.trim())
        else {
            continue;
        };
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        let Some(mac_raw) = line
            .split_whitespace()
            .skip_while(|token| *token != "at")
            .nth(1)
        else {
            continue;
        };
        let normalized: Vec<String> = mac_raw
            .split(':')
            .map(|octet| format!("{:0>2}", octet.to_ascii_lowercase()))
            .collect();
        if normalized.len() == 6 && normalized.join(":") == wanted_mac {
            return Some(ip.to_owned());
        }
    }
    None
}

/// Readiness verdict from an `ssh` probe. "The management plane answers" means
/// the TCP + SSH handshake completed — even a `Permission denied` or an
/// unpinned-host-key rejection proves sshd is up. Only a connection-level
/// failure (refused / timeout / no route) means not-yet-ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshReadiness {
    Reachable,
    NotReachable,
}

/// Classify an `ssh` probe outcome. `exit 0` (command ran) is reachable; a
/// connection-level failure keeps polling; anything else (auth/host-key) still
/// proves the port answered.
fn classify_ssh_probe(exit_ok: bool, stderr: &str) -> SshReadiness {
    if exit_ok {
        return SshReadiness::Reachable;
    }
    let lowered = stderr.to_ascii_lowercase();
    const CONNECTION_FAILURES: &[&str] = &[
        "connection refused",
        "connection timed out",
        "connection timeout",
        "operation timed out",
        "no route to host",
        "network is unreachable",
        "host is down",
        "could not resolve hostname",
        "name or service not known",
        "no address associated",
    ];
    if CONNECTION_FAILURES
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        SshReadiness::NotReachable
    } else {
        // Permission denied, host-key mismatch/unknown, banner exchange, etc.
        // — the transport layer reached sshd, so the management plane is up.
        SshReadiness::Reachable
    }
}

fn parse_backend_from_config(config_bytes: &[u8]) -> Result<UtmBackend, String> {
    let text = String::from_utf8_lossy(config_bytes);
    if text.contains("<key>Backend</key>") {
        // The value follows the key: <string>QEMU</string> / <string>Apple</string>.
        let after = text.split("<key>Backend</key>").nth(1).unwrap_or_default();
        if let Some(value) = after
            .split("<string>")
            .nth(1)
            .and_then(|rest| rest.split("</string>").next())
        {
            return UtmBackend::parse(value.trim());
        }
    }
    Err("cannot determine the UTM backend from config.plist".to_owned())
}

/// Read-only extraction of the `Network` array as JSON from a live plist.
fn extract_network_json_from_path(config_path: &Path) -> Result<String, String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", "Network", "json", "-o", "-"])
        .arg(config_path)
        .output()
        .map_err(|err| format!("plutil invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "plutil -extract Network failed for {}: {}",
            config_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "plutil produced non-UTF-8 output".to_owned())
}

impl NetworkMutationPort for LiveUtmMutationPort {
    fn read_config(&mut self, utm_name: &str) -> Result<Vec<u8>, String> {
        let path = self.config_path(utm_name)?;
        fs::read(path).map_err(|err| format!("read {} failed: {err}", path.display()))
    }

    fn read_network_state(&mut self, utm_name: &str) -> Result<(UtmBackend, String), String> {
        let path = self.config_path(utm_name)?.clone();
        let config =
            fs::read(&path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
        let backend = parse_backend_from_config(&config)?;
        let network_json = extract_network_json_from_path(&path)?;
        Ok((backend, network_json))
    }

    fn power_state(&mut self, utm_name: &str) -> Result<PowerState, String> {
        Ok(parse_power_state(&self.utmctl(&["status", utm_name])?))
    }

    fn stop_vm(&mut self, utm_name: &str) -> Result<(), String> {
        // Graceful ACPI stop first; if the VM is mid-boot (e.g. it was just
        // restarted moments ago in the apply step and rollback needs it down
        // again) the guest may not honor ACPI within the window, so fall back
        // to a forced stop rather than leaving the transaction unable to
        // complete a verified rollback.
        self.utmctl(&["stop", utm_name])?;
        if self.wait_power(utm_name, PowerState::Stopped).is_ok() {
            return Ok(());
        }
        eprintln!("{utm_name}: graceful stop timed out; forcing power off");
        // `utmctl stop --force` performs a hard power-off on QEMU guests.
        let _ = self.utmctl(&["stop", utm_name, "--force"]);
        self.wait_power(utm_name, PowerState::Stopped)
    }

    fn start_vm(&mut self, utm_name: &str) -> Result<(), String> {
        self.utmctl(&["start", utm_name])?;
        self.wait_power(utm_name, PowerState::Started)
    }

    fn apply_network_config(&mut self, utm_name: &str, network_json: &str) -> Result<(), String> {
        if self.power_state(utm_name)? != PowerState::Stopped {
            return Err(format!(
                "refusing to modify {utm_name}: configuration writes require a stopped VM"
            ));
        }
        let path = self.config_path(utm_name)?.clone();
        let output = Command::new("/usr/bin/plutil")
            .args(["-replace", "Network", "-json", network_json])
            .arg(&path)
            .output()
            .map_err(|err| format!("plutil invocation failed: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "plutil -replace Network failed for {utm_name}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    fn restore_config_bytes(&mut self, utm_name: &str, original: &[u8]) -> Result<(), String> {
        if self.power_state(utm_name)? != PowerState::Stopped {
            return Err(format!(
                "refusing to restore {utm_name}: configuration writes require a stopped VM"
            ));
        }
        let path = self.config_path(utm_name)?.clone();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("path {} has no filename", path.display()))?;
        let tmp_path = path.with_file_name(format!(".{file_name}.restore.tmp"));
        fs::write(&tmp_path, original)
            .map_err(|err| format!("write restore temp failed: {err}"))?;
        fs::rename(&tmp_path, &path).map_err(|err| {
            let _ = fs::remove_file(&tmp_path);
            format!("rename restore into place failed: {err}")
        })
    }

    fn wait_management_ready(&mut self, utm_name: &str, host: &str) -> Result<(), String> {
        // Rulebook §13 step 7: start, REDISCOVER, audit. An attachment change
        // usually changes the management address (e.g. bridged 10.x → Shared
        // 192.168.64.x), so the recorded inventory host is only a fallback
        // candidate. Live candidates come from `utmctl ip-address` (guest
        // agent) with an ARP-by-MAC fallback. Readiness is probed with the
        // real `ssh` binary — a raw TCP connect from this process is
        // false-negatived by macOS Local Network Privacy (CLAUDE.md §12.3.1).
        let Some(probe) = self.ssh_probe.clone() else {
            return Err(format!(
                "{utm_name}: no SSH probe configured; cannot verify the management plane (a raw TCP probe is unreliable on macOS)"
            ));
        };
        let user = probe
            .ssh_users
            .get(utm_name)
            .cloned()
            .unwrap_or_else(|| probe.default_user.clone());
        let deadline = Instant::now() + Duration::from_secs(MANAGEMENT_READY_TIMEOUT_SECS);
        let mac = self
            .read_network_state(utm_name)
            .ok()
            .and_then(|(backend, json)| parse_utm_nics_json(backend, &json).ok())
            .and_then(|nics| nics.first().map(|nic| nic.mac.clone()));
        loop {
            let mut candidates: Vec<String> = Vec::new();
            if let Ok(output) = self.utmctl(&["ip-address", utm_name]) {
                candidates.extend(
                    output
                        .lines()
                        .map(str::trim)
                        .filter(|line| line.parse::<std::net::Ipv4Addr>().is_ok())
                        .map(str::to_owned),
                );
            }
            if let Some(mac) = mac.as_deref()
                && let Some(ip) = arp_lookup_ipv4_by_mac(mac)
                && !candidates.contains(&ip)
            {
                candidates.push(ip);
            }
            if !host.is_empty() && !candidates.contains(&host.to_owned()) {
                candidates.push(host.to_owned());
            }
            for candidate in &candidates {
                if self.ssh_management_probe(&probe, &user, candidate) == SshReadiness::Reachable {
                    eprintln!("{utm_name}: management plane ready at {candidate}:22 (ssh)");
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{utm_name} management plane did not answer over ssh within {MANAGEMENT_READY_TIMEOUT_SECS}s (candidates tried: {}) — DHCP/management timeout",
                    if candidates.is_empty() {
                        "<none discovered>".to_owned()
                    } else {
                        candidates.join(", ")
                    }
                ));
            }
            std::thread::sleep(Duration::from_millis(MANAGEMENT_READY_POLL_MS));
        }
    }

    fn configure_guest(&mut self, utm_name: &str, plan: &GuestNetworkPlan) -> Result<(), String> {
        if plan.is_empty() {
            return Ok(());
        }
        // Guest scenario addressing is derived by the site allocator that
        // lands with orchestrator integration (Slice C). Until then a
        // non-empty plan cannot be executed live; fail closed rather than
        // improvise.
        Err(format!(
            "guest network plan for {utm_name} is not executable yet: scenario site allocation lands in Slice C"
        ))
    }

    fn verify_applied(&mut self, utm_name: &str, expected: &[TargetNic]) -> Result<(), String> {
        let (backend, network_json) = self.read_network_state(utm_name)?;
        let observed = parse_utm_nics_json(backend, &network_json)?;
        if !nics_match_targets(&observed, expected) {
            return Err(format!(
                "post-apply audit failed for {utm_name}: observed adapters do not match the target profile (possible UTM clobber)"
            ));
        }
        Ok(())
    }

    fn write_evidence(&mut self, evidence: &TransactionEvidence) -> Result<PathBuf, String> {
        create_private_dir(&self.evidence_dir)?;
        let path = self.evidence_dir.join("evidence.json");
        let serialized = serde_json::to_vec_pretty(evidence)
            .map_err(|err| format!("serialize evidence failed: {err}"))?;
        write_private_atomic(&path, &serialized)?;
        Ok(path)
    }
}

// --- Commands ---

/// Config for `rustynet ops vm-lab-network-prepare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabNetworkPrepareConfig {
    pub inventory_path: Option<PathBuf>,
    pub profile_dir: Option<PathBuf>,
    pub profile: String,
    /// Empty = every inventory VM with a local UTM controller.
    pub vm_aliases: Vec<String>,
    pub utmctl_path: Option<PathBuf>,
    /// SSH identity + known_hosts for the post-restart management-readiness
    /// probe (defaults to the lab identity / known_hosts). The probe runs the
    /// `ssh` binary, not a raw TCP connect (macOS LNP false-negatives the
    /// latter).
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    /// The explicit mutation authorization boundary. Without it the command
    /// prints the redacted dry-run plan and exits.
    pub approve_reconfigure: bool,
    pub dry_run: bool,
    pub state_dir: Option<PathBuf>,
}

/// Config for `rustynet ops vm-lab-network-restore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabNetworkRestoreConfig {
    pub transaction_id: Option<String>,
    pub list: bool,
    pub inventory_path: Option<PathBuf>,
    pub utmctl_path: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

fn selected_entries(
    entries: &[VmInventoryEntry],
    requested: &[String],
) -> Result<Vec<(String, String, String, String)>, String> {
    let mut selected = Vec::new();
    for entry in entries {
        let Some(VmController::LocalUtm {
            utm_name,
            bundle_path,
        }) = entry.controller.as_ref()
        else {
            continue;
        };
        if !requested.is_empty() && !requested.iter().any(|alias| alias == &entry.alias) {
            continue;
        }
        let host = entry
            .ssh_target
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(&entry.ssh_target)
            .to_owned();
        selected.push((
            entry.alias.clone(),
            utm_name.clone(),
            bundle_path.display().to_string(),
            host,
        ));
    }
    if !requested.is_empty() {
        for alias in requested {
            if !selected
                .iter()
                .any(|(selected_alias, ..)| selected_alias == alias)
            {
                return Err(format!(
                    "requested VM {alias:?} is not an inventory entry with a local UTM controller"
                ));
            }
        }
    }
    if selected.is_empty() {
        return Err("no local-UTM VMs selected".to_owned());
    }
    Ok(selected)
}

fn render_dry_run_plan(
    profile: &NetworkProfile,
    entries: &[(String, String, String, String)],
    port: &mut dyn NetworkMutationPort,
) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(&format!(
        "DRY-RUN network mutation plan (nothing was changed)\nprofile={} digest={}\n",
        profile.id,
        profile.canonical_digest()
    ));
    for (alias, utm_name, _bundle, _host) in entries {
        let (backend, network_json) = port.read_network_state(utm_name)?;
        let current = parse_utm_nics_json(backend, &network_json)?;
        let targets = derive_target_nics(profile, backend, utm_name, &current)?;
        let compliant = nics_match_targets(&current, &targets);
        let current_desc: Vec<String> = current
            .iter()
            .map(|nic| {
                format!(
                    "nic{}={}{}",
                    nic.index,
                    nic.mode,
                    nic.bridge_interface
                        .as_deref()
                        .map(|iface| format!("->{iface}"))
                        .unwrap_or_default()
                )
            })
            .collect();
        let target_desc: Vec<String> = targets
            .iter()
            .map(|nic| {
                format!(
                    "nic{}={}{}",
                    nic.index,
                    nic.mode,
                    nic.bridge_interface
                        .as_deref()
                        .map(|iface| format!("->{iface}"))
                        .unwrap_or_default()
                )
            })
            .collect();
        out.push_str(&format!(
            "vm={alias} backend={} current=[{}] target=[{}]{}\n",
            backend.as_str(),
            current_desc.join(" "),
            target_desc.join(" "),
            if compliant {
                " (already compliant; no change)"
            } else {
                " (WILL RECONFIGURE: stop -> rewrite -> restart)"
            }
        ));
    }
    out.push_str(
        "authorization: pass --approve-reconfigure to execute this plan through the atomic transaction\n",
    );
    Ok(out)
}

pub fn execute_ops_vm_lab_network_prepare(
    config: VmLabNetworkPrepareConfig,
) -> Result<String, String> {
    let profile_dir = config
        .profile_dir
        .unwrap_or_else(|| PathBuf::from(DEFAULT_NETWORK_PROFILE_DIR));
    let profiles = load_network_profile_dir(&profile_dir)?;
    let profile_id = NetworkProfileId::parse(&config.profile)?;
    let profile = profiles.get(&profile_id).ok_or_else(|| {
        format!(
            "network profile {:?} not found in {}",
            config.profile,
            profile_dir.display()
        )
    })?;
    let inventory_path = config
        .inventory_path
        .unwrap_or_else(|| PathBuf::from(super::DEFAULT_VM_LAB_INVENTORY_PATH));
    let entries = super::load_inventory(&inventory_path)?;
    let selected = selected_entries(&entries, &config.vm_aliases)?;
    let state_dir = config
        .state_dir
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let utmctl_path = config
        .utmctl_path
        .unwrap_or_else(super::default_utmctl_path);
    let config_paths: std::collections::BTreeMap<String, PathBuf> = entries
        .iter()
        .filter_map(|entry| {
            entry.controller.as_ref().map(
                |VmController::LocalUtm {
                     utm_name,
                     bundle_path,
                 }| (utm_name.clone(), bundle_path.join("config.plist")),
            )
        })
        .collect();
    let transaction_id = new_transaction_id();
    let ssh_users: std::collections::BTreeMap<String, String> = entries
        .iter()
        .filter_map(|entry| {
            let VmController::LocalUtm { utm_name, .. } = entry.controller.as_ref()?;
            entry.ssh_user.clone().map(|user| (utm_name.clone(), user))
        })
        .collect();
    let ssh_probe = SshProbeConfig {
        identity_file: config
            .ssh_identity_file
            .unwrap_or_else(super::default_lab_ssh_identity_path),
        known_hosts: config
            .known_hosts_path
            .unwrap_or_else(super::default_known_hosts_path),
        ssh_users,
        default_user: "root".to_owned(),
    };
    let mut port = LiveUtmMutationPort::new(
        utmctl_path,
        config_paths,
        state_dir.join(TXN_SUBDIR).join(&transaction_id),
    )
    .with_ssh_probe(ssh_probe);

    if config.dry_run || !config.approve_reconfigure {
        return render_dry_run_plan(profile, &selected, &mut port);
    }

    let owner_command: String = std::env::args().collect::<Vec<_>>().join(" ");
    let engine = NetworkTransactionEngine::begin(
        &mut port,
        &state_dir,
        &PsProcessProbe,
        profile,
        &selected,
        owner_command,
        transaction_id,
    )?;
    let journal_dir = state_dir
        .join(TXN_SUBDIR)
        .join(&engine.journal().transaction_id);
    engine
        .run_all()
        .map(|summary| format!("{summary}\njournal={}", journal_dir.display()))
}

pub fn execute_ops_vm_lab_network_restore(
    config: VmLabNetworkRestoreConfig,
) -> Result<String, String> {
    let state_dir = config
        .state_dir
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    if config.list {
        let ids = TransactionStore::list(&state_dir)?;
        if ids.is_empty() {
            return Ok("no recorded network transactions".to_owned());
        }
        let mut out = String::new();
        for id in ids {
            let store = TransactionStore::open(&state_dir, &id)?;
            match store.load_journal() {
                Ok(journal) => out.push_str(&format!(
                    "{id} profile={} outcome={} vms={}\n",
                    journal.profile_id,
                    journal.outcome.as_str(),
                    journal
                        .vms
                        .iter()
                        .map(|vm| vm.alias.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                Err(err) => out.push_str(&format!("{id} (unreadable journal: {err})\n")),
            }
        }
        return Ok(out);
    }
    let transaction_id = config
        .transaction_id
        .ok_or_else(|| "vm-lab-network-restore requires --transaction <id> or --list".to_owned())?;
    let store = TransactionStore::open(&state_dir, &transaction_id)?;
    let mut journal = store.load_journal()?;
    let inventory_path = config
        .inventory_path
        .unwrap_or_else(|| PathBuf::from(super::DEFAULT_VM_LAB_INVENTORY_PATH));
    let entries = super::load_inventory(&inventory_path)?;
    let config_paths: std::collections::BTreeMap<String, PathBuf> = entries
        .iter()
        .filter_map(|entry| {
            entry.controller.as_ref().map(
                |VmController::LocalUtm {
                     utm_name,
                     bundle_path,
                 }| (utm_name.clone(), bundle_path.join("config.plist")),
            )
        })
        .collect();
    let mut port = LiveUtmMutationPort::new(
        config
            .utmctl_path
            .unwrap_or_else(super::default_utmctl_path),
        config_paths,
        store.dir().to_path_buf(),
    );
    rollback_journal(&store, &mut port, &mut journal)?;
    journal.outcome = TxnOutcome::RestoredVerified;
    store.save_journal(&journal)?;
    // Release the lease if this transaction still holds one.
    let lease_store = LeaseStore::new(&state_dir)?;
    let lease_path = state_dir
        .join(LEASE_SUBDIR)
        .join(format!("{}.json", journal.lease_id));
    if lease_path.is_file()
        && let Ok(bytes) = fs::read(&lease_path)
        && let Ok(lease) = serde_json::from_slice::<NetworkLease>(&bytes)
        && lease.transaction_id == journal.transaction_id
    {
        let _ = lease_store.release(&lease);
    }
    Ok(format!(
        "transaction {transaction_id} restored and verified for {} VM(s)",
        journal.vms.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::super::network_profile::parse_network_profile_toml;
    use super::*;
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    // --- Mock port with scripted faults ---

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum FaultPoint {
        ReadNetworkState(&'static str),
        StopVm(&'static str),
        StartVm(&'static str),
        ApplyConfig(&'static str),
        WaitManagement,
        ConfigureGuest,
        VerifyApplied,
        WriteEvidence,
    }

    struct MockVm {
        config: Vec<u8>,
        power: PowerState,
    }

    struct MockPort {
        vms: BTreeMap<String, MockVm>,
        faults: HashMap<FaultPoint, String>,
        evidence_written: bool,
        call_log: Vec<String>,
    }

    impl MockPort {
        fn new(vms: &[(&str, &str, PowerState)]) -> Self {
            let vms = vms
                .iter()
                .map(|(name, network_json, power)| {
                    (
                        (*name).to_owned(),
                        MockVm {
                            config: mock_config_bytes(network_json),
                            power: *power,
                        },
                    )
                })
                .collect();
            Self {
                vms,
                faults: HashMap::new(),
                evidence_written: false,
                call_log: Vec::new(),
            }
        }

        fn fault(mut self, point: FaultPoint, message: &str) -> Self {
            self.faults.insert(point, message.to_owned());
            self
        }

        fn vm(&self, name: &str) -> &MockVm {
            self.vms.get(name).expect("vm exists")
        }
    }

    /// Mock config bytes carry the network JSON verbatim after a marker so
    /// snapshot/restore digests behave exactly like real full-file bytes.
    fn mock_config_bytes(network_json: &str) -> Vec<u8> {
        format!("MOCK-PLIST\n{network_json}").into_bytes()
    }

    fn network_json_from_mock_config(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .split_once('\n')
            .map(|(_, json)| json.to_owned())
            .expect("mock config carries network json")
    }

    impl NetworkMutationPort for MockPort {
        fn read_config(&mut self, utm_name: &str) -> Result<Vec<u8>, String> {
            Ok(self.vm(utm_name).config.clone())
        }

        fn read_network_state(&mut self, utm_name: &str) -> Result<(UtmBackend, String), String> {
            if let Some(msg) = self
                .faults
                .get(&FaultPoint::ReadNetworkState(match utm_name {
                    "vm-a" => "vm-a",
                    "vm-b" => "vm-b",
                    other => panic!("unexpected vm {other}"),
                }))
            {
                return Err(msg.clone());
            }
            Ok((
                UtmBackend::Qemu,
                network_json_from_mock_config(&self.vm(utm_name).config),
            ))
        }

        fn power_state(&mut self, utm_name: &str) -> Result<PowerState, String> {
            Ok(self.vm(utm_name).power)
        }

        fn stop_vm(&mut self, utm_name: &str) -> Result<(), String> {
            self.call_log.push(format!("stop:{utm_name}"));
            if let Some(msg) = self.faults.get(&FaultPoint::StopVm(match utm_name {
                "vm-a" => "vm-a",
                "vm-b" => "vm-b",
                other => panic!("unexpected vm {other}"),
            })) {
                return Err(msg.clone());
            }
            self.vms.get_mut(utm_name).unwrap().power = PowerState::Stopped;
            Ok(())
        }

        fn start_vm(&mut self, utm_name: &str) -> Result<(), String> {
            self.call_log.push(format!("start:{utm_name}"));
            if let Some(msg) = self.faults.get(&FaultPoint::StartVm(match utm_name {
                "vm-a" => "vm-a",
                "vm-b" => "vm-b",
                other => panic!("unexpected vm {other}"),
            })) {
                return Err(msg.clone());
            }
            self.vms.get_mut(utm_name).unwrap().power = PowerState::Started;
            Ok(())
        }

        fn apply_network_config(
            &mut self,
            utm_name: &str,
            network_json: &str,
        ) -> Result<(), String> {
            self.call_log.push(format!("apply:{utm_name}"));
            if self.vm(utm_name).power != PowerState::Stopped {
                return Err(format!("{utm_name} is not stopped"));
            }
            if let Some(msg) = self.faults.get(&FaultPoint::ApplyConfig(match utm_name {
                "vm-a" => "vm-a",
                "vm-b" => "vm-b",
                other => panic!("unexpected vm {other}"),
            })) {
                return Err(msg.clone());
            }
            self.vms.get_mut(utm_name).unwrap().config = mock_config_bytes(network_json);
            Ok(())
        }

        fn restore_config_bytes(&mut self, utm_name: &str, original: &[u8]) -> Result<(), String> {
            self.call_log.push(format!("restore:{utm_name}"));
            if self.vm(utm_name).power != PowerState::Stopped {
                return Err(format!("{utm_name} is not stopped"));
            }
            self.vms.get_mut(utm_name).unwrap().config = original.to_vec();
            Ok(())
        }

        fn wait_management_ready(&mut self, _utm_name: &str, _host: &str) -> Result<(), String> {
            if let Some(msg) = self.faults.get(&FaultPoint::WaitManagement) {
                return Err(msg.clone());
            }
            Ok(())
        }

        fn configure_guest(
            &mut self,
            _utm_name: &str,
            _plan: &GuestNetworkPlan,
        ) -> Result<(), String> {
            if let Some(msg) = self.faults.get(&FaultPoint::ConfigureGuest) {
                return Err(msg.clone());
            }
            Ok(())
        }

        fn verify_applied(&mut self, utm_name: &str, expected: &[TargetNic]) -> Result<(), String> {
            if let Some(msg) = self.faults.get(&FaultPoint::VerifyApplied) {
                return Err(msg.clone());
            }
            let network_json = network_json_from_mock_config(&self.vm(utm_name).config);
            let observed = parse_utm_nics_json(UtmBackend::Qemu, &network_json)
                .map_err(|err| format!("mock verify parse: {err}"))?;
            if nics_match_targets(&observed, expected) {
                Ok(())
            } else {
                Err(format!("{utm_name} does not match targets"))
            }
        }

        fn write_evidence(&mut self, _evidence: &TransactionEvidence) -> Result<PathBuf, String> {
            if let Some(msg) = self.faults.get(&FaultPoint::WriteEvidence) {
                return Err(msg.clone());
            }
            self.evidence_written = true;
            Ok(PathBuf::from("/mock/evidence.json"))
        }
    }

    struct AlwaysAliveProbe;
    impl ProcessProbe for AlwaysAliveProbe {
        fn process_command(&self, _pid: u32) -> Option<String> {
            Some("mock-command".to_owned())
        }
    }

    struct MapProbe(HashMap<u32, String>);
    impl ProcessProbe for MapProbe {
        fn process_command(&self, pid: u32) -> Option<String> {
            self.0.get(&pid).cloned()
        }
    }

    const SHARED_NIC_A: &str = r#"[{"Mode": "Shared", "MacAddress": "3e:ae:a9:5a:61:82", "Hardware": "virtio-net-pci", "IsolateFromHost": false, "PortForward": []}]"#;
    const BRIDGED_EN0_NIC_B: &str = r#"[{"Mode": "Bridged", "MacAddress": "7a:c9:3c:84:1b:99", "BridgeInterface": "en0", "Hardware": "virtio-net-pci", "IsolateFromHost": false, "PortForward": []}]"#;

    fn mgmt_profile() -> NetworkProfile {
        parse_network_profile_toml(
            "mgmt_shared_smoke_v1",
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../profiles/vm_lab/network/mgmt_shared_smoke_v1.toml"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn multivm_profile() -> NetworkProfile {
        parse_network_profile_toml(
            "isolated_multivm_v1",
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../profiles/vm_lab/network/isolated_multivm_v1.toml"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn two_vm_entries() -> Vec<(String, String, String, String)> {
        vec![
            (
                "alias-a".to_owned(),
                "vm-a".to_owned(),
                "/lab/vm-a.utm".to_owned(),
                "192.168.64.4".to_owned(),
            ),
            (
                "alias-b".to_owned(),
                "vm-b".to_owned(),
                "/lab/vm-b.utm".to_owned(),
                "192.168.64.5".to_owned(),
            ),
        ]
    }

    fn begin_engine<'a>(
        port: &'a mut MockPort,
        state_dir: &Path,
        profile: &NetworkProfile,
    ) -> NetworkTransactionEngine<'a, MockPort> {
        NetworkTransactionEngine::begin(
            port,
            state_dir,
            &AlwaysAliveProbe,
            profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            format!("txn-test-{}", now_epoch_secs()),
        )
        .unwrap()
    }

    /// Both VMs in these fault tests start as Bridged-to-en0 and running;
    /// a verified rollback must return exactly that state.
    fn assert_fully_restored(port: &MockPort) {
        assert_eq!(
            network_json_from_mock_config(&port.vm("vm-a").config),
            BRIDGED_EN0_NIC_B
        );
        assert_eq!(
            network_json_from_mock_config(&port.vm("vm-b").config),
            BRIDGED_EN0_NIC_B
        );
        assert_eq!(port.vm("vm-a").power, PowerState::Started);
        assert_eq!(port.vm("vm-b").power, PowerState::Started);
    }

    #[test]
    fn happy_path_applies_and_releases_lease() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", SHARED_NIC_A, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ]);
        let profile = mgmt_profile();
        let engine = begin_engine(&mut port, dir.path(), &profile);
        let txn_id = engine.journal().transaction_id.clone();
        let summary = engine.run_all().unwrap();
        assert!(summary.contains("applied and verified"), "{summary}");
        // vm-a was already Shared -> untouched; vm-b got reconfigured.
        assert!(!port.call_log.iter().any(|c| c == "stop:vm-a"));
        assert!(port.call_log.iter().any(|c| c == "apply:vm-b"));
        let applied = parse_utm_nics_json(
            UtmBackend::Qemu,
            &network_json_from_mock_config(&port.vm("vm-b").config),
        )
        .unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].mode, AttachmentMode::Shared);
        assert_eq!(applied[0].mac, "7a:c9:3c:84:1b:99"); // MAC preserved
        assert_eq!(port.vm("vm-b").power, PowerState::Started);
        assert!(port.evidence_written);
        // Lease released.
        let leases = fs::read_dir(dir.path().join(LEASE_SUBDIR))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        assert_eq!(leases, 0);
        // Journal outcome applied.
        let store = TransactionStore::open(dir.path(), &txn_id).unwrap();
        assert_eq!(store.load_journal().unwrap().outcome, TxnOutcome::Applied);
        // Rollback material is owner-only.
        let mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn fault_before_stop_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        // Fault at the very first boundary: a VM whose state cannot even be
        // planned aborts before any stop/apply call.
        let mut port = MockPort::new(&[
            ("vm-a", SHARED_NIC_A, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(
            FaultPoint::ReadNetworkState("vm-a"),
            "simulated unreadable configuration",
        );
        let profile = mgmt_profile();
        let err = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-nothing".to_owned(),
        )
        .err()
        .unwrap();
        assert!(err.contains("unreadable"), "{err}");
        assert!(port.call_log.is_empty(), "{:?}", port.call_log);
        // No lease left behind.
        let leases = fs::read_dir(dir.path().join(LEASE_SUBDIR))
            .map(|iter| {
                iter.filter_map(Result::ok)
                    .filter(|entry| {
                        entry.path().extension().and_then(|e| e.to_str()) == Some("json")
                    })
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(leases, 0);
    }

    #[test]
    fn fault_after_one_vm_stops_restores_everything() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(FaultPoint::StopVm("vm-b"), "simulated stop failure");
        let profile = mgmt_profile();
        // Adjust: vm-a uses bridged config too so both need reconfiguration.
        let engine = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-stopfail".to_owned(),
        )
        .unwrap();
        let err = engine.run_all().err().unwrap();
        assert!(err.contains("fully rolled back (verified)"), "{err}");
        // vm-a was stopped by the txn and must be running again with its
        // original config; vm-b never applied anything.
        assert_eq!(port.vm("vm-a").power, PowerState::Started);
        assert_eq!(port.vm("vm-b").power, PowerState::Started);
        assert_eq!(
            network_json_from_mock_config(&port.vm("vm-a").config),
            BRIDGED_EN0_NIC_B
        );
        let store = TransactionStore::open(dir.path(), "txn-test-stopfail").unwrap();
        assert_eq!(
            store.load_journal().unwrap().outcome,
            TxnOutcome::RolledBackVerified
        );
    }

    #[test]
    fn fault_after_partial_configuration_never_continues() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(FaultPoint::ApplyConfig("vm-b"), "simulated apply failure");
        let profile = mgmt_profile();
        let engine = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-partial".to_owned(),
        )
        .unwrap();
        let err = engine.run_all().err().unwrap();
        assert!(err.contains("fully rolled back"), "{err}");
        // vm-a HAD its config applied; it must be restored byte-identical.
        assert_fully_restored(&port);
        // Partial application never proceeded to start/wait/evidence.
        assert!(!port.evidence_written);
    }

    #[test]
    fn fault_on_start_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(FaultPoint::StartVm("vm-a"), "simulated start failure");
        let profile = mgmt_profile();
        let engine = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-startfail".to_owned(),
        )
        .unwrap();
        let err = engine.run_all().err().unwrap();
        // Rollback itself needs start_vm for vm-a, which keeps failing —
        // so this must surface as rollback-incomplete with the lease held.
        assert!(err.contains("rollback is incomplete"), "{err}");
        let store = TransactionStore::open(dir.path(), "txn-test-startfail").unwrap();
        assert_eq!(
            store.load_journal().unwrap().outcome,
            TxnOutcome::RollbackIncomplete
        );
        // Lease still held: overlapping work stays blocked.
        let leases = fs::read_dir(dir.path().join(LEASE_SUBDIR))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        assert_eq!(leases, 1);
        // After the operator clears the fault, restore completes and verifies.
        port.faults.clear();
        let mut journal = store.load_journal().unwrap();
        rollback_journal(&store, &mut port, &mut journal).unwrap();
        assert_fully_restored(&port);
    }

    #[test]
    fn fault_on_dhcp_timeout_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(FaultPoint::WaitManagement, "management DHCP timeout");
        let profile = mgmt_profile();
        let engine = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-dhcp".to_owned(),
        )
        .unwrap();
        let err = engine.run_all().err().unwrap();
        assert!(err.contains("fully rolled back"), "{err}");
        assert_fully_restored(&port);
    }

    #[test]
    fn fault_on_evidence_write_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ])
        .fault(
            FaultPoint::WriteEvidence,
            "simulated evidence write failure",
        );
        let profile = mgmt_profile();
        let engine = NetworkTransactionEngine::begin(
            &mut port,
            dir.path(),
            &AlwaysAliveProbe,
            &profile,
            &two_vm_entries(),
            "mock-command".to_owned(),
            "txn-test-evidence".to_owned(),
        )
        .unwrap();
        let err = engine.run_all().err().unwrap();
        assert!(err.contains("fully rolled back"), "{err}");
        assert_fully_restored(&port);
    }

    #[test]
    fn process_interruption_recovery_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ]);
        let profile = mgmt_profile();
        let txn_id;
        {
            let mut engine = NetworkTransactionEngine::begin(
                &mut port,
                dir.path(),
                &AlwaysAliveProbe,
                &profile,
                &two_vm_entries(),
                "mock-command".to_owned(),
                "txn-test-crash".to_owned(),
            )
            .unwrap();
            txn_id = engine.journal().transaction_id.clone();
            // Run through partial application, then "crash" (drop the engine
            // without any rollback, exactly like a killed process).
            engine.execute_step(TxnStep::SnapshotConfigs).unwrap();
            engine.execute_step(TxnStep::StopVms).unwrap();
            engine.execute_step(TxnStep::ApplyConfigs).unwrap();
        }
        // Recovery from the persisted journal alone.
        let store = TransactionStore::open(dir.path(), &txn_id).unwrap();
        let mut journal = store.load_journal().unwrap();
        rollback_journal(&store, &mut port, &mut journal).unwrap();
        assert_fully_restored(&port);
        // Second restore run: idempotent, still verified.
        let mut journal_again = store.load_journal().unwrap();
        rollback_journal(&store, &mut port, &mut journal_again).unwrap();
        assert_fully_restored(&port);
    }

    #[test]
    fn overlapping_lease_refused_disjoint_allowed_stale_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let lease_store = LeaseStore::new(dir.path()).unwrap();
        let lease_a = NetworkLease {
            lease_id: "lease-a".to_owned(),
            transaction_id: "txn-a".to_owned(),
            profile_id: "p".to_owned(),
            profile_digest: "sha256:x".to_owned(),
            vm_aliases: vec!["alias-a".to_owned()],
            utm_names: vec!["vm-a".to_owned()],
            owner_pid: 111,
            owner_command: "cmd-a".to_owned(),
            created_at_epoch_secs: 1,
            resources: Vec::new(),
        };
        let probe = MapProbe(HashMap::from([(111, "cmd-a".to_owned())]));
        lease_store.acquire(&lease_a, &probe).unwrap();
        // Overlap refused.
        let mut lease_b = lease_a.clone();
        lease_b.lease_id = "lease-b".to_owned();
        lease_b.transaction_id = "txn-b".to_owned();
        lease_b.owner_pid = 222;
        let err = lease_store.acquire(&lease_b, &probe).err().unwrap();
        assert!(err.contains("lease refused"), "{err}");
        // Disjoint allowed.
        let lease_c = NetworkLease {
            lease_id: "lease-c".to_owned(),
            transaction_id: "txn-c".to_owned(),
            vm_aliases: vec!["alias-z".to_owned()],
            utm_names: vec!["vm-z".to_owned()],
            ..lease_a.clone()
        };
        lease_store.acquire(&lease_c, &probe).unwrap();
        // Stale recovery: pid alive but running a DIFFERENT command (pid
        // reuse) — the lease is recoverable and the overlap acquisition
        // succeeds.
        let reuse_probe = MapProbe(HashMap::from([(111, "someone-else".to_owned())]));
        lease_store.acquire(&lease_b, &reuse_probe).unwrap();
    }

    #[test]
    fn en0_is_unrepresentable_as_target() {
        let err = TargetNic::new(
            1,
            AttachmentMode::Bridged,
            "02:00:00:00:00:01".to_owned(),
            None,
            Some("en0".to_owned()),
        )
        .err()
        .unwrap();
        assert!(err.contains("denied by policy"), "{err}");
        let err = TargetNic::new(
            1,
            AttachmentMode::Bridged,
            "02:00:00:00:00:01".to_owned(),
            None,
            None,
        )
        .err()
        .unwrap();
        assert!(err.contains("explicit host interface"), "{err}");
    }

    #[test]
    fn ssh_probe_classifier_treats_handshake_as_reachable() {
        // exit 0 = command ran.
        assert_eq!(classify_ssh_probe(true, ""), SshReadiness::Reachable);
        // Connection-level failures = not ready.
        for stderr in [
            "ssh: connect to host 192.168.64.9 port 22: Connection refused",
            "ssh: connect to host 10.230.76.58 port 22: Operation timed out",
            "ssh: connect to host x port 22: No route to host",
            "ssh: Could not resolve hostname nope: Name or service not known",
        ] {
            assert_eq!(
                classify_ssh_probe(false, stderr),
                SshReadiness::NotReachable,
                "{stderr}"
            );
        }
        // Handshake reached but auth/host-key rejected = sshd IS up = reachable.
        for stderr in [
            "windows@192.168.64.14: Permission denied (publickey,password).",
            "Host key verification failed.",
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@",
        ] {
            assert_eq!(
                classify_ssh_probe(false, stderr),
                SshReadiness::Reachable,
                "{stderr}"
            );
        }
    }

    #[test]
    fn scenario_profile_derives_second_host_only_nic_on_qemu() {
        let profile = multivm_profile();
        let current = parse_utm_nics_json(UtmBackend::Qemu, SHARED_NIC_A).unwrap();
        let targets = derive_target_nics(&profile, UtmBackend::Qemu, "vm-a", &current).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].mode, AttachmentMode::Shared);
        assert_eq!(targets[0].mac, "3e:ae:a9:5a:61:82"); // MAC preserved
        assert_eq!(targets[1].mode, AttachmentMode::HostOnly);
        // Deterministic locally-administered MAC for the new adapter.
        assert_eq!(targets[1].mac, deterministic_local_mac("vm-a", 1));
        let first_octet =
            u8::from_str_radix(targets[1].mac.split(':').next().unwrap(), 16).unwrap();
        assert_eq!(first_octet & 0x03, 0x02);
        // Apple backend refuses (multi-NIC unproven).
        let err = derive_target_nics(&profile, UtmBackend::Apple, "vm-mac", &[])
            .err()
            .unwrap();
        assert!(
            err.to_lowercase().contains("fail closed") || err.contains("multi-NIC"),
            "{err}"
        );
    }

    #[test]
    fn rendered_network_json_roundtrips_through_parser() {
        let profile = multivm_profile();
        let current = parse_utm_nics_json(UtmBackend::Qemu, SHARED_NIC_A).unwrap();
        let targets = derive_target_nics(&profile, UtmBackend::Qemu, "vm-a", &current).unwrap();
        let rendered = render_network_json(UtmBackend::Qemu, &targets).unwrap();
        let parsed = parse_utm_nics_json(UtmBackend::Qemu, &rendered).unwrap();
        assert!(nics_match_targets(&parsed, &targets));
    }

    #[test]
    fn rollback_refuses_corrupted_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut port = MockPort::new(&[
            ("vm-a", BRIDGED_EN0_NIC_B, PowerState::Started),
            ("vm-b", BRIDGED_EN0_NIC_B, PowerState::Started),
        ]);
        let profile = mgmt_profile();
        let txn_id;
        {
            let mut engine = NetworkTransactionEngine::begin(
                &mut port,
                dir.path(),
                &AlwaysAliveProbe,
                &profile,
                &two_vm_entries(),
                "mock-command".to_owned(),
                "txn-test-corrupt".to_owned(),
            )
            .unwrap();
            txn_id = engine.journal().transaction_id.clone();
            engine.execute_step(TxnStep::SnapshotConfigs).unwrap();
            engine.execute_step(TxnStep::StopVms).unwrap();
            engine.execute_step(TxnStep::ApplyConfigs).unwrap();
        }
        let store = TransactionStore::open(dir.path(), &txn_id).unwrap();
        // Corrupt one rollback snapshot.
        let journal = store.load_journal().unwrap();
        let rollback_file = journal.vms[0].rollback_file.clone();
        store
            .save_rollback_config(&rollback_file, b"tampered")
            .unwrap();
        let mut journal = store.load_journal().unwrap();
        let err = rollback_journal(&store, &mut port, &mut journal)
            .err()
            .unwrap();
        assert!(err.contains("refusing to restore corrupted state"), "{err}");
    }
}
