//! AEAD-encrypted, per-peer-namespaced, quota-enforced object store
//! (NAS design §3.1/§3.3).
//!
//! On-disk layout under the operator-provided data root:
//!
//! ```text
//! <data-root>/
//!   objects/<peer-id>/<content-hash>     # sealed chunks
//!   snapshots/<peer-id>/<snapshot-id>    # sealed snapshot manifests
//!   quota/<peer-id>                      # sealed quota record
//!   .keycheck                            # at-rest key sentinel
//! ```
//!
//! Every blob is XChaCha20-Poly1305-sealed via `rustynet-crypto`
//! with associated data binding it to its logical location
//! (`nas:<kind>:<peer>:<name>`), so a ciphertext moved or renamed —
//! including into another peer's namespace — fails its tag check.
//!
//! Fail-closed startup: missing/symlinked/world-accessible data
//! root, or an at-rest key that cannot open the `.keycheck`
//! sentinel, refuses to open the store.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rustynet_crypto::{AeadSealedBlob, aead_open, aead_seal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Hard cap on a single backup chunk's plaintext size. Uploads are
/// attacker-influenced input; the protocol layer enforces the same
/// bound before allocation.
pub const MAX_CHUNK_LEN: usize = 4 * 1024 * 1024;
/// Hard cap on a snapshot manifest's plaintext size.
pub const MAX_MANIFEST_LEN: usize = 1024 * 1024;
/// Default per-peer quota when the owner has not set one. Quota is
/// a disk-protection bound on already-authorised peers (reach is
/// separately default-deny via signed policy).
pub const DEFAULT_QUOTA_LIMIT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

const KEYCHECK_FILE: &str = ".keycheck";
const KEYCHECK_PLAINTEXT: &[u8] = b"rustynet-nas-keycheck-v1";
const SEALED_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasStoreError {
    DataRootMissing(String),
    DataRootInsecure(String),
    KeyCheckFailed(String),
    InvalidPeerId(String),
    InvalidContentHash(String),
    InvalidSnapshotId(String),
    ChunkTooLarge {
        len: usize,
    },
    ManifestTooLarge {
        len: usize,
    },
    HashMismatch {
        claimed: String,
        actual: String,
    },
    QuotaExceeded {
        used: u64,
        limit: u64,
        requested: u64,
    },
    UnknownObject {
        content_hash: String,
    },
    UnknownSnapshot {
        snapshot_id: String,
    },
    SealFailed,
    OpenFailed(String),
    Io(String),
}

impl fmt::Display for NasStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NasStoreError::DataRootMissing(reason) => {
                write!(f, "data root unavailable (fail-closed): {reason}")
            }
            NasStoreError::DataRootInsecure(reason) => {
                write!(f, "data root permissions refused (fail-closed): {reason}")
            }
            NasStoreError::KeyCheckFailed(reason) => {
                write!(f, "at-rest key check failed (fail-closed): {reason}")
            }
            NasStoreError::InvalidPeerId(_) => write!(f, "invalid peer id"),
            NasStoreError::InvalidContentHash(_) => write!(f, "invalid content hash"),
            NasStoreError::InvalidSnapshotId(_) => write!(f, "invalid snapshot id"),
            NasStoreError::ChunkTooLarge { len } => {
                write!(f, "chunk of {len} bytes exceeds cap {MAX_CHUNK_LEN}")
            }
            NasStoreError::ManifestTooLarge { len } => {
                write!(f, "manifest of {len} bytes exceeds cap {MAX_MANIFEST_LEN}")
            }
            NasStoreError::HashMismatch { claimed, actual } => {
                write!(
                    f,
                    "content hash mismatch: claimed {claimed}, actual {actual}"
                )
            }
            NasStoreError::QuotaExceeded {
                used,
                limit,
                requested,
            } => write!(
                f,
                "quota exceeded: used {used} + requested {requested} > limit {limit}"
            ),
            NasStoreError::UnknownObject { content_hash } => {
                write!(f, "unknown object {content_hash}")
            }
            NasStoreError::UnknownSnapshot { snapshot_id } => {
                write!(f, "unknown snapshot {snapshot_id}")
            }
            NasStoreError::SealFailed => write!(f, "at-rest seal failed"),
            NasStoreError::OpenFailed(what) => {
                write!(f, "at-rest open failed (tamper or wrong key): {what}")
            }
            NasStoreError::Io(what) => write!(f, "storage io failure: {what}"),
        }
    }
}

impl std::error::Error for NasStoreError {}

/// Per-peer quota record. Stored sealed (tampering the limit is a
/// privilege escalation against the disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaRecord {
    pub limit_bytes: u64,
    pub used_bytes: u64,
}

impl Default for QuotaRecord {
    fn default() -> Self {
        Self {
            limit_bytes: DEFAULT_QUOTA_LIMIT_BYTES,
            used_bytes: 0,
        }
    }
}

/// Validate a peer id for filesystem-safe namespace use. Peer ids
/// arrive from the daemon's verified identity handoff, but the
/// store still refuses anything outside the strict charset
/// (defence-in-depth against path traversal).
pub fn validate_peer_id(peer_id: &str) -> Result<(), NasStoreError> {
    let ok = !peer_id.is_empty()
        && peer_id.len() <= 64
        && !peer_id.starts_with('.')
        && peer_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
        });
    if ok {
        Ok(())
    } else {
        Err(NasStoreError::InvalidPeerId(peer_id.to_owned()))
    }
}

/// Validate a content hash: exactly 64 lowercase hex chars
/// (SHA-256).
pub fn validate_content_hash(hash: &str) -> Result<(), NasStoreError> {
    let ok = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(NasStoreError::InvalidContentHash(hash.to_owned()))
    }
}

fn validate_snapshot_id(snapshot_id: &str) -> Result<(), NasStoreError> {
    let ok = !snapshot_id.is_empty()
        && snapshot_id.len() <= 80
        && !snapshot_id.starts_with('.')
        && !snapshot_id.ends_with(".deleted")
        && snapshot_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
        });
    if ok {
        Ok(())
    } else {
        Err(NasStoreError::InvalidSnapshotId(snapshot_id.to_owned()))
    }
}

/// Lowercase hex SHA-256 of `data`.
pub fn content_hash_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Snapshot listing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub snapshot_id: String,
    pub soft_deleted: bool,
}

/// The store. Holds the at-rest key for the lifetime of the
/// process; zeroized on drop.
pub struct NasStore {
    data_root: PathBuf,
    key: [u8; 32],
}

impl Drop for NasStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl NasStore {
    /// Open (or initialise) the store. Fail-closed startup checks:
    ///
    /// - data root must exist, be a real directory (no symlink), and
    ///   be owner-only (no group/world bits) on Unix; non-Unix hosts
    ///   are refused until their ACL verifier integration lands
    ///   (platform matrix keeps them ⛔).
    /// - the `.keycheck` sentinel must open under `key` (a wrong or
    ///   rotated-away key refuses the whole store rather than
    ///   serving a mix of readable and unreadable blobs).
    pub fn open(data_root: &Path, key: [u8; 32]) -> Result<Self, NasStoreError> {
        let metadata = fs::symlink_metadata(data_root).map_err(|err| {
            NasStoreError::DataRootMissing(format!("{}: {err}", data_root.display()))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(NasStoreError::DataRootInsecure(
                "data root must be a real directory (symlink refused)".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(NasStoreError::DataRootInsecure(format!(
                    "data root mode {mode:o} grants group/world access; chmod 700 required"
                )));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(NasStoreError::DataRootInsecure(
                "data-root permission verification is not implemented on this platform; \
                 refusing to serve (fail-closed)"
                    .to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            let store = Self {
                data_root: data_root.to_path_buf(),
                key,
            };
            for sub in ["objects", "snapshots", "quota"] {
                store.ensure_private_dir(&store.data_root.join(sub))?;
            }
            store.verify_or_init_keycheck()?;
            Ok(store)
        }
    }

    fn ensure_private_dir(&self, dir: &Path) -> Result<(), NasStoreError> {
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|err| NasStoreError::Io(format!("{}: {err}", dir.display())))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|err| NasStoreError::Io(format!("{}: {err}", dir.display())))?;
        }
        Ok(())
    }

    fn verify_or_init_keycheck(&self) -> Result<(), NasStoreError> {
        let path = self.data_root.join(KEYCHECK_FILE);
        if path.exists() {
            let blob = self.read_sealed_file(&path, KEYCHECK_PLAINTEXT.len() + 64)?;
            let opened = aead_open(&self.key, b"nas:keycheck", &blob).map_err(|_| {
                NasStoreError::KeyCheckFailed(
                    "sentinel does not open under the provided at-rest key".to_owned(),
                )
            })?;
            if opened != KEYCHECK_PLAINTEXT {
                return Err(NasStoreError::KeyCheckFailed(
                    "sentinel content mismatch".to_owned(),
                ));
            }
            Ok(())
        } else {
            let blob = aead_seal(&self.key, b"nas:keycheck", KEYCHECK_PLAINTEXT)
                .map_err(|_| NasStoreError::SealFailed)?;
            self.write_sealed_file_atomic(&path, &blob)
        }
    }

    fn object_dir(&self, peer_id: &str) -> PathBuf {
        self.data_root.join("objects").join(peer_id)
    }

    fn snapshot_dir(&self, peer_id: &str) -> PathBuf {
        self.data_root.join("snapshots").join(peer_id)
    }

    fn quota_path(&self, peer_id: &str) -> PathBuf {
        self.data_root.join("quota").join(peer_id)
    }

    /// Store a content-addressed chunk in `peer_id`'s namespace.
    /// Verifies the claimed hash server-side (dedup integrity),
    /// enforces the size cap and the peer's quota, and seals with
    /// location-bound AAD. Idempotent for an already-stored hash.
    pub fn put_chunk(
        &self,
        peer_id: &str,
        claimed_hash: &str,
        plaintext: &[u8],
    ) -> Result<(), NasStoreError> {
        validate_peer_id(peer_id)?;
        validate_content_hash(claimed_hash)?;
        if plaintext.len() > MAX_CHUNK_LEN {
            return Err(NasStoreError::ChunkTooLarge {
                len: plaintext.len(),
            });
        }
        let actual = content_hash_hex(plaintext);
        if actual != claimed_hash {
            return Err(NasStoreError::HashMismatch {
                claimed: claimed_hash.to_owned(),
                actual,
            });
        }
        let dir = self.object_dir(peer_id);
        self.ensure_private_dir(&dir)?;
        let path = dir.join(claimed_hash);
        if path.exists() {
            // Content-addressed: same hash ⇒ same content. No quota
            // double-count, no rewrite.
            return Ok(());
        }

        let mut quota = self.load_quota(peer_id)?;
        let requested = plaintext.len() as u64;
        if quota.used_bytes.saturating_add(requested) > quota.limit_bytes {
            return Err(NasStoreError::QuotaExceeded {
                used: quota.used_bytes,
                limit: quota.limit_bytes,
                requested,
            });
        }

        let aad = format!("nas:object:{peer_id}:{claimed_hash}");
        let blob = aead_seal(&self.key, aad.as_bytes(), plaintext)
            .map_err(|_| NasStoreError::SealFailed)?;
        self.write_sealed_file_atomic(&path, &blob)?;

        quota.used_bytes = quota.used_bytes.saturating_add(requested);
        self.store_quota(peer_id, &quota)
    }

    /// Read a chunk back from `peer_id`'s namespace. The AAD binding
    /// plus a post-open hash check refuse blobs that were moved,
    /// renamed, swapped across namespaces, or tampered.
    pub fn get_chunk(&self, peer_id: &str, content_hash: &str) -> Result<Vec<u8>, NasStoreError> {
        validate_peer_id(peer_id)?;
        validate_content_hash(content_hash)?;
        let path = self.object_dir(peer_id).join(content_hash);
        if !path.exists() {
            return Err(NasStoreError::UnknownObject {
                content_hash: content_hash.to_owned(),
            });
        }
        let blob = self.read_sealed_file(&path, MAX_CHUNK_LEN + AEAD_TAG_LEN)?;
        let aad = format!("nas:object:{peer_id}:{content_hash}");
        let plaintext = aead_open(&self.key, aad.as_bytes(), &blob)
            .map_err(|_| NasStoreError::OpenFailed(format!("object {content_hash}")))?;
        let actual = content_hash_hex(&plaintext);
        if actual != content_hash {
            return Err(NasStoreError::HashMismatch {
                claimed: content_hash.to_owned(),
                actual,
            });
        }
        Ok(plaintext)
    }

    /// Store a snapshot manifest (sealed, location-bound).
    pub fn commit_snapshot(
        &self,
        peer_id: &str,
        snapshot_id: &str,
        manifest: &[u8],
    ) -> Result<(), NasStoreError> {
        validate_peer_id(peer_id)?;
        validate_snapshot_id(snapshot_id)?;
        if manifest.len() > MAX_MANIFEST_LEN {
            return Err(NasStoreError::ManifestTooLarge {
                len: manifest.len(),
            });
        }
        let dir = self.snapshot_dir(peer_id);
        self.ensure_private_dir(&dir)?;
        let aad = format!("nas:snapshot:{peer_id}:{snapshot_id}");
        let blob = aead_seal(&self.key, aad.as_bytes(), manifest)
            .map_err(|_| NasStoreError::SealFailed)?;
        self.write_sealed_file_atomic(&dir.join(snapshot_id), &blob)
    }

    /// Read a snapshot manifest from `peer_id`'s namespace.
    pub fn get_snapshot(&self, peer_id: &str, snapshot_id: &str) -> Result<Vec<u8>, NasStoreError> {
        validate_peer_id(peer_id)?;
        validate_snapshot_id(snapshot_id)?;
        let path = self.snapshot_dir(peer_id).join(snapshot_id);
        if !path.exists() {
            return Err(NasStoreError::UnknownSnapshot {
                snapshot_id: snapshot_id.to_owned(),
            });
        }
        let blob = self.read_sealed_file(&path, MAX_MANIFEST_LEN + AEAD_TAG_LEN)?;
        let aad = format!("nas:snapshot:{peer_id}:{snapshot_id}");
        aead_open(&self.key, aad.as_bytes(), &blob)
            .map_err(|_| NasStoreError::OpenFailed(format!("snapshot {snapshot_id}")))
    }

    /// List `peer_id`'s snapshots (their own namespace only).
    pub fn list_snapshots(&self, peer_id: &str) -> Result<Vec<SnapshotEntry>, NasStoreError> {
        validate_peer_id(peer_id)?;
        let dir = self.snapshot_dir(peer_id);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let read_dir = fs::read_dir(&dir)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", dir.display())))?;
        for entry in read_dir {
            let entry = entry.map_err(|err| NasStoreError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(base) = name.strip_suffix(".deleted") {
                entries.push(SnapshotEntry {
                    snapshot_id: base.to_owned(),
                    soft_deleted: true,
                });
            } else {
                entries.push(SnapshotEntry {
                    snapshot_id: name,
                    soft_deleted: false,
                });
            }
        }
        entries.sort_by(|a, b| a.snapshot_id.cmp(&b.snapshot_id));
        Ok(entries)
    }

    /// Soft-delete a snapshot (retention/GC stays node-owned; data
    /// is retained under a `.deleted` marker name).
    pub fn delete_snapshot(&self, peer_id: &str, snapshot_id: &str) -> Result<(), NasStoreError> {
        validate_peer_id(peer_id)?;
        validate_snapshot_id(snapshot_id)?;
        let dir = self.snapshot_dir(peer_id);
        let from = dir.join(snapshot_id);
        if !from.exists() {
            return Err(NasStoreError::UnknownSnapshot {
                snapshot_id: snapshot_id.to_owned(),
            });
        }
        let to = dir.join(format!("{snapshot_id}.deleted"));
        fs::rename(&from, &to)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", from.display())))
    }

    /// Per-peer quota + usage accounting.
    pub fn usage(&self, peer_id: &str) -> Result<QuotaRecord, NasStoreError> {
        validate_peer_id(peer_id)?;
        self.load_quota(peer_id)
    }

    /// Owner-driven quota limit update for a peer.
    pub fn set_quota_limit(&self, peer_id: &str, limit_bytes: u64) -> Result<(), NasStoreError> {
        validate_peer_id(peer_id)?;
        let mut quota = self.load_quota(peer_id)?;
        quota.limit_bytes = limit_bytes;
        self.store_quota(peer_id, &quota)
    }

    fn load_quota(&self, peer_id: &str) -> Result<QuotaRecord, NasStoreError> {
        let path = self.quota_path(peer_id);
        if !path.exists() {
            return Ok(QuotaRecord::default());
        }
        let blob = self.read_sealed_file(&path, 4096)?;
        let aad = format!("nas:quota:{peer_id}");
        let plaintext = aead_open(&self.key, aad.as_bytes(), &blob)
            .map_err(|_| NasStoreError::OpenFailed(format!("quota record for {peer_id}")))?;
        serde_json::from_slice(&plaintext)
            .map_err(|err| NasStoreError::Io(format!("quota record malformed: {err}")))
    }

    fn store_quota(&self, peer_id: &str, quota: &QuotaRecord) -> Result<(), NasStoreError> {
        let encoded = serde_json::to_vec(quota)
            .map_err(|err| NasStoreError::Io(format!("quota encode: {err}")))?;
        let aad = format!("nas:quota:{peer_id}");
        let blob = aead_seal(&self.key, aad.as_bytes(), &encoded)
            .map_err(|_| NasStoreError::SealFailed)?;
        self.write_sealed_file_atomic(&self.quota_path(peer_id), &blob)
    }

    /// Sealed-file layout: nonce(24) || ciphertext. `max_ciphertext`
    /// bounds the read before allocation (attacker-resident disk
    /// state must not drive unbounded allocation either).
    fn read_sealed_file(
        &self,
        path: &Path,
        max_ciphertext: usize,
    ) -> Result<AeadSealedBlob, NasStoreError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", path.display())))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(NasStoreError::Io(format!(
                "{}: not a regular file",
                path.display()
            )));
        }
        let len = metadata.len() as usize;
        if len < SEALED_NONCE_LEN + AEAD_TAG_LEN || len > SEALED_NONCE_LEN + max_ciphertext + 4096 {
            return Err(NasStoreError::Io(format!(
                "{}: sealed file length {len} outside bounds",
                path.display()
            )));
        }
        let bytes = fs::read(path)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", path.display())))?;
        let mut nonce = [0u8; SEALED_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..SEALED_NONCE_LEN]);
        Ok(AeadSealedBlob {
            nonce,
            ciphertext: bytes[SEALED_NONCE_LEN..].to_vec(),
        })
    }

    fn write_sealed_file_atomic(
        &self,
        path: &Path,
        blob: &AeadSealedBlob,
    ) -> Result<(), NasStoreError> {
        let parent = path
            .parent()
            .ok_or_else(|| NasStoreError::Io(format!("{}: no parent dir", path.display())))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| NasStoreError::Io(format!("{}: no file name", path.display())))?
            .to_string_lossy()
            .into_owned();
        let tmp = parent.join(format!(".{file_name}.tmp"));
        {
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|err| NasStoreError::Io(format!("{}: {err}", tmp.display())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                handle
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|err| NasStoreError::Io(format!("{}: {err}", tmp.display())))?;
            }
            handle
                .write_all(&blob.nonce)
                .and_then(|_| handle.write_all(&blob.ciphertext))
                .and_then(|_| handle.sync_all())
                .map_err(|err| NasStoreError::Io(format!("{}: {err}", tmp.display())))?;
        }
        fs::rename(&tmp, path).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            NasStoreError::Io(format!("{}: {err}", path.display()))
        })
    }

    /// Aggregate usage across peers (health/ops surface; counts
    /// only — no names or content leave the store).
    pub fn peer_usage_summary(&self) -> Result<BTreeMap<String, QuotaRecord>, NasStoreError> {
        let quota_dir = self.data_root.join("quota");
        let mut out = BTreeMap::new();
        if !quota_dir.exists() {
            return Ok(out);
        }
        let read_dir = fs::read_dir(&quota_dir)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", quota_dir.display())))?;
        for entry in read_dir {
            let entry = entry.map_err(|err| NasStoreError::Io(err.to_string()))?;
            let peer_id = entry.file_name().to_string_lossy().into_owned();
            if validate_peer_id(&peer_id).is_ok() {
                let quota = self.load_quota(&peer_id)?;
                out.insert(peer_id, quota);
            }
        }
        Ok(out)
    }

    /// Probe used by the health gate: storage root still present,
    /// still a directory, still writable (tmp write round-trip).
    pub fn probe_writable(&self) -> Result<(), NasStoreError> {
        let probe = self.data_root.join(".health-probe");
        fs::write(&probe, b"ok")
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", probe.display())))?;
        fs::remove_file(&probe)
            .map_err(|err| NasStoreError::Io(format!("{}: {err}", probe.display())))
    }
}
