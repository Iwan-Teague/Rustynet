//! FIS-0009: cross-session NAT-traversal priors.
//!
//! Happy-Eyeballs destination-history caching (RFC 8305 §5) combined with a
//! Beta-Bernoulli success estimator under exponential time decay (half-life
//! 24h, so a week-old prior barely counts). The prior only ever REORDERS an
//! already-valid, still-authenticated candidate list — the WireGuard
//! handshake stays the reachability gate — so a stale or poisoned prior
//! costs at most one wasted probe ordering and self-corrects on the next
//! outcome.
//!
//! Fail-open by construction: a missing, unreadable, or digest-mismatched
//! store loads as empty, which reproduces today's cold-ICE behavior exactly.
//! (This is an optimization cache over local observations, not trust state —
//! the fail-closed rules for signed state do not apply; failing CLOSED here
//! would turn a corrupt cache file into a traversal outage.)

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::traversal::CandidateSource;

/// Decay half-life for the Beta pseudo-counts (24h).
pub const PRIOR_DECAY_HALF_LIFE_SECS: f32 = 86_400.0;

/// Candidate taxonomy the prior keys on: class-level (not endpoint-level),
/// so it survives srflx endpoint churn across reconnects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CandidateClass {
    HostV4,
    HostV6,
    SrflxV4,
    SrflxV6,
}

impl CandidateClass {
    /// Class for a gathered candidate. Relay-source candidates return
    /// `None` — the prior scores only direct classes.
    pub fn for_candidate(source: CandidateSource, addr: IpAddr) -> Option<Self> {
        match (source, addr) {
            (CandidateSource::Host, IpAddr::V4(_)) => Some(CandidateClass::HostV4),
            (CandidateSource::Host, IpAddr::V6(_)) => Some(CandidateClass::HostV6),
            (CandidateSource::ServerReflexive, IpAddr::V4(_)) => Some(CandidateClass::SrflxV4),
            (CandidateSource::ServerReflexive, IpAddr::V6(_)) => Some(CandidateClass::SrflxV6),
            (CandidateSource::Relay, _) => None,
        }
    }
}

/// Beta pseudo-counts: `alpha` = successes + 1, `beta` = failures + 1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ClassStat {
    pub alpha: f32,
    pub beta: f32,
}

impl ClassStat {
    const UNIFORM: ClassStat = ClassStat {
        alpha: 1.0,
        beta: 1.0,
    };

    fn decay(&mut self, elapsed_secs: f32) {
        let factor = (-elapsed_secs * std::f32::consts::LN_2 / PRIOR_DECAY_HALF_LIFE_SECS).exp();
        self.alpha = 1.0 + (self.alpha - 1.0) * factor;
        self.beta = 1.0 + (self.beta - 1.0) * factor;
    }
}

/// Serializable mirror of [`crate::traversal::NatProfile`] (which
/// deliberately does not derive serde). Reserved for the FIS-0009 Phase 4
/// confident-both-ends relay-skip; recorded but not yet consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatProfileSnapshot {
    pub mapping_address_dependent: bool,
    pub mapping_port_dependent: bool,
    pub filtering_port_dependent: bool,
    pub preserves_port: bool,
}

/// Per-peer traversal prior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerTraversalPrior {
    pub peer_node_id: String,
    pub last_success_class: Option<CandidateClass>,
    pub per_class: BTreeMap<CandidateClass, ClassStat>,
    pub observed_nat: Option<NatProfileSnapshot>,
    pub updated_at_unix: u64,
}

impl PeerTraversalPrior {
    pub fn new(peer_node_id: String, now_unix: u64) -> Self {
        Self {
            peer_node_id,
            last_success_class: None,
            per_class: BTreeMap::new(),
            observed_nat: None,
            updated_at_unix: now_unix,
        }
    }

    /// Record one race outcome. `winning_class` is the class of the pair
    /// that produced the fresh handshake (`None` when the race fell back to
    /// relay — every tried class records a failure). Decay applies first so
    /// stale evidence washes out before the new observation lands.
    pub fn update(
        &mut self,
        winning_class: Option<CandidateClass>,
        tried_classes: &[CandidateClass],
        now_unix: u64,
    ) {
        let elapsed = now_unix.saturating_sub(self.updated_at_unix) as f32;
        for stat in self.per_class.values_mut() {
            stat.decay(elapsed);
        }
        if let Some(winner) = winning_class {
            self.per_class
                .entry(winner)
                .or_insert(ClassStat::UNIFORM)
                .alpha += 1.0;
            self.last_success_class = Some(winner);
        }
        for class in tried_classes {
            if Some(*class) != winning_class {
                self.per_class
                    .entry(*class)
                    .or_insert(ClassStat::UNIFORM)
                    .beta += 1.0;
            }
        }
        self.updated_at_unix = now_unix;
    }

    /// Posterior mean success probability for a class; 0.5 (uniform prior)
    /// for classes with no evidence.
    pub fn success_probability(&self, class: CandidateClass) -> f32 {
        match self.per_class.get(&class) {
            Some(stat) => stat.alpha / (stat.alpha + stat.beta),
            None => 0.5,
        }
    }
}

const STORE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct StoreBody {
    version: u32,
    priors: Vec<PeerTraversalPrior>,
}

/// On-disk store: one JSON body line + one digest line, written atomically
/// (tmp + rename, mode 0o600). Load is fail-open (see module doc).
#[derive(Debug)]
pub struct PeerPriorStore {
    path: PathBuf,
    priors: BTreeMap<String, PeerTraversalPrior>,
}

impl PeerPriorStore {
    /// Load the store; any failure (missing file, bad digest, bad JSON,
    /// unsupported version) yields an EMPTY store — today's cold behavior.
    pub fn load_or_empty(path: PathBuf) -> Self {
        let priors = Self::try_load(&path).unwrap_or_default();
        Self { path, priors }
    }

    fn try_load(path: &Path) -> Option<BTreeMap<String, PeerTraversalPrior>> {
        let raw = fs::read_to_string(path).ok()?;
        let mut lines = raw.lines();
        let body_line = lines.next()?;
        let digest_line = lines.next()?;
        let expected = digest_line.strip_prefix("digest_sha256=")?;
        let actual = hex_digest(body_line.as_bytes());
        if actual != expected {
            return None;
        }
        let body: StoreBody = serde_json::from_str(body_line).ok()?;
        if body.version != STORE_VERSION {
            return None;
        }
        Some(
            body.priors
                .into_iter()
                .map(|prior| (prior.peer_node_id.clone(), prior))
                .collect(),
        )
    }

    /// Atomic persist: tmp file (0o600, create_new) then rename.
    pub fn persist(&self) -> Result<(), String> {
        let body = StoreBody {
            version: STORE_VERSION,
            priors: self.priors.values().cloned().collect(),
        };
        let body_line =
            serde_json::to_string(&body).map_err(|err| format!("encode prior store: {err}"))?;
        let payload = format!(
            "{body_line}\ndigest_sha256={}\n",
            hex_digest(body_line.as_bytes())
        );
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create_dir_all({}): {err}", parent.display()))?;
        }
        let temp_path = self.path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            use std::io::Write;
            let mut file = options
                .open(&temp_path)
                .map_err(|err| format!("open {}: {err}", temp_path.display()))?;
            file.write_all(payload.as_bytes())
                .map_err(|err| format!("write {}: {err}", temp_path.display()))?;
            file.sync_all()
                .map_err(|err| format!("sync {}: {err}", temp_path.display()))?;
        }
        fs::rename(&temp_path, &self.path).map_err(|err| {
            let _ = fs::remove_file(&temp_path);
            format!(
                "rename {} -> {}: {err}",
                temp_path.display(),
                self.path.display()
            )
        })
    }

    pub fn prior_for(&self, peer_node_id: &str) -> Option<&PeerTraversalPrior> {
        self.priors.get(peer_node_id)
    }

    /// Record a race outcome for a peer, creating the prior on first sight.
    pub fn record_outcome(
        &mut self,
        peer_node_id: &str,
        winning_class: Option<CandidateClass>,
        tried_classes: &[CandidateClass],
        now_unix: u64,
    ) {
        self.priors
            .entry(peer_node_id.to_owned())
            .or_insert_with(|| PeerTraversalPrior::new(peer_node_id.to_owned(), now_unix))
            .update(winning_class, tried_classes, now_unix);
    }

    pub fn len(&self) -> usize {
        self.priors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.priors.is_empty()
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateClass, ClassStat, PRIOR_DECAY_HALF_LIFE_SECS, PeerPriorStore, PeerTraversalPrior,
    };
    use crate::traversal::CandidateSource;
    use std::net::IpAddr;

    #[test]
    fn candidate_class_maps_source_and_family_and_excludes_relay() {
        let v4: IpAddr = "203.0.113.7".parse().expect("v4");
        let v6: IpAddr = "2001:db8::7".parse().expect("v6");
        assert_eq!(
            CandidateClass::for_candidate(CandidateSource::Host, v4),
            Some(CandidateClass::HostV4)
        );
        assert_eq!(
            CandidateClass::for_candidate(CandidateSource::Host, v6),
            Some(CandidateClass::HostV6)
        );
        assert_eq!(
            CandidateClass::for_candidate(CandidateSource::ServerReflexive, v4),
            Some(CandidateClass::SrflxV4)
        );
        assert_eq!(
            CandidateClass::for_candidate(CandidateSource::ServerReflexive, v6),
            Some(CandidateClass::SrflxV6)
        );
        assert_eq!(
            CandidateClass::for_candidate(CandidateSource::Relay, v4),
            None
        );
    }

    #[test]
    fn prior_update_moves_posterior_toward_observed_outcomes() {
        let mut prior = PeerTraversalPrior::new("peer-a".to_owned(), 1_000);
        // No evidence: uniform 0.5.
        assert_eq!(prior.success_probability(CandidateClass::HostV4), 0.5);

        // Three wins for HostV4 where SrflxV4 was tried and lost.
        for round in 0..3u64 {
            prior.update(
                Some(CandidateClass::HostV4),
                &[CandidateClass::HostV4, CandidateClass::SrflxV4],
                1_000 + round,
            );
        }
        assert!(prior.success_probability(CandidateClass::HostV4) > 0.7);
        assert!(prior.success_probability(CandidateClass::SrflxV4) < 0.3);
        assert_eq!(prior.last_success_class, Some(CandidateClass::HostV4));

        // Relay fallback (no winner): every tried class records a failure.
        prior.update(None, &[CandidateClass::HostV4], 1_010);
        assert!(prior.success_probability(CandidateClass::HostV4) < 0.7);
        // last_success_class is history, not the latest outcome.
        assert_eq!(prior.last_success_class, Some(CandidateClass::HostV4));
    }

    #[test]
    fn prior_decay_washes_out_stale_evidence() {
        let mut prior = PeerTraversalPrior::new("peer-a".to_owned(), 0);
        for round in 0..5u64 {
            prior.update(
                Some(CandidateClass::SrflxV4),
                &[CandidateClass::SrflxV4],
                round,
            );
        }
        let fresh = prior.success_probability(CandidateClass::SrflxV4);
        assert!(fresh > 0.8, "fresh evidence should dominate: {fresh}");

        // One week later a single contrary observation lands: the decayed
        // pseudo-counts should be nearly uniform again first.
        let week = 7 * 86_400;
        prior.update(None, &[CandidateClass::SrflxV4], week);
        let stale = prior.success_probability(CandidateClass::SrflxV4);
        assert!(
            stale < 0.4,
            "week-old evidence must barely count against one fresh failure: {stale}"
        );
    }

    #[test]
    fn class_stat_decay_half_life_is_exact() {
        let mut stat = ClassStat {
            alpha: 5.0,
            beta: 1.0,
        };
        stat.decay(PRIOR_DECAY_HALF_LIFE_SECS);
        // (5.0 - 1.0) * 0.5 = 2.0 → alpha = 3.0.
        assert!((stat.alpha - 3.0).abs() < 1e-3, "alpha: {}", stat.alpha);
        assert!((stat.beta - 1.0).abs() < 1e-6, "beta: {}", stat.beta);
    }

    #[test]
    fn store_round_trips_and_fails_open_on_tamper() {
        let dir =
            std::env::temp_dir().join(format!("rustynet-prior-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("peer_traversal_priors.v1");

        let mut store = PeerPriorStore::load_or_empty(path.clone());
        assert!(store.is_empty(), "missing file loads empty (fail-open)");
        store.record_outcome(
            "peer-a",
            Some(CandidateClass::HostV4),
            &[CandidateClass::HostV4, CandidateClass::SrflxV4],
            1_000,
        );
        store.persist().expect("persist succeeds");

        let reloaded = PeerPriorStore::load_or_empty(path.clone());
        assert_eq!(reloaded.len(), 1);
        let prior = reloaded.prior_for("peer-a").expect("peer-a present");
        assert_eq!(prior.last_success_class, Some(CandidateClass::HostV4));
        assert!(prior.success_probability(CandidateClass::HostV4) > 0.5);

        // Tampering with the body invalidates the digest → empty (fail-open).
        let raw = std::fs::read_to_string(&path).expect("read store");
        let tampered = raw.replace("peer-a", "peer-x");
        std::fs::write(&path, tampered).expect("write tampered");
        let tampered_load = PeerPriorStore::load_or_empty(path.clone());
        assert!(
            tampered_load.is_empty(),
            "digest mismatch must load empty, never trust tampered priors"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("store metadata")
                .permissions()
                .mode()
                & 0o777;
            // The tampered rewrite above used default perms; check the
            // ORIGINAL persist path wrote 0o600 by re-persisting.
            store.persist().expect("re-persist");
            let mode_after = std::fs::metadata(&path)
                .expect("store metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode_after, 0o600,
                "persist must write mode 0600, was {mode:o} then {mode_after:o}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
