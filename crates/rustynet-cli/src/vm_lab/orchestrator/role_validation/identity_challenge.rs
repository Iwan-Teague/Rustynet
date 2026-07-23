//! Node-identity challenge adjudication (NodeEngineAcceptanceSpec §4.7).
//!
//! §4.7 requires that a role validator **prove** it exercised the intended
//! node "via an expected-node-id challenge in the probe itself; a name logged
//! post-hoc is insufficient (the historical MeshStatus false-green was exactly
//! a right-name/wrong-exercise pass)."
//!
//! The subtle failure mode this module exists to prevent: the orchestrator
//! already *records* each node's id at the CollectPubkeys stage, but recording
//! is not asserting. Two distinct weaknesses make a bare recorded id
//! insufficient:
//!
//!  1. **Crossed / substituted connection** — the validator's SSH session could
//!     reach a *different* node than the slot the orchestrator intends. If the
//!     probe never re-checks identity, the wrong node passes (the MeshStatus
//!     class).
//!  2. **Non-live provenance** — an "identity" read from a static on-disk config
//!     file (a launchd plist, a `rustynetd.env`, a `wireguard.pub`) proves only
//!     that a file with that value exists, not that the *running daemon* on the
//!     probed connection has that identity. A substituted node with copied
//!     config, or a node whose daemon is down, would satisfy a config-file read.
//!     Only a value the **live daemon** self-reports over its control socket is
//!     a genuine challenge.
//!
//! This module is the **pure adjudicator** for that challenge: given the
//! expected id (recorded at CollectPubkeys) and the freshly-gathered
//! [`IdentityEvidence`] (a value plus its [`IdentityProvenance`]), it decides —
//! fail-closed, default-deny — whether identity is *asserted-live-and-matching*.
//! Gathering the evidence (the per-OS live query) and deciding skip-vs-fail per
//! platform are the callers' jobs; this module makes no I/O and no policy
//! decision beyond "is this evidence a valid live assertion of the expected id?"

use std::fmt;

/// Where an observed node-id value came from. Only [`LiveDaemonSocket`] is a
/// genuine challenge under §4.7; a [`ConfigFile`] read is "recorded, not
/// asserted" and cannot, on its own, prove the live daemon's identity.
///
/// [`LiveDaemonSocket`]: IdentityProvenance::LiveDaemonSocket
/// [`ConfigFile`]: IdentityProvenance::ConfigFile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProvenance {
    /// The value was read from the running daemon over its control socket
    /// (`rustynet status`) — a live self-report from the node the probe
    /// actually reached.
    LiveDaemonSocket,
    /// The value was read from a static on-disk configuration artifact (a
    /// launchd plist, `rustynetd.env`, ...). Proves a file exists, not that
    /// the live daemon has this identity. Insufficient for a §4.7 assertion.
    ConfigFile,
}

impl fmt::Display for IdentityProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityProvenance::LiveDaemonSocket => f.write_str("live-daemon-socket"),
            IdentityProvenance::ConfigFile => f.write_str("config-file"),
        }
    }
}

/// A node-id value together with how it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEvidence {
    pub node_id: String,
    pub provenance: IdentityProvenance,
}

impl IdentityEvidence {
    pub fn live(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            provenance: IdentityProvenance::LiveDaemonSocket,
        }
    }

    pub fn config_file(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            provenance: IdentityProvenance::ConfigFile,
        }
    }
}

/// Why an identity challenge did not produce an asserted-live match. Every
/// variant is a fail-closed outcome; none may be treated as a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityChallengeError {
    /// No expected node-id was recorded for this slot, so identity cannot be
    /// asserted at all. Default-deny: an un-recorded expectation is a failure,
    /// never a silent pass.
    Unverifiable { reason: String },
    /// The live daemon reported a *different* node-id than expected — the
    /// crossed/substituted-connection catch. The Display string deliberately
    /// contains the substring `node_id mismatch`, matching the existing
    /// `assignment verify --expected-node-id` convention
    /// (`rustynetd::daemon`), so the T5 wrong-node control's classifier binds
    /// to the specific reason.
    NodeIdMismatch { expected: String, actual: String },
    /// The expected id matched, but the value was NOT a live self-report from
    /// the daemon (it came from a config file). §4.7 is not satisfied — the
    /// probe recorded a name, it did not assert the live node's identity.
    NotLiveAssertion {
        node_id: String,
        provenance: IdentityProvenance,
    },
}

impl fmt::Display for IdentityChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityChallengeError::Unverifiable { reason } => {
                write!(
                    f,
                    "node identity challenge unverifiable (no expected node_id recorded): {reason}"
                )
            }
            IdentityChallengeError::NodeIdMismatch { expected, actual } => {
                // MUST contain "node_id mismatch" — see the T5 classifier.
                write!(
                    f,
                    "node identity challenge failed: node_id mismatch: expected {expected}, \
                     live daemon reported {actual}"
                )
            }
            IdentityChallengeError::NotLiveAssertion {
                node_id,
                provenance,
            } => {
                write!(
                    f,
                    "node identity challenge not a live assertion: node_id {node_id} matched but \
                     was read from {provenance}, not the live daemon socket"
                )
            }
        }
    }
}

/// Adjudicate a node-identity challenge, fail-closed.
///
/// Returns `Ok(())` **only** when an expected id was recorded, the observed id
/// equals it, AND the observation is a live daemon self-report. Every other
/// case is an error:
///  - `expected == None`            → [`IdentityChallengeError::Unverifiable`]
///  - observed id != expected       → [`IdentityChallengeError::NodeIdMismatch`]
///  - matches but not live-sourced  → [`IdentityChallengeError::NotLiveAssertion`]
///
/// The mismatch check precedes the provenance check so a substituted node is
/// always reported as a mismatch (the security-relevant reason), regardless of
/// how its value was sourced.
pub fn adjudicate_identity(
    expected_node_id: Option<&str>,
    actual: &IdentityEvidence,
) -> Result<(), IdentityChallengeError> {
    let expected = match expected_node_id {
        Some(id) if !id.is_empty() => id,
        Some(_) => {
            return Err(IdentityChallengeError::Unverifiable {
                reason: "recorded expected node_id is empty".to_owned(),
            });
        }
        None => {
            return Err(IdentityChallengeError::Unverifiable {
                reason: "no expected node_id recorded for this node slot".to_owned(),
            });
        }
    };
    if actual.node_id != expected {
        return Err(IdentityChallengeError::NodeIdMismatch {
            expected: expected.to_owned(),
            actual: actual.node_id.clone(),
        });
    }
    if actual.provenance != IdentityProvenance::LiveDaemonSocket {
        return Err(IdentityChallengeError::NotLiveAssertion {
            node_id: actual.node_id.clone(),
            provenance: actual.provenance,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_match_passes() {
        let ev = IdentityEvidence::live("node-abc");
        assert!(adjudicate_identity(Some("node-abc"), &ev).is_ok());
    }

    #[test]
    fn live_mismatch_is_node_id_mismatch_and_carries_the_substring() {
        // The substituted-node catch: the live daemon reports its OWN id, which
        // differs from the expected (substituted) id.
        let ev = IdentityEvidence::live("node-real");
        let err = adjudicate_identity(Some("node-substituted-imposter"), &ev)
            .expect_err("mismatch must fail");
        assert!(
            matches!(err, IdentityChallengeError::NodeIdMismatch { .. }),
            "got: {err:?}"
        );
        // The T5 wrong-node classifier binds to this exact substring.
        assert!(
            err.to_string().contains("node_id mismatch"),
            "Display must contain the T5-classifier substring; got: {err}"
        );
    }

    #[test]
    fn none_expected_is_unverifiable_fail_closed() {
        let ev = IdentityEvidence::live("node-abc");
        let err = adjudicate_identity(None, &ev).expect_err("no expected id must fail closed");
        assert!(matches!(err, IdentityChallengeError::Unverifiable { .. }));
    }

    #[test]
    fn empty_expected_is_unverifiable_fail_closed() {
        let ev = IdentityEvidence::live("node-abc");
        let err = adjudicate_identity(Some(""), &ev).expect_err("empty expected id must fail");
        assert!(matches!(err, IdentityChallengeError::Unverifiable { .. }));
    }

    #[test]
    fn config_file_match_is_not_a_live_assertion() {
        // The B1 teeth: a matching id read from a static config file does NOT
        // satisfy §4.7 — it is recorded, not asserted.
        let ev = IdentityEvidence::config_file("node-abc");
        let err = adjudicate_identity(Some("node-abc"), &ev)
            .expect_err("config-file provenance must not satisfy a live challenge");
        assert!(
            matches!(err, IdentityChallengeError::NotLiveAssertion { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn config_file_mismatch_still_reports_mismatch_first() {
        // Security-relevant reason (mismatch) dominates provenance.
        let ev = IdentityEvidence::config_file("node-real");
        let err = adjudicate_identity(Some("node-imposter"), &ev).expect_err("must fail");
        assert!(
            matches!(err, IdentityChallengeError::NodeIdMismatch { .. }),
            "mismatch must dominate provenance; got: {err:?}"
        );
    }

    #[test]
    fn provenance_display_is_stable() {
        assert_eq!(
            IdentityProvenance::LiveDaemonSocket.to_string(),
            "live-daemon-socket"
        );
        assert_eq!(IdentityProvenance::ConfigFile.to_string(), "config-file");
    }
}
