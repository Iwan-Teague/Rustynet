//! Offline core of the macOS exit-serving adapter (design
//! `LiveLabMacosExitServingAdapterDesign_2026-09-02.md` §0 decision 2/3, §3,
//! §4; adversarial review §2–§4 amendments A3/A6 folded).
//!
//! Everything here is pure parsing/evaluation over captured text — no I/O, no
//! SSH, no pf mutation. The live `NodeAdapter` wiring in `adapter/macos.rs`,
//! the `active_exit_runtime_implemented` predicate flip, and the role.rs remap
//! are deliberately NOT in this module: they are lab-gated changes (design §6)
//! and land separately. Until then most of these helpers are intentionally
//! unreferenced outside their tests.
//!
//! Two evidence surfaces, both defined by this design (§3, §4):
//! 1. the daemon's own `macos-exit-nat-lifecycle-snapshot` JSON (schema v1,
//!    `rustynetd::macos_exit_nat_lifecycle::MacosExitNatLifecycleSnapshot` —
//!    the exact field names come from the daemon, never invented here), and
//! 2. the pf state translation records from a read-only `pfctl -s state`
//!    capture, parsed into [`PfStateTranslation`] and correlated in Rust with
//!    the client's mesh address and the exit's egress address (the Windows
//!    adapter's identity-check-in-Rust pattern, `windows_traffic.rs`).

#![cfg_attr(not(test), allow(dead_code))] // live adapter wiring + predicate flip are lab-gated (design §6); this is the offline-tested core only

use rustynetd::macos_exit_nat_lifecycle::MacosExitNatLifecycleSnapshot;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Schema version of the S2 egress-evidence artifact this module evaluates
/// (design §4: "Sink-side capture format is defined in this design and
/// versioned … so the evaluator can reject foreign payloads").
pub const MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Snapshot verdicts (design §3 — assert the daemon's own verifier)
// ---------------------------------------------------------------------------

/// Outcome of a successful [`assess_exit_snapshot`] call. Every field is the
/// individual requirement the snapshot was required to satisfy; a verdict is
/// only returned when all three hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSnapshotVerdict {
    /// The `com.rustynet/nat` pf anchor is loaded in the guest's pf.
    pub pf_anchor_present: bool,
    /// IPv4 forwarding is enabled (`sysctl net.inet.ip.forwarding == 1`;
    /// the producer reports "Enabled"/"Disabled"/"Unknown").
    pub forwarding_enabled: bool,
    /// The NAT rule's observed internal prefix equals the run's mesh CIDR.
    pub internal_prefix_matches: bool,
}

/// Assess one daemon `macos-exit-nat-lifecycle-snapshot` JSON document (the
/// `activate_exit_serving` / `assert_exit_actively_serving` evidence shape,
/// design §3).
///
/// Fail-closed: malformed JSON, an unknown `schema_version`, an absent anchor,
/// disabled (or unmeasurable — "Unknown") forwarding, or an `internal_prefix`
/// that drifts from `expected_mesh_cidr` is a named rejection. The three
/// serving branches are named so the stage can surface exactly which posture
/// regressed.
pub fn assess_exit_snapshot(
    snapshot_json: &str,
    expected_mesh_cidr: &str,
) -> Result<ExitSnapshotVerdict, String> {
    let snapshot: MacosExitNatLifecycleSnapshot =
        serde_json::from_str(snapshot_json).map_err(|e| format!("malformed_snapshot_json: {e}"))?;
    if snapshot.schema_version
        != rustynetd::macos_exit_nat_lifecycle::MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION
    {
        return Err(format!(
            "unknown_schema_version: got {}, expected {}",
            snapshot.schema_version,
            rustynetd::macos_exit_nat_lifecycle::MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION
        ));
    }
    let pf_anchor_present = snapshot.pf_anchor_present;
    if !pf_anchor_present {
        return Err("pf_anchor_absent: the com.rustynet/nat anchor is not loaded".to_owned());
    }
    // Both fields exist because the merge target is per-direction, but on
    // macOS a single `ip.forwarding` sysctl feeds both. Require BOTH to read
    // "Enabled": the producer sets them identically, and any "Unknown" (a
    // failed sysctl capture) must fail closed, never pass.
    let forwarding_enabled =
        snapshot.tunnel_forwarding == "Enabled" && snapshot.egress_forwarding == "Enabled";
    if !forwarding_enabled {
        return Err(format!(
            "forwarding_disabled: tunnel_forwarding='{}' egress_forwarding='{}' \
             (expected both 'Enabled'; 'Unknown' means the sysctl capture failed)",
            snapshot.tunnel_forwarding, snapshot.egress_forwarding
        ));
    }
    let internal_prefix_matches = snapshot.internal_prefix == expected_mesh_cidr;
    if !internal_prefix_matches {
        return Err(format!(
            "internal_prefix_drift: snapshot reports '{}' but the run's mesh CIDR is '{}'",
            snapshot.internal_prefix, expected_mesh_cidr
        ));
    }
    Ok(ExitSnapshotVerdict {
        pf_anchor_present,
        forwarding_enabled,
        internal_prefix_matches,
    })
}

// ---------------------------------------------------------------------------
// pfctl -s state translation parsing (design §3; review §2 / amendment A3)
// ---------------------------------------------------------------------------

/// One NAT translation record parsed from a global `pfctl -s state` line on
/// the macOS exit.
///
/// ASSUMED FORMAT (fixture-derived, UNVERIFIED on the UTM guest — design §10
/// Q1 / review §2 amendment A3): pf prints a state line for a source-NATed
/// connection as
///
/// ```text
/// <family-or-iface> <proto> <translated-source>:<port> (<original-source>:<port>) -> <dst>:<port>  <STATE>
/// ```
///
/// e.g. `ALL udp 192.168.64.10:51820 (100.64.0.9:51820) -> 1.1.1.1:53  MULTIPLE:MULTIPLE`
/// — the FIRST address is the post-NAT (translated) source, the PARENTHESIZED
/// address is the pre-NAT (original) source, the arrow target is the
/// destination. The first token is the address-family/interface field (macOS
/// global state views print `ALL`); it is carried through verbatim but not
/// interpreted. Any line that does not decompose into exactly this shape is a
/// parse error, never a guess — the adapter fail-closes on parse failure
/// until a captured fixture from the lab guest validates the format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfStateTranslation {
    /// Verbatim first field (`ALL` on macOS global views; uninterpreted).
    pub family_or_iface: String,
    /// Lowercase protocol token (`udp`, `tcp`, …).
    pub protocol: String,
    /// Post-NAT source address (the exit's egress address for client egress).
    pub translated_source: IpAddr,
    /// Post-NAT source port (`None` for portless protocols).
    pub translated_source_port: Option<u16>,
    /// Pre-NAT source address (the client's mesh address for client egress).
    pub original_source: IpAddr,
    /// Pre-NAT source port (`None` for portless protocols).
    pub original_source_port: Option<u16>,
    /// Destination address of the NATed connection.
    pub destination: IpAddr,
    /// Destination port (`None` for portless protocols).
    pub destination_port: Option<u16>,
    /// Trailing state field (`MULTIPLE:MULTIPLE`, `ESTABLISHED:ESTABLISHED`,
    /// …) when present; empty when the line ends at the destination.
    pub state: String,
}

/// Why a `pfctl -s state` line could not be parsed as a NAT translation
/// record. Every variant carries the offending raw text so the caller can log
/// the failure without the parser guessing at intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfStateParseError {
    /// Not enough tokens for the `<fam> <proto> <src> (<orig>) -> <dst>` shape.
    MissingFields(String),
    /// The protocol token is not a lowercase alphabetic token.
    UnknownProtocol(String),
    /// A `<addr>` or `<addr>:<port>` token did not parse.
    BadAddress(String),
    /// A port suffix was present but not a `u16`.
    BadPort(String),
}

impl std::fmt::Display for PfStateParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfStateParseError::MissingFields(line) => {
                write!(
                    f,
                    "pf state line does not have the expected translation shape: {line}"
                )
            }
            PfStateParseError::UnknownProtocol(tok) => write!(f, "unknown protocol token: {tok}"),
            PfStateParseError::BadAddress(tok) => write!(f, "unparseable address token: {tok}"),
            PfStateParseError::BadPort(tok) => write!(f, "unparseable port in token: {tok}"),
        }
    }
}

/// Parse one `addr[:port]` token. IPv4 dotted-quad with an optional port; a
/// bracketed IPv6 with port (`[v6]:p`) is accepted; a bare IPv6 (no port) is
/// accepted. Anything else — empty host, non-`u16` port, malformed literal —
/// is an error. Fail closed on ambiguity: for an unbracketed token the split
/// is `rsplit_once(':')` ONLY when the suffix parses as `u16` AND the prefix
/// parses as an address; otherwise the whole token must parse as a bare
/// address (which rejects ambiguous IPv6-with-port spellings instead of
/// guessing).
fn parse_addr_port_token(token: &str) -> Result<(IpAddr, Option<u16>), PfStateParseError> {
    // Bracketed IPv6 `[2001:db8::1]:53`.
    if let Some(rest) = token.strip_prefix('[') {
        let (addr, tail) = rest
            .split_once(']')
            .ok_or_else(|| PfStateParseError::BadAddress(token.to_owned()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| PfStateParseError::BadPort(token.to_owned()))?,
            ),
            None if tail.is_empty() => None,
            None => return Err(PfStateParseError::BadAddress(token.to_owned())),
        };
        let addr =
            IpAddr::from_str(addr).map_err(|_| PfStateParseError::BadAddress(token.to_owned()))?;
        return Ok((addr, port));
    }
    if let Some((addr, port)) = token.rsplit_once(':')
        && let (Ok(a), Ok(p)) = (IpAddr::from_str(addr), port.parse::<u16>())
    {
        return Ok((a, Some(p)));
    }
    let addr =
        IpAddr::from_str(token).map_err(|_| PfStateParseError::BadAddress(token.to_owned()))?;
    Ok((addr, None))
}

/// Parse a single `pfctl -s state` NAT translation record.
///
/// Malformed input is an error, never a guess: a line that does not decompose
/// into the documented shape (see [`PfStateTranslation`]) is rejected. Plain
/// (non-NATed) state lines — no parenthesized original source — are also
/// rejected, because this parser exists to find translations; the caller's
/// fail-closed posture treats a capture with zero parsable translation
/// records as "no evidence", not "no NAT".
pub fn parse_macos_pf_state_translation_line(
    line: &str,
) -> Result<PfStateTranslation, PfStateParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(PfStateParseError::MissingFields(line.to_owned()));
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // Shape: <fam> <proto> <taddr> (<oaddr>) -> <daddr> [STATE...]
    // The family-or-iface token and the protocol must be separate tokens.
    if tokens.len() < 6 {
        return Err(PfStateParseError::MissingFields(line.to_owned()));
    }
    let family_or_iface = tokens[0].to_owned();
    let protocol = tokens[1].to_owned();
    if protocol.is_empty() || !protocol.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(PfStateParseError::UnknownProtocol(tokens[1].to_owned()));
    }
    let (translated_source, translated_source_port) = parse_addr_port_token(tokens[2])?;
    // The original source arrives parenthesized as ONE token: `(100.64.0.9:51820)`.
    let original_token = tokens[3]
        .strip_prefix('(')
        .and_then(|t| t.strip_suffix(')'))
        .ok_or_else(|| PfStateParseError::MissingFields(line.to_owned()))?;
    let (original_source, original_source_port) = parse_addr_port_token(original_token)?;
    if tokens[4] != "->" {
        return Err(PfStateParseError::MissingFields(line.to_owned()));
    }
    let (destination, destination_port) = parse_addr_port_token(tokens[5])?;
    let state = tokens[6..].join(" ");
    Ok(PfStateTranslation {
        family_or_iface,
        protocol,
        translated_source,
        translated_source_port,
        original_source,
        original_source_port,
        destination,
        destination_port,
        state,
    })
}

/// True when `addr` is inside the mesh CGNAT range `100.64.0.0/10` — IPv4
/// with first octet 100 and second octet 64–127. Mirrors the Linux/Windows
/// adapters' mesh-source classification; non-IPv4 (or any IPv6) is false.
fn is_mesh_cgnat_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(_) => false,
    }
}

/// The mesh range's network address and prefix length, as `(addr, prefix)`.
const MESH_CGNAT_NET: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

/// Select the pf state translation record that correlates the expected
/// client with the exit's egress identity (design §3/§4 — the identity check
/// is applied in RUST, never in the guest command; the Windows pattern).
///
/// Requires, for exactly one record:
/// - `original_source == client_mesh_addr` AND that address is inside
///   `100.64.0.0/10` (a non-mesh client address is rejected even if it
///   matches — the evidence must be a mesh-sourced translation), AND
/// - `translated_source == exit_egress_addr`.
///
/// No match (wrong source, wrong translated side, or no record) is a named
/// error; when several records match, the first is returned (duplicates
/// describe the same correlation and carry no extra evidence).
pub fn select_macos_client_nat_state(
    states: &[PfStateTranslation],
    client_mesh_addr: IpAddr,
    exit_egress_addr: IpAddr,
) -> Result<PfStateTranslation, String> {
    if !is_mesh_cgnat_addr(client_mesh_addr) {
        return Err(format!(
            "client_mesh_addr_not_in_mesh_range: {client_mesh_addr} is outside {} /{}",
            MESH_CGNAT_NET.0, MESH_CGNAT_NET.1
        ));
    }
    states
        .iter()
        .find(|s| s.original_source == client_mesh_addr && s.translated_source == exit_egress_addr)
        .cloned()
        .ok_or_else(|| {
            if states.iter().any(|s| s.original_source == client_mesh_addr) {
                format!(
                    "pf_state_translated_side_mismatch: client {client_mesh_addr} has a \
                     translation but none whose translated source is {exit_egress_addr}"
                )
            } else if states
                .iter()
                .any(|s| s.translated_source == exit_egress_addr)
            {
                format!(
                    "pf_state_other_source: a translation for {exit_egress_addr} exists but \
                     none whose original source is the client {client_mesh_addr}"
                )
            } else {
                format!(
                    "pf_state_no_correlating_record: no pf state record correlates client \
                     {client_mesh_addr} with translated source {exit_egress_addr}"
                )
            }
        })
}

// ---------------------------------------------------------------------------
// S2 egress-evidence evaluation (design §4; review §3 / amendment A6)
// ---------------------------------------------------------------------------

/// The burst window during which the client drove probe traffic
/// (`[start_unix, end_unix]`, Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitBurstWindow {
    pub start_unix: i64,
    pub end_unix: i64,
}

/// A lab-local sink observation (design §4/A6): the sink sits on the exit's
/// post-CP-1 egress segment (`192.168.64.0/24`) and records the source
/// address it actually saw, so the translated source is observed rather than
/// inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitSinkObservation {
    pub source_addr: String,
    pub observed_unix: i64,
}

/// The two-phase reachability fallback (design §4/A6): bursts to the same
/// target from the same client FAIL while the NAT anchor is flushed and
/// SUCCEED while it is present. Acceptable only WITH pf-state capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitTwoPhaseFallback {
    pub anchor_flushed_bursts_failed: bool,
    pub anchor_present_bursts_succeeded: bool,
}

/// The macOS S2 egress-evidence artifact (`active_exit.egress_evidence.json`,
/// macOS extension — design §4). Schema version
/// [`MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION`]; foreign payloads are
/// rejected by version, and evaluation is fail-closed end to end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitEgressEvidence {
    pub schema_version: u32,
    /// The live `--node` run the artifact was produced under. A dry run has
    /// no live run id, so a missing/mismatched id can never pass (design §4:
    /// "the evaluator rejects any artifact lacking the live run id it was
    /// produced under").
    pub live_run_id: String,
    /// The client's mesh address, as the stage observed it.
    pub client_mesh_addr: String,
    /// The exit's egress address (the expected translated source).
    pub exit_egress_addr: String,
    pub burst_window: MacosExitBurstWindow,
    /// `pfctl -s state` translation records captured on the exit during the
    /// window. At least one must correlate the client (via
    /// [`select_macos_client_nat_state`]).
    pub pf_state_records: Vec<PfStateTranslation>,
    pub sink_observation: Option<MacosExitSinkObservation>,
    pub two_phase_fallback: Option<MacosExitTwoPhaseFallback>,
}

/// Evaluate the macOS S2 egress-evidence artifact, offline and fail-closed
/// (design §4; review §3).
///
/// Returns `Ok(claim)` — the human-readable evidence claim for the stage
/// report — only on a complete, correlated, in-window record set:
/// - the artifact must parse and carry
///   `schema_version == MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION`;
/// - `live_run_id` must be present and equal `expected_live_run_id` (dry-run
///   provenance is rejected; there is no dry-run-as-pass path);
/// - the artifact's self-declared client/exit addresses must match the
///   expected pair (a mis-associated artifact is rejected, not reinterpreted);
/// - the burst window must be well-formed (`start <= end`);
/// - at least one pf state record must correlate the expected client/exit
///   address pair (identity checked in Rust);
/// - acceptance then needs ONE of, satisfied fail-closed:
///   * a sink observation whose `source_addr` equals the exit's egress
///     address AND whose `observed_unix` lies inside the burst window, or
///   * the two-phase fallback with BOTH bits true AND pf-state records
///     present (the correlation above) — the fallback never stands alone;
/// - out-of-window timestamps, a partial fallback (one bit false), or a
///   sink observation from any other source address is a rejection naming
///   the failed branch. Missing evidence is `Failed`, never `Partial` and
///   never a skip.
pub fn evaluate_macos_exit_egress_evidence(
    artifact_json: &str,
    expected_live_run_id: &str,
    client_mesh_addr: IpAddr,
    exit_egress_addr: IpAddr,
) -> Result<String, String> {
    let artifact: MacosExitEgressEvidence = serde_json::from_str(artifact_json)
        .map_err(|e| format!("missing_or_malformed_artifact: {e}"))?;
    if artifact.schema_version != MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION {
        return Err(format!(
            "unknown_schema_version: got {}, expected {MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION}",
            artifact.schema_version
        ));
    }
    if artifact.live_run_id.is_empty() {
        return Err(
            "dry_run_provenance: artifact carries no live run id (dry runs can never pass)"
                .to_owned(),
        );
    }
    if artifact.live_run_id != expected_live_run_id {
        return Err(format!(
            "live_run_id_mismatch: artifact was produced under '{}' but this run is '{}'",
            artifact.live_run_id, expected_live_run_id
        ));
    }
    let declared_client = IpAddr::from_str(artifact.client_mesh_addr.trim()).map_err(|_| {
        format!(
            "malformed_artifact_field: client_mesh_addr '{}'",
            artifact.client_mesh_addr
        )
    })?;
    let declared_exit = IpAddr::from_str(artifact.exit_egress_addr.trim()).map_err(|_| {
        format!(
            "malformed_artifact_field: exit_egress_addr '{}'",
            artifact.exit_egress_addr
        )
    })?;
    if declared_client != client_mesh_addr {
        return Err(format!(
            "client_addr_mismatch: artifact declares {declared_client}, this run expected {client_mesh_addr}"
        ));
    }
    if declared_exit != exit_egress_addr {
        return Err(format!(
            "exit_addr_mismatch: artifact declares {declared_exit}, this run expected {exit_egress_addr}"
        ));
    }
    if artifact.burst_window.start_unix > artifact.burst_window.end_unix {
        return Err(format!(
            "malformed_burst_window: start {} > end {}",
            artifact.burst_window.start_unix, artifact.burst_window.end_unix
        ));
    }
    // The identity correlation: a pf state record whose original source is
    // the client's mesh address (in 100.64.0.0/10) translated to the exit's
    // egress address. Without it nothing else is acceptable — the fallback
    // never stands alone and a sink hit without the client correlation could
    // belong to any host on the egress segment.
    let correlated = select_macos_client_nat_state(
        &artifact.pf_state_records,
        client_mesh_addr,
        exit_egress_addr,
    )
    .map_err(|e| format!("partial_correlation: {e}"))?;

    let in_window =
        |ts: i64| artifact.burst_window.start_unix <= ts && ts <= artifact.burst_window.end_unix;
    if let Some(sink) = &artifact.sink_observation {
        let sink_addr = IpAddr::from_str(sink.source_addr.trim()).map_err(|_| {
            format!(
                "malformed_artifact_field: sink source_addr '{}'",
                sink.source_addr
            )
        })?;
        if sink_addr != exit_egress_addr {
            return Err(format!(
                "sink_source_mismatch: sink observed {sink_addr}, expected the exit's \
                 egress address {exit_egress_addr}"
            ));
        }
        if !in_window(sink.observed_unix) {
            return Err(format!(
                "out_of_window_timestamps: sink observation at {} is outside [{}, {}]",
                sink.observed_unix,
                artifact.burst_window.start_unix,
                artifact.burst_window.end_unix
            ));
        }
        return Ok(format!(
            "client {client_mesh_addr}'s traffic was translated by the exit's NAT to \
             {exit_egress_addr} (pf state {} -> {} -> sink-observed source {sink_addr} \
             within [{}, {}])",
            correlated.original_source,
            correlated.translated_source,
            artifact.burst_window.start_unix,
            artifact.burst_window.end_unix
        ));
    }
    if let Some(fallback) = &artifact.two_phase_fallback {
        if !fallback.anchor_flushed_bursts_failed {
            return Err(
                "fallback_not_satisfied: bursts did NOT fail with the NAT anchor flushed"
                    .to_owned(),
            );
        }
        if !fallback.anchor_present_bursts_succeeded {
            return Err(
                "fallback_not_satisfied: bursts did NOT succeed with the NAT anchor present"
                    .to_owned(),
            );
        }
        if artifact.pf_state_records.is_empty() {
            // Unreachable given the correlation requirement above, but kept
            // explicit: the fallback is acceptable only WITH pf-state capture.
            return Err(
                "fallback_without_pf_state: the two-phase fallback never stands alone".to_owned(),
            );
        }
        return Ok(format!(
            "client {client_mesh_addr}'s traffic gated by the exit's NAT anchor (bursts \
             fail flushed, succeed present) with pf state {} -> {} captured",
            correlated.original_source, correlated.translated_source
        ));
    }
    Err(
        "partial_correlation: pf state correlates the client but neither a sink \
         observation nor a two-phase fallback record is present"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- fixture helpers -------------------------------------------------

    fn snapshot_json(
        schema_version: u32,
        anchor_present: bool,
        forwarding: &str,
        prefix: &str,
    ) -> String {
        format!(
            r#"{{
                "schema_version": {schema_version},
                "captured_at_unix": 1788000000,
                "mesh_cidr": "100.64.0.0/24",
                "pf_anchor": "com.rustynet/nat",
                "pf_anchor_present": {anchor_present},
                "internal_prefix": "{prefix}",
                "tunnel_forwarding": "{forwarding}",
                "egress_forwarding": "{forwarding}"
            }}"#
        )
    }

    fn translation(original: &str, translated: &str) -> PfStateTranslation {
        let line = format!(
            "ALL udp {translated}:51820 ({original}:51820) -> 1.1.1.1:53  MULTIPLE:MULTIPLE"
        );
        parse_macos_pf_state_translation_line(&line)
            .unwrap_or_else(|e| panic!("fixture line should parse: {e}"))
    }

    fn evidence_json(
        live_run_id: &str,
        records: &[PfStateTranslation],
        sink: Option<MacosExitSinkObservation>,
        fallback: Option<MacosExitTwoPhaseFallback>,
    ) -> String {
        let artifact = MacosExitEgressEvidence {
            schema_version: MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION,
            live_run_id: live_run_id.to_owned(),
            client_mesh_addr: "100.64.0.9".to_owned(),
            exit_egress_addr: "192.168.64.10".to_owned(),
            burst_window: MacosExitBurstWindow {
                start_unix: 1_788_000_000,
                end_unix: 1_788_000_060,
            },
            pf_state_records: records.to_vec(),
            sink_observation: sink,
            two_phase_fallback: fallback,
        };
        serde_json::to_string(&artifact).expect("fixture artifact serialises")
    }

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
    const EXIT_EGRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10));

    // ----- snapshot verdicts (design §7) -----------------------------------

    #[test]
    fn assert_exit_actively_serving_rejects_absent_anchor() {
        let err = assess_exit_snapshot(
            &snapshot_json(1, false, "Enabled", "100.64.0.0/24"),
            "100.64.0.0/24",
        )
        .expect_err("absent anchor must reject");
        assert!(err.starts_with("pf_anchor_absent"), "{err}");
    }

    #[test]
    fn assert_exit_actively_serving_rejects_forwarding_disabled() {
        for forwarding in ["Disabled", "Unknown"] {
            let err = assess_exit_snapshot(
                &snapshot_json(1, true, forwarding, "100.64.0.0/24"),
                "100.64.0.0/24",
            )
            .expect_err("non-Enabled forwarding must reject");
            assert!(err.starts_with("forwarding_disabled"), "{err}");
        }
    }

    #[test]
    fn assert_exit_actively_serving_rejects_internal_prefix_drift() {
        let err = assess_exit_snapshot(
            &snapshot_json(1, true, "Enabled", "192.168.65.0/24"),
            "100.64.0.0/24",
        )
        .expect_err("prefix drift must reject");
        assert!(err.starts_with("internal_prefix_drift"), "{err}");
    }

    #[test]
    fn assert_exit_actively_serving_rejects_unknown_schema_version() {
        let err = assess_exit_snapshot(
            &snapshot_json(2, true, "Enabled", "100.64.0.0/24"),
            "100.64.0.0/24",
        )
        .expect_err("unknown schema_version must reject");
        assert!(err.starts_with("unknown_schema_version"), "{err}");
    }

    #[test]
    fn assert_exit_actively_serving_rejects_malformed_json() {
        let err = assess_exit_snapshot("not json at all", "100.64.0.0/24")
            .expect_err("malformed JSON must reject");
        assert!(err.starts_with("malformed_snapshot_json"), "{err}");
    }

    #[test]
    fn assert_exit_actively_serving_accepts_matching_snapshot() {
        let verdict = assess_exit_snapshot(
            &snapshot_json(1, true, "Enabled", "100.64.0.0/24"),
            "100.64.0.0/24",
        )
        .expect("matching snapshot must accept");
        assert!(verdict.pf_anchor_present);
        assert!(verdict.forwarding_enabled);
        assert!(verdict.internal_prefix_matches);
    }

    // ----- pf state line parsing (design §7; review §2 A3) -----------------

    #[test]
    fn parse_pf_state_translation_line_accepts_fixture() {
        let parsed = parse_macos_pf_state_translation_line(
            "ALL udp 192.168.64.10:51820 (100.64.0.9:51820) -> 1.1.1.1:53  MULTIPLE:MULTIPLE",
        )
        .expect("fixture line must parse");
        assert_eq!(parsed.family_or_iface, "ALL");
        assert_eq!(parsed.protocol, "udp");
        assert_eq!(
            parsed.translated_source,
            IpAddr::V4(Ipv4Addr::new(192, 168, 64, 10))
        );
        assert_eq!(parsed.translated_source_port, Some(51820));
        assert_eq!(parsed.original_source, CLIENT);
        assert_eq!(parsed.original_source_port, Some(51820));
        assert_eq!(parsed.destination, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(parsed.destination_port, Some(53));
        assert_eq!(parsed.state, "MULTIPLE:MULTIPLE");

        // Portless destination spelling (icmp-style) still parses.
        let portless =
            parse_macos_pf_state_translation_line("ALL icmp 192.168.64.10 (100.64.0.9) -> 1.1.1.1")
                .expect("portless fixture must parse");
        assert_eq!(portless.original_source, CLIENT);
        assert_eq!(portless.original_source_port, None);
        assert_eq!(portless.destination_port, None);
        assert_eq!(portless.state, "");
    }

    #[test]
    fn parse_pf_state_translation_line_rejects_malformed() {
        let cases = [
            "garbage",
            "",
            "ALL udp",
            "ALL udp 192.168.64.10:51820 (100.64.0.9:51820) 1.1.1.1:53", // no arrow
            "ALL udp 192.168.64.10:51820 100.64.0.9:51820 -> 1.1.1.1:53", // no parens: not a NAT translation
            "ALL 123 192.168.64.10:51820 (100.64.0.9:51820) -> 1.1.1.1:53", // bad protocol
            "ALL udp not-an-address (100.64.0.9:51820) -> 1.1.1.1:53",
            "ALL udp 192.168.64.10:99999 (100.64.0.9:51820) -> 1.1.1.1:53", // port overflow
            "ALL udp 192.168.64.10:51820 (nope:51820) -> 1.1.1.1:53",
        ];
        for line in cases {
            let err = parse_macos_pf_state_translation_line(line)
                .expect_err("malformed line must reject");
            assert!(
                matches!(
                    err,
                    PfStateParseError::MissingFields(_)
                        | PfStateParseError::UnknownProtocol(_)
                        | PfStateParseError::BadAddress(_)
                        | PfStateParseError::BadPort(_)
                ),
                "{line}: {err}"
            );
        }
    }

    // ----- identity selection (design §7) ----------------------------------

    #[test]
    fn select_client_nat_state_accepts_identity() {
        let records = vec![
            translation("100.64.0.5", "192.168.64.10"), // another mesh client, same exit
            translation("100.64.0.9", "192.168.64.10"), // the expected client
        ];
        let selected = select_macos_client_nat_state(&records, CLIENT, EXIT_EGRESS)
            .expect("correlating record must be selected");
        assert_eq!(selected.original_source, CLIENT);
        assert_eq!(selected.translated_source, EXIT_EGRESS);
    }

    #[test]
    fn select_client_nat_state_rejects_other_source() {
        let records = vec![translation("100.64.0.5", "192.168.64.10")];
        let err = select_macos_client_nat_state(&records, CLIENT, EXIT_EGRESS)
            .expect_err("a translation for a different client must reject");
        assert!(err.contains("pf_state_other_source"), "{err}");
    }

    #[test]
    fn select_client_nat_state_rejects_other_translated_side() {
        let records = vec![translation("100.64.0.9", "192.168.64.11")];
        let err = select_macos_client_nat_state(&records, CLIENT, EXIT_EGRESS)
            .expect_err("a translation to a different egress address must reject");
        assert!(err.contains("pf_state_translated_side_mismatch"), "{err}");
    }

    #[test]
    fn select_client_nat_state_rejects_non_mesh_client_addr() {
        let lan_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 64, 99));
        let err = select_macos_client_nat_state(&[], lan_addr, EXIT_EGRESS)
            .expect_err("a client address outside 100.64.0.0/10 must reject");
        assert!(err.contains("client_mesh_addr_not_in_mesh_range"), "{err}");
    }

    // ----- S2 egress evidence evaluation (design §7) ------------------------

    #[test]
    fn evaluate_macos_exit_egress_evidence_fails_closed_on_missing_artifact() {
        for bad in ["", "not json", "{}"] {
            let err = evaluate_macos_exit_egress_evidence(bad, "run-1", CLIENT, EXIT_EGRESS)
                .expect_err("missing/malformed artifact must reject");
            assert!(
                err.starts_with("missing_or_malformed_artifact"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_on_partial_correlation() {
        // pf record correlates, but no sink observation and no fallback.
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            None,
            None,
        );
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("correlation without sink or fallback must reject");
        assert!(err.contains("partial_correlation"), "{err}");

        // Sink observation from the wrong source address.
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            Some(MacosExitSinkObservation {
                source_addr: "192.168.64.99".to_owned(),
                observed_unix: 1_788_000_030,
            }),
            None,
        );
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("wrong sink source must reject");
        assert!(err.contains("sink_source_mismatch"), "{err}");

        // No correlating pf record even though the fallback bits hold.
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.5", "192.168.64.10")],
            None,
            Some(MacosExitTwoPhaseFallback {
                anchor_flushed_bursts_failed: true,
                anchor_present_bursts_succeeded: true,
            }),
        );
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("fallback without a correlating record must reject");
        assert!(err.contains("partial_correlation"), "{err}");
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_on_out_of_window_timestamps() {
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            Some(MacosExitSinkObservation {
                source_addr: "192.168.64.10".to_owned(),
                observed_unix: 1_788_000_061, // one second past the window
            }),
            None,
        );
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("out-of-window sink timestamp must reject");
        assert!(err.contains("out_of_window_timestamps"), "{err}");
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_on_dry_run_provenance() {
        let cases = [
            // Empty live_run_id: the dry-run artifact shape.
            evidence_json(
                "",
                &[translation("100.64.0.9", "192.168.64.10")],
                None,
                None,
            ),
            // A live_run_id from a different run.
            evidence_json(
                "run-2",
                &[translation("100.64.0.9", "192.168.64.10")],
                None,
                None,
            ),
        ];
        for json in cases {
            let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
                .expect_err("dry-run / mismatched provenance must reject");
            assert!(
                err.contains("dry_run_provenance") || err.contains("live_run_id_mismatch"),
                "{err}"
            );
        }
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_accepts_complete_sink_observation() {
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            Some(MacosExitSinkObservation {
                source_addr: "192.168.64.10".to_owned(),
                observed_unix: 1_788_000_030,
            }),
            None,
        );
        let claim = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect("complete sink observation must accept");
        assert!(claim.contains("sink-observed"), "{claim}");
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_accepts_two_phase_fallback_with_pf_state() {
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            None,
            Some(MacosExitTwoPhaseFallback {
                anchor_flushed_bursts_failed: true,
                anchor_present_bursts_succeeded: true,
            }),
        );
        let claim = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect("two-phase fallback WITH pf state must accept");
        assert!(claim.contains("pf state"), "{claim}");
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_rejects_fallback_without_pf_state() {
        // Direct-shape artifact: fallback bits hold, pf records empty. The
        // evaluator's correlation requirement rejects it (the fallback never
        // stands alone — design §4/A6), and the empty-records guard names it.
        let artifact = MacosExitEgressEvidence {
            schema_version: MACOS_EXIT_EGRESS_EVIDENCE_SCHEMA_VERSION,
            live_run_id: "run-1".to_owned(),
            client_mesh_addr: "100.64.0.9".to_owned(),
            exit_egress_addr: "192.168.64.10".to_owned(),
            burst_window: MacosExitBurstWindow {
                start_unix: 1_788_000_000,
                end_unix: 1_788_000_060,
            },
            pf_state_records: Vec::new(),
            sink_observation: None,
            two_phase_fallback: Some(MacosExitTwoPhaseFallback {
                anchor_flushed_bursts_failed: true,
                anchor_present_bursts_succeeded: true,
            }),
        };
        let json = serde_json::to_string(&artifact).expect("fixture serialises");
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("fallback without pf state must reject");
        assert!(
            err.contains("partial_correlation") || err.contains("fallback_without_pf_state"),
            "{err}"
        );
    }

    #[test]
    fn evaluate_macos_exit_egress_evidence_rejects_partial_fallback_and_mismatched_addrs() {
        // One fallback bit false → reject even with a correlating record.
        let json = evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            None,
            Some(MacosExitTwoPhaseFallback {
                anchor_flushed_bursts_failed: true,
                anchor_present_bursts_succeeded: false,
            }),
        );
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("partial fallback must reject");
        assert!(err.contains("fallback_not_satisfied"), "{err}");

        // Artifact self-declares a different exit address → reject.
        let mut artifact: MacosExitEgressEvidence = serde_json::from_str(&evidence_json(
            "run-1",
            &[translation("100.64.0.9", "192.168.64.10")],
            None,
            None,
        ))
        .expect("fixture parses");
        artifact.exit_egress_addr = "192.168.64.11".to_owned();
        let json = serde_json::to_string(&artifact).expect("fixture serialises");
        let err = evaluate_macos_exit_egress_evidence(&json, "run-1", CLIENT, EXIT_EGRESS)
            .expect_err("mismatched declared exit address must reject");
        assert!(err.contains("exit_addr_mismatch"), "{err}");
    }
}
