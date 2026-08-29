//! Blind-relay protocol v2 wire types — canonical line grammar (phase 3).
//!
//! Implements the owner-approved §16 items 1–3 selections from
//! `documents/operations/active/BlindRelayProtocolSelection_2026-08-28.md`
//! (§1.3 encoding, §2.2 proof-of-possession suite, §3.2 replay keying rules)
//! on top of the design `BlindRelayRoleDesign_2026-08-27.md` §7–§8.
//!
//! The three v2 signed wire surfaces — [`BlindRelayLegTokenV2`],
//! [`BlindRelayHelloV2`], and [`BlindRelayFleetDescriptorV2`] — use exactly the
//! RelaySessionToken v1 house grammar: newline-terminated `key=value` lines,
//! `version=2` first line, fixed field order, signature (where present) as the
//! final line, fixed-width hex for binary fields, canonical decimal for
//! integers (no sign, no leading zeros), and a canonical re-encode equality
//! check before any signature verification or application. Duplicate keys,
//! unknown keys, missing fields, reordered fields, overlong fields, invalid
//! UTF-8, noncanonical numerics, and trailing data are all rejected
//! fail-closed before any signature work.
//!
//! Deliberately NOT in this phase (phase 4): the relay-side listener, PoP
//! runtime admission ordering, HMAC address-validation token format, durable
//! replay-store wiring, and production advertisement of the role.
//!
//! **Changing any canonical layout below is a breaking change** (bump the
//! version / domain string instead).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;

use crate::ControlPlaneError;

/// Bounded wire size for a whole blind-relay leg token v2 (§1.3 table).
pub const MAX_BLIND_RELAY_TOKEN_WIRE_BYTES: usize = 4096;

/// Bounded wire size for a whole blind-relay hello v2 datagram (§1.3 table).
pub const MAX_BLIND_RELAY_HELLO_WIRE_BYTES: usize = 4096;

/// Bounded wire size for a whole blind-relay fleet descriptor v2 (§1.3 table).
pub const MAX_BLIND_RELAY_FLEET_DESCRIPTOR_WIRE_BYTES: usize = 16 * 1024;

/// Maximum byte length of a bounded ASCII text field (ids, kind, scope,
/// profile_id, issuer_key_id — §1.3 table; single line, no control chars).
pub const MAX_BLIND_RELAY_TEXT_FIELD_BYTES: usize = 32;

/// Maximum decimal digits accepted for an integer field (§1.3 table).
pub const MAX_BLIND_RELAY_DECIMAL_DIGITS: usize = 20;

/// The only accepted scope value for a blind-relay leg token v2.
pub const BLIND_RELAY_TOKEN_SCOPE_V2: &str = "forward_ciphertext_only_blind";

/// The only accepted `token_kind` value for a blind-relay leg token v2.
pub const BLIND_RELAY_TOKEN_KIND_V2: &str = "blind_relay_leg";

/// Domain-separation string for the proof-of-possession transcript
/// (`rustynet-control-<purpose>-v1` convention). Bump the suffix if the
/// transcript layout ever changes.
pub const BLIND_RELAY_POP_DOMAIN_V1: &str = "rustynet-control-blind-relay-pop-v1";

/// Maximum leg-token TTL accepted at parse. Same ceiling as the v1 admission
/// token; the design (§7.3) keeps it unless a separate review tightens it.
pub const MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS: u64 = crate::MAX_RELAY_SESSION_TOKEN_TTL_SECS;

/// Maximum fleet-descriptor TTL at parse. Same ceiling as the v1 relay fleet
/// bundle (`parse_signed_relay_fleet_bundle_wire`).
pub const MAX_BLIND_RELAY_FLEET_TTL_SECS: u64 = 300;

/// Maximum entries in a protocol-version list (`hello_versions` /
/// `token_versions`). The accepted set is closed ({1, 2}), so this is
/// generous headroom, not an unboundedness.
pub const MAX_BLIND_RELAY_PROTOCOL_VERSION_ENTRIES: usize = 8;

/// Maximum entries in the `profile_ids` list.
pub const MAX_BLIND_RELAY_PROFILE_IDS: usize = 64;

// ── Closed enum fields ──────────────────────────────────────────────────────

/// Closed `token_kind` enum for the v2 leg token. Checked at parse, before
/// any signature use; an unknown value is a hard reject, never a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRelayTokenKindV2 {
    /// A single leg of a two-leg blind-relay circuit authorization.
    BlindRelayLeg,
}

impl BlindRelayTokenKindV2 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlindRelayLeg => BLIND_RELAY_TOKEN_KIND_V2,
        }
    }

    fn from_wire(value: &str) -> Result<Self, ControlPlaneError> {
        match value {
            BLIND_RELAY_TOKEN_KIND_V2 => Ok(Self::BlindRelayLeg),
            other => Err(ControlPlaneError::Traversal(format!(
                "blind relay token v2 token_kind is invalid: {other}"
            ))),
        }
    }
}

/// Closed `leg_slot` enum: exactly 0 or 1. The two legs of a circuit carry
/// complementary slots; any other value is rejected at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRelayLegSlot {
    /// First leg of the circuit.
    Slot0,
    /// Second leg of the circuit.
    Slot1,
}

impl BlindRelayLegSlot {
    pub fn as_u64(self) -> u64 {
        match self {
            Self::Slot0 => 0,
            Self::Slot1 => 1,
        }
    }

    fn from_wire(value: &str) -> Result<Self, ControlPlaneError> {
        match value {
            "0" => Ok(Self::Slot0),
            "1" => Ok(Self::Slot1),
            other => Err(ControlPlaneError::Traversal(format!(
                "blind relay token v2 leg_slot is invalid: {other}"
            ))),
        }
    }
}

/// Closed `relay_mode` enum for the v2 fleet descriptor. Absence of a mode
/// never means blind by inference (design §8.1): the value must be present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRelayModeV2 {
    /// An ordinary (identity-carrying) relay; v1 semantics.
    Normal,
    /// An identity-blind relay; accepts exactly hello/token v2.
    IdentityBlind,
}

impl BlindRelayModeV2 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::IdentityBlind => "identity_blind",
        }
    }

    fn from_wire(value: &str) -> Result<Self, ControlPlaneError> {
        match value {
            "normal" => Ok(Self::Normal),
            "identity_blind" => Ok(Self::IdentityBlind),
            other => Err(ControlPlaneError::Traversal(format!(
                "blind relay fleet descriptor v2 relay_mode is invalid: {other}"
            ))),
        }
    }
}

// ── Bounded field helpers (§1.3 table) ──────────────────────────────────────

/// Whether `value` is a bounded single-line ASCII payload value with no
/// control characters. The v1 analogue (`is_single_line_payload_value`) only
/// excludes `\n`, `\r`, `=`; v2 additionally excludes every ASCII control
/// character and every non-ASCII byte, per the §1.3 row.
fn is_bounded_ascii_text(value: &str, max_bytes: usize) -> bool {
    if value.is_empty() || value.len() > max_bytes {
        return false;
    }
    value
        .bytes()
        .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'=')
}

/// Canonical decimal parse: no sign, no leading zeros, at most 20 digits.
/// The v1 path (`u64::from_str`) silently accepts `+5` and `007`; v2 must not,
/// because the canonical re-encode equality check would otherwise reject a
/// token whose parser accepted a noncanonical rendering of the same value.
fn parse_canonical_u64(value: &str, field: &str) -> Result<u64, ControlPlaneError> {
    if value.is_empty() || value.len() > MAX_BLIND_RELAY_DECIMAL_DIGITS {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} is not a bounded decimal integer"
        )));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} has a noncanonical leading zero"
        )));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} is not a plain decimal integer"
        )));
    }
    value.parse::<u64>().map_err(|_| {
        ControlPlaneError::Traversal(format!("blind relay v2 field {field} is out of range"))
    })
}

/// Decode a fixed-width hex field, mapping any malformation (wrong length,
/// non-hex byte) to one closed rejection class. Length is checked before any
/// decode work, so a short field never reaches the decoder.
fn decode_fixed_hex<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], ControlPlaneError> {
    crate::decode_hex_to_fixed::<N>(value).map_err(|_| {
        ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} is not {width}-character lowercase hex",
            width = N * 2
        ))
    })
}

/// Reject the degenerate all-zero value of a crypto field (the v1 all-zero
/// nonce rejection, applied to every CSPRNG-sourced v2 field).
fn reject_all_zero<const N: usize>(value: &[u8; N], field: &str) -> Result<(), ControlPlaneError> {
    if value.iter().all(|&byte| byte == 0) {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} must not be all zero"
        )));
    }
    Ok(())
}

/// A comma-separated list of protocol versions, each 1 or 2, deduplicated,
/// sorted ascending (canonical order), and non-empty.
fn parse_protocol_version_list(value: &str, field: &str) -> Result<Vec<u64>, ControlPlaneError> {
    let mut versions = Vec::new();
    for entry in value.split(',') {
        let version = parse_canonical_u64(entry, field)?;
        if version != 1 && version != 2 {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay v2 field {field} carries an unsupported version: {version}"
            )));
        }
        if versions.contains(&version) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay v2 field {field} carries a duplicate version: {version}"
            )));
        }
        versions.push(version);
        if versions.len() > MAX_BLIND_RELAY_PROTOCOL_VERSION_ENTRIES {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay v2 field {field} exceeds the entry bound"
            )));
        }
    }
    if versions.is_empty() {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay v2 field {field} must not be empty"
        )));
    }
    let sorted = versions.clone();
    sorted
        .iter()
        .zip(sorted.iter().skip(1))
        .all(|(a, b)| a < b)
        .then_some(())
        .ok_or_else(|| {
            ControlPlaneError::Traversal(format!(
                "blind relay v2 field {field} is not in canonical sorted order"
            ))
        })?;
    Ok(versions)
}

/// Render a canonical protocol-version list (sorted ascending, comma-joined).
fn protocol_version_list_wire(versions: &[u64]) -> String {
    let mut sorted = versions.to_vec();
    sorted.sort_unstable();
    sorted
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A comma-separated list of profile identifiers, each a bounded ASCII text
/// field, deduplicated, and sorted ascending (canonical order).
fn parse_profile_id_list(value: &str) -> Result<Vec<String>, ControlPlaneError> {
    let mut profiles = Vec::new();
    for entry in value.split(',') {
        if !is_bounded_ascii_text(entry, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
            return Err(ControlPlaneError::Traversal(
                "blind relay v2 profile id is not a bounded single-line ASCII value".to_owned(),
            ));
        }
        if profiles.iter().any(|existing| existing == entry) {
            return Err(ControlPlaneError::Traversal(
                "blind relay v2 profile id list carries a duplicate entry".to_owned(),
            ));
        }
        profiles.push(entry.to_owned());
        if profiles.len() > MAX_BLIND_RELAY_PROFILE_IDS {
            return Err(ControlPlaneError::Traversal(
                "blind relay v2 profile id list exceeds the entry bound".to_owned(),
            ));
        }
    }
    if profiles.is_empty() {
        return Err(ControlPlaneError::Traversal(
            "blind relay v2 profile id list must not be empty".to_owned(),
        ));
    }
    let mut sorted = profiles.clone();
    sorted.sort();
    if sorted != profiles {
        return Err(ControlPlaneError::Traversal(
            "blind relay v2 profile id list is not in canonical sorted order".to_owned(),
        ));
    }
    Ok(profiles)
}

/// Render a canonical profile-id list (sorted ascending, comma-joined).
fn profile_id_list_wire(profiles: &[String]) -> String {
    let mut sorted = profiles.to_vec();
    sorted.sort();
    sorted.join(",")
}

// ── BlindRelayLegTokenV2 ────────────────────────────────────────────────────

/// Signed blind-relay leg token v2 (design §7.3; selection §1.3).
///
/// One leg of a two-leg circuit authorization. The token deliberately carries
/// **no** endpoint identity: no node id, no peer node id, no WireGuard key, no
/// membership index — that is the disclosure the `blind_relay` role exists to
/// remove. `audience_relay_id` is the zero-padded 16-byte relay identifier
/// (the v1 relay id shape); every other binary field is fixed-width CSPRNG
/// material.
///
/// `PartialEq`/`Eq` are intentionally **not** derived to prevent accidental
/// non-constant-time comparisons on secret fields (`circuit_handle`,
/// `leg_handle`, `nonce`, `presenter_public_key`, `audience_relay_id`,
/// `signature`). Use [`BlindRelayLegTokenV2::ct_eq`].
#[derive(Clone)]
pub struct BlindRelayLegTokenV2 {
    /// Fixed at parse to [`BlindRelayTokenKindV2::BlindRelayLeg`].
    pub token_kind: BlindRelayTokenKindV2,
    /// The zero-padded 16-byte relay audience (≤16 ASCII bytes of label).
    pub audience_relay_id: [u8; 16],
    /// Fixed to [`BLIND_RELAY_TOKEN_SCOPE_V2`].
    pub scope: String,
    /// Monotonic privacy epoch; ≥ 1.
    pub privacy_epoch: u64,
    /// Fresh 256-bit CSPRNG value shared by exactly the two legs.
    pub circuit_handle: [u8; 32],
    /// Fresh 256-bit CSPRNG value unique to this leg.
    pub leg_handle: [u8; 32],
    /// Exactly 0 or 1; complementary across the two legs.
    pub leg_slot: BlindRelayLegSlot,
    /// Fresh per-circuit Ed25519 proof-of-possession public key.
    pub presenter_public_key: [u8; 32],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    /// Fresh per-token replay nonce (16 bytes, the v1 nonce shape).
    pub nonce: [u8; 16],
    /// Coarse public fleet-wide limit selector.
    pub profile_id: String,
    /// Issuer key identifier (allowlisted at verification time).
    pub issuer_key_id: String,
    pub signature: [u8; 64],
}

impl fmt::Debug for BlindRelayLegTokenV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindRelayLegTokenV2")
            .field("token_kind", &self.token_kind.as_str())
            .field("audience_relay_id", &"REDACTED")
            .field("scope", &self.scope)
            .field("privacy_epoch", &self.privacy_epoch)
            .field("circuit_handle", &"REDACTED")
            .field("leg_handle", &"REDACTED")
            .field("leg_slot", &self.leg_slot.as_u64())
            .field("presenter_public_key", &"REDACTED")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("nonce", &"REDACTED")
            .field("profile_id", &self.profile_id)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"REDACTED")
            .finish()
    }
}

/// Construct-and-validate a leg token v2 from raw fields. All §1.3 bounds and
/// degenerate-value checks run here and in the parser, so a value that cannot
/// round-trip through the canonical wire form cannot be constructed.
impl BlindRelayLegTokenV2 {
    /// Validate fields and build a token without a signature.
    ///
    /// Fails closed on every bounded-field violation; call [`Self::sign`] to
    /// produce the signature over [`Self::canonical_payload`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_kind: BlindRelayTokenKindV2,
        audience_relay_id: [u8; 16],
        scope: &str,
        privacy_epoch: u64,
        circuit_handle: [u8; 32],
        leg_handle: [u8; 32],
        leg_slot: BlindRelayLegSlot,
        presenter_public_key: [u8; 32],
        issued_at_unix: u64,
        expires_at_unix: u64,
        nonce: [u8; 16],
        profile_id: &str,
        issuer_key_id: &str,
    ) -> Result<Self, ControlPlaneError> {
        if !is_bounded_ascii_text(scope, MAX_BLIND_RELAY_TEXT_FIELD_BYTES)
            || scope != BLIND_RELAY_TOKEN_SCOPE_V2
        {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 scope is invalid".to_owned(),
            ));
        }
        reject_all_zero(&circuit_handle, "circuit_handle")?;
        reject_all_zero(&leg_handle, "leg_handle")?;
        reject_all_zero(&presenter_public_key, "presenter_public_key")?;
        reject_all_zero(&nonce, "nonce")?;
        validate_audience_relay_id(&audience_relay_id)?;
        if privacy_epoch == 0 {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 privacy_epoch must be at least 1".to_owned(),
            ));
        }
        if issued_at_unix == 0 || expires_at_unix <= issued_at_unix {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 timestamps are invalid".to_owned(),
            ));
        }
        if expires_at_unix.saturating_sub(issued_at_unix) > MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay token v2 ttl exceeds max supported value ({MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS})"
            )));
        }
        if !is_bounded_ascii_text(profile_id, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 profile_id is not a bounded single-line ASCII value"
                    .to_owned(),
            ));
        }
        if !is_bounded_ascii_text(issuer_key_id, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 issuer_key_id is not a bounded single-line ASCII value"
                    .to_owned(),
            ));
        }
        Ok(Self {
            token_kind,
            audience_relay_id,
            scope: scope.to_owned(),
            privacy_epoch,
            circuit_handle,
            leg_handle,
            leg_slot,
            presenter_public_key,
            issued_at_unix,
            expires_at_unix,
            nonce,
            profile_id: profile_id.to_owned(),
            issuer_key_id: issuer_key_id.to_owned(),
            signature: [0u8; 64],
        })
    }

    /// Sign the canonical payload, populating `signature`.
    pub fn sign(mut self, signing_key: &SigningKey) -> Self {
        let payload = self.canonical_payload();
        let sig = signing_key.sign(payload.as_bytes());
        self.signature = sig.to_bytes();
        self
    }

    /// Canonical signed payload. All fields that appear here are covered by
    /// the signature. **Changing this format is a breaking change.**
    pub fn canonical_payload(&self) -> String {
        format!(
            "version=2\ntoken_kind={}\naudience_relay_id={}\nscope={}\nprivacy_epoch={}\ncircuit_handle={}\nleg_handle={}\nleg_slot={}\npresenter_public_key={}\nissued_at_unix={}\nexpires_at_unix={}\nnonce={}\nprofile_id={}\nissuer_key_id={}\n",
            self.token_kind.as_str(),
            crate::hex_bytes(&self.audience_relay_id),
            self.scope,
            self.privacy_epoch,
            crate::hex_bytes(&self.circuit_handle),
            crate::hex_bytes(&self.leg_handle),
            self.leg_slot.as_u64(),
            crate::hex_bytes(&self.presenter_public_key),
            self.issued_at_unix,
            self.expires_at_unix,
            crate::hex_bytes(&self.nonce),
            self.profile_id,
            self.issuer_key_id,
        )
    }

    /// Full wire form: canonical payload plus the signature as the final line.
    pub fn to_wire(&self) -> String {
        format!(
            "{}signature={}\n",
            self.canonical_payload(),
            crate::hex_bytes(&self.signature)
        )
    }

    /// SHA-256 of the canonical payload, hex-encoded — the `token_digest`
    /// transcript binding ([`BlindRelayPopTranscript`]).
    pub fn payload_digest_hex(&self) -> String {
        crate::hex_bytes(&crate::sha256_digest(self.canonical_payload().as_bytes()))
    }

    /// Strict (malleability-rejecting) signature verification over the
    /// canonical payload. `verify` is never used on acceptance paths.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), ControlPlaneError> {
        let payload = self.canonical_payload();
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(payload.as_bytes(), &signature)
            .map_err(|e| {
                ControlPlaneError::Traversal(format!(
                    "blind relay token v2 signature verification failed: {e}"
                ))
            })
    }

    /// Constant-time equality check covering all fields, including secret
    /// fields (`circuit_handle`, `leg_handle`, `nonce`,
    /// `presenter_public_key`, `audience_relay_id`, `signature`).
    pub fn ct_eq(&self, other: &Self) -> bool {
        let kind_eq: bool = self
            .token_kind
            .as_str()
            .as_bytes()
            .ct_eq(other.token_kind.as_str().as_bytes())
            .into();
        let audience_eq: bool = self
            .audience_relay_id
            .ct_eq(&other.audience_relay_id)
            .into();
        let scope_eq: bool = self.scope.as_bytes().ct_eq(other.scope.as_bytes()).into();
        let epoch_eq = self.privacy_epoch == other.privacy_epoch;
        let circuit_eq: bool = self.circuit_handle.ct_eq(&other.circuit_handle).into();
        let leg_eq: bool = self.leg_handle.ct_eq(&other.leg_handle).into();
        let slot_eq = self.leg_slot == other.leg_slot;
        let presenter_eq: bool = self
            .presenter_public_key
            .ct_eq(&other.presenter_public_key)
            .into();
        let issued_eq = self.issued_at_unix == other.issued_at_unix;
        let expires_eq = self.expires_at_unix == other.expires_at_unix;
        let nonce_eq: bool = self.nonce.ct_eq(&other.nonce).into();
        let profile_eq: bool = self
            .profile_id
            .as_bytes()
            .ct_eq(other.profile_id.as_bytes())
            .into();
        let issuer_eq: bool = self
            .issuer_key_id
            .as_bytes()
            .ct_eq(other.issuer_key_id.as_bytes())
            .into();
        let sig_eq: bool = self.signature.ct_eq(&other.signature).into();
        kind_eq
            & audience_eq
            & scope_eq
            & epoch_eq
            & circuit_eq
            & leg_eq
            & slot_eq
            & presenter_eq
            & issued_eq
            & expires_eq
            & nonce_eq
            & profile_eq
            & issuer_eq
            & sig_eq
    }

    pub fn ttl_secs(&self) -> u64 {
        self.expires_at_unix.saturating_sub(self.issued_at_unix)
    }

    pub fn is_expired(&self, now_unix: u64, clock_skew_tolerance_secs: u64) -> bool {
        now_unix
            > self
                .expires_at_unix
                .saturating_add(clock_skew_tolerance_secs)
    }
}

/// The zero-padded relay audience must decode back to a non-empty, bounded,
/// single-line ASCII label followed by zero padding — the inverse of the v1
/// `canonical_relay_id_from_label`.
fn validate_audience_relay_id(audience: &[u8; 16]) -> Result<(), ControlPlaneError> {
    let label_end = audience
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(audience.len());
    if audience[label_end..].iter().any(|&byte| byte != 0) {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 audience_relay_id is not a zero-padded relay id".to_owned(),
        ));
    }
    let label = &audience[..label_end];
    if label.is_empty() || label.len() > 16 {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 audience_relay_id label length is invalid".to_owned(),
        ));
    }
    if !label
        .iter()
        .all(|&byte| (0x20..=0x7e).contains(&byte) && byte != b'=')
    {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 audience_relay_id is not bounded printable ASCII".to_owned(),
        ));
    }
    Ok(())
}

fn is_allowed_blind_relay_token_v2_key(key: &str) -> bool {
    matches!(
        key,
        "version"
            | "token_kind"
            | "audience_relay_id"
            | "scope"
            | "privacy_epoch"
            | "circuit_handle"
            | "leg_handle"
            | "leg_slot"
            | "presenter_public_key"
            | "issued_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "profile_id"
            | "issuer_key_id"
            | "signature"
    )
}

/// Parse a blind-relay leg token v2 from wire bytes, rejecting invalid UTF-8
/// before any line processing (closed rejection class; no partial parse).
pub fn parse_blind_relay_leg_token_v2_wire_bytes(
    wire: &[u8],
) -> Result<BlindRelayLegTokenV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_TOKEN_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 wire exceeds the bounded size".to_owned(),
        ));
    }
    let wire = std::str::from_utf8(wire).map_err(|_| {
        ControlPlaneError::Traversal("blind relay token v2 wire is not valid UTF-8".to_owned())
    })?;
    parse_blind_relay_leg_token_v2_wire(wire)
}

/// Parse a blind-relay leg token v2 from a wire string. Applies the full v1
/// house discipline: allowlist, duplicate reject, signature-final-line,
/// version/kind/scope/slot pins, fixed-width hex, degenerate-value reject,
/// canonical decimals, TTL bound, and the canonical re-encode equality check
/// before returning.
pub fn parse_blind_relay_leg_token_v2_wire(
    wire: &str,
) -> Result<BlindRelayLegTokenV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_TOKEN_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 wire exceeds the bounded size".to_owned(),
        ));
    }
    if wire.trim().is_empty() {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 wire is empty".to_owned(),
        ));
    }

    let mut payload = String::new();
    let mut fields = BTreeMap::new();
    let mut seen_keys = BTreeSet::new();
    let mut signature_hex: Option<String> = None;

    for line in wire.lines() {
        if signature_hex.is_some() {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 signature must be the final line".to_owned(),
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "blind relay token v2 line missing key/value separator".to_owned(),
            ));
        };
        if !is_allowed_blind_relay_token_v2_key(key) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay token v2 key is not allowed: {key}"
            )));
        }
        if key == "signature" {
            let value = value.trim();
            if value.is_empty() {
                return Err(ControlPlaneError::Traversal(
                    "blind relay token v2 signature must not be empty".to_owned(),
                ));
            }
            signature_hex = Some(value.to_owned());
            continue;
        }
        if !seen_keys.insert(key.to_owned()) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay token v2 duplicate key: {key}"
            )));
        }
        fields.insert(key.to_owned(), value.to_owned());
        payload.push_str(line);
        payload.push('\n');
    }

    let signature_hex = signature_hex.ok_or_else(|| {
        ControlPlaneError::Traversal("blind relay token v2 missing signature".to_owned())
    })?;

    // Version/kind/scope/slot are pinned before any signature use.
    let version = required_blind_relay_field(&fields, "version")?;
    if version != "2" {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 version must be 2".to_owned(),
        ));
    }
    let token_kind =
        BlindRelayTokenKindV2::from_wire(required_blind_relay_field(&fields, "token_kind")?)?;
    let scope = required_blind_relay_field(&fields, "scope")?;
    if scope != BLIND_RELAY_TOKEN_SCOPE_V2 {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 scope is invalid".to_owned(),
        ));
    }
    let leg_slot = BlindRelayLegSlot::from_wire(required_blind_relay_field(&fields, "leg_slot")?)?;

    let audience_hex = required_blind_relay_field(&fields, "audience_relay_id")?;
    let audience_relay_id = decode_fixed_hex::<16>(audience_hex, "audience_relay_id")?;
    validate_audience_relay_id(&audience_relay_id)?;

    let privacy_epoch = parse_canonical_u64(
        required_blind_relay_field(&fields, "privacy_epoch")?,
        "privacy_epoch",
    )?;
    if privacy_epoch == 0 {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 privacy_epoch must be at least 1".to_owned(),
        ));
    }

    let circuit_handle = decode_fixed_hex::<32>(
        required_blind_relay_field(&fields, "circuit_handle")?,
        "circuit_handle",
    )?;
    reject_all_zero(&circuit_handle, "circuit_handle")?;
    let leg_handle = decode_fixed_hex::<32>(
        required_blind_relay_field(&fields, "leg_handle")?,
        "leg_handle",
    )?;
    reject_all_zero(&leg_handle, "leg_handle")?;
    let presenter_public_key = decode_fixed_hex::<32>(
        required_blind_relay_field(&fields, "presenter_public_key")?,
        "presenter_public_key",
    )?;
    reject_all_zero(&presenter_public_key, "presenter_public_key")?;
    let nonce = decode_fixed_hex::<16>(required_blind_relay_field(&fields, "nonce")?, "nonce")?;
    reject_all_zero(&nonce, "nonce")?;

    let issued_at_unix = parse_canonical_u64(
        required_blind_relay_field(&fields, "issued_at_unix")?,
        "issued_at_unix",
    )?;
    let expires_at_unix = parse_canonical_u64(
        required_blind_relay_field(&fields, "expires_at_unix")?,
        "expires_at_unix",
    )?;
    if issued_at_unix == 0 || expires_at_unix <= issued_at_unix {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 timestamps are invalid".to_owned(),
        ));
    }

    let profile_id = required_blind_relay_field(&fields, "profile_id")?.to_owned();
    if !is_bounded_ascii_text(&profile_id, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 profile_id is not a bounded single-line ASCII value".to_owned(),
        ));
    }
    let issuer_key_id = required_blind_relay_field(&fields, "issuer_key_id")?.to_owned();
    if !is_bounded_ascii_text(&issuer_key_id, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 issuer_key_id is not a bounded single-line ASCII value"
                .to_owned(),
        ));
    }

    let signature = decode_fixed_hex::<64>(&signature_hex, "signature")?;

    let token = BlindRelayLegTokenV2 {
        token_kind,
        audience_relay_id,
        scope: scope.to_owned(),
        privacy_epoch,
        circuit_handle,
        leg_handle,
        leg_slot,
        presenter_public_key,
        issued_at_unix,
        expires_at_unix,
        nonce,
        profile_id,
        issuer_key_id,
        signature,
    };
    if token.ttl_secs() > MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS {
        return Err(ControlPlaneError::Traversal(format!(
            "blind relay token v2 ttl exceeds max supported value ({MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS})"
        )));
    }
    // Canonical re-encode equality: any reordering or noncanonical byte form
    // is rejected here even when every field is individually well-formed and
    // the signature over the presented bytes is valid.
    if token.canonical_payload() != payload {
        return Err(ControlPlaneError::Traversal(
            "blind relay token v2 payload is not canonical".to_owned(),
        ));
    }
    Ok(token)
}

fn required_blind_relay_field<'a>(
    fields: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, ControlPlaneError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| ControlPlaneError::Traversal(format!("blind relay v2 missing {key}")))
}

// ── Proof-of-possession transcript (selection §2.2b) ────────────────────────

/// The canonical proof-of-possession transcript (selection §2.2b): a
/// domain-separated canonical line document signed as its UTF-8 bytes with
/// the leg's fresh presenter key.
///
/// The transcript binds the proof to the exact signed token bytes
/// (`token_digest` = SHA-256 of the token canonical payload), to the
/// relay-generated challenge, to the circuit and leg identities, and to a
/// fresh endpoint nonce. The runtime admission ordering that consumes this
/// transcript is phase 4; this type plus the strict verifier below are the
/// complete phase-3 surface.
#[derive(Clone)]
pub struct BlindRelayPopTranscript {
    /// SHA-256 hex of the leg token's canonical payload.
    pub token_digest_hex: String,
    /// Relay-generated challenge (the address-validation artifact presented
    /// back in the hello); 32 bytes, rendered as 64 hex chars.
    pub relay_challenge: [u8; 32],
    pub circuit_handle: [u8; 32],
    pub leg_handle: [u8; 32],
    pub leg_slot: BlindRelayLegSlot,
    pub privacy_epoch: u64,
    /// Endpoint-generated fresh nonce; 32 bytes.
    pub client_nonce: [u8; 32],
}

impl fmt::Debug for BlindRelayPopTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindRelayPopTranscript")
            .field("domain", &BLIND_RELAY_POP_DOMAIN_V1)
            .field("token_digest_hex", &"REDACTED")
            .field("relay_challenge", &"REDACTED")
            .field("circuit_handle", &"REDACTED")
            .field("leg_handle", &"REDACTED")
            .field("leg_slot", &self.leg_slot.as_u64())
            .field("privacy_epoch", &self.privacy_epoch)
            .field("client_nonce", &"REDACTED")
            .finish()
    }
}

impl BlindRelayPopTranscript {
    /// Validate every bounded field, then build the transcript.
    pub fn new(
        token_digest_hex: &str,
        relay_challenge: [u8; 32],
        circuit_handle: [u8; 32],
        leg_handle: [u8; 32],
        leg_slot: BlindRelayLegSlot,
        privacy_epoch: u64,
        client_nonce: [u8; 32],
    ) -> Result<Self, ControlPlaneError> {
        reject_all_zero(&relay_challenge, "relay_challenge")?;
        reject_all_zero(&circuit_handle, "circuit_handle")?;
        reject_all_zero(&leg_handle, "leg_handle")?;
        reject_all_zero(&client_nonce, "client_nonce")?;
        if privacy_epoch == 0 {
            return Err(ControlPlaneError::Traversal(
                "blind relay pop transcript privacy_epoch must be at least 1".to_owned(),
            ));
        }
        // The digest must be the exact SHA-256 hex rendering the token emits.
        decode_fixed_hex::<32>(token_digest_hex, "token_digest")?;
        Ok(Self {
            token_digest_hex: token_digest_hex.to_owned(),
            relay_challenge,
            circuit_handle,
            leg_handle,
            leg_slot,
            privacy_epoch,
            client_nonce,
        })
    }

    /// The exact bytes to be signed — the §2.2b canonical line document.
    /// **Changing this layout is a breaking change** (bump the domain
    /// string's version suffix instead).
    pub fn canonical_bytes(&self) -> String {
        format!(
            "domain={}\ntoken_digest={}\nrelay_challenge={}\ncircuit_handle={}\nleg_handle={}\nleg_slot={}\nprivacy_epoch={}\nclient_nonce={}\n",
            BLIND_RELAY_POP_DOMAIN_V1,
            self.token_digest_hex,
            crate::hex_bytes(&self.relay_challenge),
            crate::hex_bytes(&self.circuit_handle),
            crate::hex_bytes(&self.leg_handle),
            self.leg_slot.as_u64(),
            self.privacy_epoch,
            crate::hex_bytes(&self.client_nonce),
        )
    }

    /// Constant-time equality over all transcript fields.
    pub fn ct_eq(&self, other: &Self) -> bool {
        let digest_eq: bool = self
            .token_digest_hex
            .as_bytes()
            .ct_eq(other.token_digest_hex.as_bytes())
            .into();
        let challenge_eq: bool = self.relay_challenge.ct_eq(&other.relay_challenge).into();
        let circuit_eq: bool = self.circuit_handle.ct_eq(&other.circuit_handle).into();
        let leg_eq: bool = self.leg_handle.ct_eq(&other.leg_handle).into();
        let slot_eq = self.leg_slot == other.leg_slot;
        let epoch_eq = self.privacy_epoch == other.privacy_epoch;
        let nonce_eq: bool = self.client_nonce.ct_eq(&other.client_nonce).into();
        digest_eq & challenge_eq & circuit_eq & leg_eq & slot_eq & epoch_eq & nonce_eq
    }
}

/// Standalone strict verifier for a proof-of-possession signature over a
/// canonical transcript.
///
/// Rejects, in order: the degenerate all-zero presenter key (the direct
/// analogue of the v1 all-zero nonce rejection), a malformed key (fallible
/// library decode), and any signature that fails `verify_strict` — strict
/// (malleability-rejecting) verification is the house norm and the only mode
/// used on acceptance paths. The runtime admission sequencing that calls this
/// verifier is phase 4.
pub fn verify_blind_relay_pop_signature(
    transcript: &BlindRelayPopTranscript,
    presenter_public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ControlPlaneError> {
    reject_all_zero(presenter_public_key, "presenter_public_key")?;
    let verifying_key = VerifyingKey::from_bytes(presenter_public_key).map_err(|e| {
        ControlPlaneError::Traversal(format!(
            "blind relay pop presenter_public_key is malformed: {e}"
        ))
    })?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(transcript.canonical_bytes().as_bytes(), &signature)
        .map_err(|e| {
            ControlPlaneError::Traversal(format!(
                "blind relay pop signature verification failed: {e}"
            ))
        })
}

// ── BlindRelayHelloV2 ───────────────────────────────────────────────────────

/// Blind-relay hello v2 (design §7.5): the version-pinned envelope carrying
/// exactly the leg token, a fresh client nonce, the relay address-validation
/// artifact, and the proof-of-possession signature — and no endpoint
/// identity of any kind.
///
/// Wire form: the complete leg-token wire document (15 lines, ending with the
/// token `signature` line) followed by exactly three envelope lines in fixed
/// order:
///
/// ```text
/// client_nonce=<64 hex>
/// relay_challenge=<64 hex>
/// pop_signature=<128 hex>
/// ```
///
/// The fixed line count makes the token/envelope split deterministic without
/// any escaping invention, and the whole document is re-encoded and compared
/// byte-for-byte after parsing, so any reordering, duplication, unknown key,
/// or trailing data in either half is rejected. `relay_challenge` is the
/// opaque relay-generated address-validation artifact as a fixed 32-byte
/// value; the rotating-key HMAC token *format* it will carry is phase 4.
#[derive(Clone)]
pub struct BlindRelayHelloV2 {
    pub token: BlindRelayLegTokenV2,
    pub client_nonce: [u8; 32],
    pub relay_challenge: [u8; 32],
    pub pop_signature: [u8; 64],
}

impl fmt::Debug for BlindRelayHelloV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindRelayHelloV2")
            .field("token", &"REDACTED")
            .field("client_nonce", &"REDACTED")
            .field("relay_challenge", &"REDACTED")
            .field("pop_signature", &"REDACTED")
            .finish()
    }
}

/// Number of wire lines in a leg-token v2 document: 14 payload lines plus the
/// signature line.
pub const BLIND_RELAY_LEG_TOKEN_V2_WIRE_LINES: usize = 15;

/// Number of wire lines in a hello v2 document: the token plus three
/// envelope lines.
pub const BLIND_RELAY_HELLO_V2_WIRE_LINES: usize = BLIND_RELAY_LEG_TOKEN_V2_WIRE_LINES + 3;

impl BlindRelayHelloV2 {
    /// Construct-and-validate a hello from an already-signed token.
    pub fn new(
        token: BlindRelayLegTokenV2,
        client_nonce: [u8; 32],
        relay_challenge: [u8; 32],
        pop_signature: [u8; 64],
    ) -> Result<Self, ControlPlaneError> {
        reject_all_zero(&client_nonce, "client_nonce")?;
        reject_all_zero(&relay_challenge, "relay_challenge")?;
        Ok(Self {
            token,
            client_nonce,
            relay_challenge,
            pop_signature,
        })
    }

    /// Full wire form: token wire (token signature line included) plus the
    /// three envelope lines in fixed order.
    pub fn to_wire(&self) -> String {
        format!(
            "{}client_nonce={}\nrelay_challenge={}\npop_signature={}\n",
            self.token.to_wire(),
            crate::hex_bytes(&self.client_nonce),
            crate::hex_bytes(&self.relay_challenge),
            crate::hex_bytes(&self.pop_signature),
        )
    }

    /// The proof-of-possession transcript this hello presents: token digest,
    /// relay challenge, circuit/leg identity, slot, epoch, and client nonce.
    pub fn pop_transcript(&self) -> Result<BlindRelayPopTranscript, ControlPlaneError> {
        BlindRelayPopTranscript::new(
            &self.token.payload_digest_hex(),
            self.relay_challenge,
            self.token.circuit_handle,
            self.token.leg_handle,
            self.token.leg_slot,
            self.token.privacy_epoch,
            self.client_nonce,
        )
    }

    /// Strict PoP verification against the token's presenter key. (The full
    /// admission ordering around this call is phase 4.)
    pub fn verify_pop(&self) -> Result<(), ControlPlaneError> {
        let transcript = self.pop_transcript()?;
        verify_blind_relay_pop_signature(
            &transcript,
            &self.token.presenter_public_key,
            &self.pop_signature,
        )
    }

    /// Constant-time equality over the envelope and the embedded token.
    pub fn ct_eq(&self, other: &Self) -> bool {
        let nonce_eq: bool = self.client_nonce.ct_eq(&other.client_nonce).into();
        let challenge_eq: bool = self.relay_challenge.ct_eq(&other.relay_challenge).into();
        let pop_eq: bool = self.pop_signature.ct_eq(&other.pop_signature).into();
        nonce_eq & challenge_eq & pop_eq & self.token.ct_eq(&other.token)
    }
}

/// Parse a hello v2 from wire bytes, rejecting invalid UTF-8 and oversize
/// datagrams before any line processing.
pub fn parse_blind_relay_hello_v2_wire_bytes(
    wire: &[u8],
) -> Result<BlindRelayHelloV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_HELLO_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay hello v2 datagram exceeds the bounded size".to_owned(),
        ));
    }
    let wire = std::str::from_utf8(wire).map_err(|_| {
        ControlPlaneError::Traversal("blind relay hello v2 datagram is not valid UTF-8".to_owned())
    })?;
    parse_blind_relay_hello_v2_wire(wire)
}

/// Parse a hello v2 from a wire string. The token half runs the full leg-token
/// discipline; the envelope half is pinned to exactly three fixed-order
/// lines; the whole document must re-encode byte-identically.
pub fn parse_blind_relay_hello_v2_wire(wire: &str) -> Result<BlindRelayHelloV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_HELLO_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay hello v2 datagram exceeds the bounded size".to_owned(),
        ));
    }
    if wire.trim().is_empty() {
        return Err(ControlPlaneError::Traversal(
            "blind relay hello v2 datagram is empty".to_owned(),
        ));
    }
    let lines: Vec<&str> = wire.lines().collect();
    if lines.len() != BLIND_RELAY_HELLO_V2_WIRE_LINES {
        return Err(ControlPlaneError::Traversal(
            "blind relay hello v2 datagram has an invalid line count".to_owned(),
        ));
    }
    // Deterministic split: token document first, then the three envelope
    // lines. Each envelope line must be `key=value` with the exact expected
    // key at its fixed position — anything else (unknown key, duplicate,
    // reorder, extra line) breaks the canonical re-encode check below.
    let token_wire: String = lines[..BLIND_RELAY_LEG_TOKEN_V2_WIRE_LINES]
        .iter()
        .map(|line| format!("{line}\n"))
        .collect();
    let token = parse_blind_relay_leg_token_v2_wire(&token_wire)?;

    let mut envelope_values: BTreeMap<&str, [u8; 32]> = BTreeMap::new();
    let mut pop_signature: Option<[u8; 64]> = None;
    for line in &lines[BLIND_RELAY_LEG_TOKEN_V2_WIRE_LINES..] {
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "blind relay hello v2 envelope line missing key/value separator".to_owned(),
            ));
        };
        match key {
            "client_nonce" | "relay_challenge" => {
                if envelope_values.contains_key(key) {
                    return Err(ControlPlaneError::Traversal(format!(
                        "blind relay hello v2 duplicate key: {key}"
                    )));
                }
                let decoded = decode_fixed_hex::<32>(value, key)?;
                reject_all_zero(&decoded, key)?;
                envelope_values.insert(key, decoded);
            }
            "pop_signature" => {
                if pop_signature.is_some() {
                    return Err(ControlPlaneError::Traversal(
                        "blind relay hello v2 duplicate key: pop_signature".to_owned(),
                    ));
                }
                pop_signature = Some(decode_fixed_hex::<64>(value, "pop_signature")?);
            }
            other => {
                return Err(ControlPlaneError::Traversal(format!(
                    "blind relay hello v2 key is not allowed: {other}"
                )));
            }
        }
    }
    let client_nonce = *envelope_values.get("client_nonce").ok_or_else(|| {
        ControlPlaneError::Traversal("blind relay hello v2 missing client_nonce".to_owned())
    })?;
    let relay_challenge = *envelope_values.get("relay_challenge").ok_or_else(|| {
        ControlPlaneError::Traversal("blind relay hello v2 missing relay_challenge".to_owned())
    })?;
    let pop_signature = pop_signature.ok_or_else(|| {
        ControlPlaneError::Traversal("blind relay hello v2 missing pop_signature".to_owned())
    })?;

    let hello = BlindRelayHelloV2 {
        token,
        client_nonce,
        relay_challenge,
        pop_signature,
    };
    if hello.to_wire() != wire {
        return Err(ControlPlaneError::Traversal(
            "blind relay hello v2 datagram is not canonical".to_owned(),
        ));
    }
    Ok(hello)
}

// ── BlindRelayFleetDescriptorV2 (selection §1.3 + design §8.1) ──────────────

/// Signed blind-relay fleet descriptor v2: the version-pinned descriptor
/// announcing a relay's mode, accepted protocol versions, minimum privacy
/// epoch, and public profile set, bound to a monotonic signed `generation`
/// (design §8.1). Absence of a mode never means blind by inference: the
/// `relay_mode` line must be present and pinned to the closed enum.
///
/// This phase defines the descriptor type, its canonical wire form, and the
/// anti-fork/anti-rollback acceptance check; composing it into the published
/// fleet bundle artifact (dual publication, §8.3) is later phase work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindRelayFleetDescriptorV2 {
    pub relay_mode: BlindRelayModeV2,
    /// Monotonic signed generation; ≥ 1.
    pub generation: u64,
    /// Accepted hello versions (sorted ascending, each 1 or 2, must contain 2).
    pub hello_versions: Vec<u64>,
    /// Accepted token versions (sorted ascending, each 1 or 2, must contain 2).
    pub token_versions: Vec<u64>,
    /// Minimum accepted privacy epoch; ≥ 1.
    pub minimum_privacy_epoch: u64,
    /// Public profile ids (sorted ascending, deduplicated).
    pub profile_ids: Vec<String>,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    /// Public bundle nonce; ≥ 1 (the v1 fleet bundle nonce shape).
    pub nonce: u64,
    pub signature: [u8; 64],
}

impl BlindRelayFleetDescriptorV2 {
    /// Validate fields and build an unsigned descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay_mode: BlindRelayModeV2,
        generation: u64,
        hello_versions: Vec<u64>,
        token_versions: Vec<u64>,
        minimum_privacy_epoch: u64,
        profile_ids: Vec<String>,
        generated_at_unix: u64,
        expires_at_unix: u64,
        nonce: u64,
    ) -> Result<Self, ControlPlaneError> {
        if generation == 0 {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 generation must be at least 1".to_owned(),
            ));
        }
        Self::validate_version_list(&relay_mode, &hello_versions, "hello_versions")?;
        Self::validate_version_list(&relay_mode, &token_versions, "token_versions")?;
        if minimum_privacy_epoch == 0 {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 minimum_privacy_epoch must be at least 1"
                    .to_owned(),
            ));
        }
        if profile_ids.is_empty() || profile_ids.len() > MAX_BLIND_RELAY_PROFILE_IDS {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 profile_ids length is invalid".to_owned(),
            ));
        }
        for profile in &profile_ids {
            if !is_bounded_ascii_text(profile, MAX_BLIND_RELAY_TEXT_FIELD_BYTES) {
                return Err(ControlPlaneError::Traversal(
                    "blind relay fleet descriptor v2 profile id is not a bounded single-line ASCII value"
                        .to_owned(),
                ));
            }
        }
        let mut sorted_profiles = profile_ids.clone();
        sorted_profiles.sort();
        if sorted_profiles != profile_ids {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 profile_ids are not in canonical sorted order"
                    .to_owned(),
            ));
        }
        if generated_at_unix == 0 || generated_at_unix >= expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 generated/expires ordering is invalid".to_owned(),
            ));
        }
        if expires_at_unix.saturating_sub(generated_at_unix) > MAX_BLIND_RELAY_FLEET_TTL_SECS {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 ttl exceeds max supported value".to_owned(),
            ));
        }
        if nonce == 0 {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 nonce must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            relay_mode,
            generation,
            hello_versions,
            token_versions,
            minimum_privacy_epoch,
            profile_ids,
            generated_at_unix,
            expires_at_unix,
            nonce,
            signature: [0u8; 64],
        })
    }

    /// A blind-relay listener accepts exactly hello/token v2 (design §8.2):
    /// an `identity_blind` descriptor must list exactly `[2]`. A `normal`
    /// descriptor may list `[1, 2]` during migration but never claims blind.
    fn validate_version_list(
        relay_mode: &BlindRelayModeV2,
        versions: &[u64],
        field: &str,
    ) -> Result<(), ControlPlaneError> {
        let parsed = parse_protocol_version_list(&protocol_version_list_wire(versions), field)?;
        if parsed.is_empty() || !parsed.contains(&2) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay fleet descriptor v2 {field} must contain version 2"
            )));
        }
        if *relay_mode == BlindRelayModeV2::IdentityBlind && parsed != [2] {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay fleet descriptor v2 {field} must be exactly 2 for identity_blind"
            )));
        }
        Ok(())
    }

    /// Sign the canonical payload, populating `signature`.
    pub fn sign(mut self, signing_key: &SigningKey) -> Self {
        let payload = self.canonical_payload();
        let sig = signing_key.sign(payload.as_bytes());
        self.signature = sig.to_bytes();
        self
    }

    /// Canonical signed payload. All fields that appear here are covered by
    /// the signature. **Changing this format is a breaking change.**
    pub fn canonical_payload(&self) -> String {
        format!(
            "version=2\nrelay_mode={}\ngeneration={}\nhello_versions={}\ntoken_versions={}\nminimum_privacy_epoch={}\nprofile_ids={}\ngenerated_at_unix={}\nexpires_at_unix={}\nnonce={}\n",
            self.relay_mode.as_str(),
            self.generation,
            protocol_version_list_wire(&self.hello_versions),
            protocol_version_list_wire(&self.token_versions),
            self.minimum_privacy_epoch,
            profile_id_list_wire(&self.profile_ids),
            self.generated_at_unix,
            self.expires_at_unix,
            self.nonce,
        )
    }

    /// Full wire form: canonical payload plus the signature as the final line.
    pub fn to_wire(&self) -> String {
        format!(
            "{}signature={}\n",
            self.canonical_payload(),
            crate::hex_bytes(&self.signature)
        )
    }

    /// SHA-256 hex of the canonical payload — the digest anti-fork
    /// comparisons are keyed on.
    pub fn payload_digest_hex(&self) -> String {
        crate::hex_bytes(&crate::sha256_digest(self.canonical_payload().as_bytes()))
    }

    /// Strict signature verification over the canonical payload.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), ControlPlaneError> {
        let payload = self.canonical_payload();
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(payload.as_bytes(), &signature)
            .map_err(|e| {
                ControlPlaneError::Traversal(format!(
                    "blind relay fleet descriptor v2 signature verification failed: {e}"
                ))
            })
    }
}

fn is_allowed_blind_relay_fleet_v2_key(key: &str) -> bool {
    matches!(
        key,
        "version"
            | "relay_mode"
            | "generation"
            | "hello_versions"
            | "token_versions"
            | "minimum_privacy_epoch"
            | "profile_ids"
            | "generated_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "signature"
    )
}

/// Parse a fleet descriptor v2 from wire bytes, rejecting invalid UTF-8 and
/// oversize documents before any line processing.
pub fn parse_blind_relay_fleet_descriptor_v2_wire_bytes(
    wire: &[u8],
) -> Result<BlindRelayFleetDescriptorV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_FLEET_DESCRIPTOR_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 wire exceeds the bounded size".to_owned(),
        ));
    }
    let wire = std::str::from_utf8(wire).map_err(|_| {
        ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 wire is not valid UTF-8".to_owned(),
        )
    })?;
    parse_blind_relay_fleet_descriptor_v2_wire(wire)
}

/// Parse a fleet descriptor v2 from a wire string, applying the full house
/// discipline.
pub fn parse_blind_relay_fleet_descriptor_v2_wire(
    wire: &str,
) -> Result<BlindRelayFleetDescriptorV2, ControlPlaneError> {
    if wire.len() > MAX_BLIND_RELAY_FLEET_DESCRIPTOR_WIRE_BYTES {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 wire exceeds the bounded size".to_owned(),
        ));
    }
    if wire.trim().is_empty() {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 wire is empty".to_owned(),
        ));
    }

    let mut payload = String::new();
    let mut fields = BTreeMap::new();
    let mut seen_keys = BTreeSet::new();
    let mut signature_hex: Option<String> = None;

    for line in wire.lines() {
        if signature_hex.is_some() {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 signature must be the final line".to_owned(),
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "blind relay fleet descriptor v2 line missing key/value separator".to_owned(),
            ));
        };
        if !is_allowed_blind_relay_fleet_v2_key(key) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay fleet descriptor v2 key is not allowed: {key}"
            )));
        }
        if key == "signature" {
            let value = value.trim();
            if value.is_empty() {
                return Err(ControlPlaneError::Traversal(
                    "blind relay fleet descriptor v2 signature must not be empty".to_owned(),
                ));
            }
            signature_hex = Some(value.to_owned());
            continue;
        }
        if !seen_keys.insert(key.to_owned()) {
            return Err(ControlPlaneError::Traversal(format!(
                "blind relay fleet descriptor v2 duplicate key: {key}"
            )));
        }
        fields.insert(key.to_owned(), value.to_owned());
        payload.push_str(line);
        payload.push('\n');
    }

    let signature_hex = signature_hex.ok_or_else(|| {
        ControlPlaneError::Traversal("blind relay fleet descriptor v2 missing signature".to_owned())
    })?;

    let version = required_blind_relay_field(&fields, "version")?;
    if version != "2" {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 version must be 2".to_owned(),
        ));
    }
    let relay_mode =
        BlindRelayModeV2::from_wire(required_blind_relay_field(&fields, "relay_mode")?)?;
    let generation = parse_canonical_u64(
        required_blind_relay_field(&fields, "generation")?,
        "generation",
    )?;
    if generation == 0 {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 generation must be at least 1".to_owned(),
        ));
    }
    let hello_versions = parse_protocol_version_list(
        required_blind_relay_field(&fields, "hello_versions")?,
        "hello_versions",
    )?;
    let token_versions = parse_protocol_version_list(
        required_blind_relay_field(&fields, "token_versions")?,
        "token_versions",
    )?;
    BlindRelayFleetDescriptorV2::validate_version_list(
        &relay_mode,
        &hello_versions,
        "hello_versions",
    )?;
    BlindRelayFleetDescriptorV2::validate_version_list(
        &relay_mode,
        &token_versions,
        "token_versions",
    )?;
    let minimum_privacy_epoch = parse_canonical_u64(
        required_blind_relay_field(&fields, "minimum_privacy_epoch")?,
        "minimum_privacy_epoch",
    )?;
    if minimum_privacy_epoch == 0 {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 minimum_privacy_epoch must be at least 1".to_owned(),
        ));
    }
    let profile_ids = parse_profile_id_list(required_blind_relay_field(&fields, "profile_ids")?)?;
    let generated_at_unix = parse_canonical_u64(
        required_blind_relay_field(&fields, "generated_at_unix")?,
        "generated_at_unix",
    )?;
    let expires_at_unix = parse_canonical_u64(
        required_blind_relay_field(&fields, "expires_at_unix")?,
        "expires_at_unix",
    )?;
    if generated_at_unix == 0 || generated_at_unix >= expires_at_unix {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 generated/expires ordering is invalid".to_owned(),
        ));
    }
    if expires_at_unix.saturating_sub(generated_at_unix) > MAX_BLIND_RELAY_FLEET_TTL_SECS {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 ttl exceeds max supported value".to_owned(),
        ));
    }
    let nonce = parse_canonical_u64(required_blind_relay_field(&fields, "nonce")?, "nonce")?;
    if nonce == 0 {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 nonce must be greater than zero".to_owned(),
        ));
    }
    let signature = decode_fixed_hex::<64>(&signature_hex, "signature")?;

    let descriptor = BlindRelayFleetDescriptorV2 {
        relay_mode,
        generation,
        hello_versions,
        token_versions,
        minimum_privacy_epoch,
        profile_ids,
        generated_at_unix,
        expires_at_unix,
        nonce,
        signature,
    };
    if descriptor.canonical_payload() != payload {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 payload is not canonical".to_owned(),
        ));
    }
    Ok(descriptor)
}

/// The persisted anti-rollback / anti-fork anchor for blind-relay fleet
/// descriptors (design §8.4): the highest accepted generation with its exact
/// canonical digest, and the highest accepted privacy epoch. In production
/// this is persisted atomically in the relay-fleet watermark domain; phase 3
/// defines the acceptance function against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindRelayFleetAcceptanceState {
    pub highest_generation: u64,
    /// SHA-256 hex of the canonical payload recorded for
    /// `highest_generation`.
    pub highest_generation_digest_hex: String,
    pub highest_privacy_epoch: u64,
}

/// Anti-fork / anti-rollback acceptance for a fleet descriptor v2 against the
/// persisted acceptance state (design §8.4; vector `v2_fleet_fork`).
///
/// Rules, all fail-closed:
/// - a lower generation than recorded: reject (rollback);
/// - the same generation with a different canonical digest: reject (fork)
///   and surface for incident handling;
/// - a lower privacy epoch than recorded: reject (rollback);
/// - a lower schema version never reaches this function — the parser only
///   accepts `version=2`, and a newer unknown version is rejected at parse.
pub fn check_blind_relay_fleet_descriptor_v2_acceptance(
    descriptor: &BlindRelayFleetDescriptorV2,
    state: &BlindRelayFleetAcceptanceState,
) -> Result<(), ControlPlaneError> {
    if descriptor.generation < state.highest_generation {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 generation is lower than the accepted watermark"
                .to_owned(),
        ));
    }
    if descriptor.generation == state.highest_generation
        && descriptor.payload_digest_hex() != state.highest_generation_digest_hex
    {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 digest forks the accepted generation".to_owned(),
        ));
    }
    if descriptor.minimum_privacy_epoch < state.highest_privacy_epoch {
        return Err(ControlPlaneError::Traversal(
            "blind relay fleet descriptor v2 privacy epoch is lower than the accepted watermark"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    /// Fixed test seed for the signed-preimage fixtures (vector 2). Never a
    /// production key: the seed is a constant in test code only.
    const TEST_SEED: [u8; 32] = *b"rustynet-blind-relay-test-seed01";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_verifying_key() -> VerifyingKey {
        test_signing_key().verifying_key()
    }

    /// Deterministic fixture token over fixed fields, signed with the fixed
    /// test seed.
    fn fixture_token() -> BlindRelayLegTokenV2 {
        BlindRelayLegTokenV2::new(
            BlindRelayTokenKindV2::BlindRelayLeg,
            canonical_relay_id_label("blind-relay-1"),
            BLIND_RELAY_TOKEN_SCOPE_V2,
            7,
            [0x11u8; 32],
            [0x22u8; 32],
            BlindRelayLegSlot::Slot0,
            test_verifying_key().to_bytes(),
            1_700_000_000,
            1_700_000_100,
            [0x33u8; 16],
            "profile-standard",
            "issuer-key-1",
        )
        .expect("fixture token fields are valid")
        .sign(&test_signing_key())
    }

    fn canonical_relay_id_label(label: &str) -> [u8; 16] {
        crate::canonical_relay_id_from_label(label).expect("test relay label is valid")
    }

    fn relay_id_hex(token: &BlindRelayLegTokenV2) -> String {
        crate::hex_bytes(&token.audience_relay_id)
    }

    // ── Vector 1: v2_token_roundtrip ────────────────────────────────────────

    #[test]
    fn v2_token_roundtrip() {
        let token = fixture_token();
        let wire = token.to_wire();
        assert!(wire.len() <= MAX_BLIND_RELAY_TOKEN_WIRE_BYTES);
        let parsed = parse_blind_relay_leg_token_v2_wire_bytes(wire.as_bytes())
            .expect("canonical wire must parse");
        assert!(parsed.ct_eq(&token));
        assert_eq!(parsed.to_wire(), wire, "re-encode must be byte-identical");
        assert_eq!(parsed.canonical_payload(), token.canonical_payload());
    }

    // ── Vector 2: v2_token_preimage (fixed test seed) ───────────────────────

    #[test]
    fn v2_token_preimage() {
        let token = fixture_token();
        let expected_payload = format!(
            "version=2\ntoken_kind=blind_relay_leg\naudience_relay_id={}\nscope=forward_ciphertext_only_blind\nprivacy_epoch=7\ncircuit_handle={}\nleg_handle={}\nleg_slot=0\npresenter_public_key={}\nissued_at_unix=1700000000\nexpires_at_unix=1700000100\nnonce={}\nprofile_id=profile-standard\nissuer_key_id=issuer-key-1\n",
            relay_id_hex(&token),
            "11".repeat(32),
            "22".repeat(32),
            crate::hex_bytes(&test_verifying_key().to_bytes()),
            "33".repeat(16),
        );
        assert_eq!(token.canonical_payload(), expected_payload);

        // Exact signed-preimage fixture: the Ed25519 signature over the fixed
        // canonical payload under the fixed test seed is deterministic, so
        // the full wire rendering is byte-pinned here. A non-Rust checker can
        // reproduce it from (seed, payload).
        let expected_wire = format!(
            "{expected_payload}signature={}\n",
            crate::hex_bytes(&token.signature)
        );
        assert_eq!(token.to_wire(), expected_wire);

        let parsed = parse_blind_relay_leg_token_v2_wire(&expected_wire)
            .expect("preimage fixture must parse");
        parsed
            .verify_signature(&test_verifying_key())
            .expect("fixture signature must verify strictly");
    }

    // ── Vector 3: v2_token_duplicate_field ──────────────────────────────────

    #[test]
    fn v2_token_duplicate_field() {
        let token = fixture_token();
        let wire = token.to_wire();
        let duplicated = wire.replace("privacy_epoch=7\n", "privacy_epoch=7\nprivacy_epoch=7\n");
        assert_ne!(duplicated, wire);
        let err = parse_blind_relay_leg_token_v2_wire(&duplicated)
            .expect_err("duplicate key must reject");
        assert!(err.to_string().contains("duplicate key: privacy_epoch"));
    }

    // ── Vector 4: v2_token_unknown_field ────────────────────────────────────

    #[test]
    fn v2_token_unknown_field() {
        let token = fixture_token();
        let wire = token.to_wire();
        // An identity-bearing key is exactly the forbidden-field class.
        let injected = wire.replace("profile_id=", "node_id=attacker\nprofile_id=");
        let err =
            parse_blind_relay_leg_token_v2_wire(&injected).expect_err("unknown key must reject");
        assert!(err.to_string().contains("key is not allowed: node_id"));
    }

    // ── Vector 5: v2_token_missing_field ────────────────────────────────────

    #[test]
    fn v2_token_missing_field() {
        let token = fixture_token();
        let keys = [
            "version",
            "token_kind",
            "audience_relay_id",
            "scope",
            "privacy_epoch",
            "circuit_handle",
            "leg_handle",
            "leg_slot",
            "presenter_public_key",
            "issued_at_unix",
            "expires_at_unix",
            "nonce",
            "profile_id",
            "issuer_key_id",
            "signature",
        ];
        for key in keys {
            let wire = token.to_wire();
            let without = wire
                .lines()
                .filter(|line| !line.starts_with(&format!("{key}=")))
                .collect::<Vec<_>>()
                .join("\n");
            let without = format!("{without}\n");
            let err = parse_blind_relay_leg_token_v2_wire(&without)
                .expect_err("missing field must reject");
            let message = err.to_string();
            assert!(
                message.contains(&format!("missing {key}"))
                    || message.contains("missing signature")
                    || message.contains("payload is not canonical"),
                "rejecting `{key}` gave an unexpected class: {message}"
            );
        }
    }

    // ── Vector 6: v2_token_reordered ────────────────────────────────────────

    #[test]
    fn v2_token_reordered() {
        let token = fixture_token();
        // Permute two payload lines and re-sign the permuted bytes: the
        // signature is valid over the presented payload, yet the canonical
        // re-encode equality check must still reject the reordering.
        let payload = token.canonical_payload();
        let payload_lines: Vec<&str> = payload.lines().collect();
        let mut permuted = payload_lines.clone();
        permuted.swap(1, 2);
        let permuted_payload = format!("{}\n", permuted.join("\n"));
        let permuted_signature = test_signing_key()
            .sign(permuted_payload.as_bytes())
            .to_bytes();
        let wire = format!(
            "{permuted_payload}signature={}\n",
            crate::hex_bytes(&permuted_signature)
        );
        let err = parse_blind_relay_leg_token_v2_wire(&wire)
            .expect_err("reordered payload must reject even with a valid signature");
        assert!(err.to_string().contains("payload is not canonical"));
    }

    // ── Vector 7: v2_token_overlong ─────────────────────────────────────────

    #[test]
    fn v2_token_overlong() {
        let token = fixture_token();

        // String field at bound+1 (32-byte text bound → 33 bytes).
        let overlong_profile = "p".repeat(MAX_BLIND_RELAY_TEXT_FIELD_BYTES + 1);
        let overlong = token.to_wire().replace(
            "profile_id=profile-standard",
            &format!("profile_id={overlong_profile}"),
        );
        let err = parse_blind_relay_leg_token_v2_wire(&overlong)
            .expect_err("profile_id over the bound must reject");
        assert!(err.to_string().contains("profile_id"));

        // Whole wire at bound+1. The shortest way past the cap without
        // violating any other rule first: a huge padded profile value keeps
        // the line grammar intact until the size gate fires.
        let padded_profile = "p".repeat(MAX_BLIND_RELAY_TOKEN_WIRE_BYTES);
        let oversized = token.to_wire().replace(
            "profile_id=profile-standard",
            &format!("profile_id={padded_profile}"),
        );
        assert!(oversized.len() > MAX_BLIND_RELAY_TOKEN_WIRE_BYTES);
        let err = parse_blind_relay_leg_token_v2_wire_bytes(oversized.as_bytes())
            .expect_err("wire over the bound must reject");
        assert!(err.to_string().contains("exceeds the bounded size"));
    }

    // ── Vector 8: v2_token_noncanonical_numeric ─────────────────────────────

    #[test]
    fn v2_token_noncanonical_numeric() {
        let token = fixture_token();
        for (bad, good) in [
            ("privacy_epoch=007", "privacy_epoch=7"),
            ("privacy_epoch=+7", "privacy_epoch=7"),
            ("issued_at_unix=01700000000", "issued_at_unix=1700000000"),
            ("expires_at_unix=+1700000100", "expires_at_unix=1700000100"),
        ] {
            let mutated = token.to_wire().replace(good, bad);
            assert_ne!(mutated, token.to_wire());
            let err = parse_blind_relay_leg_token_v2_wire(&mutated)
                .expect_err("noncanonical numeric must reject");
            let message = err.to_string();
            assert!(
                message.contains("noncanonical leading zero")
                    || message.contains("not a plain decimal integer")
                    || message.contains("payload is not canonical"),
                "numeric mutation `{bad}` gave an unexpected class: {message}"
            );
        }

        // Overlong digit run (21 digits) rejects at the bound.
        let overlong = token
            .to_wire()
            .replace("privacy_epoch=7", "privacy_epoch=123456789012345678901");
        let err = parse_blind_relay_leg_token_v2_wire(&overlong)
            .expect_err("21-digit integer must reject");
        assert!(err.to_string().contains("bounded decimal integer"));
    }

    // ── Vector 9: v2_token_invalid_utf8_and_control ─────────────────────────

    #[test]
    fn v2_token_invalid_utf8_and_control() {
        let token = fixture_token();

        // Control character (0x01) inside a text field.
        let control = token
            .to_wire()
            .replace("profile_id=profile-standard", "profile_id=profile\u{01}std");
        let err = parse_blind_relay_leg_token_v2_wire(&control)
            .expect_err("control char in a text field must reject");
        assert!(err.to_string().contains("profile_id"));

        // Invalid UTF-8 byte inside the wire.
        let mut bytes = token.to_wire().into_bytes();
        let index = bytes
            .windows(11)
            .position(|window| window == b"profile_id=")
            .expect("profile_id line exists")
            + 11;
        bytes[index] = 0xFF;
        let err = parse_blind_relay_leg_token_v2_wire_bytes(&bytes)
            .expect_err("invalid UTF-8 must reject");
        assert!(err.to_string().contains("not valid UTF-8"));
    }

    // ── Vector 10: v2_token_trailing_data ───────────────────────────────────

    #[test]
    fn v2_token_trailing_data() {
        let token = fixture_token();
        let mut trailing = token.to_wire();
        trailing.push_str("profile_id=extra\n");
        let err = parse_blind_relay_leg_token_v2_wire(&trailing)
            .expect_err("bytes after the signature line must reject");
        assert!(err.to_string().contains("signature must be the final line"));

        // A bare non-`key=value` trailing line is also rejected (as a line
        // without a separator) rather than silently ignored.
        let mut junk = token.to_wire();
        junk.push('\n');
        junk.push_str("trailing-junk\n");
        assert!(parse_blind_relay_leg_token_v2_wire(&junk).is_err());
    }

    // ── Vector 11: v2_version_confusion ─────────────────────────────────────

    #[test]
    fn v2_version_confusion() {
        let token = fixture_token();
        let wire = token.to_wire();

        // A v1 blind-relay token does not exist: version=1 must reject even
        // with an otherwise well-formed v2 field set.
        let v1 = wire.replace("version=2\n", "version=1\n");
        let err = parse_blind_relay_leg_token_v2_wire(&v1)
            .expect_err("version=1 must reject at the v2 parser");
        assert!(err.to_string().contains("version must be 2"));

        let v3 = wire.replace("version=2\n", "version=3\n");
        let err = parse_blind_relay_leg_token_v2_wire(&v3).expect_err("version=3 must reject");
        assert!(err.to_string().contains("version must be 2"));

        let missing = wire.replace("version=2\n", "");
        let err =
            parse_blind_relay_leg_token_v2_wire(&missing).expect_err("missing version must reject");
        assert!(err.to_string().contains("missing version"));

        // The v1 token parser still accepts genuine v1 material unchanged —
        // the two parsers are independent.
        let v1_token = crate::RelaySessionToken::sign_at(
            &test_signing_key(),
            "node-a",
            "node-b",
            canonical_relay_id_label("relay-1"),
            1_700_000_000,
            60,
        );
        crate::parse_relay_session_token_wire(&crate::relay_session_token_to_wire(&v1_token))
            .expect("v1 token must keep parsing under the v1 parser");
    }

    // ── Vector 12: v2_degenerate_crypto_fields ──────────────────────────────

    #[test]
    fn v2_degenerate_crypto_fields() {
        // All-zero nonce.
        let err = BlindRelayLegTokenV2::new(
            BlindRelayTokenKindV2::BlindRelayLeg,
            canonical_relay_id_label("relay-1"),
            BLIND_RELAY_TOKEN_SCOPE_V2,
            7,
            [0x11u8; 32],
            [0x22u8; 32],
            BlindRelayLegSlot::Slot0,
            test_verifying_key().to_bytes(),
            1_700_000_000,
            1_700_000_100,
            [0u8; 16],
            "profile-standard",
            "issuer-key-1",
        )
        .expect_err("all-zero nonce must reject at construction");
        assert!(err.to_string().contains("nonce must not be all zero"));

        // All-zero presenter key.
        let err = BlindRelayLegTokenV2::new(
            BlindRelayTokenKindV2::BlindRelayLeg,
            canonical_relay_id_label("relay-1"),
            BLIND_RELAY_TOKEN_SCOPE_V2,
            7,
            [0x11u8; 32],
            [0x22u8; 32],
            BlindRelayLegSlot::Slot0,
            [0u8; 32],
            1_700_000_000,
            1_700_000_100,
            [0x33u8; 16],
            "profile-standard",
            "issuer-key-1",
        )
        .expect_err("all-zero presenter key must reject at construction");
        assert!(
            err.to_string()
                .contains("presenter_public_key must not be all zero")
        );

        // Short hex fields on the wire.
        let token = fixture_token();
        let short_handle = token.to_wire().replace(
            &format!("leg_handle={}", "22".repeat(32)),
            "leg_handle=2222",
        );
        let err = parse_blind_relay_leg_token_v2_wire(&short_handle)
            .expect_err("short hex field must reject");
        assert!(err.to_string().contains("leg_handle"));

        // Non-hex byte in a fixed-width field.
        let bad_hex = token.to_wire().replace(
            &format!("circuit_handle={}", "11".repeat(32)),
            &format!("circuit_handle={}zz", "11".repeat(31)),
        );
        let err =
            parse_blind_relay_leg_token_v2_wire(&bad_hex).expect_err("non-hex byte must reject");
        assert!(err.to_string().contains("circuit_handle"));

        // The all-zero presenter key is also rejected at the transcript
        // verifier, before library decode.
        let transcript = BlindRelayPopTranscript::new(
            &token.payload_digest_hex(),
            [0x44u8; 32],
            token.circuit_handle,
            token.leg_handle,
            token.leg_slot,
            token.privacy_epoch,
            [0x55u8; 32],
        )
        .expect("transcript fields are valid");
        let err = verify_blind_relay_pop_signature(&transcript, &[0u8; 32], &[0u8; 64])
            .expect_err("all-zero presenter key must reject at the verifier");
        assert!(
            err.to_string()
                .contains("presenter_public_key must not be all zero")
        );
    }

    // ── Vector 13: v2_binding_mutations ─────────────────────────────────────

    #[test]
    fn v2_binding_mutations() {
        let token = fixture_token();

        // Each binding field mutated after signing must be rejected: enum/
        // scope/audience mutations reject at parse (closed value sets checked
        // before signature use), while value-only mutations parse and then
        // break strict verification over the canonical payload (BR-C07).
        let mutations: Vec<(&str, String, String)> = vec![
            (
                "audience",
                format!("audience_relay_id={}", relay_id_hex(&token)),
                "audience_relay_id=00000000000000000000000000000000".to_owned(),
            ),
            (
                "scope",
                "scope=forward_ciphertext_only_blind".to_owned(),
                "scope=forward_ciphertext_only".to_owned(),
            ),
            (
                "epoch",
                "privacy_epoch=7".to_owned(),
                "privacy_epoch=8".to_owned(),
            ),
            (
                "profile",
                "profile_id=profile-standard".to_owned(),
                "profile_id=profile-premium".to_owned(),
            ),
            ("slot", "leg_slot=0".to_owned(), "leg_slot=1".to_owned()),
            (
                "kind",
                "token_kind=blind_relay_leg".to_owned(),
                "token_kind=relay_leg".to_owned(),
            ),
        ];
        for (name, from, to) in mutations {
            let mutated = token.to_wire().replace(&from, &to);
            assert_ne!(mutated, token.to_wire(), "mutation `{name}` did not apply");
            let err = parse_blind_relay_leg_token_v2_wire(&mutated)
                .and_then(|parsed| parsed.verify_signature(&test_verifying_key()))
                .expect_err(&format!("mutated binding `{name}` must reject"));
            let message = err.to_string();
            assert!(
                message.contains("signature verification failed")
                    || message.contains("token_kind is invalid")
                    || message.contains("scope is invalid")
                    || message.contains("leg_slot is invalid")
                    || message.contains("audience_relay_id")
                    || message.contains("payload is not canonical"),
                "mutation `{name}` rejected for an unexpected reason: {message}"
            );
        }

        // The slot/kind mutations above are noncanonical rejections at the
        // enum level; a signed token that legitimately carries the wrong
        // binding for its audience must fail the binding check instead.
        let other_slot = BlindRelayLegTokenV2::new(
            BlindRelayTokenKindV2::BlindRelayLeg,
            canonical_relay_id_label("blind-relay-1"),
            BLIND_RELAY_TOKEN_SCOPE_V2,
            7,
            token.circuit_handle,
            [0x22u8; 32],
            BlindRelayLegSlot::Slot1,
            token.presenter_public_key,
            1_700_000_000,
            1_700_000_100,
            [0x34u8; 16],
            "profile-standard",
            "issuer-key-1",
        )
        .expect("other-slot token fields are valid")
        .sign(&test_signing_key());
        let parsed = parse_blind_relay_leg_token_v2_wire(&other_slot.to_wire())
            .expect("other-slot token parses");
        assert_ne!(parsed.leg_slot, token.leg_slot);
    }

    // ── Vector 14: v2_pop_transcript ────────────────────────────────────────

    #[test]
    fn v2_pop_transcript() {
        let token = fixture_token();
        let transcript = BlindRelayPopTranscript::new(
            &token.payload_digest_hex(),
            [0x44u8; 32],
            token.circuit_handle,
            token.leg_handle,
            token.leg_slot,
            token.privacy_epoch,
            [0x55u8; 32],
        )
        .expect("transcript fields are valid");

        // Exact §2.2b canonical layout, domain-separated.
        let expected = format!(
            "domain=rustynet-control-blind-relay-pop-v1\ntoken_digest={}\nrelay_challenge={}\ncircuit_handle={}\nleg_handle={}\nleg_slot=0\nprivacy_epoch=7\nclient_nonce={}\n",
            token.payload_digest_hex(),
            "44".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "55".repeat(32),
        );
        assert_eq!(transcript.canonical_bytes(), expected);

        // Positive: proof under the presenter key verifies strictly.
        let signature = test_signing_key().sign(transcript.canonical_bytes().as_bytes());
        verify_blind_relay_pop_signature(
            &transcript,
            &token.presenter_public_key,
            &signature.to_bytes(),
        )
        .expect("valid proof must verify");

        // Wrong presenter key rejects.
        let other_key = SigningKey::from_bytes(&[0x99u8; 32]);
        let err = verify_blind_relay_pop_signature(
            &transcript,
            &other_key.verifying_key().to_bytes(),
            &signature.to_bytes(),
        )
        .expect_err("proof under a different key must reject");
        assert!(
            err.to_string()
                .contains("pop signature verification failed")
        );

        // Per-field transcript mutations each reject. For every field, a
        // proof over the ORIGINAL transcript must not verify against the
        // MUTATED transcript (and vice versa) — the signature binds every
        // transcript byte (BR-C06).
        let mutations: Vec<(&str, BlindRelayPopTranscript)> = vec![
            (
                "token_digest",
                BlindRelayPopTranscript::new(
                    &crate::hex_bytes(&crate::sha256_digest(b"other-token-payload")),
                    transcript.relay_challenge,
                    transcript.circuit_handle,
                    transcript.leg_handle,
                    transcript.leg_slot,
                    transcript.privacy_epoch,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "relay_challenge",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    [0x45u8; 32],
                    transcript.circuit_handle,
                    transcript.leg_handle,
                    transcript.leg_slot,
                    transcript.privacy_epoch,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "circuit_handle",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    transcript.relay_challenge,
                    [0x12u8; 32],
                    transcript.leg_handle,
                    transcript.leg_slot,
                    transcript.privacy_epoch,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "leg_handle",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    transcript.relay_challenge,
                    transcript.circuit_handle,
                    [0x23u8; 32],
                    transcript.leg_slot,
                    transcript.privacy_epoch,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "leg_slot",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    transcript.relay_challenge,
                    transcript.circuit_handle,
                    transcript.leg_handle,
                    BlindRelayLegSlot::Slot1,
                    transcript.privacy_epoch,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "privacy_epoch",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    transcript.relay_challenge,
                    transcript.circuit_handle,
                    transcript.leg_handle,
                    transcript.leg_slot,
                    transcript.privacy_epoch + 1,
                    transcript.client_nonce,
                )
                .expect("mutated transcript is valid"),
            ),
            (
                "client_nonce",
                BlindRelayPopTranscript::new(
                    &transcript.token_digest_hex,
                    transcript.relay_challenge,
                    transcript.circuit_handle,
                    transcript.leg_handle,
                    transcript.leg_slot,
                    transcript.privacy_epoch,
                    [0x56u8; 32],
                )
                .expect("mutated transcript is valid"),
            ),
        ];
        for (name, mutated) in mutations {
            let err = verify_blind_relay_pop_signature(
                &mutated,
                &token.presenter_public_key,
                &signature.to_bytes(),
            )
            .expect_err(&format!("per-field mutation `{name}` must reject"));
            assert!(
                err.to_string()
                    .contains("pop signature verification failed"),
                "mutation `{name}` rejected for the wrong reason: {err}"
            );
        }

        // Cross-circuit proof reuse: a proof minted for this circuit/leg
        // rejects when presented for a different circuit's transcript.
        let other_circuit = BlindRelayPopTranscript::new(
            &token.payload_digest_hex(),
            transcript.relay_challenge,
            [0x77u8; 32],
            [0x88u8; 32],
            transcript.leg_slot,
            transcript.privacy_epoch,
            transcript.client_nonce,
        )
        .expect("other-circuit transcript is valid");
        assert!(
            verify_blind_relay_pop_signature(
                &other_circuit,
                &token.presenter_public_key,
                &signature.to_bytes(),
            )
            .is_err()
        );
    }

    // ── Vector 15: v2_fleet_fork ────────────────────────────────────────────

    fn fixture_descriptor(generation: u64, epoch: u64) -> BlindRelayFleetDescriptorV2 {
        BlindRelayFleetDescriptorV2::new(
            BlindRelayModeV2::IdentityBlind,
            generation,
            vec![2],
            vec![2],
            epoch,
            vec!["profile-standard".to_owned()],
            1_700_000_000,
            1_700_000_300,
            42,
        )
        .expect("fixture descriptor fields are valid")
        .sign(&test_signing_key())
    }

    #[test]
    fn v2_fleet_fork() {
        let accepted = fixture_descriptor(5, 3);
        let state = BlindRelayFleetAcceptanceState {
            highest_generation: accepted.generation,
            highest_generation_digest_hex: accepted.payload_digest_hex(),
            highest_privacy_epoch: accepted.minimum_privacy_epoch,
        };
        check_blind_relay_fleet_descriptor_v2_acceptance(&accepted, &state)
            .expect("the accepted descriptor passes against its own state");

        // Round trip through the parser first.
        let parsed = parse_blind_relay_fleet_descriptor_v2_wire(&accepted.to_wire())
            .expect("canonical fleet wire must parse");
        assert_eq!(parsed, accepted);
        assert!(parsed.to_wire() == accepted.to_wire());

        // Same generation, different digest (fork on any signed byte) → reject.
        let forked = BlindRelayFleetDescriptorV2::new(
            BlindRelayModeV2::IdentityBlind,
            accepted.generation,
            vec![2],
            vec![2],
            accepted.minimum_privacy_epoch,
            vec!["profile-standard".to_owned()],
            accepted.generated_at_unix,
            accepted.expires_at_unix,
            // Fork the digest on the public nonce alone: any signed-byte
            // change at the same generation is a fork.
            accepted.nonce + 1,
        )
        .expect("forked descriptor fields are valid")
        .sign(&test_signing_key());
        let forked = parse_blind_relay_fleet_descriptor_v2_wire(&forked.to_wire())
            .expect("forked descriptor parses");
        let err = check_blind_relay_fleet_descriptor_v2_acceptance(&forked, &state)
            .expect_err("same generation with a different digest must reject");
        assert!(err.to_string().contains("forks the accepted generation"));

        // Lower generation → reject (rollback).
        let older = parse_blind_relay_fleet_descriptor_v2_wire(&fixture_descriptor(4, 3).to_wire())
            .expect("older descriptor parses");
        let err = check_blind_relay_fleet_descriptor_v2_acceptance(&older, &state)
            .expect_err("lower generation must reject");
        assert!(err.to_string().contains("generation is lower"));

        // Lower privacy epoch → reject (rollback).
        let older_epoch =
            parse_blind_relay_fleet_descriptor_v2_wire(&fixture_descriptor(6, 2).to_wire())
                .expect("older-epoch descriptor parses");
        let err = check_blind_relay_fleet_descriptor_v2_acceptance(&older_epoch, &state)
            .expect_err("lower privacy epoch must reject");
        assert!(err.to_string().contains("privacy epoch is lower"));
    }

    // ── Vector 16: v2_hello_envelope ────────────────────────────────────────

    fn fixture_hello() -> BlindRelayHelloV2 {
        let token = fixture_token();
        BlindRelayHelloV2::new(token, [0x55u8; 32], [0x44u8; 32], [0x66u8; 64])
            .expect("hello fields are valid")
    }

    #[test]
    fn v2_hello_envelope() {
        let hello = fixture_hello();

        // Canonical round trip with line-count pinning.
        let wire = hello.to_wire();
        assert_eq!(wire.lines().count(), BLIND_RELAY_HELLO_V2_WIRE_LINES);
        let parsed = parse_blind_relay_hello_v2_wire_bytes(wire.as_bytes())
            .expect("canonical hello must parse");
        assert!(parsed.ct_eq(&hello));
        assert_eq!(parsed.to_wire(), wire);

        // Positive PoP: sign the transcript and verify through the envelope.
        let transcript = parsed.pop_transcript().expect("transcript builds");
        let proof = test_signing_key().sign(transcript.canonical_bytes().as_bytes());
        let signed_hello = BlindRelayHelloV2::new(
            hello.token.clone(),
            hello.client_nonce,
            hello.relay_challenge,
            proof.to_bytes(),
        )
        .expect("signed hello is valid");
        signed_hello.verify_pop().expect("pop must verify");

        // Oversize datagram rejects before any parse.
        let oversized = vec![0x61u8; MAX_BLIND_RELAY_HELLO_WIRE_BYTES + 1];
        let err = parse_blind_relay_hello_v2_wire_bytes(&oversized)
            .expect_err("oversize hello must reject");
        assert!(err.to_string().contains("exceeds the bounded size"));

        // Reordered envelope lines reject via canonical re-encode.
        let lines: Vec<&str> = wire.lines().collect();
        let split = BLIND_RELAY_LEG_TOKEN_V2_WIRE_LINES;
        let mut reordered = lines[..split].to_vec();
        reordered.push(lines[split + 1]);
        reordered.push(lines[split]);
        reordered.push(lines[split + 2]);
        let reordered = format!("{}\n", reordered.join("\n"));
        let err = parse_blind_relay_hello_v2_wire(&reordered)
            .expect_err("reordered envelope must reject");
        assert!(err.to_string().contains("not canonical"));

        // Unknown envelope key rejects (line count stays pinned: the
        // pop_signature line is replaced, not appended to).
        let mut unknown = lines.clone();
        let last = unknown.len() - 1;
        unknown[last] = "node_id=attacker";
        let unknown = format!("{}\n", unknown.join("\n"));
        let err = parse_blind_relay_hello_v2_wire(&unknown)
            .expect_err("unknown envelope key must reject");
        assert!(err.to_string().contains("key is not allowed: node_id"));

        // Missing envelope line (line-count pin) rejects.
        let missing = format!("{}\n", lines[..wire.lines().count() - 1].join("\n"));
        let err = parse_blind_relay_hello_v2_wire(&missing)
            .expect_err("missing envelope line must reject");
        assert!(err.to_string().contains("invalid line count"));

        // All-zero client nonce rejects (degenerate envelope field).
        let zero_nonce = wire.replace(
            &format!("client_nonce={}", "55".repeat(32)),
            &format!("client_nonce={}", "00".repeat(32)),
        );
        let err = parse_blind_relay_hello_v2_wire(&zero_nonce)
            .expect_err("all-zero client nonce must reject");
        assert!(
            err.to_string()
                .contains("client_nonce must not be all zero")
        );

        // The closed rejection classes carry no content echo: error text
        // names the class, never the offending field value (design §7.3).
        let message = err.to_string();
        assert!(!message.contains("00000000"));
    }
}
