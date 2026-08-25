#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const MAX_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_BUNDLE_LINES: usize = 16_384;
const MAX_LINE_BYTES: usize = 4_096;
const MAX_KEY_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 1_536;
const MAX_KEY_DEPTH: usize = 5;
const MAX_RECORD_COUNT: usize = 1_024;
const MAX_ALIAS_COUNT: usize = 8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
}

impl DnsRecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
        }
    }
}

impl FromStr for DnsRecordType {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "A" => Ok(DnsRecordType::A),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTargetAddrKind {
    MeshIpv4,
}

impl DnsTargetAddrKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsTargetAddrKind::MeshIpv4 => "mesh_ipv4",
        }
    }
}

impl FromStr for DnsTargetAddrKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mesh_ipv4" => Ok(DnsTargetAddrKind::MeshIpv4),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsZoneRecordInput {
    pub label: String,
    pub target_node_id: String,
    pub rr_type: DnsRecordType,
    pub target_addr_kind: DnsTargetAddrKind,
    pub expected_ip: String,
    pub ttl_secs: u64,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsZoneRecord {
    pub label: String,
    pub fqdn: String,
    pub target_node_id: String,
    pub rr_type: DnsRecordType,
    pub target_addr_kind: DnsTargetAddrKind,
    pub expected_ip: String,
    pub ttl_secs: u64,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDnsZoneBundle {
    pub payload: String,
    pub signature_hex: String,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub zone_name: String,
    pub subject_node_id: String,
    pub nonce: u64,
    pub records: Vec<DnsZoneRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsZoneWatermark {
    pub version: u8,
    pub generated_at_unix: u64,
    pub nonce: u64,
    pub payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsZoneError {
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
}

impl fmt::Display for DnsZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsZoneError::InvalidFormat(message) => f.write_str(message),
            DnsZoneError::KeyInvalid => f.write_str("dns zone verifier key is invalid"),
            DnsZoneError::SignatureInvalid => f.write_str("dns zone signature verification failed"),
        }
    }
}

impl std::error::Error for DnsZoneError {}

pub fn canonicalize_dns_zone_name(value: &str) -> Result<String, DnsZoneError> {
    let normalized = canonicalize_dns_relative_name(value)?;
    if normalized.len() > 64 {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone name exceeds max length".to_owned(),
        ));
    }
    Ok(normalized)
}

pub fn canonicalize_dns_relative_name(value: &str) -> Result<String, DnsZoneError> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns name must not be empty".to_owned(),
        ));
    }
    if trimmed.starts_with('.') || trimmed.contains('*') {
        return Err(DnsZoneError::InvalidFormat(
            "dns name contains forbidden characters".to_owned(),
        ));
    }
    let mut parts = Vec::new();
    for raw_part in trimmed.split('.') {
        if raw_part.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "dns name contains an empty label".to_owned(),
            ));
        }
        let part = raw_part.to_ascii_lowercase();
        if part.len() > 63 {
            return Err(DnsZoneError::InvalidFormat(
                "dns label exceeds maximum length".to_owned(),
            ));
        }
        if part.starts_with('-') || part.ends_with('-') {
            return Err(DnsZoneError::InvalidFormat(
                "dns label must not start or end with '-'".to_owned(),
            ));
        }
        if !part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DnsZoneError::InvalidFormat(
                "dns label contains invalid characters".to_owned(),
            ));
        }
        parts.push(part);
    }
    let joined = parts.join(".");
    if joined.len() > 253 {
        return Err(DnsZoneError::InvalidFormat(
            "dns name exceeds maximum length".to_owned(),
        ));
    }
    Ok(joined)
}

pub fn canonicalize_dns_zone_fqdn(value: &str) -> Result<String, DnsZoneError> {
    canonicalize_dns_relative_name(value)
}

pub fn parse_dns_zone_verifying_key(contents: &str) -> Result<VerifyingKey, DnsZoneError> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "missing dns zone verifier key".to_owned(),
        ));
    }
    let key_line = trimmed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing dns zone verifier key".to_owned()))?;
    let key_bytes = decode_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| DnsZoneError::KeyInvalid)
}

pub fn build_signed_dns_zone_bundle(
    signing_key: &SigningKey,
    zone_name: &str,
    subject_node_id: &str,
    generated_at_unix: u64,
    ttl_secs: u64,
    nonce: u64,
    records: &[DnsZoneRecordInput],
) -> Result<SignedDnsZoneBundle, DnsZoneError> {
    if generated_at_unix == 0 {
        return Err(DnsZoneError::InvalidFormat(
            "generated_at_unix must be greater than zero".to_owned(),
        ));
    }
    if ttl_secs == 0 || ttl_secs > 300 {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone ttl must be in range 1..=300".to_owned(),
        ));
    }
    if records.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone requires at least one record".to_owned(),
        ));
    }
    if records.len() > MAX_RECORD_COUNT {
        return Err(DnsZoneError::InvalidFormat(format!(
            "dns zone exceeds max record count ({MAX_RECORD_COUNT})"
        )));
    }

    let zone_name = canonicalize_dns_zone_name(zone_name)?;
    let subject_node_id = subject_node_id.trim();
    if subject_node_id.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "subject_node_id must not be empty".to_owned(),
        ));
    }
    let expires_at_unix = generated_at_unix.saturating_add(ttl_secs);
    if generated_at_unix >= expires_at_unix {
        return Err(DnsZoneError::InvalidFormat(
            "invalid generated/expires ordering".to_owned(),
        ));
    }

    let canonical_records = canonicalize_dns_zone_records(zone_name.as_str(), records)?;
    let payload = serialize_dns_zone_payload(
        zone_name.as_str(),
        subject_node_id,
        generated_at_unix,
        expires_at_unix,
        nonce,
        &canonical_records,
    );
    ensure_payload_within_wire_parser_bounds(payload.as_str())?;
    let signature = signing_key.sign(payload.as_bytes());
    Ok(SignedDnsZoneBundle {
        payload,
        signature_hex: hex_bytes(&signature.to_bytes()),
        generated_at_unix,
        expires_at_unix,
        zone_name,
        subject_node_id: subject_node_id.to_owned(),
        nonce,
        records: canonical_records,
    })
}

pub fn verify_signed_dns_zone_bundle(
    bundle: &SignedDnsZoneBundle,
    verifying_key: &VerifyingKey,
) -> Result<(), DnsZoneError> {
    if bundle.generated_at_unix >= bundle.expires_at_unix {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone bundle has invalid generated/expires ordering".to_owned(),
        ));
    }
    let signature_bytes = decode_hex_to_fixed::<64>(&bundle.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(bundle.payload.as_bytes(), &signature)
        .map_err(|_| DnsZoneError::SignatureInvalid)?;
    Ok(())
}

pub fn parse_signed_dns_zone_bundle_wire(wire: &str) -> Result<SignedDnsZoneBundle, DnsZoneError> {
    if wire.len() > MAX_BUNDLE_BYTES {
        return Err(DnsZoneError::InvalidFormat(format!(
            "dns zone bundle exceeds maximum size ({MAX_BUNDLE_BYTES} bytes)"
        )));
    }

    let mut fields = std::collections::BTreeMap::<String, String>::new();
    let mut line_count = 0usize;
    for raw_line in wire.lines() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_BUNDLE_LINES {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns zone bundle exceeds maximum line count ({MAX_BUNDLE_LINES})"
            )));
        }
        if raw_line.is_empty() {
            continue;
        }
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns zone line exceeds maximum size ({MAX_LINE_BYTES} bytes)"
            )));
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| DnsZoneError::InvalidFormat("invalid dns zone line".to_owned()))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "dns zone field key must not be empty".to_owned(),
            ));
        }
        if key.len() > MAX_KEY_BYTES {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns zone key exceeds maximum size ({MAX_KEY_BYTES} bytes)"
            )));
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns zone value exceeds maximum size ({MAX_VALUE_BYTES} bytes)"
            )));
        }
        if key.split('.').count() > MAX_KEY_DEPTH {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns zone key depth exceeds maximum depth ({MAX_KEY_DEPTH})"
            )));
        }
        if !is_allowed_dns_zone_key(key) {
            return Err(DnsZoneError::InvalidFormat(format!(
                "unsupported dns zone field: {key}"
            )));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(DnsZoneError::InvalidFormat(format!(
                "duplicate dns zone field: {key}"
            )));
        }
    }

    if fields.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone bundle is empty".to_owned(),
        ));
    }

    let version = fields
        .get("version")
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing version".to_owned()))?;
    if version != "1" {
        return Err(DnsZoneError::InvalidFormat(
            "unsupported dns zone bundle version".to_owned(),
        ));
    }

    let zone_name = canonicalize_dns_zone_name(
        fields
            .get("zone_name")
            .ok_or_else(|| DnsZoneError::InvalidFormat("missing zone_name".to_owned()))?,
    )?;
    let subject_node_id = fields
        .get("subject_node_id")
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing subject_node_id".to_owned()))?
        .trim()
        .to_owned();
    if subject_node_id.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "subject_node_id must not be empty".to_owned(),
        ));
    }
    let generated_at_unix = parse_u64_field(&fields, "generated_at_unix")?;
    let expires_at_unix = parse_u64_field(&fields, "expires_at_unix")?;
    if generated_at_unix >= expires_at_unix {
        return Err(DnsZoneError::InvalidFormat(
            "invalid generated/expires ordering".to_owned(),
        ));
    }
    let nonce = parse_u64_field(&fields, "nonce")?;
    let signature_hex = fields
        .get("signature")
        .cloned()
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing dns zone signature".to_owned()))?;
    let record_count = parse_usize_field(&fields, "record_count")?;
    if record_count == 0 || record_count > MAX_RECORD_COUNT {
        return Err(DnsZoneError::InvalidFormat(format!(
            "dns zone record_count must be in range 1..={MAX_RECORD_COUNT}"
        )));
    }
    let expected_field_count = record_count
        .checked_mul(8)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| DnsZoneError::InvalidFormat("dns zone field count overflow".to_owned()))?;
    if fields.len() != expected_field_count {
        return Err(DnsZoneError::InvalidFormat(format!(
            "dns zone field count mismatch: expected {expected_field_count}, found {}",
            fields.len()
        )));
    }

    let mut records = Vec::with_capacity(record_count);
    let mut seen_names = HashSet::new();
    for index in 0..record_count {
        let label =
            canonicalize_dns_relative_name(required_indexed_field(&fields, index, "label")?)?;
        let expected_fqdn = format!("{label}.{zone_name}");
        let fqdn = canonicalize_dns_zone_fqdn(required_indexed_field(&fields, index, "fqdn")?)?;
        if fqdn != expected_fqdn {
            return Err(DnsZoneError::InvalidFormat(format!(
                "record {index} fqdn does not match label and zone_name"
            )));
        }
        if !seen_names.insert(fqdn.clone()) {
            return Err(DnsZoneError::InvalidFormat(
                "duplicate dns record name".to_owned(),
            ));
        }

        let target_node_id = required_indexed_field(&fields, index, "target_node_id")?
            .trim()
            .to_owned();
        if target_node_id.is_empty() {
            return Err(DnsZoneError::InvalidFormat(format!(
                "record {index} target_node_id must not be empty"
            )));
        }

        let rr_type = required_indexed_field(&fields, index, "rr_type")?
            .parse::<DnsRecordType>()
            .map_err(|_| {
                DnsZoneError::InvalidFormat(format!("invalid rr_type for record {index}"))
            })?;
        let target_addr_kind = required_indexed_field(&fields, index, "target_addr_kind")?
            .parse::<DnsTargetAddrKind>()
            .map_err(|_| {
                DnsZoneError::InvalidFormat(format!("invalid target_addr_kind for record {index}"))
            })?;
        let expected_ip = parse_expected_ip(
            required_indexed_field(&fields, index, "expected_ip")?,
            target_addr_kind,
            index,
        )?;
        let ttl_secs = required_indexed_field(&fields, index, "ttl_secs")?
            .parse::<u64>()
            .map_err(|_| {
                DnsZoneError::InvalidFormat(format!("invalid ttl_secs for record {index}"))
            })?;
        if ttl_secs == 0 || ttl_secs > 300 {
            return Err(DnsZoneError::InvalidFormat(format!(
                "record {index} ttl_secs must be in range 1..=300"
            )));
        }
        let aliases = parse_aliases(
            required_indexed_field(&fields, index, "aliases")?,
            zone_name.as_str(),
            index,
        )?;
        if aliases.len() > MAX_ALIAS_COUNT {
            return Err(DnsZoneError::InvalidFormat(format!(
                "record {index} exceeds maximum alias count ({MAX_ALIAS_COUNT})"
            )));
        }
        for alias in &aliases {
            let alias_fqdn = format!("{alias}.{zone_name}");
            if !seen_names.insert(alias_fqdn) {
                return Err(DnsZoneError::InvalidFormat(
                    "dns alias collides with another record".to_owned(),
                ));
            }
        }

        records.push(DnsZoneRecord {
            label,
            fqdn,
            target_node_id,
            rr_type,
            target_addr_kind,
            expected_ip,
            ttl_secs,
            aliases,
        });
    }

    let payload = serialize_dns_zone_payload(
        zone_name.as_str(),
        subject_node_id.as_str(),
        generated_at_unix,
        expires_at_unix,
        nonce,
        &records,
    );
    Ok(SignedDnsZoneBundle {
        payload,
        signature_hex,
        generated_at_unix,
        expires_at_unix,
        zone_name,
        subject_node_id,
        nonce,
        records,
    })
}

pub fn render_signed_dns_zone_bundle_wire(bundle: &SignedDnsZoneBundle) -> String {
    format!("{}signature={}\n", bundle.payload, bundle.signature_hex)
}

pub fn dns_zone_payload_digest(bundle: &SignedDnsZoneBundle) -> [u8; 32] {
    sha256_digest(bundle.payload.as_bytes())
}

pub fn dns_zone_watermark_ordering(
    current: &DnsZoneWatermark,
    previous: &DnsZoneWatermark,
) -> std::cmp::Ordering {
    current
        .generated_at_unix
        .cmp(&previous.generated_at_unix)
        .then_with(|| current.nonce.cmp(&previous.nonce))
}

fn canonicalize_dns_zone_records(
    zone_name: &str,
    records: &[DnsZoneRecordInput],
) -> Result<Vec<DnsZoneRecord>, DnsZoneError> {
    let mut canonical_records = Vec::with_capacity(records.len());
    let mut seen_names = HashSet::new();
    for record in records {
        if record.ttl_secs == 0 || record.ttl_secs > 300 {
            return Err(DnsZoneError::InvalidFormat(
                "dns record ttl must be in range 1..=300".to_owned(),
            ));
        }
        let label = canonicalize_dns_relative_name(record.label.as_str())?;
        let fqdn = format!("{label}.{zone_name}");
        // The wire parser enforces the 253-byte bound on the ASSEMBLED fqdn
        // (canonicalize_dns_zone_fqdn); enforce it here too. The label and
        // zone-name bounds are per-part, so their assembly could otherwise
        // exceed the parser's limit and the builder would mint a signed
        // bundle its own verifier refuses — a failure that surfaces only
        // after signing and distribution, far from the operator's input.
        if fqdn.len() > 253 {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns record fqdn exceeds maximum length ({} > 253)",
                fqdn.len()
            )));
        }
        if !seen_names.insert(fqdn.clone()) {
            return Err(DnsZoneError::InvalidFormat(
                "duplicate dns record name".to_owned(),
            ));
        }
        let target_node_id = record.target_node_id.trim().to_owned();
        if target_node_id.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "target_node_id must not be empty".to_owned(),
            ));
        }
        let expected_ip = parse_expected_ip(
            record.expected_ip.as_str(),
            record.target_addr_kind,
            canonical_records.len(),
        )?;
        let mut aliases = record
            .aliases
            .iter()
            .map(|alias| canonicalize_dns_relative_name(alias))
            .collect::<Result<Vec<_>, _>>()?;
        aliases.sort();
        aliases.dedup();
        if aliases.len() > MAX_ALIAS_COUNT {
            return Err(DnsZoneError::InvalidFormat(format!(
                "dns record exceeds maximum alias count ({MAX_ALIAS_COUNT})"
            )));
        }
        for alias in &aliases {
            let alias_fqdn = format!("{alias}.{zone_name}");
            // Same assembled-name bound the parser enforces in `parse_aliases`;
            // see the fqdn check above for why it belongs on the build side too.
            if alias_fqdn.len() > 253 {
                return Err(DnsZoneError::InvalidFormat(format!(
                    "record {} alias exceeds maximum fqdn length ({} > 253)",
                    canonical_records.len(),
                    alias_fqdn.len()
                )));
            }
            if !seen_names.insert(alias_fqdn) {
                return Err(DnsZoneError::InvalidFormat(
                    "dns alias collides with another record".to_owned(),
                ));
            }
        }
        canonical_records.push(DnsZoneRecord {
            label,
            fqdn,
            target_node_id,
            rr_type: record.rr_type,
            target_addr_kind: record.target_addr_kind,
            expected_ip,
            ttl_secs: record.ttl_secs,
            aliases,
        });
    }
    canonical_records.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
    Ok(canonical_records)
}

/// The wire parser (`parse_signed_dns_zone_bundle_wire`) refuses bundles
/// whose total wire size or any field VALUE exceeds its DoS bounds
/// (`MAX_BUNDLE_BYTES` / `MAX_VALUE_BYTES`). The builder serializes
/// operator-controlled strings (the joined alias list, target/subject node
/// ids) into those fields with no per-field cap of its own, so it must
/// refuse to MINT a bundle the verifier-side parser would reject — the same
/// build-vs-parse contract the assembled 253-byte fqdn checks enforce per
/// name. Bundle keys here are fixed-format (bounded well below
/// MAX_KEY_BYTES / MAX_KEY_DEPTH), so only the two reachable bounds are
/// mirrored.
fn ensure_payload_within_wire_parser_bounds(payload: &str) -> Result<(), DnsZoneError> {
    // render_signed_dns_zone_bundle_wire appends "signature=<128 hex>\n".
    const SIGNATURE_WIRE_SUFFIX_BYTES: usize = "signature=".len() + 128 + 1;
    let rendered_len = payload.len() + SIGNATURE_WIRE_SUFFIX_BYTES;
    if rendered_len > MAX_BUNDLE_BYTES {
        return Err(DnsZoneError::InvalidFormat(format!(
            "serialized dns zone bundle exceeds maximum wire size ({rendered_len} > {MAX_BUNDLE_BYTES})"
        )));
    }
    for line in payload.lines() {
        let Some((_, value)) = line.split_once('=') else {
            return Err(DnsZoneError::InvalidFormat(
                "serialized dns zone line is malformed".to_owned(),
            ));
        };
        if value.len() > MAX_VALUE_BYTES {
            return Err(DnsZoneError::InvalidFormat(format!(
                "serialized dns zone field value exceeds maximum size ({} > {MAX_VALUE_BYTES})",
                value.len()
            )));
        }
    }
    Ok(())
}

fn serialize_dns_zone_payload(
    zone_name: &str,
    subject_node_id: &str,
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
    records: &[DnsZoneRecord],
) -> String {
    let mut payload = String::new();
    payload.push_str("version=1\n");
    payload.push_str(&format!("zone_name={zone_name}\n"));
    payload.push_str(&format!("subject_node_id={subject_node_id}\n"));
    payload.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
    payload.push_str(&format!("expires_at_unix={expires_at_unix}\n"));
    payload.push_str(&format!("nonce={nonce}\n"));
    payload.push_str(&format!("record_count={}\n", records.len()));
    for (index, record) in records.iter().enumerate() {
        payload.push_str(&format!("record.{index}.label={}\n", record.label));
        payload.push_str(&format!("record.{index}.fqdn={}\n", record.fqdn));
        payload.push_str(&format!(
            "record.{index}.target_node_id={}\n",
            record.target_node_id
        ));
        payload.push_str(&format!(
            "record.{index}.rr_type={}\n",
            record.rr_type.as_str()
        ));
        payload.push_str(&format!(
            "record.{index}.target_addr_kind={}\n",
            record.target_addr_kind.as_str()
        ));
        payload.push_str(&format!(
            "record.{index}.expected_ip={}\n",
            record.expected_ip
        ));
        payload.push_str(&format!("record.{index}.ttl_secs={}\n", record.ttl_secs));
        payload.push_str(&format!(
            "record.{index}.aliases={}\n",
            record.aliases.join(",")
        ));
    }
    payload
}

fn parse_expected_ip(
    value: &str,
    target_addr_kind: DnsTargetAddrKind,
    index: usize,
) -> Result<String, DnsZoneError> {
    match target_addr_kind {
        DnsTargetAddrKind::MeshIpv4 => {
            let ip = value.parse::<std::net::Ipv4Addr>().map_err(|_| {
                DnsZoneError::InvalidFormat(format!("record {index} expected_ip must be ipv4"))
            })?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(DnsZoneError::InvalidFormat(format!(
                    "record {index} expected_ip must be a unicast ipv4 address"
                )));
            }
            // Defense-in-depth (related to SecurityHardeningAudit B.4.1):
            // a malicious zone-publisher must not be able to inject an
            // expected_ip in a range that is universally-inappropriate
            // for a mesh peer. The daemon's loopback resolver answer
            // filter (B.4.1 proper) is still pending — once the
            // protocol-level DNS responder lands the same posture
            // applies at the resolver-output layer too. Until then,
            // catching these at zone-bundle parse time is the strictest
            // defense the signed-state contract can publish.
            if is_universally_inappropriate_mesh_ipv4(&ip) {
                return Err(DnsZoneError::InvalidFormat(format!(
                    "record {index} expected_ip {ip} is in a range that cannot host a mesh peer (loopback, link-local, or RFC 5737 documentation)"
                )));
            }
            Ok(ip.to_string())
        }
    }
}

/// Returns true for IPv4 ranges that are universally inappropriate as
/// a mesh-peer `expected_ip` — irrespective of operator network choices.
/// The list is intentionally narrow: loopback, link-local APIPA, and
/// the three RFC 5737 documentation ranges. RFC1918 ranges (10/8,
/// 172.16-31/16, 192.168/16) are NOT rejected here because some
/// operators legitimately deploy meshes inside their corporate RFC1918
/// space; rejecting RFC1918 globally would break those deployments.
/// An operator who wants to additionally constrain the mesh IP range
/// to a specific allowlist publishes that constraint via a separate
/// per-deployment policy gate (out of scope for the zone-bundle
/// validator, which intentionally publishes only universally-true
/// invariants).
fn is_universally_inappropriate_mesh_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Loopback: 127.0.0.0/8 — RFC 6890. Never a mesh peer.
    if octets[0] == 127 {
        return true;
    }
    // Link-local APIPA: 169.254.0.0/16 — RFC 3927.
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // RFC 5737 documentation / TEST-NET-{1,2,3}.
    // 192.0.2.0/24
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    // 198.51.100.0/24
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    false
}

fn parse_aliases(value: &str, zone_name: &str, index: usize) -> Result<Vec<String>, DnsZoneError> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut aliases = value
        .split(',')
        .map(str::trim)
        .filter(|alias| !alias.is_empty())
        .map(canonicalize_dns_relative_name)
        .collect::<Result<Vec<_>, _>>()?;
    aliases.sort();
    aliases.dedup();
    for alias in &aliases {
        let alias_fqdn = format!("{alias}.{zone_name}");
        if alias_fqdn.len() > 253 {
            return Err(DnsZoneError::InvalidFormat(format!(
                "record {index} alias exceeds maximum fqdn length"
            )));
        }
    }
    Ok(aliases)
}

fn required_indexed_field<'a>(
    fields: &'a std::collections::BTreeMap<String, String>,
    index: usize,
    field: &str,
) -> Result<&'a str, DnsZoneError> {
    let key = format!("record.{index}.{field}");
    fields
        .get(&key)
        .map(String::as_str)
        .ok_or_else(|| DnsZoneError::InvalidFormat(format!("missing {key}")))
}

fn parse_u64_field(
    fields: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<u64, DnsZoneError> {
    fields
        .get(key)
        .ok_or_else(|| DnsZoneError::InvalidFormat(format!("missing {key}")))?
        .parse::<u64>()
        .map_err(|_| DnsZoneError::InvalidFormat(format!("invalid {key}")))
}

fn parse_usize_field(
    fields: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<usize, DnsZoneError> {
    fields
        .get(key)
        .ok_or_else(|| DnsZoneError::InvalidFormat(format!("missing {key}")))?
        .parse::<usize>()
        .map_err(|_| DnsZoneError::InvalidFormat(format!("invalid {key}")))
}

fn is_allowed_dns_zone_key(key: &str) -> bool {
    matches!(
        key,
        "version"
            | "zone_name"
            | "subject_node_id"
            | "generated_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "record_count"
            | "signature"
    ) || record_indexed_key(key).is_some()
}

fn record_indexed_key(key: &str) -> Option<(&str, usize)> {
    let mut parts = key.split('.');
    let root = parts.next()?;
    if root != "record" {
        return None;
    }
    let index = parts.next()?.parse::<usize>().ok()?;
    let field = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    match field {
        "label" | "fqdn" | "target_node_id" | "rr_type" | "target_addr_kind" | "expected_ip"
        | "ttl_secs" | "aliases" => Some((field, index)),
        _ => None,
    }
}

fn sha256_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    // Nibble lookup instead of a per-byte `format!` allocation;
    // byte-identical output (feeds the signed zone canonical payload).
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX_LOWER[(byte >> 4) as usize]);
        encoded.push(HEX_LOWER[(byte & 0x0f) as usize]);
    }
    String::from_utf8(encoded).expect("hex alphabet is valid ASCII")
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], DnsZoneError> {
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(DnsZoneError::InvalidFormat(
            "hex value has invalid length".to_owned(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut bytes = [0u8; N];
    for index in 0..N {
        let hi = decode_hex_nibble(raw[index * 2])?;
        let lo = decode_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, DnsZoneError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DnsZoneError::InvalidFormat(
            "hex value contains invalid character".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnsRecordType, DnsTargetAddrKind, DnsZoneRecordInput, DnsZoneWatermark,
        build_signed_dns_zone_bundle, dns_zone_payload_digest, dns_zone_watermark_ordering,
        parse_dns_zone_verifying_key, parse_signed_dns_zone_bundle_wire,
        render_signed_dns_zone_bundle_wire, verify_signed_dns_zone_bundle,
    };
    use ed25519_dalek::SigningKey;

    fn build_bundle_with_expected_ip(
        ip: &str,
    ) -> Result<super::SignedDnsZoneBundle, super::DnsZoneError> {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: ip.to_owned(),
                ttl_secs: 60,
                aliases: vec![],
            }],
        )
    }

    fn build_bundle_with_ttl(
        ttl_secs: u64,
    ) -> Result<super::SignedDnsZoneBundle, super::DnsZoneError> {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            ttl_secs,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.64.0.5".to_owned(),
                ttl_secs,
                aliases: vec![],
            }],
        )
    }

    #[test]
    fn build_bundle_rejects_ttl_above_cap() {
        // The signed-zone TTL is hard-capped at 1..=300 s. An over-large value
        // (e.g. an env-issuer that let DNS_ZONE_TTL_SECS through in 301..=86400)
        // must be rejected at build time, never silently widening the bundle's
        // freshness/replay window.
        let err = build_bundle_with_ttl(301).expect_err("ttl above 300 must be rejected");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => assert!(
                reason.contains("range 1..=300"),
                "rejection must cite the 1..=300 bound: {reason}"
            ),
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn build_bundle_rejects_zero_ttl() {
        let err = build_bundle_with_ttl(0).expect_err("zero ttl must be rejected");
        assert!(matches!(err, super::DnsZoneError::InvalidFormat(_)));
    }

    #[test]
    fn build_bundle_accepts_max_ttl() {
        build_bundle_with_ttl(300).expect("ttl at the 300 s cap must be accepted");
    }

    #[test]
    fn build_bundle_rejects_loopback_expected_ip() {
        let err = build_bundle_with_expected_ip("127.0.0.1")
            .expect_err("loopback expected_ip must be rejected");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("loopback") && reason.contains("127.0.0.1"),
                    "rejection must cite loopback + the IP: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn build_bundle_rejects_link_local_expected_ip() {
        let err = build_bundle_with_expected_ip("169.254.42.1")
            .expect_err("link-local expected_ip must be rejected");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("link-local"),
                    "rejection must cite link-local: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn build_bundle_rejects_documentation_expected_ip_test_net_1() {
        let err = build_bundle_with_expected_ip("192.0.2.50")
            .expect_err("RFC 5737 TEST-NET-1 expected_ip must be rejected");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("documentation"),
                    "rejection must cite documentation range: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn build_bundle_rejects_documentation_expected_ip_test_net_2() {
        let err = build_bundle_with_expected_ip("198.51.100.5")
            .expect_err("RFC 5737 TEST-NET-2 expected_ip must be rejected");
        assert!(matches!(err, super::DnsZoneError::InvalidFormat(_)));
    }

    #[test]
    fn build_bundle_rejects_documentation_expected_ip_test_net_3() {
        let err = build_bundle_with_expected_ip("203.0.113.99")
            .expect_err("RFC 5737 TEST-NET-3 expected_ip must be rejected");
        assert!(matches!(err, super::DnsZoneError::InvalidFormat(_)));
    }

    #[test]
    fn build_bundle_accepts_rfc1918_10_dot_space() {
        // RFC1918 10/8 stays permissive — operators sometimes deploy
        // mesh in their corporate 10.x space. The zone-bundle
        // validator does not reject; per-deployment policy may
        // narrow further (out of scope here).
        build_bundle_with_expected_ip("10.0.0.5")
            .expect("RFC1918 10.x must remain permissive at zone-bundle layer");
    }

    #[test]
    fn build_bundle_accepts_rfc1918_192_168_dot_space() {
        build_bundle_with_expected_ip("192.168.1.42")
            .expect("RFC1918 192.168.x must remain permissive at zone-bundle layer");
    }

    #[test]
    fn build_bundle_accepts_tailnet_style_100_dot_64_dot_space() {
        build_bundle_with_expected_ip("100.68.1.10")
            .expect("tailnet-style 100.64/10 mesh IP must be accepted");
    }

    #[test]
    fn signed_bundle_roundtrip_verifies_and_preserves_records() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let bundle = build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec!["storage".to_owned()],
            }],
        )
        .expect("bundle should build");
        let wire = render_signed_dns_zone_bundle_wire(&bundle);
        let parsed = parse_signed_dns_zone_bundle_wire(&wire).expect("wire should parse");
        verify_signed_dns_zone_bundle(&parsed, &signing_key.verifying_key())
            .expect("signature should verify");
        assert_eq!(parsed.zone_name, "rustynet");
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].fqdn, "nas.rustynet");
        assert_eq!(parsed.records[0].aliases, vec!["storage".to_owned()]);
    }

    fn valid_wire_bundle() -> String {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let bundle = build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec![],
            }],
        )
        .expect("bundle should build");
        render_signed_dns_zone_bundle_wire(&bundle)
    }

    #[test]
    fn dns_relative_name_rejects_malformed_names() {
        let long_label = "a".repeat(64);
        let total_too_long = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ]
        .join(".");
        let cases = [".nas", "na*s", long_label.as_str(), total_too_long.as_str()];

        for case in cases {
            assert!(
                super::canonicalize_dns_relative_name(case).is_err(),
                "malformed dns name must be rejected: {case}"
            );
        }
    }

    #[test]
    fn parse_wire_rejects_oversized_bundle_line_and_line_count() {
        let oversized_bundle = "a".repeat(super::MAX_BUNDLE_BYTES + 1);
        assert!(parse_signed_dns_zone_bundle_wire(&oversized_bundle).is_err());

        let oversized_line = format!("{}=1", "a".repeat(super::MAX_LINE_BYTES + 1));
        assert!(parse_signed_dns_zone_bundle_wire(&oversized_line).is_err());

        let too_many_lines = "\n".repeat(super::MAX_BUNDLE_LINES + 1);
        assert!(parse_signed_dns_zone_bundle_wire(&too_many_lines).is_err());
    }

    #[test]
    fn parse_wire_enforces_per_line_key_value_and_depth_bounds() {
        // Each per-line bound is checked in the parse loop before the
        // allowed-key check, so a single over-limit line exercises the exact
        // control and must fail closed with the matching reason.
        let long_key = format!("{}=v", "k".repeat(super::MAX_KEY_BYTES + 1));
        let err = parse_signed_dns_zone_bundle_wire(&long_key).unwrap_err();
        assert!(
            format!("{err:?}").contains("key exceeds maximum"),
            "MAX_KEY_BYTES not enforced: {err:?}"
        );

        let long_value = format!("k={}", "v".repeat(super::MAX_VALUE_BYTES + 1));
        let err = parse_signed_dns_zone_bundle_wire(&long_value).unwrap_err();
        assert!(
            format!("{err:?}").contains("value exceeds maximum"),
            "MAX_VALUE_BYTES not enforced: {err:?}"
        );

        // MAX_KEY_DEPTH+1 labels -> split('.').count() exceeds the depth cap.
        let deep_key = format!("{}=v", ["a"; super::MAX_KEY_DEPTH + 1].join("."));
        let err = parse_signed_dns_zone_bundle_wire(&deep_key).unwrap_err();
        assert!(
            format!("{err:?}").contains("depth exceeds maximum"),
            "MAX_KEY_DEPTH not enforced: {err:?}"
        );
    }

    #[test]
    fn parse_wire_rejects_unsupported_version_duplicate_and_field_mismatch() {
        let wire = valid_wire_bundle();

        let bad_version = wire.replacen("version=1", "version=2", 1);
        assert!(parse_signed_dns_zone_bundle_wire(&bad_version).is_err());

        let duplicate_version = format!("version=1\n{wire}");
        assert!(parse_signed_dns_zone_bundle_wire(&duplicate_version).is_err());

        let missing_field = wire
            .lines()
            .filter(|line| !line.starts_with("record.0.aliases="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_signed_dns_zone_bundle_wire(&missing_field).is_err());
    }

    #[test]
    fn verify_bundle_rejects_tampered_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut bundle = build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec![],
            }],
        )
        .expect("bundle should build");

        let replacement = if bundle.signature_hex.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        bundle.signature_hex.replace_range(0..2, replacement);
        assert_eq!(
            verify_signed_dns_zone_bundle(&bundle, &signing_key.verifying_key()).err(),
            Some(super::DnsZoneError::SignatureInvalid)
        );
    }

    #[test]
    fn bundle_builder_rejects_alias_collision() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let err = build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            7,
            &[
                DnsZoneRecordInput {
                    label: "nas".to_owned(),
                    target_node_id: "node-1".to_owned(),
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    expected_ip: "100.68.1.10".to_owned(),
                    ttl_secs: 60,
                    aliases: vec!["backup".to_owned()],
                },
                DnsZoneRecordInput {
                    label: "vault".to_owned(),
                    target_node_id: "node-2".to_owned(),
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    expected_ip: "100.68.1.11".to_owned(),
                    ttl_secs: 60,
                    aliases: vec!["nas".to_owned()],
                },
            ],
        )
        .expect_err("alias collision must fail");
        assert!(err.to_string().contains("collides"));
    }

    #[test]
    fn verifier_key_parser_rejects_empty_content() {
        let err = parse_dns_zone_verifying_key("").expect_err("empty key should fail");
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn watermark_ordering_treats_equal_timestamp_and_nonce_as_equal() {
        let earlier = DnsZoneWatermark {
            version: 1,
            generated_at_unix: 10,
            nonce: 2,
            payload_digest: [1u8; 32],
        };
        let later = DnsZoneWatermark {
            version: 1,
            generated_at_unix: 10,
            nonce: 2,
            payload_digest: [2u8; 32],
        };
        assert_eq!(
            dns_zone_watermark_ordering(&later, &earlier),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn payload_digest_is_stable_for_same_payload() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let bundle = build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: Vec::new(),
            }],
        )
        .expect("bundle should build");
        assert_eq!(
            dns_zone_payload_digest(&bundle),
            dns_zone_payload_digest(&bundle)
        );
    }

    /// Builder/verifier contract gap: the WIRE PARSER enforces the 253-byte
    /// bound on the fully-assembled FQDN (`canonicalize_dns_zone_fqdn`), but
    /// the BUILDER validated only the relative label (`<=253`) and the zone
    /// name (`<=64`) separately — never their assembly. A record whose parts
    /// are individually legal could therefore be SIGNED and DISTRIBUTED, and
    /// only then rejected by every peer's parser: the zone never applies and
    /// the failure surfaces far from the operator's input point. The builder
    /// must enforce the same assembled-name contract it will later verify
    /// against.
    #[test]
    fn build_bundle_rejects_record_fqdn_exceeding_parser_bound() {
        // Four DNS-legal labels: relative name 247 bytes (< 253, accepted by
        // the label canonicalizer), but fqdn = 247 + 1 + 8 = 256 bytes, which
        // is exactly the shape the parser refuses.
        let long_label = [
            "a".repeat(61),
            "b".repeat(61),
            "c".repeat(61),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(long_label.len(), 247);
        let err = build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[11u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: long_label,
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec![],
            }],
        )
        .expect_err("a record whose assembled fqdn exceeds 253 bytes must not build");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("exceeds maximum"),
                    "rejection must cite the fqdn length bound: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }

        // Boundary control: the longest label assembly that still fits the
        // assembled bound (244 + 1 + 8 = 253) must remain buildable, so the
        // check narrows exactly at the parser's limit and not below it.
        let boundary_label = [
            "e".repeat(61),
            "f".repeat(61),
            "g".repeat(61),
            "h".repeat(58),
        ]
        .join(".");
        assert_eq!(boundary_label.len(), 244);
        let bundle = build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[11u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: boundary_label,
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec![],
            }],
        )
        .expect("an fqdn of exactly 253 bytes must still build");
        assert_eq!(bundle.records[0].fqdn.len(), 253);
    }

    /// Alias half of the same gap: `parse_aliases` enforces
    /// `alias.{zone_name}` <= 253 bytes on the wire, but the builder checked
    /// only the relative alias name — a signed bundle carrying an over-long
    /// alias fqdn was un-parseable by its own verifier.
    #[test]
    fn build_bundle_rejects_alias_fqdn_exceeding_parser_bound() {
        let long_alias = [
            "i".repeat(61),
            "j".repeat(61),
            "k".repeat(61),
            "l".repeat(61),
        ]
        .join(".");
        assert_eq!(long_alias.len(), 247);
        let err = build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[12u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec![long_alias],
            }],
        )
        .expect_err("an alias whose assembled fqdn exceeds 253 bytes must not build");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("alias exceeds maximum"),
                    "rejection must cite the alias fqdn length bound: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }

        // Control: a normal short alias still builds (positive path intact).
        build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[12u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: vec!["storage".to_owned()],
            }],
        )
        .expect("a short alias must still build");
    }

    /// Same mint-vs-refuse class, field-size half: each of the 8 aliases
    /// below is individually legal (assembled fqdn 209 <= 253, so the
    /// per-alias bound passes), but the SERIALIZED aliases value the parser
    /// reads is their comma join — 8 x 200 + 7 = 1607 bytes, over the
    /// parser's MAX_VALUE_BYTES (1536) per-line DoS bound. The builder must
    /// refuse to sign what its own verifier would refuse at line-parse time.
    #[test]
    fn build_bundle_rejects_alias_list_exceeding_parser_value_bound() {
        let alias_at = |first: char| {
            format!(
                "{first}{}.{}.{}.{}",
                "a".repeat(49),
                "b".repeat(50),
                "c".repeat(50),
                "d".repeat(47)
            )
        };
        let long_aliases: Vec<String> = (0..8).map(|i| alias_at((b'a' + i) as char)).collect();
        let joined_len: usize = long_aliases.iter().map(String::len).sum::<usize>()
            + long_aliases.len().saturating_sub(1);
        assert_eq!(joined_len, 1607);
        assert!(joined_len > super::MAX_VALUE_BYTES);
        for alias in &long_aliases {
            assert!(alias.len() + 1 + "rustynet".len() <= 253);
        }
        let err = build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[13u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: long_aliases,
            }],
        )
        .expect_err(
            "aliases whose serialized value exceeds the parser's per-line bound must not build",
        );
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("value exceeds maximum"),
                    "rejection must cite the serialized value bound: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }

        // Boundary control: the same shape with shorter aliases joins to a
        // value under MAX_VALUE_BYTES and must still build.
        let short_aliases: Vec<String> = (0..8)
            .map(|i| {
                format!(
                    "{i}{}.{}.{}.{}",
                    "e".repeat(44),
                    "f".repeat(45),
                    "g".repeat(45),
                    "h".repeat(42)
                )
            })
            .collect();
        let short_joined: usize = short_aliases.iter().map(String::len).sum::<usize>() + 7;
        assert_eq!(short_joined, 1447);
        assert!(short_joined <= super::MAX_VALUE_BYTES);
        build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[13u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &[DnsZoneRecordInput {
                label: "nas".to_owned(),
                target_node_id: "node-nas-1".to_owned(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_owned(),
                ttl_secs: 60,
                aliases: short_aliases,
            }],
        )
        .expect("aliases under the serialized value bound must still build");
    }

    /// Aggregate half: the builder caps records only PER RECORD; the parser
    /// refuses any wire over MAX_BUNDLE_BYTES (256 KiB) outright. Enough
    /// individually-legal mid-size records therefore mint a signed bundle no
    /// peer can parse. The builder must enforce the parser's total-size
    /// contract before signing.
    #[test]
    fn build_bundle_rejects_serialized_bundle_exceeding_parser_size_bound() {
        let record = |index: usize| DnsZoneRecordInput {
            label: format!("n{index:04}-{}.{}", "a".repeat(48), "b".repeat(55)),
            target_node_id: format!("node-{index:04}-{}", "x".repeat(50)),
            rr_type: DnsRecordType::A,
            target_addr_kind: DnsTargetAddrKind::MeshIpv4,
            expected_ip: "100.68.1.10".to_owned(),
            ttl_secs: 60,
            aliases: vec![],
        };
        let err = build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[14u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &(0..800).map(record).collect::<Vec<_>>(),
        )
        .expect_err("a bundle whose rendered wire exceeds MAX_BUNDLE_BYTES must not build");
        match err {
            super::DnsZoneError::InvalidFormat(reason) => {
                assert!(
                    reason.contains("exceeds maximum wire size"),
                    "rejection must cite the aggregate wire-size bound: {reason}"
                );
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }

        // Control: the same record shape at a count that stays under the
        // aggregate bound must still build (the check narrows at size, not
        // at record count).
        build_signed_dns_zone_bundle(
            &SigningKey::from_bytes(&[14u8; 32]),
            "rustynet",
            "client-1",
            1_773_000_000,
            60,
            42,
            &(0..200).map(record).collect::<Vec<_>>(),
        )
        .expect("a bundle under the aggregate wire-size bound must still build");
    }

    #[test]
    fn parse_wire_never_panics_on_truncations_and_arbitrary_input() {
        // Parser-never-panics invariant (the property a fuzzer would assert):
        // the signed-zone wire decoder parses untrusted bundle bytes, so on any
        // input — truncated mid-field, bit-flipped, or arbitrary — it must
        // return Err, never panic. Any panic propagates and fails the test.
        let valid = valid_wire_bundle();

        // Every char-boundary prefix of a valid wire (truncation inside any
        // field, incl. a length/count field).
        for (offset, _) in valid
            .char_indices()
            .chain(std::iter::once((valid.len(), ' ')))
        {
            let _ = parse_signed_dns_zone_bundle_wire(&valid[..offset]);
        }

        // Single-byte ASCII corruption at every offset (the wire is ASCII).
        let valid_bytes = valid.as_bytes();
        for i in 0..valid_bytes.len() {
            let mut corrupted = valid_bytes.to_vec();
            corrupted[i] = corrupted[i].wrapping_add(1);
            if let Ok(text) = std::str::from_utf8(&corrupted) {
                let _ = parse_signed_dns_zone_bundle_wire(text);
            }
        }

        // Structural garbage: empty, whitespace, partial key=value lines, a
        // flood of lines, and deterministic pseudo-random ASCII.
        for probe in [
            "",
            "\n\n\n",
            "version=",
            "version=1\n",
            "=\n=\n=\n",
            &"a=b\n".repeat(10_000),
        ] {
            let _ = parse_signed_dns_zone_bundle_wire(probe);
        }
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        for len in 0..256usize {
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Printable ASCII range so we always have a valid &str.
                s.push((0x20 + (seed >> 40) as u8 % 0x5f) as char);
            }
            let _ = parse_signed_dns_zone_bundle_wire(&s);
        }
    }
}
