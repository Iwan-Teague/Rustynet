#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
            "dns zone name exceeds max length".to_string(),
        ));
    }
    Ok(normalized)
}

pub fn canonicalize_dns_relative_name(value: &str) -> Result<String, DnsZoneError> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns name must not be empty".to_string(),
        ));
    }
    if trimmed.starts_with('.') || trimmed.contains('*') {
        return Err(DnsZoneError::InvalidFormat(
            "dns name contains forbidden characters".to_string(),
        ));
    }
    let mut parts = Vec::new();
    for raw_part in trimmed.split('.') {
        if raw_part.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "dns name contains an empty label".to_string(),
            ));
        }
        let part = raw_part.to_ascii_lowercase();
        if part.len() > 63 {
            return Err(DnsZoneError::InvalidFormat(
                "dns label exceeds maximum length".to_string(),
            ));
        }
        if part.starts_with('-') || part.ends_with('-') {
            return Err(DnsZoneError::InvalidFormat(
                "dns label must not start or end with '-'".to_string(),
            ));
        }
        if !part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DnsZoneError::InvalidFormat(
                "dns label contains invalid characters".to_string(),
            ));
        }
        parts.push(part);
    }
    let joined = parts.join(".");
    if joined.len() > 253 {
        return Err(DnsZoneError::InvalidFormat(
            "dns name exceeds maximum length".to_string(),
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
            "missing dns zone verifier key".to_string(),
        ));
    }
    let key_line = trimmed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing dns zone verifier key".to_string()))?;
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
            "generated_at_unix must be greater than zero".to_string(),
        ));
    }
    if ttl_secs == 0 || ttl_secs > 300 {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone ttl must be in range 1..=300".to_string(),
        ));
    }
    if records.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone requires at least one record".to_string(),
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
            "subject_node_id must not be empty".to_string(),
        ));
    }
    let expires_at_unix = generated_at_unix.saturating_add(ttl_secs);
    if generated_at_unix >= expires_at_unix {
        return Err(DnsZoneError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
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
    let signature = signing_key.sign(payload.as_bytes());
    Ok(SignedDnsZoneBundle {
        payload,
        signature_hex: hex_bytes(&signature.to_bytes()),
        generated_at_unix,
        expires_at_unix,
        zone_name,
        subject_node_id: subject_node_id.to_string(),
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
            "dns zone bundle has invalid generated/expires ordering".to_string(),
        ));
    }
    let signature_bytes = decode_hex_to_fixed::<64>(&bundle.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(bundle.payload.as_bytes(), &signature)
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
            .ok_or_else(|| DnsZoneError::InvalidFormat("invalid dns zone line".to_string()))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "dns zone field key must not be empty".to_string(),
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
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(DnsZoneError::InvalidFormat(format!(
                "duplicate dns zone field: {key}"
            )));
        }
    }

    if fields.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "dns zone bundle is empty".to_string(),
        ));
    }

    let version = fields
        .get("version")
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing version".to_string()))?;
    if version != "1" {
        return Err(DnsZoneError::InvalidFormat(
            "unsupported dns zone bundle version".to_string(),
        ));
    }

    let zone_name = canonicalize_dns_zone_name(
        fields
            .get("zone_name")
            .ok_or_else(|| DnsZoneError::InvalidFormat("missing zone_name".to_string()))?,
    )?;
    let subject_node_id = fields
        .get("subject_node_id")
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing subject_node_id".to_string()))?
        .trim()
        .to_string();
    if subject_node_id.is_empty() {
        return Err(DnsZoneError::InvalidFormat(
            "subject_node_id must not be empty".to_string(),
        ));
    }
    let generated_at_unix = parse_u64_field(&fields, "generated_at_unix")?;
    let expires_at_unix = parse_u64_field(&fields, "expires_at_unix")?;
    if generated_at_unix >= expires_at_unix {
        return Err(DnsZoneError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
        ));
    }
    let nonce = parse_u64_field(&fields, "nonce")?;
    let signature_hex = fields
        .get("signature")
        .cloned()
        .ok_or_else(|| DnsZoneError::InvalidFormat("missing dns zone signature".to_string()))?;
    let record_count = parse_usize_field(&fields, "record_count")?;
    if record_count == 0 || record_count > MAX_RECORD_COUNT {
        return Err(DnsZoneError::InvalidFormat(format!(
            "dns zone record_count must be in range 1..={MAX_RECORD_COUNT}"
        )));
    }
    let expected_field_count = record_count
        .checked_mul(8)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| DnsZoneError::InvalidFormat("dns zone field count overflow".to_string()))?;
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
                "duplicate dns record name".to_string(),
            ));
        }

        let target_node_id = required_indexed_field(&fields, index, "target_node_id")?
            .trim()
            .to_string();
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
                    "dns alias collides with another record".to_string(),
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
        .then_with(|| current.payload_digest.cmp(&previous.payload_digest))
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
                "dns record ttl must be in range 1..=300".to_string(),
            ));
        }
        let label = canonicalize_dns_relative_name(record.label.as_str())?;
        let fqdn = format!("{label}.{zone_name}");
        if !seen_names.insert(fqdn.clone()) {
            return Err(DnsZoneError::InvalidFormat(
                "duplicate dns record name".to_string(),
            ));
        }
        let target_node_id = record.target_node_id.trim().to_string();
        if target_node_id.is_empty() {
            return Err(DnsZoneError::InvalidFormat(
                "target_node_id must not be empty".to_string(),
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
            if !seen_names.insert(alias_fqdn) {
                return Err(DnsZoneError::InvalidFormat(
                    "dns alias collides with another record".to_string(),
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
            Ok(ip.to_string())
        }
    }
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
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], DnsZoneError> {
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(DnsZoneError::InvalidFormat(
            "hex value has invalid length".to_string(),
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
            "hex value contains invalid character".to_string(),
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
                label: "nas".to_string(),
                target_node_id: "node-nas-1".to_string(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_string(),
                ttl_secs: 60,
                aliases: vec!["storage".to_string()],
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
        assert_eq!(parsed.records[0].aliases, vec!["storage".to_string()]);
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
                    label: "nas".to_string(),
                    target_node_id: "node-1".to_string(),
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    expected_ip: "100.68.1.10".to_string(),
                    ttl_secs: 60,
                    aliases: vec!["backup".to_string()],
                },
                DnsZoneRecordInput {
                    label: "vault".to_string(),
                    target_node_id: "node-2".to_string(),
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    expected_ip: "100.68.1.11".to_string(),
                    ttl_secs: 60,
                    aliases: vec!["nas".to_string()],
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
    fn watermark_ordering_uses_digest_after_timestamp_and_nonce() {
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
            std::cmp::Ordering::Greater
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
                label: "nas".to_string(),
                target_node_id: "node-nas-1".to_string(),
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                expected_ip: "100.68.1.10".to_string(),
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
}
