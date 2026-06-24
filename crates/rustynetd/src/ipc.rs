#![forbid(unsafe_code)]

use std::io::BufRead;

#[derive(Debug)]
pub enum RemoteOpsEnvelopeParseError {
    Io(std::io::Error),
    MissingSignature,
    InvalidSignatureHex(String),
    MissingSubject,
    MissingNonce,
    MissingCommand,
    InvalidFormat,
    InvalidNonce(String),
}

impl std::fmt::Display for RemoteOpsEnvelopeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::MissingSignature => write!(f, "missing signature"),
            Self::InvalidSignatureHex(e) => write!(f, "invalid signature hex: {e}"),
            Self::MissingSubject => write!(f, "missing subject"),
            Self::MissingNonce => write!(f, "missing nonce"),
            Self::MissingCommand => write!(f, "missing command"),
            Self::InvalidFormat => write!(f, "invalid format"),
            Self::InvalidNonce(e) => write!(f, "invalid nonce: {e}"),
        }
    }
}

impl std::error::Error for RemoteOpsEnvelopeParseError {}

impl From<std::io::Error> for RemoteOpsEnvelopeParseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcCommand {
    Status,
    Netcheck,
    StateRefresh,
    ExitNodeSelect(String),
    ExitNodeOff,
    LanAccessOn,
    LanAccessOff,
    DnsInspect,
    RouteAdvertise(String),
    /// D12.b — symmetric counterpart of `RouteAdvertise`. Removes
    /// a previously-advertised route from `advertised_routes` and
    /// triggers a dataplane reconcile. For `0.0.0.0/0` on an
    /// admin primary this tears down exit-serving forwarding +
    /// NAT (the `exit → admin` role transition in the
    /// `NodeRoleTaxonomy_2026-05-21` design). Admin-gated.
    RouteRetract(String),
    KeyRotate,
    KeyRevoke,
    /// D2.5 push-loop entry point. Carries the already-serialised
    /// wire bytes of a [`crate::peer_gossip::GossipBundle`]; the
    /// daemon hands them straight to `deserialise_bundle` +
    /// `accept_bundle`. NB: the IPC envelope's outer signature (when
    /// present via `remote-op-v1`) is irrelevant for authenticity —
    /// the bundle carries its own Ed25519 signature, and that is the
    /// only authority the daemon trusts.
    PushGossipBundle {
        wire_bytes: Vec<u8>,
    },
    /// D2.7 enrollment-token consume entry point. The operator passes
    /// the token (URL-safe base64), the enrollee's Ed25519 verifying
    /// key (URL-safe base64 of 32 bytes), and the enrollee's gossip
    /// push address (`ip:port`). The daemon runs
    /// `enrollment_consume::consume_and_register_peer` under
    /// `PushAddressPolicy::Strict`, persists the ledger, and
    /// registers the enrollee in the gossip subsystem.
    EnrollmentConsume {
        token: String,
        pubkey_b64: String,
        push_addr: String,
    },
    /// Membership governance signed-update apply entry point.
    /// Carries the canonical signed-update envelope bytes (UTF-8
    /// key=value text from `encode_signed_update`). The daemon
    /// re-runs every signature/freshness/replay/threshold/state-root
    /// check in `apply_signed_update` before any snapshot/log
    /// mutation: passing the daemon's local IPC peer-credential gate
    /// is NOT sufficient on its own — quorum-signed approval remains
    /// mandatory. The envelope itself is a public artifact (its
    /// signatures bind the content), so the wire form transports the
    /// raw bytes base64-url-safe-no-pad encoded.
    MembershipApply {
        signed_update_wire: Vec<u8>,
    },
    Unknown(String),
}

impl IpcCommand {
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            IpcCommand::ExitNodeSelect(_)
                | IpcCommand::ExitNodeOff
                | IpcCommand::LanAccessOn
                | IpcCommand::LanAccessOff
                | IpcCommand::StateRefresh
                | IpcCommand::RouteAdvertise(_)
                | IpcCommand::RouteRetract(_)
                | IpcCommand::KeyRotate
                | IpcCommand::KeyRevoke
                | IpcCommand::PushGossipBundle { .. }
                | IpcCommand::EnrollmentConsume { .. }
                | IpcCommand::MembershipApply { .. }
        )
    }

    pub fn as_wire(&self) -> String {
        match self {
            IpcCommand::Status => "status".to_owned(),
            IpcCommand::Netcheck => "netcheck".to_owned(),
            IpcCommand::StateRefresh => "state refresh".to_owned(),
            IpcCommand::ExitNodeSelect(node) => format!("exit-node select {node}"),
            IpcCommand::ExitNodeOff => "exit-node off".to_owned(),
            IpcCommand::LanAccessOn => "lan-access on".to_owned(),
            IpcCommand::LanAccessOff => "lan-access off".to_owned(),
            IpcCommand::DnsInspect => "dns inspect".to_owned(),
            IpcCommand::RouteAdvertise(cidr) => format!("route advertise {cidr}"),
            IpcCommand::RouteRetract(cidr) => format!("route retract {cidr}"),
            IpcCommand::KeyRotate => "key rotate".to_owned(),
            IpcCommand::KeyRevoke => "key revoke".to_owned(),
            IpcCommand::PushGossipBundle { wire_bytes } => {
                use base64::Engine;
                format!(
                    "gossip push {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire_bytes)
                )
            }
            IpcCommand::EnrollmentConsume {
                token,
                pubkey_b64,
                push_addr,
            } => format!("enrollment consume {token} {pubkey_b64} {push_addr}"),
            IpcCommand::MembershipApply { signed_update_wire } => {
                use base64::Engine;
                format!(
                    "membership apply {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed_update_wire)
                )
            }
            IpcCommand::Unknown(raw) => raw.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcResponse {
    pub ok: bool,
    pub message: String,
}

impl IpcResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }

    pub fn to_wire(&self) -> String {
        let status = if self.ok { "ok" } else { "err" };
        format!("{status}|{}", self.message.replace('\n', " "))
    }

    pub fn from_wire(value: &str) -> Self {
        let trimmed = value.trim();
        let mut parts = trimmed.splitn(2, '|');
        let status = parts.next().unwrap_or("err");
        let message = parts.next().unwrap_or("invalid response").to_owned();
        Self {
            ok: status == "ok",
            message,
        }
    }
}

pub fn parse_command(raw: &str) -> IpcCommand {
    let tokens = raw
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    match tokens.as_slice() {
        [cmd] if cmd == "status" => IpcCommand::Status,
        [cmd] if cmd == "netcheck" => IpcCommand::Netcheck,
        [cmd, subcmd] if cmd == "state" && subcmd == "refresh" => IpcCommand::StateRefresh,
        [cmd, subcmd, node] if cmd == "exit-node" && subcmd == "select" => {
            IpcCommand::ExitNodeSelect(node.clone())
        }
        [cmd, subcmd] if cmd == "exit-node" && subcmd == "off" => IpcCommand::ExitNodeOff,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "on" => IpcCommand::LanAccessOn,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "off" => IpcCommand::LanAccessOff,
        [cmd, subcmd] if cmd == "dns" && subcmd == "inspect" => IpcCommand::DnsInspect,
        [cmd, subcmd, cidr] if cmd == "route" && subcmd == "advertise" => {
            IpcCommand::RouteAdvertise(cidr.clone())
        }
        [cmd, subcmd, cidr] if cmd == "route" && subcmd == "retract" => {
            IpcCommand::RouteRetract(cidr.clone())
        }
        [cmd, subcmd] if cmd == "key" && subcmd == "rotate" => IpcCommand::KeyRotate,
        [cmd, subcmd] if cmd == "key" && subcmd == "revoke" => IpcCommand::KeyRevoke,
        [cmd, subcmd, token, pubkey_b64, push_addr]
            if cmd == "enrollment" && subcmd == "consume" =>
        {
            // D2.7 — `enrollment consume <token> <pubkey-b64> <addr:port>`.
            // The token, pubkey, and address are all bytes/text the
            // operator paste-edits; the daemon-side handler validates
            // each individually before mutating any state. We
            // intentionally do NOT pre-validate them here so a
            // malformed input surfaces as a typed daemon-side error
            // rather than a generic Unknown dispatch.
            IpcCommand::EnrollmentConsume {
                token: token.clone(),
                pubkey_b64: pubkey_b64.clone(),
                push_addr: push_addr.clone(),
            }
        }
        [cmd, subcmd, payload_b64] if cmd == "gossip" && subcmd == "push" => {
            // D2.5: the third token is the URL-safe-base64-no-pad
            // encoding of a serialised GossipBundle. The bundle
            // itself carries its own Ed25519 signature; we therefore
            // only need to surface the raw wire bytes here and let
            // the daemon's accept_bundle path do all real
            // verification. A malformed base64 dispatches as
            // `Unknown` so the daemon answers with an explicit error
            // string instead of silently accepting empty input.
            use base64::Engine;
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()) {
                Ok(wire_bytes) => IpcCommand::PushGossipBundle { wire_bytes },
                Err(_) => IpcCommand::Unknown(raw.trim().to_owned()),
            }
        }
        [cmd, subcmd, payload_b64] if cmd == "membership" && subcmd == "apply" => {
            // Gap 2 daemon-side apply: the third token is the URL-
            // safe-base64-no-pad encoding of the canonical signed
            // membership update envelope (UTF-8 key=value text
            // produced by `encode_signed_update`). The envelope
            // carries its own approver Ed25519 signatures and the
            // daemon-side handler re-runs every threshold / signer-
            // authorisation / freshness / replay check via
            // `apply_signed_update` before any snapshot/log
            // mutation. Local IPC peer-credential authorisation
            // alone is NOT sufficient to mutate membership.
            // Malformed base64 dispatches as `Unknown` so the
            // operator sees an explicit error string instead of a
            // silent accept of empty payload.
            use base64::Engine;
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()) {
                Ok(signed_update_wire) => IpcCommand::MembershipApply { signed_update_wire },
                Err(_) => IpcCommand::Unknown(raw.trim().to_owned()),
            }
        }
        _ => IpcCommand::Unknown(raw.trim().to_owned()),
    }
}

pub fn validate_cidr(value: &str) -> bool {
    // Structural parse (RSA-0027): a character-set-only pre-filter accepts
    // malformed inputs like `999.999.999.999/33`. Require a parseable IP base
    // and a family-appropriate prefix length, mirroring the privileged-helper
    // `is_cidr_token` gate so this is an actual validation, not a weak filter.
    if value.len() > 43 {
        return false;
    }
    let Some((base, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(addr) = base.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommandEnvelope {
    pub subject: String,
    pub nonce: u64,
    pub command: IpcCommand,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEnvelope {
    Local(IpcCommand),
    Remote(RemoteCommandEnvelope),
}

pub const REMOTE_OPS_WIRE_PREFIX: &str = "remote-op-v1 ";
pub const DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT: &str = "user:admin";
pub const MAX_COMMAND_BYTES: u64 = 4096;

pub fn remote_ops_signature_payload(subject: &str, nonce: u64, command: &IpcCommand) -> Vec<u8> {
    format!(
        "subject={}\nnonce={}\ncommand={}\n",
        subject,
        nonce,
        command.as_wire()
    )
    .into_bytes()
}

pub fn read_command_envelope<R: std::io::Read>(
    stream: R,
) -> Result<CommandEnvelope, RemoteOpsEnvelopeParseError> {
    let mut reader = std::io::BufReader::new(stream.take(MAX_COMMAND_BYTES));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim();
    if line.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty command").into());
    }
    if line.contains('\0') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "command contains null byte",
        )
        .into());
    }

    if let Some(payload) = line.strip_prefix(REMOTE_OPS_WIRE_PREFIX) {
        // expected format: subject=<sub|b64> nonce=<u64> command=<wire> signature=<hex>

        let parts: Vec<&str> = payload.split(" signature=").collect();
        if parts.len() != 2 {
            return Err(RemoteOpsEnvelopeParseError::MissingSignature);
        }
        let content = parts[0];
        let signature_hex = parts[1];

        // **Security**: reject odd-length hex strings BEFORE entering
        // the slice loop. The original code did `signature_hex[i..i + 2]`
        // which would panic on slice-out-of-bounds when `len % 2 != 0`
        // and `i = len - 1`. A crafted IPC envelope with an odd-length
        // signature= field could panic the daemon. Fail-closed here.
        if !signature_hex.len().is_multiple_of(2) {
            return Err(RemoteOpsEnvelopeParseError::InvalidSignatureHex(format!(
                "signature hex length {} is not a multiple of 2",
                signature_hex.len()
            )));
        }
        // Also reject anything that isn't ASCII — the str-slice into a
        // multi-byte UTF-8 codepoint would panic on a non-char-boundary.
        if !signature_hex.is_ascii() {
            return Err(RemoteOpsEnvelopeParseError::InvalidSignatureHex(
                "signature hex contains non-ASCII characters".to_owned(),
            ));
        }
        let signature = (0..signature_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&signature_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| RemoteOpsEnvelopeParseError::InvalidSignatureHex(e.to_string()))?;

        // content: subject=... nonce=... command=...
        let mut parts = content.splitn(3, ' ');
        let subject_part = parts
            .next()
            .ok_or(RemoteOpsEnvelopeParseError::MissingSubject)?;
        let nonce_part = parts
            .next()
            .ok_or(RemoteOpsEnvelopeParseError::MissingNonce)?;
        let command_part = parts
            .next()
            .ok_or(RemoteOpsEnvelopeParseError::MissingCommand)?;

        if !subject_part.starts_with("subject=")
            || !nonce_part.starts_with("nonce=")
            || !command_part.starts_with("command=")
        {
            return Err(RemoteOpsEnvelopeParseError::InvalidFormat);
        }

        let subject = subject_part["subject=".len()..].to_string();
        let nonce = nonce_part["nonce=".len()..]
            .parse::<u64>()
            .map_err(|e| RemoteOpsEnvelopeParseError::InvalidNonce(e.to_string()))?;
        let command_wire = &command_part["command=".len()..];

        let command = parse_command(command_wire);

        Ok(CommandEnvelope::Remote(RemoteCommandEnvelope {
            subject,
            nonce,
            command,
            signature,
        }))
    } else {
        Ok(CommandEnvelope::Local(parse_command(line)))
    }
}

#[cfg(test)]
mod tests {
    use super::{IpcCommand, IpcResponse, parse_command, read_command_envelope, validate_cidr};

    #[test]
    fn parse_and_wire_roundtrip_for_mutating_command() {
        let command = parse_command("exit-node select mini-pc-1");
        assert_eq!(command, IpcCommand::ExitNodeSelect("mini-pc-1".to_owned()));
        assert!(command.is_mutating());
        assert_eq!(command.as_wire(), "exit-node select mini-pc-1");
    }

    #[test]
    fn parse_key_rotation_mutations() {
        let rotate = parse_command("key rotate");
        assert_eq!(rotate, IpcCommand::KeyRotate);
        assert!(rotate.is_mutating());
        assert_eq!(rotate.as_wire(), "key rotate");

        let revoke = parse_command("key revoke");
        assert_eq!(revoke, IpcCommand::KeyRevoke);
        assert!(revoke.is_mutating());
        assert_eq!(revoke.as_wire(), "key revoke");
    }

    #[test]
    fn parse_state_refresh_mutation() {
        let command = parse_command("state refresh");
        assert_eq!(command, IpcCommand::StateRefresh);
        assert!(command.is_mutating());
        assert_eq!(command.as_wire(), "state refresh");
    }

    #[test]
    fn response_wire_roundtrip_preserves_ok_and_message() {
        let wire = IpcResponse::ok("done").to_wire();
        let decoded = IpcResponse::from_wire(&wire);
        assert!(decoded.ok);
        assert_eq!(decoded.message, "done");
    }

    #[test]
    fn cidr_validation_rejects_non_numeric_payloads() {
        assert!(validate_cidr("192.168.1.0/24"));
        assert!(validate_cidr("fd00::/64"));
        assert!(!validate_cidr("192.168.1.0/24; rm -rf /"));
        assert!(!validate_cidr("not-a-cidr"));
    }

    #[test]
    fn cidr_validation_is_structural_not_just_charset() {
        // RSA-0027: the char-set-only pre-filter wrongly accepted these.
        assert!(!validate_cidr("999.999.999.999/33"), "out-of-range octets");
        assert!(!validate_cidr("192.168.1.0/33"), "IPv4 prefix > 32");
        assert!(!validate_cidr("fd00::/129"), "IPv6 prefix > 128");
        assert!(!validate_cidr("192.168.1.0"), "missing prefix");
        assert!(!validate_cidr("192.168.1.0/"), "empty prefix");
        assert!(!validate_cidr("/24"), "missing address");
        assert!(!validate_cidr("dead::beef::1/64"), "malformed IPv6");
        // Boundary values still accepted.
        assert!(validate_cidr("0.0.0.0/0"));
        assert!(validate_cidr("255.255.255.255/32"));
        assert!(validate_cidr("::/0"));
    }

    #[test]
    fn read_command_envelope_rejects_odd_length_signature_hex_without_panicking() {
        // Security pin: a crafted IPC envelope with an odd-length
        // `signature=` field would previously hit
        // `signature_hex[i..i + 2]` slice-out-of-bounds and panic
        // the daemon. Must fail gracefully.
        let bad_odd = b"remote-op-v1 subject=foo nonce=1 command=status signature=abc\n";
        let err = read_command_envelope(&bad_odd[..])
            .expect_err("odd-length signature hex must surface as error");
        let display = format!("{err:?}");
        assert!(
            display.contains("multiple of 2") || display.contains("InvalidSignatureHex"),
            "diagnostic should describe the odd-length problem, got: {display}"
        );
    }

    #[test]
    fn parse_and_wire_round_trips_push_gossip_bundle() {
        // Round-trip pin for the D2.5 IPC verb. The wire form uses
        // URL-safe base64 with no padding so the third token never
        // contains '+', '/', or '=' — all of which would split-
        // whitespace OK but historically confuse hand-typed clients.
        let bundle_bytes = vec![1u8, 2, 3, 4, 0xff, 0, 7, 8];
        let cmd = IpcCommand::PushGossipBundle {
            wire_bytes: bundle_bytes.clone(),
        };
        let wire = cmd.as_wire();
        assert!(
            wire.starts_with("gossip push "),
            "wire form must start with the verb prefix; got: {wire}"
        );
        assert!(
            cmd.is_mutating(),
            "PushGossipBundle must classify as mutating"
        );
        let parsed = parse_command(&wire);
        match parsed {
            IpcCommand::PushGossipBundle { wire_bytes } => {
                assert_eq!(wire_bytes, bundle_bytes);
            }
            other => panic!("expected PushGossipBundle, got {other:?}"),
        }
    }

    #[test]
    fn parse_and_wire_round_trips_enrollment_consume() {
        // D2.7 wire-form pin: the verb must round-trip a 3-token
        // payload (token, pubkey-b64, push-addr) exactly. Any
        // future re-ordering or whitespace mishandling would break
        // the CLI ↔ daemon contract.
        let cmd = IpcCommand::EnrollmentConsume {
            token: "abcDEF123-_".to_owned(),
            pubkey_b64: "uvwXYZ456__".to_owned(),
            push_addr: "10.0.0.5:51821".to_owned(),
        };
        let wire = cmd.as_wire();
        assert!(
            wire.starts_with("enrollment consume "),
            "wire form must start with the verb prefix; got: {wire}"
        );
        assert!(cmd.is_mutating(), "EnrollmentConsume must be mutating");
        let parsed = parse_command(&wire);
        match parsed {
            IpcCommand::EnrollmentConsume {
                token,
                pubkey_b64,
                push_addr,
            } => {
                assert_eq!(token, "abcDEF123-_");
                assert_eq!(pubkey_b64, "uvwXYZ456__");
                assert_eq!(push_addr, "10.0.0.5:51821");
            }
            other => panic!("expected EnrollmentConsume, got {other:?}"),
        }
    }

    #[test]
    fn route_retract_round_trips_through_wire_and_parse() {
        // D12.b: symmetric counterpart of RouteAdvertise. Pin the
        // wire format (`route retract <cidr>`) + parse round-trip +
        // is_mutating bit so the role-set orchestrator can call it
        // through the existing send_command path.
        let cmd = IpcCommand::RouteRetract("0.0.0.0/0".to_owned());
        let wire = cmd.as_wire();
        assert_eq!(wire, "route retract 0.0.0.0/0");
        assert!(cmd.is_mutating(), "RouteRetract must be mutating");
        let parsed = parse_command(&wire);
        assert_eq!(parsed, IpcCommand::RouteRetract("0.0.0.0/0".to_owned()));
    }

    #[test]
    fn route_retract_distinguished_from_route_advertise() {
        let advertise = parse_command("route advertise 10.0.0.0/24");
        let retract = parse_command("route retract 10.0.0.0/24");
        assert_eq!(
            advertise,
            IpcCommand::RouteAdvertise("10.0.0.0/24".to_owned())
        );
        assert_eq!(retract, IpcCommand::RouteRetract("10.0.0.0/24".to_owned()));
        assert_ne!(advertise, retract);
    }

    #[test]
    fn parse_command_rejects_malformed_base64_for_gossip_push() {
        // A `gossip push <not-base64>` envelope must fall through to
        // Unknown so the daemon answers with an explicit error
        // string. Specifically: must NOT silently produce a
        // PushGossipBundle with an empty wire payload.
        let parsed = parse_command("gossip push !@#$%not-base64");
        assert!(
            matches!(parsed, IpcCommand::Unknown(_)),
            "malformed base64 must dispatch as Unknown; got {parsed:?}"
        );
    }

    #[test]
    fn parse_and_wire_round_trips_membership_apply() {
        // Gap 2 wire-form pin: the verb must round-trip a canonical
        // signed-update envelope payload exactly. The envelope is
        // UTF-8 text in production; we round-trip arbitrary bytes
        // here so the wire form does not silently truncate non-text
        // bytes that a future schema bump might include.
        let payload =
            b"payload_hex=deadbeef\nsig_count=1\nsig.0.approver_id=owner\nsig.0.signature_hex=00\n"
                .to_vec();
        let cmd = IpcCommand::MembershipApply {
            signed_update_wire: payload.clone(),
        };
        let wire = cmd.as_wire();
        assert!(
            wire.starts_with("membership apply "),
            "wire form must start with the verb prefix; got: {wire}"
        );
        assert!(
            cmd.is_mutating(),
            "MembershipApply must classify as mutating"
        );
        let parsed = parse_command(&wire);
        match parsed {
            IpcCommand::MembershipApply { signed_update_wire } => {
                assert_eq!(signed_update_wire, payload);
            }
            other => panic!("expected MembershipApply, got {other:?}"),
        }
    }

    #[test]
    fn parse_command_rejects_malformed_base64_for_membership_apply() {
        // A `membership apply <not-base64>` envelope must fall
        // through to Unknown rather than silently produce an empty
        // MembershipApply. The daemon-side handler trusts that an
        // explicit MembershipApply variant always carries a
        // base64-decoded payload that was at least syntactically
        // well-formed at the IPC layer.
        let parsed = parse_command("membership apply !@#$%not-base64");
        assert!(
            matches!(parsed, IpcCommand::Unknown(_)),
            "malformed base64 must dispatch as Unknown; got {parsed:?}"
        );
    }

    #[test]
    fn read_command_envelope_rejects_non_ascii_signature_hex_without_panicking() {
        // Security pin: a `signature=` value containing multi-byte
        // UTF-8 codepoints would previously panic when slicing on
        // a non-char-boundary. Must fail gracefully.
        let envelope: Vec<u8> =
            b"remote-op-v1 subject=foo nonce=1 command=status signature=ab\xc3\xa9\n".to_vec();
        let err =
            read_command_envelope(&envelope[..]).expect_err("non-ASCII signature hex must error");
        let display = format!("{err:?}");
        assert!(
            display.contains("non-ASCII") || display.contains("InvalidSignatureHex"),
            "diagnostic should describe the non-ASCII problem, got: {display}"
        );
    }
}
