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
                | IpcCommand::KeyRotate
                | IpcCommand::KeyRevoke
                | IpcCommand::PushGossipBundle { .. }
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
            IpcCommand::KeyRotate => "key rotate".to_owned(),
            IpcCommand::KeyRevoke => "key revoke".to_owned(),
            IpcCommand::PushGossipBundle { wire_bytes } => {
                use base64::Engine;
                format!(
                    "gossip push {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire_bytes)
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
        [cmd, subcmd] if cmd == "key" && subcmd == "rotate" => IpcCommand::KeyRotate,
        [cmd, subcmd] if cmd == "key" && subcmd == "revoke" => IpcCommand::KeyRevoke,
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
        _ => IpcCommand::Unknown(raw.trim().to_owned()),
    }
}

pub fn validate_cidr(value: &str) -> bool {
    if value.len() < 3 || value.len() > 43 {
        return false;
    }
    if !value.contains('/') {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() || ch == '.' || ch == ':' || ch == '/')
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
