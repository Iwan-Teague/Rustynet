#![forbid(unsafe_code)]

use std::io::{BufRead, Read};

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
            Self::Io(e) => write!(f, "io error: {}", e),
            Self::MissingSignature => write!(f, "missing signature"),
            Self::InvalidSignatureHex(e) => write!(f, "invalid signature hex: {}", e),
            Self::MissingSubject => write!(f, "missing subject"),
            Self::MissingNonce => write!(f, "missing nonce"),
            Self::MissingCommand => write!(f, "missing command"),
            Self::InvalidFormat => write!(f, "invalid format"),
            Self::InvalidNonce(e) => write!(f, "invalid nonce: {}", e),
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
        )
    }

    pub fn as_wire(&self) -> String {
        match self {
            IpcCommand::Status => "status".to_string(),
            IpcCommand::Netcheck => "netcheck".to_string(),
            IpcCommand::StateRefresh => "state refresh".to_string(),
            IpcCommand::ExitNodeSelect(node) => format!("exit-node select {node}"),
            IpcCommand::ExitNodeOff => "exit-node off".to_string(),
            IpcCommand::LanAccessOn => "lan-access on".to_string(),
            IpcCommand::LanAccessOff => "lan-access off".to_string(),
            IpcCommand::DnsInspect => "dns inspect".to_string(),
            IpcCommand::RouteAdvertise(cidr) => format!("route advertise {cidr}"),
            IpcCommand::KeyRotate => "key rotate".to_string(),
            IpcCommand::KeyRevoke => "key revoke".to_string(),
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
        let message = parts.next().unwrap_or("invalid response").to_string();
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
        _ => IpcCommand::Unknown(raw.trim().to_string()),
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
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim();

    if line.starts_with(REMOTE_OPS_WIRE_PREFIX) {
        let payload = &line[REMOTE_OPS_WIRE_PREFIX.len()..];
        // expected format: subject=<sub|b64> nonce=<u64> command=<wire> signature=<hex>

        let parts: Vec<&str> = payload.split(" signature=").collect();
        if parts.len() != 2 {
            return Err(RemoteOpsEnvelopeParseError::MissingSignature);
        }
        let content = parts[0];
        let signature_hex = parts[1];

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
    use super::{IpcCommand, IpcResponse, parse_command, validate_cidr};

    #[test]
    fn parse_and_wire_roundtrip_for_mutating_command() {
        let command = parse_command("exit-node select mini-pc-1");
        assert_eq!(command, IpcCommand::ExitNodeSelect("mini-pc-1".to_string()));
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
}
