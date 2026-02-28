#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcCommand {
    Status,
    Netcheck,
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
                | IpcCommand::RouteAdvertise(_)
                | IpcCommand::KeyRotate
                | IpcCommand::KeyRevoke
        )
    }

    pub fn as_wire(&self) -> String {
        match self {
            IpcCommand::Status => "status".to_string(),
            IpcCommand::Netcheck => "netcheck".to_string(),
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
