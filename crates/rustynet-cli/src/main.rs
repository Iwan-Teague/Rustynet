#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use rustynetd::daemon::DEFAULT_SOCKET_PATH;
use rustynetd::ipc::{IpcCommand, IpcResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Status,
    Login,
    Netcheck,
    ExitNodeSelect(String),
    ExitNodeOff,
    LanAccessOn,
    LanAccessOff,
    DnsInspect,
    RouteAdvertise(String),
    KeyRotate,
    KeyRevoke,
    Help,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = parse_command(&args);
    let output = execute(command);
    println!("{output}");
}

fn parse_command(args: &[String]) -> CliCommand {
    match args {
        [cmd] if cmd == "status" => CliCommand::Status,
        [cmd] if cmd == "login" => CliCommand::Login,
        [cmd] if cmd == "netcheck" => CliCommand::Netcheck,
        [cmd, subcmd, node] if cmd == "exit-node" && subcmd == "select" => {
            CliCommand::ExitNodeSelect(node.clone())
        }
        [cmd, subcmd] if cmd == "exit-node" && subcmd == "off" => CliCommand::ExitNodeOff,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "on" => CliCommand::LanAccessOn,
        [cmd, subcmd] if cmd == "lan-access" && subcmd == "off" => CliCommand::LanAccessOff,
        [cmd, subcmd] if cmd == "dns" && subcmd == "inspect" => CliCommand::DnsInspect,
        [cmd, subcmd, cidr] if cmd == "route" && subcmd == "advertise" => {
            CliCommand::RouteAdvertise(cidr.clone())
        }
        [cmd, subcmd] if cmd == "key" && subcmd == "rotate" => CliCommand::KeyRotate,
        [cmd, subcmd] if cmd == "key" && subcmd == "revoke" => CliCommand::KeyRevoke,
        _ => CliCommand::Help,
    }
}

fn execute(command: CliCommand) -> String {
    match command {
        CliCommand::Help => help_text(),
        CliCommand::Login => "login: open auth URL and complete device enrollment".to_string(),
        other => {
            let ipc_command = to_ipc_command(other);
            match send_command(ipc_command) {
                Ok(response) => {
                    if response.ok {
                        response.message
                    } else {
                        format!("error: {}", response.message)
                    }
                }
                Err(err) => format!("error: daemon unreachable: {err}"),
            }
        }
    }
}

fn to_ipc_command(command: CliCommand) -> IpcCommand {
    match command {
        CliCommand::Status => IpcCommand::Status,
        CliCommand::Netcheck => IpcCommand::Netcheck,
        CliCommand::ExitNodeSelect(node) => IpcCommand::ExitNodeSelect(node),
        CliCommand::ExitNodeOff => IpcCommand::ExitNodeOff,
        CliCommand::LanAccessOn => IpcCommand::LanAccessOn,
        CliCommand::LanAccessOff => IpcCommand::LanAccessOff,
        CliCommand::DnsInspect => IpcCommand::DnsInspect,
        CliCommand::RouteAdvertise(cidr) => IpcCommand::RouteAdvertise(cidr),
        CliCommand::KeyRotate => IpcCommand::KeyRotate,
        CliCommand::KeyRevoke => IpcCommand::KeyRevoke,
        CliCommand::Login | CliCommand::Help => IpcCommand::Unknown("unsupported".to_string()),
    }
}

fn daemon_socket_path() -> PathBuf {
    std::env::var("RUSTYNET_DAEMON_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH))
}

fn send_command(command: IpcCommand) -> Result<IpcResponse, String> {
    send_command_with_socket(command, daemon_socket_path())
}

fn send_command_with_socket(
    command: IpcCommand,
    socket_path: PathBuf,
) -> Result<IpcResponse, String> {
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|err| format!("connect {} failed: {err}", socket_path.display()))?;

    stream
        .write_all(format!("{}\n", command.as_wire()).as_bytes())
        .map_err(|err| format!("write failed: {err}"))?;

    let mut line = String::new();
    let mut reader = BufReader::new(&stream);
    reader
        .read_line(&mut line)
        .map_err(|err| format!("read failed: {err}"))?;

    Ok(IpcResponse::from_wire(&line))
}

fn help_text() -> String {
    [
        "commands:",
        "  status",
        "  login",
        "  netcheck",
        "  exit-node select <node>",
        "  exit-node off",
        "  lan-access on|off",
        "  dns inspect",
        "  route advertise <cidr>",
        "  key rotate",
        "  key revoke",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{execute, parse_command};

    #[test]
    fn parse_supports_phase10_route_advertise_command() {
        let command = parse_command(&[
            "route".to_string(),
            "advertise".to_string(),
            "192.168.1.0/24".to_string(),
        ]);
        assert!(format!("{command:?}").contains("RouteAdvertise"));
    }

    #[test]
    fn parse_supports_key_commands() {
        let rotate = parse_command(&["key".to_string(), "rotate".to_string()]);
        assert!(format!("{rotate:?}").contains("KeyRotate"));

        let revoke = parse_command(&["key".to_string(), "revoke".to_string()]);
        assert!(format!("{revoke:?}").contains("KeyRevoke"));
    }

    #[test]
    fn execute_reports_error_when_daemon_is_unreachable() {
        let output = execute(parse_command(&["status".to_string()]));
        assert!(output.starts_with("error: daemon unreachable:"));
    }
}
