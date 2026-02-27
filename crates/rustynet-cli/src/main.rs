#![forbid(unsafe_code)]

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
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CliState {
    selected_exit_node: Option<String>,
    lan_access_enabled: bool,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = parse_command(&args);
    let output = execute(command, &mut CliState::default());
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
        _ => CliCommand::Help,
    }
}

fn execute(command: CliCommand, state: &mut CliState) -> String {
    match command {
        CliCommand::Status => format!(
            "status: exit_node={} lan_access={}",
            state.selected_exit_node.as_deref().unwrap_or("none"),
            if state.lan_access_enabled {
                "on"
            } else {
                "off"
            }
        ),
        CliCommand::Login => "login: open auth URL and complete device enrollment".to_string(),
        CliCommand::Netcheck => {
            "netcheck: direct-path preferred, relay fallback available".to_string()
        }
        CliCommand::ExitNodeSelect(node) => {
            state.selected_exit_node = Some(node.clone());
            format!("exit-node: selected {node}")
        }
        CliCommand::ExitNodeOff => {
            state.selected_exit_node = None;
            "exit-node: disabled".to_string()
        }
        CliCommand::LanAccessOn => {
            state.lan_access_enabled = true;
            "lan-access: enabled".to_string()
        }
        CliCommand::LanAccessOff => {
            state.lan_access_enabled = false;
            "lan-access: disabled".to_string()
        }
        CliCommand::DnsInspect => "dns inspect: zone=rustynet records=dynamic".to_string(),
        CliCommand::Help => [
            "commands:",
            "  status",
            "  login",
            "  netcheck",
            "  exit-node select <node>",
            "  exit-node off",
            "  lan-access on|off",
            "  dns inspect",
        ]
        .join("\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::{CliState, execute, parse_command};

    #[test]
    fn phase4_cli_supports_exit_node_flows() {
        let mut state = CliState::default();

        let out = execute(
            parse_command(&[
                "exit-node".to_string(),
                "select".to_string(),
                "mini-pc-1".to_string(),
            ]),
            &mut state,
        );
        assert!(out.contains("selected mini-pc-1"));

        let out = execute(
            parse_command(&["exit-node".to_string(), "off".to_string()]),
            &mut state,
        );
        assert!(out.contains("disabled"));
    }

    #[test]
    fn phase4_cli_supports_lan_toggle_and_dns_inspect() {
        let mut state = CliState::default();

        let on = execute(
            parse_command(&["lan-access".to_string(), "on".to_string()]),
            &mut state,
        );
        assert_eq!(on, "lan-access: enabled");
        let off = execute(
            parse_command(&["lan-access".to_string(), "off".to_string()]),
            &mut state,
        );
        assert_eq!(off, "lan-access: disabled");
        let dns = execute(
            parse_command(&["dns".to_string(), "inspect".to_string()]),
            &mut state,
        );
        assert!(dns.contains("dns inspect"));
    }
}
