use crate::launch::ExitChainHops;

pub fn endpoint_host_from_value(endpoint: &str) -> Option<String> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after.strip_prefix(':')?;
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        let port_ok = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        return (host_ok && port_ok).then(|| host.to_owned());
    }

    let (host, port) = endpoint.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let octets: Vec<&str> = host.split('.').collect();
    let ipv4_shaped = octets.len() == 4
        && octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.bytes().all(|b| b.is_ascii_digit()));
    ipv4_shaped.then(|| host.to_owned())
}

pub fn parse_linux_default_route_iface(ip_output: &str) -> Option<String> {
    let line = ip_output.lines().next()?;
    line.split_whitespace().nth(4).map(str::to_owned)
}

pub fn parse_macos_default_route_iface(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find(|line| line.contains("interface:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
}

pub fn parse_route_get_dev(ip_output: &str) -> Option<String> {
    let line = ip_output.lines().next()?;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens
        .iter()
        .position(|token| *token == "dev")
        .and_then(|idx| tokens.get(idx + 1))
        .map(|token| (*token).to_owned())
}

pub fn effective_selected_exit_node_for_egress(
    hops: ExitChainHops,
    entry: Option<&str>,
    final_node: Option<&str>,
    device_node_id: &str,
) -> Option<String> {
    if hops == ExitChainHops::Two && entry == Some(device_node_id) {
        return final_node.map(str::to_owned);
    }
    entry.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_host_ipv4_and_ipv6() {
        assert_eq!(
            endpoint_host_from_value("192.168.1.5:51820").as_deref(),
            Some("192.168.1.5")
        );
        assert_eq!(
            endpoint_host_from_value("[fd00::1]:51820").as_deref(),
            Some("fd00::1")
        );
        assert_eq!(
            endpoint_host_from_value("[::ffff:1.2.3.4]:1").as_deref(),
            Some("::ffff:1.2.3.4")
        );
        assert_eq!(endpoint_host_from_value("not-an-endpoint"), None);
        assert_eq!(endpoint_host_from_value("192.168.1.5"), None);
        assert_eq!(endpoint_host_from_value("[fd00::1]:notaport"), None);
    }

    #[test]
    fn linux_default_route_field_five() {
        let output = "default via 10.0.0.1 dev eth0 proto dhcp metric 100";
        assert_eq!(
            parse_linux_default_route_iface(output).as_deref(),
            Some("eth0")
        );
        assert_eq!(parse_linux_default_route_iface(""), None);
    }

    #[test]
    fn macos_default_route_interface_line() {
        let output = "   route to: default\n   gateway: 10.0.0.1\n   interface: en0\n";
        assert_eq!(
            parse_macos_default_route_iface(output).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn route_get_dev_token() {
        let output = "10.0.0.1 dev wlan0 src 10.0.0.5 uid 1000";
        assert_eq!(parse_route_get_dev(output).as_deref(), Some("wlan0"));
        assert_eq!(parse_route_get_dev("blackhole 10.0.0.1"), None);
    }

    #[test]
    fn effective_exit_selects_final_on_two_hop_self_entry() {
        assert_eq!(
            effective_selected_exit_node_for_egress(
                ExitChainHops::Two,
                Some("me"),
                Some("dst"),
                "me"
            )
            .as_deref(),
            Some("dst")
        );
        assert_eq!(
            effective_selected_exit_node_for_egress(
                ExitChainHops::Two,
                Some("other"),
                Some("dst"),
                "me"
            )
            .as_deref(),
            Some("other")
        );
        assert_eq!(
            effective_selected_exit_node_for_egress(ExitChainHops::One, Some("entry"), None, "me")
                .as_deref(),
            Some("entry")
        );
    }
}
