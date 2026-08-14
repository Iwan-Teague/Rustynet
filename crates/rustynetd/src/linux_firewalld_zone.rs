//! firewalld zone coexistence for the Linux tunnel interface (QH-46).
//!
//! # Why this module exists
//!
//! Rustynet installs its forward chain at `type filter hook forward priority 0`
//! with `policy drop`, and appends the relay hairpin allow there. In netfilter a
//! base chain's `accept` is `NF_ACCEPT` — "continue to the next base chain at
//! this hook" — and NOT a final verdict. firewalld installs its own base chain
//! at the same hook with a HIGHER priority number (`filter + 10`), whose last
//! rule is `reject with icmpx admin-prohibited`. The tunnel interface is created
//! at runtime by this daemon rather than by NetworkManager, so firewalld binds
//! it to no zone, its policy jump never accepts it, and forwarded tunnel traffic
//! falls through to that reject.
//!
//! The packet therefore dies BETWEEN the FORWARD and POSTROUTING hooks: Rustynet
//! accepts and counts it, firewalld destroys it, and the masquerade on the later
//! hook never sees it. Measured on `fedora-utm-1`; it is why
//! `live_two_hop_validation` has never passed on a firewalld-family entry node,
//! and why any RHEL-family host running the distribution default cannot serve as
//! a relay or exit forwarder.
//!
//! Because a `reject` verdict is TERMINAL, no additional chain Rustynet installs
//! can rescue the packet — a later chain never runs. The conflict has to be
//! resolved where it originates, by making firewalld accept the interface.
//!
//! # What this does, and what it deliberately does not do
//!
//! It binds the tunnel interface to the host's **effective default zone**, at
//! **runtime only**.
//!
//! * **Not the `trusted` zone**, even though that is what comparable VPN daemons
//!   do. Rustynet installs NO `hook input` base chain and structurally cannot —
//!   the helper's chain validator accepts only filter/output, filter/forward,
//!   nat/postrouting and nat/output. On a firewalld host, firewalld's zone is
//!   therefore the ONLY network-layer inbound filter on the tunnel, and a
//!   `trusted` (target ACCEPT) binding would remove it with nothing behind it.
//!   The FORWARD direction is the opposite case: our chain is `policy drop` and
//!   a drop is terminal, so firewalld can only ever SUBTRACT from a forward
//!   verdict we already made. Conceding FORWARD costs nothing; conceding INPUT
//!   would cost everything.
//! * **The default zone, not a new one.** A zoneless interface already reaches
//!   the default zone through the catch-all dispatch at the tail of
//!   `filter_FORWARD_POLICIES`, so binding changes WHICH dispatch rule matches,
//!   not which allow chain runs. The entire delta is the one hairpin permission
//!   that is currently missing.
//! * **Runtime, never `--permanent`.** A permanent binding writes into the
//!   operator's `/etc/firewalld/zones/<zone>.xml` and outlives uninstall and
//!   role demotion — the residue class this project treats as release-blocking.
//! * **Over D-Bus, never `firewall-cmd`.** The CLI routes `--add-interface`
//!   through a path that writes `connection.zone` into
//!   `/etc/NetworkManager/system-connections/*.nmconnection`, mutating a third
//!   daemon's on-disk configuration. The D-Bus zone API has no such branch, so
//!   the persistence hazard is removed by mechanism rather than mitigated.
//!
//! The zone name never crosses the privileged boundary at all: the helper always
//! passes the empty string, which firewalld resolves to the effective default
//! zone server-side. `trusted`, `drop` and every other zone are therefore
//! UNREPRESENTABLE in this grammar rather than merely rejected by validation.
//!
//! This module is pure: it decodes/encodes the helper's argv grammar and parses
//! the posture line the builtin emits. Privileged execution lives in
//! `privileged_helper`.

#![forbid(unsafe_code)]

/// Helper program name for the in-helper firewalld zone builtin.
pub const LINUX_FIREWALLD_ZONE_PROGRAM: &str = "linux-firewalld-zone";

/// The operation requested of the builtin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewalldZoneOp {
    /// Read posture only. Mutates nothing.
    Query,
    /// Bind the tunnel interface to the effective default zone.
    Bind,
    /// Remove the binding (role demotion / teardown).
    Unbind,
}

impl FirewalldZoneOp {
    pub fn as_str(self) -> &'static str {
        match self {
            FirewalldZoneOp::Query => "query",
            FirewalldZoneOp::Bind => "bind",
            FirewalldZoneOp::Unbind => "unbind",
        }
    }

    /// Exact-match parse. There is deliberately no default arm: an unrecognised
    /// operation is an error, never a silently-downgraded `Query`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "query" => Some(FirewalldZoneOp::Query),
            "bind" => Some(FirewalldZoneOp::Bind),
            "unbind" => Some(FirewalldZoneOp::Unbind),
            _ => None,
        }
    }
}

/// Whether firewalld is present and owning the host firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewalldPresence {
    /// No firewalld on the D-Bus system bus — nothing to coexist with.
    Absent,
    /// firewalld owns its well-known bus name.
    Running,
    /// Presence could not be determined. Treated as PRESENT by callers, because
    /// assuming absence here is precisely the fail-open this module exists to
    /// prevent.
    Unknown,
}

impl FirewalldPresence {
    pub fn as_str(self) -> &'static str {
        match self {
            FirewalldPresence::Absent => "absent",
            FirewalldPresence::Running => "running",
            FirewalldPresence::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "absent" => Some(FirewalldPresence::Absent),
            "running" => Some(FirewalldPresence::Running),
            "unknown" => Some(FirewalldPresence::Unknown),
            _ => None,
        }
    }

    /// True when the caller must NOT assume the forward path is unobstructed.
    ///
    /// `Unknown` counts as obstructive on purpose: a failed probe must never be
    /// mapped to "no firewall here".
    pub fn may_obstruct_forwarding(self) -> bool {
        matches!(
            self,
            FirewalldPresence::Running | FirewalldPresence::Unknown
        )
    }
}

/// A decoded request for the builtin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewalldZoneSpec {
    pub op: FirewalldZoneOp,
    pub interface: String,
}

impl FirewalldZoneSpec {
    pub fn new(op: FirewalldZoneOp, interface: impl Into<String>) -> Result<Self, String> {
        let spec = Self {
            op,
            interface: interface.into(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Render the argv the daemon sends. Exactly two tokens; no zone token
    /// exists in the grammar.
    pub fn encode(&self) -> Vec<String> {
        vec![
            format!("op={}", self.op.as_str()),
            format!("interface={}", self.interface),
        ]
    }

    /// Decode and validate the helper-side argv.
    ///
    /// Decode success IS the validation, matching the macOS pf-load builtin: the
    /// helper's `validate_request` arm calls this and nothing else, so any shape
    /// this refuses is a shape the helper will not execute.
    pub fn decode(args: &[&str]) -> Result<Self, String> {
        let mut op: Option<&str> = None;
        let mut interface: Option<&str> = None;
        for arg in args {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| format!("firewalld zone token is not key=value: {arg:?}"))?;
            match key {
                "op" => set_once(&mut op, key, value)?,
                "interface" => set_once(&mut interface, key, value)?,
                _ => return Err(format!("unknown firewalld zone token: {key:?}")),
            }
        }
        let op = op.ok_or_else(|| "firewalld zone spec missing token: op".to_owned())?;
        let interface =
            interface.ok_or_else(|| "firewalld zone spec missing token: interface".to_owned())?;
        let op = FirewalldZoneOp::parse(op)
            .ok_or_else(|| format!("unsupported firewalld zone op: {op:?}"))?;
        let spec = Self {
            op,
            interface: interface.to_owned(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Interface-name validation applied on BOTH sides of the boundary.
    ///
    /// The helper additionally requires, for `bind` only, that the name equals
    /// its own configured tunnel interface — a check this pure module cannot
    /// make because it does not know the helper's configuration.
    fn validate(&self) -> Result<(), String> {
        if !is_plausible_interface_name(self.interface.as_str()) {
            return Err(format!(
                "invalid firewalld zone interface name: {:?}",
                self.interface
            ));
        }
        if self.interface == "lo" {
            return Err("firewalld zone builtin must not act on the loopback interface".to_owned());
        }
        Ok(())
    }
}

/// Conservative interface-name grammar: non-empty, at most `IFNAMSIZ - 1`
/// bytes, ASCII alphanumeric plus `.`, `-` and `_`, and never a path component.
///
/// This mirrors the helper's existing interface validator rather than inventing
/// a looser one; the point is that no argument reaching `busctl` can be anything
/// but a device name.
pub fn is_plausible_interface_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 15 {
        return false;
    }
    if value == "." || value == ".." {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The posture the builtin reports back, parsed from its structured stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewalldPosture {
    pub presence: FirewalldPresence,
    pub default_zone: Option<String>,
    pub interface_bound: Option<bool>,
}

impl FirewalldPosture {
    /// Render the single structured line the builtin writes to stdout.
    pub fn encode(&self) -> String {
        let mut parts = vec![format!("presence={}", self.presence.as_str())];
        if let Some(zone) = self.default_zone.as_deref() {
            parts.push(format!("default_zone={zone}"));
        }
        if let Some(bound) = self.interface_bound {
            parts.push(format!("bound={bound}"));
        }
        parts.join(" ")
    }

    /// Parse the builtin's stdout.
    ///
    /// Fails closed on anything it does not understand: an unparseable posture
    /// must surface as an error, never as a default-constructed value that reads
    /// like "firewalld absent, nothing to do".
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut presence: Option<FirewalldPresence> = None;
        let mut default_zone: Option<String> = None;
        let mut interface_bound: Option<bool> = None;
        for token in line.split_whitespace() {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| format!("firewalld posture token is not key=value: {token:?}"))?;
            match key {
                "presence" => {
                    if presence.is_some() {
                        return Err("duplicate firewalld posture token: presence".to_owned());
                    }
                    presence = Some(
                        FirewalldPresence::parse(value)
                            .ok_or_else(|| format!("unknown firewalld presence: {value:?}"))?,
                    );
                }
                "default_zone" => {
                    if default_zone.is_some() {
                        return Err("duplicate firewalld posture token: default_zone".to_owned());
                    }
                    default_zone = Some(value.to_owned());
                }
                "bound" => {
                    if interface_bound.is_some() {
                        return Err("duplicate firewalld posture token: bound".to_owned());
                    }
                    interface_bound = Some(match value {
                        "true" => true,
                        "false" => false,
                        other => {
                            return Err(format!(
                                "firewalld posture bound is not a bool: {other:?}"
                            ));
                        }
                    });
                }
                other => return Err(format!("unknown firewalld posture token: {other:?}")),
            }
        }
        let presence =
            presence.ok_or_else(|| "firewalld posture missing token: presence".to_owned())?;
        Ok(Self {
            presence,
            default_zone,
            interface_bound,
        })
    }

    /// Is the forward path clear for a node that must forward?
    ///
    /// `true` only when firewalld is definitively absent, or present WITH the
    /// interface confirmed bound. Every other combination — including a running
    /// firewalld whose binding state could not be read — is `false`, so the
    /// caller fails closed rather than serving a forwarding role whose traffic
    /// another firewall silently rejects.
    pub fn forwarding_unobstructed(&self) -> bool {
        match self.presence {
            FirewalldPresence::Absent => true,
            FirewalldPresence::Running | FirewalldPresence::Unknown => {
                self.interface_bound == Some(true)
            }
        }
    }
}

fn set_once<'a>(slot: &mut Option<&'a str>, key: &str, value: &'a str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate firewalld zone token: {key}"));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips_and_carries_no_zone_token() {
        let spec = FirewalldZoneSpec::new(FirewalldZoneOp::Bind, "rustynet0").unwrap();
        let argv = spec.encode();
        assert_eq!(argv, vec!["op=bind", "interface=rustynet0"]);
        // The zone is NOT expressible: the helper always sends the empty string
        // and firewalld resolves the default zone server-side.
        assert!(!argv.iter().any(|token| token.contains("zone=")));
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_eq!(FirewalldZoneSpec::decode(&borrowed).unwrap(), spec);
    }

    /// The security property that makes this grammar safe: a caller cannot ask
    /// for `trusted`, cannot ask for `--permanent`, and cannot smuggle a free
    /// string, because no such token exists.
    #[test]
    fn unknown_tokens_are_refused_rather_than_ignored() {
        for argv in [
            vec!["op=bind", "interface=rustynet0", "zone=trusted"],
            vec!["op=bind", "interface=rustynet0", "permanent=true"],
            vec!["op=bind", "interface=rustynet0", "--permanent"],
        ] {
            assert!(
                FirewalldZoneSpec::decode(&argv).is_err(),
                "must refuse: {argv:?}"
            );
        }
    }

    #[test]
    fn unknown_op_is_refused_and_never_downgraded_to_query() {
        assert!(FirewalldZoneSpec::decode(&["op=reload", "interface=rustynet0"]).is_err());
        assert!(FirewalldZoneSpec::decode(&["op=", "interface=rustynet0"]).is_err());
        assert!(FirewalldZoneSpec::decode(&["op=BIND", "interface=rustynet0"]).is_err());
    }

    #[test]
    fn duplicate_and_missing_tokens_are_refused() {
        assert!(
            FirewalldZoneSpec::decode(&["op=bind", "op=unbind", "interface=rustynet0"]).is_err()
        );
        assert!(FirewalldZoneSpec::decode(&["interface=rustynet0"]).is_err());
        assert!(FirewalldZoneSpec::decode(&["op=bind"]).is_err());
        assert!(FirewalldZoneSpec::decode(&["opbind", "interface=rustynet0"]).is_err());
    }

    /// Nothing that could reach a shell, a path, or another host's device may
    /// pass as an interface name.
    #[test]
    fn interface_names_are_constrained_to_device_names() {
        for bad in [
            "",
            "lo",
            "../etc",
            "eth0;reboot",
            "eth0 rm",
            "eth0\n",
            "a/b",
            "$IF",
            "`id`",
            "0123456789abcdef",
        ] {
            assert!(
                FirewalldZoneSpec::decode(&["op=bind", &format!("interface={bad}")]).is_err(),
                "must refuse interface {bad:?}"
            );
        }
        for good in ["rustynet0", "wg0", "tun-1", "br_0"] {
            assert!(
                FirewalldZoneSpec::decode(&["op=query", &format!("interface={good}")]).is_ok(),
                "must accept interface {good:?}"
            );
        }
    }

    #[test]
    fn posture_round_trips() {
        let posture = FirewalldPosture {
            presence: FirewalldPresence::Running,
            default_zone: Some("FedoraServer".to_owned()),
            interface_bound: Some(true),
        };
        assert_eq!(FirewalldPosture::parse(&posture.encode()).unwrap(), posture);
    }

    /// An unreadable posture must be an error, not a value that reads like
    /// "no firewalld here".
    #[test]
    fn unparseable_posture_fails_closed() {
        for bad in [
            "",
            "presence=maybe",
            "bound=yes presence=running",
            "garbage",
        ] {
            let parsed = FirewalldPosture::parse(bad);
            assert!(parsed.is_err(), "must refuse posture {bad:?}");
        }
    }

    /// The fail-closed decision table. Only two combinations may report the
    /// forward path clear.
    #[test]
    fn forwarding_is_unobstructed_only_when_absent_or_confirmed_bound() {
        let case = |presence, bound| {
            FirewalldPosture {
                presence,
                default_zone: None,
                interface_bound: bound,
            }
            .forwarding_unobstructed()
        };

        assert!(case(FirewalldPresence::Absent, None));
        assert!(case(FirewalldPresence::Running, Some(true)));

        assert!(!case(FirewalldPresence::Running, Some(false)));
        assert!(!case(FirewalldPresence::Running, None));
        // A probe that failed must never read as "no firewall".
        assert!(!case(FirewalldPresence::Unknown, None));
        assert!(!case(FirewalldPresence::Unknown, Some(false)));
        assert!(case(FirewalldPresence::Unknown, Some(true)));
    }

    #[test]
    fn unknown_presence_counts_as_possibly_obstructing() {
        assert!(FirewalldPresence::Unknown.may_obstruct_forwarding());
        assert!(FirewalldPresence::Running.may_obstruct_forwarding());
        assert!(!FirewalldPresence::Absent.may_obstruct_forwarding());
    }
}
