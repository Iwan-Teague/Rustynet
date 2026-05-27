#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchProfile {
    Menu,
    QuickConnect,
    QuickExitNode,
    QuickHybrid,
}

impl LaunchProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Menu => "menu",
            Self::QuickConnect => "quick-connect",
            Self::QuickExitNode => "quick-exit-node",
            Self::QuickHybrid => "quick-hybrid",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "menu" => Some(Self::Menu),
            "quick-connect" => Some(Self::QuickConnect),
            "quick-exit-node" => Some(Self::QuickExitNode),
            "quick-hybrid" => Some(Self::QuickHybrid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanMode {
    Skip,
    On,
    Off,
}

impl LanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "skip" => Some(Self::Skip),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitChainHops {
    One,
    Two,
}

impl ExitChainHops {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::One => "1",
            Self::Two => "2",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "1" => Some(Self::One),
            "2" => Some(Self::Two),
            _ => None,
        }
    }
}

pub fn is_valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitChain {
    pub hops: ExitChainHops,
    pub entry: Option<String>,
    pub final_node: Option<String>,
}

impl ExitChain {
    pub fn sanitize(mut self, is_blind_exit: bool) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();

        if self
            .entry
            .as_deref()
            .is_some_and(|id| !is_valid_node_id(id))
        {
            let id = self.entry.take().unwrap_or_default();
            warnings.push(format!(
                "Invalid EXIT_CHAIN_ENTRY_NODE_ID='{id}', clearing."
            ));
        }
        if self
            .final_node
            .as_deref()
            .is_some_and(|id| !is_valid_node_id(id))
        {
            let id = self.final_node.take().unwrap_or_default();
            warnings.push(format!(
                "Invalid EXIT_CHAIN_FINAL_NODE_ID='{id}', clearing."
            ));
        }
        if self.hops != ExitChainHops::Two {
            self.final_node = None;
        }
        if is_blind_exit {
            self.hops = ExitChainHops::One;
            self.entry = None;
            self.final_node = None;
        }

        (self, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_lan_round_trip() {
        for profile in [
            LaunchProfile::Menu,
            LaunchProfile::QuickConnect,
            LaunchProfile::QuickExitNode,
            LaunchProfile::QuickHybrid,
        ] {
            assert_eq!(LaunchProfile::parse(profile.as_str()), Some(profile));
        }
        assert_eq!(LaunchProfile::parse("turbo"), None);

        for mode in [LanMode::Skip, LanMode::On, LanMode::Off] {
            assert_eq!(LanMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(LanMode::parse("maybe"), None);
    }

    #[test]
    fn node_id_charset() {
        assert!(is_valid_node_id("node-1.host_A"));
        assert!(!is_valid_node_id(""));
        assert!(!is_valid_node_id("bad id"));
        assert!(!is_valid_node_id("slash/here"));
    }

    #[test]
    fn sanitize_clears_invalid_and_couples_hops() {
        let chain = ExitChain {
            hops: ExitChainHops::One,
            entry: Some("ok-id".to_owned()),
            final_node: Some("also-ok".to_owned()),
        };
        let (chain, _) = chain.sanitize(false);
        assert_eq!(chain.entry.as_deref(), Some("ok-id"));
        assert!(chain.final_node.is_none());

        let chain = ExitChain {
            hops: ExitChainHops::Two,
            entry: Some("bad id".to_owned()),
            final_node: Some("good".to_owned()),
        };
        let (chain, warnings) = chain.sanitize(false);
        assert!(chain.entry.is_none());
        assert_eq!(chain.final_node.as_deref(), Some("good"));
        assert!(warnings.iter().any(|msg| msg.contains("ENTRY_NODE_ID")));
    }

    #[test]
    fn blind_exit_forces_bare_single_hop() {
        let chain = ExitChain {
            hops: ExitChainHops::Two,
            entry: Some("a".to_owned()),
            final_node: Some("b".to_owned()),
        };
        let (chain, _) = chain.sanitize(true);
        assert_eq!(chain.hops, ExitChainHops::One);
        assert!(chain.entry.is_none());
        assert!(chain.final_node.is_none());
    }
}
