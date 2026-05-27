use crate::launch::{LanMode, LaunchProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedLaunch {
    SavedDefault,
    Profile(LaunchProfile),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StartArgs {
    pub requested_profile: Option<RequestedLaunch>,
    pub auto_only: bool,
    pub requested_exit_node_id: Option<String>,
    pub requested_lan_mode: Option<LanMode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsOutcome {
    Run(StartArgs),
    ShowHelp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgsError(pub String);

pub fn parse_start_args<I>(argv: I) -> Result<ArgsOutcome, ArgsError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = StartArgs::default();
    let mut requested_profile_raw: Option<String> = None;
    let mut iter = argv.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--profile" => {
                requested_profile_raw = Some(
                    iter.next()
                        .ok_or_else(|| ArgsError("--profile requires a value.".to_owned()))?,
                );
            }
            "--auto" => {
                args.requested_profile = Some(RequestedLaunch::SavedDefault);
                args.auto_only = true;
            }
            "--exit-node-id" => {
                args.requested_exit_node_id = Some(
                    iter.next()
                        .ok_or_else(|| ArgsError("--exit-node-id requires a value.".to_owned()))?,
                );
            }
            "--lan" => {
                let value = iter
                    .next()
                    .ok_or_else(|| ArgsError("--lan requires a value (skip|on|off).".to_owned()))?;
                args.requested_lan_mode = Some(LanMode::parse(&value).ok_or_else(|| {
                    ArgsError(format!(
                        "Invalid --lan value '{value}'. Expected skip|on|off."
                    ))
                })?);
            }
            "--help" | "-h" => return Ok(ArgsOutcome::ShowHelp),
            other => return Err(ArgsError(format!("Unknown argument: {other}"))),
        }
    }

    if let Some(raw) = requested_profile_raw {
        if raw == "auto" {
            args.requested_profile = Some(RequestedLaunch::SavedDefault);
            args.auto_only = true;
        } else {
            let profile = LaunchProfile::parse(&raw)
                .ok_or_else(|| ArgsError(format!("Invalid --profile value '{raw}'.")))?;
            args.requested_profile = Some(RequestedLaunch::Profile(profile));
            if profile != LaunchProfile::Menu {
                args.auto_only = true;
            }
        }
    }

    Ok(ArgsOutcome::Run(args))
}

pub fn help_text() -> &'static str {
    "Rustynet startup options:\n  \
     ./start.sh\n    Interactive menu mode.\n    \
     Exit-node selection supports 1-hop and 2-hop chain prompts.\n\n  \
     ./start.sh --profile <menu|quick-connect|quick-exit-node|quick-hybrid>\n    \
     Apply a launch profile once. Non-menu profiles apply and exit.\n    \
     blind_exit role accepts only 'menu' or 'quick-exit-node'.\n\n  \
     ./start.sh --auto\n    Apply saved default launch profile once and exit.\n\n  \
     Optional modifiers:\n    \
     --exit-node-id <node-id>   Override configured exit node id for this run.\n    \
     --lan <skip|on|off>        Override configured LAN mode for this run.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn parses_explicit_profile_and_sets_auto_only() {
        let ArgsOutcome::Run(args) =
            parse_start_args(argv(&["--profile", "quick-connect"])).unwrap()
        else {
            panic!("expected run");
        };
        assert_eq!(
            args.requested_profile,
            Some(RequestedLaunch::Profile(LaunchProfile::QuickConnect))
        );
        assert!(args.auto_only);
    }

    #[test]
    fn menu_profile_stays_interactive() {
        let ArgsOutcome::Run(args) = parse_start_args(argv(&["--profile", "menu"])).unwrap() else {
            panic!("expected run");
        };
        assert!(!args.auto_only);
    }

    #[test]
    fn auto_flag_requests_saved_default() {
        let ArgsOutcome::Run(args) = parse_start_args(argv(&["--auto"])).unwrap() else {
            panic!("expected run");
        };
        assert_eq!(args.requested_profile, Some(RequestedLaunch::SavedDefault));
        assert!(args.auto_only);
    }

    #[test]
    fn missing_values_are_rejected() {
        assert!(parse_start_args(argv(&["--profile"])).is_err());
        assert!(parse_start_args(argv(&["--exit-node-id"])).is_err());
        assert!(parse_start_args(argv(&["--lan"])).is_err());
    }

    #[test]
    fn invalid_values_and_unknown_flags_are_rejected() {
        assert!(parse_start_args(argv(&["--profile", "turbo"])).is_err());
        assert!(parse_start_args(argv(&["--lan", "perhaps"])).is_err());
        assert!(parse_start_args(argv(&["--frobnicate"])).is_err());
    }

    #[test]
    fn help_short_circuits() {
        assert_eq!(
            parse_start_args(argv(&["--help"])).unwrap(),
            ArgsOutcome::ShowHelp
        );
        assert_eq!(
            parse_start_args(argv(&["-h"])).unwrap(),
            ArgsOutcome::ShowHelp
        );
    }
}
