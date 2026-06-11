//! D13.d — `rustynet llm` admin verbs (LLM design §7).
//!
//! `rustynet llm allow <peer|group> [--models a,b] [--quota N]
//! [--rate N]` / `rustynet llm deny <peer|group>` are convenience
//! wrappers that build the **unsigned** service-access policy
//! record for the membership owner to sign — mirroring the
//! assignment/capability flow. Nothing here mutates policy: a node
//! cannot grant LLM access to itself or anyone else; only the
//! owner-signed policy applied through the membership path changes
//! who may reach the service. `rustynet llm access list` is
//! read-only and reports the access state the daemon materialised
//! from signed policy (absent state ⇒ default-deny, honestly
//! reported as "nobody authorised").

use std::fmt;
use std::path::PathBuf;

/// Default directory where the daemon materialises the current
/// signed service-access state for the LLM gateway. Mirrors
/// `RUSTYNET_LLM_ACCESS_DIR` in `rustynet-llm-gateway.service`.
pub const DEFAULT_LLM_ACCESS_DIR: &str = "/var/lib/rustynet-llm/access";
/// File inside the access dir listing currently-authorised peer
/// selectors (one per line), written by the daemon from signed
/// policy. Missing file ⇒ default-deny.
pub const ACCESS_GRANTS_FILE: &str = "grants.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmCommand {
    Allow {
        peer: String,
        models: Option<Vec<String>>,
        max_tokens_per_window: Option<u64>,
        max_requests_per_minute: Option<u32>,
    },
    Deny {
        peer: String,
    },
    AccessList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmCliError {
    InvalidPeerSelector { raw: String },
    InvalidFlagValue { flag: &'static str, raw: String },
}

impl fmt::Display for LlmCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmCliError::InvalidPeerSelector { raw } => write!(
                f,
                "invalid peer selector {raw:?}: expected node:<id> or group:<name>"
            ),
            LlmCliError::InvalidFlagValue { flag, raw } => {
                write!(f, "invalid value {raw:?} for {flag}")
            }
        }
    }
}

/// Validate a peer/group selector. Strict: explicit `node:` or
/// `group:` prefix with a safe charset — the selector lands in a
/// record the owner signs.
pub fn validate_peer_selector(raw: &str) -> Result<String, LlmCliError> {
    let valid_body = |body: &str| {
        !body.is_empty()
            && body.len() <= 64
            && body.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
            })
    };
    let ok = match raw.split_once(':') {
        Some(("node", body)) | Some(("group", body)) => valid_body(body),
        _ => false,
    };
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(LlmCliError::InvalidPeerSelector {
            raw: raw.to_owned(),
        })
    }
}

/// Canonical unsigned record the owner signs and applies from the
/// admin box. Line-oriented `key=value` (the same signing-input
/// discipline as the membership pre-images).
pub fn render_unsigned_access_record(command: &LlmCommand) -> Option<String> {
    match command {
        LlmCommand::Allow {
            peer,
            models,
            max_tokens_per_window,
            max_requests_per_minute,
        } => {
            let mut out = String::from("record=llm_access_v1\naction=allow\n");
            out.push_str(&format!("peer={peer}\n"));
            out.push_str("context=llm_service\n");
            if let Some(models) = models {
                out.push_str(&format!("models={}\n", models.join(",")));
            }
            if let Some(quota) = max_tokens_per_window {
                out.push_str(&format!("max_tokens_per_window={quota}\n"));
            }
            if let Some(rate) = max_requests_per_minute {
                out.push_str(&format!("max_requests_per_minute={rate}\n"));
            }
            Some(out)
        }
        LlmCommand::Deny { peer } => Some(format!(
            "record=llm_access_v1\naction=deny\npeer={peer}\ncontext=llm_service\n"
        )),
        LlmCommand::AccessList => None,
    }
}

/// Execute an `rustynet llm` verb. Allow/deny emit the unsigned
/// record + owner instructions; `access list` reads the
/// daemon-materialised state read-only.
pub fn execute_llm(command: &LlmCommand, access_dir: Option<PathBuf>) -> Result<String, String> {
    match command {
        LlmCommand::Allow { peer, .. } | LlmCommand::Deny { peer } => {
            let record = render_unsigned_access_record(command).unwrap_or_default();
            let action = match command {
                LlmCommand::Allow { .. } => "allow",
                _ => "deny",
            };
            let mut out = String::new();
            out.push_str(&format!(
                "Unsigned LLM service-access record ({action} {peer}):\n\n{record}\n"
            ));
            out.push_str(
                "This node cannot change LLM access by itself (capability is not authority).\n\
                 Next steps on your ADMIN box with the membership owner key:\n\
                 1. Review the record above.\n\
                 2. Sign and apply it through the membership/policy update flow\n\
                    (`rustynet membership` tooling) — the signed policy is what the\n\
                    LLM node enforces.\n\
                 3. Revocations take effect immediately on apply: in-flight streams\n\
                    for a denied peer are severed before the update lands.\n",
            );
            Ok(out)
        }
        LlmCommand::AccessList => {
            let dir = access_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_LLM_ACCESS_DIR));
            let grants_path = dir.join(ACCESS_GRANTS_FILE);
            if !grants_path.exists() {
                return Ok(format!(
                    "LLM service access: DEFAULT-DENY (no signed service-access policy \
                     materialised at {}).\nNobody is authorised to reach this node's \
                     inference endpoint. Authorise a device from your admin box with \
                     `rustynet llm allow node:<id>`.\n",
                    grants_path.display()
                ));
            }
            let body = std::fs::read_to_string(&grants_path)
                .map_err(|err| format!("read {} failed: {err}", grants_path.display()))?;
            let peers: Vec<&str> = body
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            if peers.is_empty() {
                return Ok(
                    "LLM service access: DEFAULT-DENY (signed policy authorises nobody).\n"
                        .to_owned(),
                );
            }
            let mut out = String::from("LLM service access (from signed policy):\n");
            for peer in peers {
                out.push_str(&format!("  - {peer}\n"));
            }
            out.push_str(
                "Reach requires BOTH tunnel membership and this signed authorisation; \
                 model/quota scopes apply per peer.\n",
            );
            Ok(out)
        }
    }
}

/// Parse the flag tail of `llm allow <peer> [--models a,b]
/// [--quota N] [--rate N]`.
pub fn parse_allow_flags(peer: &str, rest: &[String]) -> Result<LlmCommand, LlmCliError> {
    let peer = validate_peer_selector(peer)?;
    let mut models: Option<Vec<String>> = None;
    let mut max_tokens_per_window: Option<u64> = None;
    let mut max_requests_per_minute: Option<u32> = None;
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--models" => {
                let raw = iter.next().ok_or(LlmCliError::InvalidFlagValue {
                    flag: "--models",
                    raw: "<missing>".to_owned(),
                })?;
                let list: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                if list.is_empty() {
                    return Err(LlmCliError::InvalidFlagValue {
                        flag: "--models",
                        raw: raw.clone(),
                    });
                }
                models = Some(list);
            }
            "--quota" => {
                let raw = iter.next().ok_or(LlmCliError::InvalidFlagValue {
                    flag: "--quota",
                    raw: "<missing>".to_owned(),
                })?;
                max_tokens_per_window =
                    Some(
                        raw.parse::<u64>()
                            .map_err(|_| LlmCliError::InvalidFlagValue {
                                flag: "--quota",
                                raw: raw.clone(),
                            })?,
                    );
            }
            "--rate" => {
                let raw = iter.next().ok_or(LlmCliError::InvalidFlagValue {
                    flag: "--rate",
                    raw: "<missing>".to_owned(),
                })?;
                max_requests_per_minute =
                    Some(
                        raw.parse::<u32>()
                            .map_err(|_| LlmCliError::InvalidFlagValue {
                                flag: "--rate",
                                raw: raw.clone(),
                            })?,
                    );
            }
            other => {
                return Err(LlmCliError::InvalidFlagValue {
                    flag: "llm allow",
                    raw: other.to_owned(),
                });
            }
        }
    }
    Ok(LlmCommand::Allow {
        peer,
        models,
        max_tokens_per_window,
        max_requests_per_minute,
    })
}
