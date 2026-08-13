#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORT_FILENAME: &str = "live_managed_dns_report.json";

pub struct LiveManagedDnsValidationStage;

impl OrchestrationStage for LiveManagedDnsValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveManagedDnsValidation
    }
    fn name(&self) -> &str {
        "live_managed_dns_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveTwoHopValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let signer_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };

        let signer_node_id = match ctx.node_ids.get(&signer_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("signer (exit) node_id not found".into()),
        };
        let client_node_id = match ctx.node_ids.get(&client_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("client node_id not found".into()),
        };

        let report_path = ctx.report_dir.join(REPORT_FILENAME);
        let log_path = ctx.report_dir.join("live_managed_dns.log");

        let ssh_allow_cidrs = "0.0.0.0/0";

        let signer_target = format!("{}@{}", signer_params.user, signer_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path_str = report_path
            .to_str()
            .unwrap_or("live_managed_dns_report.json");
        let log_path_str = log_path.to_str().unwrap_or("live_managed_dns.log");
        let identity_file = signer_params.identity_file.to_str().unwrap_or("");
        let known_hosts = signer_params.known_hosts.to_str().unwrap_or("");

        if let Err(e) = reject_unsupported_platforms(ctx) {
            return StageOutcome::Failed(e);
        }
        if signer_params.alias == client_params.alias {
            return StageOutcome::Failed(format!(
                "signer (exit) and client resolve to the same node '{}'",
                signer_params.alias
            ));
        }
        let managed_peers: Vec<String> =
            match managed_peer_args(ctx, &signer_params.alias, &client_params.alias) {
                Ok(p) => p,
                Err(e) => return StageOutcome::Failed(e),
            };

        let mut args: Vec<&str> = vec![
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
            "--bin",
            "live_linux_managed_dns_test",
            "--",
            "--ssh-identity-file",
            identity_file,
            "--known-hosts-file",
            known_hosts,
            "--signer-host",
            &signer_target,
            "--signer-node-id",
            &signer_node_id,
            "--client-host",
            &client_target,
            "--client-node-id",
            &client_node_id,
            "--ssh-allow-cidrs",
            ssh_allow_cidrs,
            "--report-path",
            report_path_str,
            "--log-path",
            log_path_str,
        ];
        for peer in &managed_peers {
            args.extend(["--managed-peer", peer.as_str()]);
        }

        let result = std::process::Command::new("cargo").args(&args).output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    StageOutcome::Passed
                } else {
                    StageOutcome::Failed(
                        crate::vm_lab::orchestrator::stage::format_stage_binary_failure(
                            "live_managed_dns binary",
                            output.status,
                            &output.stdout,
                            &output.stderr,
                        ),
                    )
                }
            }
            Err(e) => {
                StageOutcome::Failed(format!("live_managed_dns binary invocation failed: {e}"))
            }
        }
    }
}

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: std::path::PathBuf,
    known_hosts: std::path::PathBuf,
}

fn alias_matching_label(ctx: &OrchestrationContext, label: &str) -> Option<String> {
    ctx.assignments
        .iter()
        .find(|a| a.role.as_str() == label)
        .map(|a| a.alias.clone())
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let alias = alias_matching_label(ctx, label)
        .ok_or_else(|| format!("no node with role label '{label}' in assignments"))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (label '{label}')"))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{alias} ({label}): no SSH connection params available"))?;
    let user = params.user.unwrap_or_else(|| {
        match adapter.platform() {
            VmGuestPlatform::Linux => "root",
            VmGuestPlatform::Macos => "admin",
            VmGuestPlatform::Windows => "administrator",
            _ => "root",
        }
        .to_owned()
    });
    Ok(ResolvedParams {
        alias,
        host: params.host,
        user,
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
}

fn platform_str(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Linux => "linux",
        VmGuestPlatform::Macos => "macos",
        VmGuestPlatform::Windows => "windows",
        _ => "linux",
    }
}

/// Pure selection, extracted so it is testable without an
/// `OrchestrationContext`: every alias except the two passed separately.
///
/// Separate deliberately — a test that re-implements this filter proves nothing
/// about the code that runs.
fn managed_peer_aliases<'a, I>(aliases: I, signer_alias: &str, client_alias: &str) -> Vec<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    aliases
        .into_iter()
        .filter(|alias| *alias != signer_alias && *alias != client_alias)
        .collect()
}

/// Every assigned node EXCEPT the two already passed as `--signer-*` /
/// `--client-*`, excluded by **alias**.
///
/// Excluding by ROLE was the defect: the signer and client are selected by
/// alias, so a topology with two `client` nodes silently dropped the second
/// while `distribute_assignments` still named it in the full-mesh ALLOW_SPEC.
/// The validator then saw a bundle referencing a host it was never given and
/// failed closed with "references unmanaged peer".
///
/// Alias, not `node_id`: `ctx.node_ids` is an alias-keyed map whose VALUES come
/// off the live daemon and are never checked for uniqueness, and
/// assignments/adapters/node_ids are all alias-keyed. Excluding by node_id would
/// over-exclude if two aliases ever shared one, reproducing the silent drop this
/// fixes. Keeping the node instead lets the validator's own `validate_targets`
/// reject a genuine duplicate loudly, before any SSH.
///
/// Deliberately NOT platform-filtered. `build_authorized_allow_spec` requires a
/// scope for every node it is given, and the bundle is a full mesh over
/// `ctx.assignments` with no platform condition, so this set must be a SUPERSET
/// of the assignments; any platform filter is a proper subset and re-creates the
/// identical error. macOS is fine in practice — both bundle re-push sites gate on
/// platform, and an archived run shows a macOS managed peer skipping re-push
/// twelve times and still passing end to end.
fn managed_peer_args(
    ctx: &OrchestrationContext,
    signer_alias: &str,
    client_alias: &str,
) -> Result<Vec<String>, String> {
    let mut peers: Vec<String> = Vec::new();
    for alias in managed_peer_aliases(
        ctx.assignments.iter().map(|a| a.alias.as_str()),
        signer_alias,
        client_alias,
    ) {
        // Fail closed on every lookup. A silent `continue` drops a node the
        // full-mesh bundle still names, reproducing this very failure from an
        // unrelated cause.
        let node_id = ctx
            .node_ids
            .get(alias)
            .ok_or_else(|| format!("managed peer '{alias}': no node_id in context"))?;
        let adapter = ctx
            .adapters
            .get(alias)
            .ok_or_else(|| format!("managed peer '{alias}': no adapter in context"))?;
        let params = adapter
            .ssh_connection_params()
            .ok_or_else(|| format!("managed peer '{alias}': no SSH connection params"))?;
        let user = params.user.unwrap_or_else(|| {
            match adapter.platform() {
                VmGuestPlatform::Linux => "root",
                VmGuestPlatform::Macos => "admin",
                VmGuestPlatform::Windows => "administrator",
                _ => "root",
            }
            .to_owned()
        });
        peers.push(format!(
            "{node_id}|{user}@{}|{}",
            params.host,
            platform_str(adapter.platform())
        ));
    }
    Ok(peers)
}

/// Refuse a topology containing a Windows guest, with the reason.
///
/// The validator reads every node's assignment bundle over `sudo -n cat` inside
/// `sh -lc`, and its `wireguard.pub` from a POSIX state root. Neither exists on
/// Windows. Omitting the node is NOT a fallback: the full-mesh bundle names it
/// either way, so a filter just returns the same failure by another route.
fn reject_unsupported_platforms(ctx: &OrchestrationContext) -> Result<(), String> {
    for assignment in &ctx.assignments {
        let Some(adapter) = ctx.adapters.get(assignment.alias.as_str()) else {
            continue;
        };
        if adapter.platform() == VmGuestPlatform::Windows {
            return Err(format!(
                "live_managed_dns_validation cannot validate a topology containing the Windows \
                 node '{}': the validator reads each node's assignment bundle over sudo/sh -lc \
                 and its wireguard.pub from a POSIX state root. Omitting the node is not a \
                 fallback, because the full-mesh assignment bundle names it either way.",
                assignment.alias
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_managed_dns() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.id(), StageId::LiveManagedDnsValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.name(), "live_managed_dns_validation");
    }

    #[test]
    fn depends_on_live_two_hop() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.dependencies(), &[StageId::LiveTwoHopValidation]);
    }

    #[test]
    fn fanout_is_once() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.fanout(), StageFanout::Once);
    }
}

#[cfg(test)]
mod managed_peer_selection_tests {
    use super::managed_peer_aliases;

    /// The live defect: two `client` nodes, and the one NOT passed as
    /// `--client-*` must still be a managed peer.
    #[test]
    fn second_client_is_still_a_managed_peer() {
        let aliases = ["deb-exit", "deb-client", "rocky-client", "fedora-relay"];
        let selected = managed_peer_aliases(aliases.iter().copied(), "deb-exit", "deb-client");
        assert!(
            selected.contains(&"rocky-client"),
            "the client not passed as --client-* must remain a managed peer; got {selected:?}"
        );
        assert!(
            selected.contains(&"fedora-relay"),
            "a non-client role must remain a managed peer; got {selected:?}"
        );
        assert!(
            !selected.contains(&"deb-exit") && !selected.contains(&"deb-client"),
            "the two nodes passed separately must not be duplicated; got {selected:?}"
        );
    }

    /// Duplicates must NOT be silently deduped here; the validator's own
    /// `validate_targets` reports a duplicate node id loudly.
    #[test]
    fn duplicate_aliases_are_not_deduped() {
        let aliases = ["a", "dup", "dup"];
        let selected = managed_peer_aliases(aliases.iter().copied(), "a", "none");
        assert_eq!(selected, vec!["dup", "dup"], "selection must not dedupe");
    }
}
