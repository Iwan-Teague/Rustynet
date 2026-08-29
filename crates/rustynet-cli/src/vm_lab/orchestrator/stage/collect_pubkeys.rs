#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{GossipIdentity, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::cross_network::substrate::EndpointPlane;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct CollectPubkeysStage;

impl OrchestrationStage for CollectPubkeysStage {
    fn id(&self) -> StageId {
        StageId::CollectPubkeys
    }
    fn name(&self) -> &str {
        "collect_pubkeys"
    }
    fn dependencies(&self) -> &[StageId] {
        // The substrate-setup dependency is the topology-level seam: when an
        // overlay substrate is requested and fails, collecting (and later
        // distributing) unroutable underlay endpoints must cascade-skip
        // rather than run. On the default no-substrate path the setup stage
        // passes as a no-op and this edge changes nothing.
        &[StageId::BootstrapHosts, StageId::CrossNetworkSubstrateSetup]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        use crate::vm_lab::orchestrator::error::WireguardPublicKey;

        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        struct NodeData {
            alias: String,
            pubkey: Result<WireguardPublicKey, String>,
            gossip: Result<GossipIdentity, String>,
            node_id: Result<String, String>,
            mesh_ip: Option<String>,
            endpoint: String,
        }

        // Collect pass: no ctx mutation
        let data: Vec<NodeData> = aliases
            .iter()
            .map(|alias| {
                let (pubkey, gossip, node_id, mesh_ip, endpoint) =
                    match ctx.adapters.get(alias.as_str()) {
                        Some(adapter) => {
                            let pk = adapter
                                .collect_wireguard_public_key()
                                .map_err(|e| e.to_string());
                            let gk = adapter.collect_gossip_identity().map_err(|e| e.to_string());
                            let nid = adapter
                                .collect_node_id()
                                .map(|n| n.0)
                                .map_err(|e| e.to_string());
                            let mip = adapter.collect_mesh_ip().ok();
                            let ep = adapter.endpoint();
                            (pk, gk, nid, mip, ep)
                        }
                        None => (
                            Err(format!("no adapter for '{alias}'")),
                            Err(format!("no adapter for '{alias}'")),
                            Err(format!("no adapter for '{alias}'")),
                            None,
                            "0.0.0.0:51820".to_owned(),
                        ),
                    };
                NodeData {
                    alias: alias.clone(),
                    pubkey,
                    gossip,
                    node_id,
                    mesh_ip,
                    endpoint,
                }
            })
            .collect();

        // Mutate pass: adapter borrows no longer live
        let mut errors = Vec::new();
        for d in data {
            match d.pubkey {
                Ok(pk) => {
                    ctx.collected_pubkeys.insert(d.alias.clone(), pk);
                }
                Err(e) => errors.push(format!("{}: pubkey: {e}", d.alias)),
            }
            match d.gossip {
                Ok(identity) => {
                    ctx.collected_gossip_identities
                        .insert(d.alias.clone(), identity);
                }
                // Fails CLOSED: no fallback to the WireGuard key. A node that
                // cannot prove its gossip identity must not get a membership
                // entry claiming one.
                Err(e) => errors.push(format!("{}: gossip_identity: {e}", d.alias)),
            }
            match d.node_id {
                Ok(nid) => {
                    ctx.node_ids.insert(d.alias.clone(), nid);
                }
                Err(e) => errors.push(format!("{}: node_id: {e}", d.alias)),
            }
            if let Some(ip) = d.mesh_ip {
                ctx.mesh_ips.insert(d.alias.clone(), ip);
            }
            // TOPOLOGY-SUBSTRATE SEAM: when a provisioned substrate supplies
            // an overlay address for this alias, THAT is the routable
            // dataplane endpoint peers must dial — the raw discovered
            // underlay IP sits on another LAN's private prefix and is
            // unroutable cross-LAN (spec §0.5, 2026-08-27). SSH/management
            // continues on the management IP; only the recorded WireGuard
            // endpoint changes. A malformed endpoint is an error, never a
            // silent fall-through to the unroutable address.
            //
            // The substrate is asked through `SubstrateHandle::endpoint()`
            // rather than by reaching into `overlay_ips`, so the
            // overlay-vs-underlay decision has exactly ONE implementation.
            // Only the `Overlay` plane may override: an `Underlay` answer is
            // the handle telling us it provisioned nothing for this alias,
            // which is precisely the address already discovered.
            let overlay = ctx.substrate.as_ref().and_then(|handle| {
                handle
                    .endpoint(d.alias.as_str())
                    .filter(|resolved| resolved.plane == EndpointPlane::Overlay)
                    .map(|resolved| resolved.address)
            });
            let endpoint = match overlay {
                Some(overlay_ip) => match override_endpoint_host(&d.endpoint, &overlay_ip) {
                    Ok(endpoint) => endpoint,
                    Err(e) => {
                        errors.push(format!("{}: endpoint: {e}", d.alias));
                        continue;
                    }
                },
                None => d.endpoint,
            };
            ctx.endpoints.insert(d.alias.clone(), endpoint);
        }

        if errors.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

/// Swap the host half of a `host:port` endpoint for the overlay address,
/// keeping the port. Fails (closed) on an endpoint with no port separator
/// rather than guessing.
fn override_endpoint_host(endpoint: &str, overlay_ip: &str) -> Result<String, String> {
    match endpoint.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Ok(format!("{overlay_ip}:{port}"))
        }
        _ => Err(format!(
            "cannot substitute overlay address into malformed endpoint {endpoint:?} (expected host:port)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_assignments_passes() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
        };
        assert_eq!(CollectPubkeysStage.execute(&mut ctx), StageOutcome::Passed);
    }

    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
        NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::{
        SubstrateHandle, SubstrateRecord,
    };
    use std::path::Path;

    /// Minimal adapter double for the collect pass. Only the five methods the
    /// stage actually calls answer; everything else is `unimplemented!()` so a
    /// future change that starts calling one fails loudly.
    #[derive(Debug)]
    struct FakeCollectAdapter {
        alias: String,
        endpoint: String,
    }

    impl NodeAdapter for FakeCollectAdapter {
        fn platform(&self) -> crate::vm_lab::VmGuestPlatform {
            crate::vm_lab::VmGuestPlatform::Linux
        }
        fn alias(&self) -> &str {
            &self.alias
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            Ok(WireguardPublicKey("a".repeat(64)))
        }
        fn collect_gossip_identity(
            &self,
        ) -> Result<crate::vm_lab::orchestrator::error::GossipIdentity, AdapterError> {
            Ok(crate::vm_lab::orchestrator::error::GossipIdentity::DeferredPlatform)
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            Ok(NodeId(format!("{}-node-id", self.alias)))
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            Ok("100.64.0.1".to_owned())
        }
        fn endpoint(&self) -> String {
            self.endpoint.clone()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: crate::vm_lab::orchestrator::error::BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: crate::vm_lab::orchestrator::error::BundleKind,
            _pub_key_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: crate::vm_lab::orchestrator::error::BundleKind,
            _env_content: &str,
            _local_out_dir: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn ctx_with_nodes(nodes: &[(&str, &str)]) -> OrchestrationContext {
        let mut ctx = OrchestrationContext::new(
            nodes
                .iter()
                .map(|(alias, _)| NodeRoleAssignment {
                    alias: (*alias).to_owned(),
                    role: NodeRole::Client,
                })
                .collect(),
            std::env::temp_dir(),
            "net".to_owned(),
        );
        for (alias, endpoint) in nodes {
            ctx.adapters.insert(
                (*alias).to_owned(),
                Box::new(FakeCollectAdapter {
                    alias: (*alias).to_owned(),
                    endpoint: (*endpoint).to_owned(),
                }),
            );
        }
        ctx
    }

    fn overlay_handle(pairs: &[(&str, &str)]) -> SubstrateHandle {
        SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: pairs.iter().map(|(alias, _)| (*alias).to_owned()).collect(),
            },
            overlay_ips: pairs
                .iter()
                .map(|(alias, ip)| ((*alias).to_owned(), (*ip).to_owned()))
                .collect(),
            underlay_ips: std::collections::BTreeMap::new(),
            created_resources: Vec::new(),
        }
    }

    /// Invariant (a): with no substrate, endpoints are the adapters' raw
    /// discovered values — single-LAN runs are byte-for-byte unaffected.
    #[test]
    fn without_a_substrate_endpoints_keep_the_discovered_underlay_addresses() {
        let mut ctx = ctx_with_nodes(&[
            ("utm-1", "192.168.64.10:51820"),
            ("lenovo-1", "192.168.0.30:51820"),
        ]);
        assert_eq!(CollectPubkeysStage.execute(&mut ctx), StageOutcome::Passed);
        assert_eq!(
            ctx.endpoints.get("utm-1").map(String::as_str),
            Some("192.168.64.10:51820")
        );
        assert_eq!(
            ctx.endpoints.get("lenovo-1").map(String::as_str),
            Some("192.168.0.30:51820")
        );
    }

    /// Invariant (b): a provisioned substrate overrides the endpoint host for
    /// EXACTLY the participating aliases, preserving each node's port.
    #[test]
    fn overlay_substrate_overrides_endpoints_for_exactly_the_participating_aliases() {
        let mut ctx = ctx_with_nodes(&[
            ("utm-1", "192.168.64.10:51820"),
            ("lenovo-1", "192.168.0.30:51821"),
            ("outsider", "192.168.64.11:51822"),
        ]);
        ctx.substrate = Some(overlay_handle(&[
            ("utm-1", "172.20.20.2"),
            ("lenovo-1", "172.20.10.2"),
        ]));
        assert_eq!(CollectPubkeysStage.execute(&mut ctx), StageOutcome::Passed);
        assert_eq!(
            ctx.endpoints.get("utm-1").map(String::as_str),
            Some("172.20.20.2:51820"),
            "participant gets the overlay address with its own port"
        );
        assert_eq!(
            ctx.endpoints.get("lenovo-1").map(String::as_str),
            Some("172.20.10.2:51821")
        );
        assert_eq!(
            ctx.endpoints.get("outsider").map(String::as_str),
            Some("192.168.64.11:51822"),
            "a non-participating alias keeps its discovered endpoint"
        );
    }

    /// Negative path for the accessor seam: a handle that KNOWS the alias but
    /// only on the underlay plane must not override anything. This is the
    /// exact shape a non-overlay substrate (netns) produces — it provisions a
    /// simulator inside one guest, no cross-LAN overlay address for any lab
    /// alias — and a plane-blind implementation would silently rewrite every
    /// endpoint to the address it already had, or worse, to another node's.
    #[test]
    fn an_underlay_plane_answer_never_overrides_the_discovered_endpoint() {
        let mut ctx = ctx_with_nodes(&[("utm-1", "192.168.64.10:51820")]);
        let mut handle = overlay_handle(&[]);
        handle
            .underlay_ips
            .insert("utm-1".to_owned(), "192.168.64.10".to_owned());
        // The handle resolves the alias, but on the underlay plane.
        assert_eq!(
            handle.endpoint("utm-1").map(|resolved| resolved.plane),
            Some(EndpointPlane::Underlay)
        );
        ctx.substrate = Some(handle);
        assert_eq!(CollectPubkeysStage.execute(&mut ctx), StageOutcome::Passed);
        assert_eq!(
            ctx.endpoints.get("utm-1").map(String::as_str),
            Some("192.168.64.10:51820"),
            "an underlay-plane answer is not an overlay override"
        );
    }

    /// A malformed endpoint under an overlay must fail the stage, never fall
    /// through silently to the unroutable underlay address.
    #[test]
    fn overlay_substrate_with_malformed_endpoint_fails_closed() {
        let mut ctx = ctx_with_nodes(&[("utm-1", "no-port-here")]);
        ctx.substrate = Some(overlay_handle(&[("utm-1", "172.20.20.2")]));
        let outcome = CollectPubkeysStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(ref msg) if msg.contains("malformed endpoint")),
            "{outcome:?}"
        );
        assert!(
            !ctx.endpoints.contains_key("utm-1"),
            "no endpoint may be recorded for the failed alias"
        );
    }

    #[test]
    fn override_endpoint_host_swaps_host_and_keeps_port() {
        assert_eq!(
            override_endpoint_host("192.168.64.10:51820", "172.20.20.2").unwrap(),
            "172.20.20.2:51820"
        );
        assert!(override_endpoint_host("192.168.64.10", "172.20.20.2").is_err());
        assert!(override_endpoint_host("host:", "172.20.20.2").is_err());
    }
}
