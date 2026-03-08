# Role Switch Matrix (current commit)

Captured at: 2026-03-07T23:39:38Z

## debian13 (debian@192.168.18.50)
- baseline: node_id=client-50 node_role=client state=ExitActive generation=2 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=132 reconcile_failures=0 last_reconcile_unix=1772926777 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926772:1772926772660799739 membership_epoch=5 membership_active_nodes=5
- after_temp: node_id=client-50 node_role=admin state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=1 reconcile_failures=0 last_reconcile_unix=1772926783 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926772:1772926772660799739 membership_epoch=5 membership_active_nodes=5
- after_restore: node_id=client-50 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=1 reconcile_failures=0 last_reconcile_unix=1772926788 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926772:1772926772660799739 membership_epoch=5 membership_active_nodes=5
- temp_role: admin
- switch_execution: pass
- post_switch_reconcile: pass
- policy_still_enforced: pass
- least_privilege_preserved: pass

## fedora (fedora@192.168.18.51)
- baseline: node_id=client-51 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=on restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=124 reconcile_failures=0 last_reconcile_unix=1772926790 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926657:1772926657657040468 membership_epoch=5 membership_active_nodes=5
- after_temp: node_id=client-51 node_role=blind_exit state=ExitActive generation=1 exit_node=none serving_exit_node=true lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772926797 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926657:1772926657657040468 membership_epoch=5 membership_active_nodes=5
- after_restore: node_id=client-51 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=on restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=0 reconcile_failures=0 last_reconcile_unix=none last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926657:1772926657657040468 membership_epoch=5 membership_active_nodes=5
- temp_role: blind_exit
- switch_execution: pass
- post_switch_reconcile: pass
- policy_still_enforced: pass
- least_privilege_preserved: pass

## ubuntu (ubuntu@192.168.18.52)
- baseline: node_id=client-52 node_role=client state=ExitActive generation=2 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=128 reconcile_failures=0 last_reconcile_unix=1772926804 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926734:1772926734986663201 membership_epoch=5 membership_active_nodes=5
- after_temp: node_id=client-52 node_role=admin state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772926810 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926734:1772926734986663201 membership_epoch=5 membership_active_nodes=5
- after_restore: node_id=client-52 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772926815 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926734:1772926734986663201 membership_epoch=5 membership_active_nodes=5
- temp_role: admin
- switch_execution: pass
- post_switch_reconcile: pass
- policy_still_enforced: pass
- least_privilege_preserved: pass

## mint (mint@192.168.18.53)
- baseline: node_id=client-53 node_role=client state=ExitActive generation=2 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=132 reconcile_failures=0 last_reconcile_unix=1772926816 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926745:1772926745649506784 membership_epoch=5 membership_active_nodes=5
- after_temp: node_id=client-53 node_role=admin state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772926823 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926745:1772926745649506784 membership_epoch=5 membership_active_nodes=5
- after_restore: node_id=client-53 node_role=client state=ExitActive generation=1 exit_node=exit-49 serving_exit_node=false lan_access=off restricted_safe_mode=false restriction_mode=None bootstrap_error=none reconcile_attempts=2 reconcile_failures=0 last_reconcile_unix=1772926828 last_reconcile_error=none encrypted_key_store=true auto_tunnel_enforce=true auto_port_forward_exit=false port_forward_external_port=none port_forward_error=none last_assignment=1772926745:1772926745649506784 membership_epoch=5 membership_active_nodes=5
- temp_role: admin
- switch_execution: pass
- post_switch_reconcile: pass
- policy_still_enforced: pass
- least_privilege_preserved: pass

