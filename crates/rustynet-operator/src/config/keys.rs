pub fn is_allowed_config_key(key: &str) -> bool {
    matches!(
        key,
        "SOCKET_PATH"
            | "STATE_PATH"
            | "TRUST_EVIDENCE_PATH"
            | "TRUST_VERIFIER_KEY_PATH"
            | "TRUST_WATERMARK_PATH"
            | "AUTO_TUNNEL_ENFORCE"
            | "AUTO_TUNNEL_BUNDLE_PATH"
            | "AUTO_TUNNEL_VERIFIER_KEY_PATH"
            | "AUTO_TUNNEL_WATERMARK_PATH"
            | "AUTO_TUNNEL_MAX_AGE_SECS"
            | "TRAVERSAL_BUNDLE_PATH"
            | "TRAVERSAL_VERIFIER_KEY_PATH"
            | "TRAVERSAL_WATERMARK_PATH"
            | "TRAVERSAL_MAX_AGE_SECS"
            | "WG_INTERFACE"
            | "WG_LISTEN_PORT"
            | "AUTO_PORT_FORWARD_EXIT"
            | "AUTO_PORT_FORWARD_LEASE_SECS"
            | "WG_PRIVATE_KEY_PATH"
            | "WG_ENCRYPTED_PRIVATE_KEY_PATH"
            | "WG_KEY_PASSPHRASE_PATH"
            | "WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH"
            | "SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH"
            | "WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT"
            | "WG_PUBLIC_KEY_PATH"
            | "EGRESS_INTERFACE"
            | "MEMBERSHIP_SNAPSHOT_PATH"
            | "MEMBERSHIP_LOG_PATH"
            | "MEMBERSHIP_WATERMARK_PATH"
            | "MEMBERSHIP_OWNER_SIGNING_KEY_PATH"
            | "BACKEND_MODE"
            | "DATAPLANE_MODE"
            | "PRIVILEGED_HELPER_SOCKET_PATH"
            | "PRIVILEGED_HELPER_TIMEOUT_MS"
            | "RECONCILE_INTERVAL_MS"
            | "MAX_RECONCILE_FAILURES"
            | "FAIL_CLOSED_SSH_ALLOW"
            | "FAIL_CLOSED_SSH_ALLOW_CIDRS"
            | "TRUST_SIGNER_KEY_PATH"
            | "AUTO_REFRESH_TRUST"
            | "DEVICE_NODE_ID"
            | "SETUP_COMPLETE"
            | "NODE_ROLE"
            | "SETUP_ROLE_PRESET"
            | "MANUAL_PEER_OVERRIDE"
            | "MANUAL_PEER_AUDIT_LOG"
            | "DEFAULT_LAUNCH_PROFILE"
            | "AUTO_LAUNCH_ON_START"
            | "AUTO_LAUNCH_EXIT_NODE_ID"
            | "AUTO_LAUNCH_LAN_MODE"
            | "EXIT_CHAIN_HOPS"
            | "EXIT_CHAIN_ENTRY_NODE_ID"
            | "EXIT_CHAIN_FINAL_NODE_ID"
            | "HOST_PROFILE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_known_keys_and_rejects_unknown() {
        assert!(is_allowed_config_key("NODE_ROLE"));
        assert!(is_allowed_config_key("WG_LISTEN_PORT"));
        assert!(!is_allowed_config_key("DROP_ALL_TABLES"));
        assert!(!is_allowed_config_key("node_role"));
        assert!(!is_allowed_config_key(""));
    }
}
