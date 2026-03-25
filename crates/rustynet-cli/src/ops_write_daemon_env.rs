use std::env;
use std::path::{Path, PathBuf};
use crate::ops_install_systemd::{execute_ops_install_systemd, read_env_file_values};

pub fn execute_ops_write_daemon_env(config_path: PathBuf, egress_interface: Option<String>) -> Result<String, String> {
    // 1. Load wizard.env config
    let mut config = read_env_file_values(&config_path)
        .map_err(|e| format!("failed to read config file {}: {}", config_path.display(), e))?;

    // 2. Apply policy logic (defaults and enforcement)
    
    // Default: NODE_ROLE
    let setup_complete = config.get("SETUP_COMPLETE").map(|s| s.as_str()).unwrap_or("0");
    if !config.contains_key("NODE_ROLE") {
        let default_role = if setup_complete == "1" { "admin" } else { "client" };
        config.insert("NODE_ROLE".to_string(), default_role.to_string());
    }

    // Validate NODE_ROLE
    let node_role = {
        let role = config.get("NODE_ROLE").unwrap(); // Safe because inserted above
        match role.as_str() {
            "admin" | "client" | "blind_exit" => role.clone(),
            _ => {
                eprintln!("[warn] Invalid NODE_ROLE='{}', defaulting to 'client'.", role);
                "client".to_string()
            }
        }
    };
    // Re-insert normalized role if it was invalid
    if config.get("NODE_ROLE").unwrap() != &node_role {
        config.insert("NODE_ROLE".to_string(), node_role.clone());
    }

    // enforce_role_policy_defaults logic
    if node_role == "client" {
        // Force specific settings for client
        if let Some(profile) = config.get("DEFAULT_LAUNCH_PROFILE") {
             match profile.as_str() {
                "quick-exit-node" | "quick-hybrid" => {
                    eprintln!("[warn] Launch profile '{}' is admin-only; forcing 'quick-connect' for client role.", profile);
                    config.insert("DEFAULT_LAUNCH_PROFILE".to_string(), "quick-connect".to_string());
                },
                _ => {}
             }
        }
        config.insert("AUTO_PORT_FORWARD_EXIT".to_string(), "0".to_string());
    } else if node_role == "blind_exit" {
        // Force settings for blind_exit
        if config.get("DEFAULT_LAUNCH_PROFILE").map(|s| s.as_str()) != Some("quick-exit-node") {
             eprintln!("[warn] blind_exit role enforces default launch profile 'quick-exit-node'.");
             config.insert("DEFAULT_LAUNCH_PROFILE".to_string(), "quick-exit-node".to_string());
        }
        config.insert("EXIT_CHAIN_HOPS".to_string(), "1".to_string());
        config.remove("EXIT_CHAIN_ENTRY_NODE_ID");
        config.remove("EXIT_CHAIN_FINAL_NODE_ID");
        config.insert("AUTO_LAUNCH_ON_START".to_string(), "1".to_string());
        config.remove("AUTO_LAUNCH_EXIT_NODE_ID");
        config.insert("AUTO_LAUNCH_LAN_MODE".to_string(), "off".to_string());
        config.insert("FAIL_CLOSED_SSH_ALLOW".to_string(), "0".to_string());
        config.remove("FAIL_CLOSED_SSH_ALLOW_CIDRS");
    }

    // Manual peer override is disabled
    config.insert("MANUAL_PEER_OVERRIDE".to_string(), "0".to_string());

    // enforce_backend_mode
    if !config.contains_key("BACKEND_MODE") {
         config.insert("BACKEND_MODE".to_string(), "linux-wireguard".to_string());
    }

    // enforce_auto_tunnel_policy
    if config.get("AUTO_TUNNEL_ENFORCE").map(|s| s.as_str()) != Some("1") {
         eprintln!("[warn] Unsigned/manual tunnel assignment is not allowed by default; forcing AUTO_TUNNEL_ENFORCE=1.");
         config.insert("AUTO_TUNNEL_ENFORCE".to_string(), "1".to_string());
    }

    // enforce_fail_closed_ssh_policy
    if config.get("FAIL_CLOSED_SSH_ALLOW").map(|s| s.as_str()) != Some("1") {
        config.insert("FAIL_CLOSED_SSH_ALLOW".to_string(), "0".to_string());
        config.remove("FAIL_CLOSED_SSH_ALLOW_CIDRS");
    } else {
         if config.get("FAIL_CLOSED_SSH_ALLOW_CIDRS").map(|s| s.trim()).unwrap_or("").is_empty() {
             return Err("FAIL_CLOSED_SSH_ALLOW_CIDRS is required when FAIL_CLOSED_SSH_ALLOW=1".to_string());
         }
    }

    // enforce_wg_listen_port_policy
    if let Some(port) = config.get("WG_LISTEN_PORT") {
        if let Ok(p) = port.parse::<u16>() {
            if p == 0 {
                 return Err(format!("Invalid WG_LISTEN_PORT '{}'. Expected numeric range 1..65535.", port));
            }
        } else {
             return Err(format!("Invalid WG_LISTEN_PORT '{}'. Expected numeric range 1..65535.", port));
        }
    }

    // enforce_auto_port_forward_policy
    if config.get("AUTO_PORT_FORWARD_EXIT").map(|s| s.as_str()) != Some("1") {
        config.insert("AUTO_PORT_FORWARD_EXIT".to_string(), "0".to_string());
    } else {
        // Check lease secs
        if let Some(lease) = config.get("AUTO_PORT_FORWARD_LEASE_SECS") {
             if let Ok(l) = lease.parse::<u64>() {
                 if l < 60 {
                      return Err(format!("Invalid AUTO_PORT_FORWARD_LEASE_SECS '{}'. Expected numeric value >= 60.", lease));
                 }
             } else {
                  return Err(format!("Invalid AUTO_PORT_FORWARD_LEASE_SECS '{}'. Expected numeric value >= 60.", lease));
             }
        }
        // Role check
        if node_role == "client" {
             eprintln!("[warn] Auto port-forward applies only to exit-serving roles. Forcing AUTO_PORT_FORWARD_EXIT=0 for role '{}'.", node_role);
             config.insert("AUTO_PORT_FORWARD_EXIT".to_string(), "0".to_string());
        }
    }

    // 3. Override Egress Interface if provided
    if let Some(egress) = egress_interface {
        config.insert("EGRESS_INTERFACE".to_string(), egress);
    }

    // 4. Set ENV variables for ops_install_systemd to consume
    for (key, value) in config {
        let env_key = if key.starts_with("RUSTYNET_") {
            key
        } else {
            format!("RUSTYNET_{}", key)
        };
        env::set_var(env_key, value);
    }

    // 5. Call install-systemd
    execute_ops_install_systemd()
}
