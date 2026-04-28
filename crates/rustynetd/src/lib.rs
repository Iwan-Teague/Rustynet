#![forbid(unsafe_code)]

pub mod daemon;
pub mod dataplane;
pub mod fetcher;
pub mod ipc;
pub mod key_material;
pub mod perf;
pub mod phase10;
pub mod platform;
pub mod privileged_helper;
pub mod relay_client;
pub mod resilience;
pub mod stun_client;
pub mod traversal;
pub mod windows_authenticode;
pub mod windows_backend_gate;
pub mod windows_backend_readiness;
pub mod windows_dns_failclosed;
pub mod windows_ipc;
pub mod windows_key_custody;
pub mod windows_mesh_status;
pub mod windows_paths;
pub mod windows_runtime_boundary;
pub mod windows_service;
pub mod windows_service_hardening;
