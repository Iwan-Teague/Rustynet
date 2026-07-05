#![allow(dead_code)]
//! Cross-OS role-validation primitives for the standard orchestrator.
//!
//! Each submodule folds a formerly Linux-only role-lifecycle test bin
//! into a platform-agnostic check driven through the orchestrator's
//! hardened [`RemoteShellHost`](crate::vm_lab::orchestrator::remote_shell)
//! seam, so the standard orchestrator's role-validation stages run the
//! same proof on Linux, macOS, and Windows.
//!
//! The `anchor` submodule validates the anchor capability-advertisement
//! surface (cross-OS); `relay` validates the relay service lifecycle.

pub mod anchor;
pub mod relay;
pub mod security_audit;
