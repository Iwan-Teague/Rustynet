#![forbid(unsafe_code)]
//! Portable operator-UX logic for the `start.sh` shell-to-Rust migration.
//!
//! This crate intentionally holds pure, unit-testable decisions: config
//! parsing, role normalization, launch/argument validation, and route-output
//! parsing. TTY rendering and process dispatch stay in `rustynet-cli`.

pub mod args;
pub mod config;
pub mod egress;
pub mod host;
pub mod launch;
pub mod menu;
pub mod role;
