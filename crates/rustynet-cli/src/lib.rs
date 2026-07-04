#![forbid(unsafe_code)]

//! Library surface for the `rustynet-cli` package.
//!
//! `src/main.rs` remains the primary Unix-oriented `rustynet` operator
//! binary. This crate exists so sibling binaries under `src/bin/` —
//! notably the Windows daemon-control CLI
//! (`src/bin/rustynet-windows-trust-cli.rs`) — can reuse the pure,
//! platform-neutral role-transition planner instead of forking a second
//! copy of it (CLAUDE.md §3: one hardened execution path per
//! security-sensitive workflow).

#[path = "role_cli.rs"]
pub mod role_cli;
