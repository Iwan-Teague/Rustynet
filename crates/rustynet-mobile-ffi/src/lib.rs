//! Mobile FFI boundary for the Rustynet Android and iOS shells (MC1d, compile scope).
//!
//! This crate is std only. It holds the hand-written C ABI (`c_abi`), the panic
//! containment wrapper used by every export (`panic`), and the JNI shim skeleton
//! (`jni_shim`). The shim forwards to the C ABI and holds no logic.
//!
//! `rn_mobile_start_raw_fd` is `unsafe extern "C"`. It adopts the integer descriptor into
//! an `OwnedFd` and returns `Unsupported`, because the engine is not wired until MC1e.
//! Panics never cross the C ABI. The crate needs `panic = "unwind"`, which the check
//! below enforces.
//!
//! `unsafe` is confined to this crate by design (DESIGN-mobile-security-architecture
//! section 5.2, U-1 and U-2). The unsafe census is pinned by
//! `scripts/ci/mobile_unsafe_confinement_gate.sh`.
//!
//! Security notes for reviewers (the in-repo record for this boundary):
//! - Ownership. On Android, the native shell passes `pfd.dup().detachFd()` and keeps the
//!   original `ParcelFileDescriptor` (design section 3.10). Native code never closes a
//!   descriptor it has passed in. The C ABI closes it on every path after adoption, and
//!   a second close could hit a reused number.
//! - Caller responsibility. A refused integer is reported by its status, and the caller
//!   must act on it. `InvalidArgument` (negative) owns nothing. `StdioNotAdopted` (0..=2)
//!   leaves the integer with the caller, which must close it if it is the caller's own.
//!   After any other status, the descriptor has been closed by Rust, and the caller must
//!   not close it.
//! - MC1e requirement (not implemented in MC1c-2 or MC1d). A second adoption of the same
//!   integer must be refused by started-state. The MC1d skeleton returns `Unsupported`
//!   before any state exists.
//! - Every export runs its body under `catch_unwind`. A panic becomes `PanicCaught` (or 0
//!   for the ABI version), and the payload is neither printed nor dropped inside the guard.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

#[cfg(panic = "abort")]
compile_error!(
    "rustynet-mobile-ffi requires panic = \"unwind\": catch_unwind must observe every panic before it can cross the C ABI"
);

pub mod c_abi;
pub mod jni_shim;
mod panic;
