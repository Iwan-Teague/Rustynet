//! Build script: embeds the building toolchain's `rustc --version` string so
//! `rustynet info` can report the compiler that built the artifact without
//! spawning a subprocess at runtime. Runs the compiler cargo itself provides
//! (the `RUSTC` env var, falling back to `rustc`) argv-only — no shell, no
//! network. On any failure the constant is embedded empty and the runtime
//! accessor returns `None`.

use std::env;
use std::process::Command;

fn main() {
    // A toolchain switch changes RUSTC; re-run so the embedded constant
    // tracks the compiler actually building the artifact.
    println!("cargo:rerun-if-env-changed=RUSTC");

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    println!("cargo:rustc-env=RUSTYNET_BUILD_RUSTC_VERSION={version}");
}
