//! Build script: bakes the Rustynet repo root into the binary at compile time.
//! The MCP servers use this to find documents/ and crates/ regardless of CWD.

use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR = .../Rustynet/crates/rustynet-mcp
    // Go up two levels to get the repo root
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // Rustynet/
        .expect("Failed to resolve repo root from CARGO_MANIFEST_DIR");

    println!(
        "cargo:rustc-env=RUSTYNET_REPO_BAKED={}",
        repo_root.display()
    );
}
