# CI-faithful pinned-toolchain runner.
#
# Bare `cargo` on this Mac resolves rustc and cargo-clippy to the
# Homebrew-installed toolchain that shadows them on PATH, while CI builds with
# the toolchain pinned in rust-toolchain.toml — a locally green run can be red
# in CI. Every recipe below prepends the pinned rustup toolchain's bin
# directory to PATH and builds into a dedicated CARGO_TARGET_DIR
# (target-pinned/, gitignored), echoing the pinned rustc version first so any
# drift between local and CI is visible immediately.

set shell := ["bash", "-cu", "-o", "pipefail"]

pin := "1.88.0-aarch64-apple-darwin"
pinned_bin := home_directory() + "/.rustup/toolchains/" + pin + "/bin"

export PATH := pinned_bin + ":" + env_var_or_default("PATH", "/usr/bin:/bin")
export CARGO_TARGET_DIR := justfile_directory() / "target-pinned"

# Show the available recipes by default.
default:
    @just --list

# Fail closed when the pinned toolchain is not installed, and print the pinned
# rustc version so toolchain drift is visible on every run.
[private]
guard:
    if [ ! -x "{{pinned_bin}}/cargo" ]; then
        echo "ERROR: pinned toolchain not found: {{pinned_bin}}" >&2
        echo "Install it with: rustup toolchain install 1.88.0 --profile minimal --component rustfmt clippy" >&2
        exit 1
    fi
    echo "== pinned $(rustc --version), $(cargo --version), CARGO_TARGET_DIR={{CARGO_TARGET_DIR}}"

# cargo check under the pinned toolchain. Optional package scope:
#   just check            (whole workspace)
#   just check rustynet-relay
check pkg="":
    @just guard
    cargo check {{ if pkg == "" { "" } else { "-p " + pkg } }} --all-targets --all-features

# cargo clippy with CI's warning-as-errors flags. Optional package scope.
clippy pkg="":
    @just guard
    cargo clippy {{ if pkg == "" { "" } else { "-p " + pkg } }} --all-targets --all-features -- -D warnings

# cargo test. Optional package scope.
test pkg="":
    @just guard
    cargo test {{ if pkg == "" { "" } else { "-p " + pkg } }} --all-targets --all-features

# rustfmt check over the whole workspace under the pinned PATH.
fmt:
    @just guard
    cargo fmt --all -- --check

# The full gate chain CI runs: fmt-check -> clippy -> test, stopping on the
# first failure. This is the habit to build before pushing.
gates:
    @just fmt && just clippy && just test
