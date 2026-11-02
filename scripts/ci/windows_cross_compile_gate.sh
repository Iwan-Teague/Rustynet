#!/usr/bin/env bash
# Windows cross-compile gate.
#
# Exit modes:
#   0  + "PASS" line — at least one crate was cross-checked and every crate
#                      checked compiled. The PASS line states how many crate
#                      checks and legs ran; legs skipped for a missing linker or
#                      cargo-xwin are listed so a partial run is never silent.
#   1                — compilation failure; treat as regression.
#   65 (X6 ConfigError) — NOTHING WAS CHECKED: no rustup cargo, no installed
#                      Windows target, or no leg had its linker/cargo-xwin
#                      prerequisite. This is a failure, never a pass: a gate that
#                      compiled zero crates has proven nothing about Windows.
#                      Install the prerequisite, or do not invoke this gate on
#                      hosts that cannot cross-compile (it is deliberately not
#                      wired into the Linux/macOS/Windows CI legs).
#
# Toolchain notes:
#   - MUST use rustup cargo (has Windows targets).
#     Homebrew cargo only has aarch64-apple-darwin and will error "can't find crate for `core`".
#   - x86_64-pc-windows-gnu  → linker is x86_64-w64-mingw32-gcc (Homebrew mingw-w64).
#   - aarch64-pc-windows-gnullvm → skipped unless aarch64-w64-mingw32-clang is on PATH.
#   - aarch64-pc-windows-msvc  → skipped unless cargo-xwin is available (set up by Task 4).

set -euo pipefail

# Bookkeeping that makes "zero legs ran" detectable. CRATES_CHECKED counts crate
# checks actually attempted; LEGS_RUN counts targets whose prerequisites were met.
# SKIPPED_LEGS is a newline-joined string (not an array: bash 3.2 on macOS hosts
# aborts under `set -u` when expanding an empty array).
LEGS_RUN=0
CRATES_CHECKED=0
SKIPPED_LEGS=""

note_skip() {
  echo "SKIP $1"
  SKIPPED_LEGS="${SKIPPED_LEGS}  - $1"$'\n'
}

nothing_checked() {
  echo "FAIL: Windows cross-compile gate checked ZERO crates: $1" >&2
  echo "FAIL: a gate that compiled nothing proves nothing about Windows; this is not a pass" >&2
  exit 65
}

RUSTUP_CARGO="$(
  # Prefer the explicit 1.88 toolchain; fall back to whatever rustup exposes.
  for candidate in \
    "$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/cargo" \
    "$(rustup which cargo 2>/dev/null || true)"; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      break
    fi
  done
)"

if [[ -z "$RUSTUP_CARGO" ]]; then
  nothing_checked "rustup cargo not found"
fi

RUSTUP_BIN_DIR="$(dirname "$RUSTUP_CARGO")"
export PATH="$RUSTUP_BIN_DIR:$PATH"

# Check that at least one Windows target is installed.
INSTALLED_WINDOWS_TARGETS=$(rustup target list --installed 2>/dev/null | grep -E '^.*-windows-' || true)
if [[ -z "$INSTALLED_WINDOWS_TARGETS" ]]; then
  nothing_checked "no Windows targets installed in rustup (rustup target add x86_64-pc-windows-gnu)"
fi

FAILED=0

# ---------------------------------------------------------------------------
# x86_64-pc-windows-gnu  (mingw-w64 linker, always attempted when target installed)
# ---------------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q 'x86_64-pc-windows-gnu'; then
  echo "--- x86_64-pc-windows-gnu ---"

  MINGW_LINKER="$(command -v x86_64-w64-mingw32-gcc 2>/dev/null || true)"
  if [[ -z "$MINGW_LINKER" ]]; then
    note_skip "x86_64-pc-windows-gnu: x86_64-w64-mingw32-gcc not on PATH"
  else
    LEGS_RUN=$((LEGS_RUN + 1))
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$MINGW_LINKER"

    # Core Windows-supported crates.
    # rustynet-cli is excluded: it uses nix / std::os::unix and is Unix-only by design.
    #
    # Phase 28 fold-in (MED-1) coverage gap, deferred fix:
    #   The WindowsShellHost backend in
    #   crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell.rs
    #   IS Windows-runtime code but is never cross-compiled by this
    #   gate. The wrapping `rustynet-cli` crate pulls in `nix` and
    #   `std::os::unix` so `cargo check -p rustynet-cli --target
    #   *-windows-*` cannot succeed. Extending coverage to the
    #   submodule requires either:
    #     (a) extracting `live_lab_bin_support` into a no-`nix`
    #         sub-crate (`rustynet-live-lab-support`) that depends
    #         only on portable std + base64, and re-exporting from
    #         the bins, or
    #     (b) gating the Unix-only helpers in `mod.rs` behind
    #         `#[cfg(unix)]` so the bare `remote_shell` submodule
    #         can compile alone on Windows.
    #   Both are intentionally out of scope for the Phase 28 review
    #   fold-in to avoid a crate restructure inside a security fix.
    #   The Windows backend's runtime behaviour is still gated by the
    #   `pub(crate)` script-builder unit tests
    #   (`windows_write_file_script_*`, `windows_tcp_send_recv_script_*`,
    #   `windows_mode_to_acl_script_*`) which run on the host arch
    #   and verify the PowerShell body the remote will actually
    #   execute. A future task should land option (a) or (b) so the
    #   PowerShell-bearing module participates in this gate.
    for CRATE in \
      rustynet-backend-api \
      rustynet-backend-stub \
      rustynet-backend-wireguard \
      rustynet-backend-userspace \
      rustynet-windows-native \
      rustynet-control \
      rustynet-policy \
      rustynet-crypto \
      rustynet-dns-zone \
      rustynet-local-security \
      rustynet-relay \
      rustynet-sysinfo \
      rustynetd; do
      echo "  cargo check -p $CRATE --target x86_64-pc-windows-gnu"
      CRATES_CHECKED=$((CRATES_CHECKED + 1))
      if ! cargo check -p "$CRATE" --target x86_64-pc-windows-gnu 2>&1; then
        echo "FAIL: $CRATE failed x86_64-pc-windows-gnu check"
        FAILED=1
      fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# aarch64-pc-windows-gnullvm  (requires aarch64-w64-mingw32-clang — not installed by default)
# ---------------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q 'aarch64-pc-windows-gnullvm'; then
  echo "--- aarch64-pc-windows-gnullvm ---"

  AARCH64_CLANG="$(command -v aarch64-w64-mingw32-clang 2>/dev/null || true)"
  if [[ -z "$AARCH64_CLANG" ]]; then
    note_skip "aarch64-pc-windows-gnullvm: aarch64-w64-mingw32-clang not on PATH"
  else
    LEGS_RUN=$((LEGS_RUN + 1))
    export CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER="$AARCH64_CLANG"

    for CRATE in \
      rustynet-backend-api \
      rustynet-backend-stub \
      rustynet-windows-native \
      rustynet-control \
      rustynet-policy \
      rustynet-crypto \
      rustynet-dns-zone \
      rustynet-local-security; do
      echo "  cargo check -p $CRATE --target aarch64-pc-windows-gnullvm"
      CRATES_CHECKED=$((CRATES_CHECKED + 1))
      if ! cargo check -p "$CRATE" --target aarch64-pc-windows-gnullvm 2>&1; then
        echo "FAIL: $CRATE failed aarch64-pc-windows-gnullvm check"
        FAILED=1
      fi
    done

    # rustynetd skipped on aarch64-gnullvm when clang missing (per design).
    echo "  SKIP rustynetd aarch64-pc-windows-gnullvm (aarch64-w64-mingw32-clang required)"
  fi
fi

# ---------------------------------------------------------------------------
# aarch64-pc-windows-msvc  (requires cargo-xwin — set up by Task 4)
# ---------------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q 'aarch64-pc-windows-msvc'; then
  echo "--- aarch64-pc-windows-msvc ---"

  if ! cargo xwin --version >/dev/null 2>&1; then
    note_skip "aarch64-pc-windows-msvc: cargo-xwin not installed (run: cargo install cargo-xwin)"
  else
    LEGS_RUN=$((LEGS_RUN + 1))
    # rustynet-cli excluded: Unix-only.
    # rustynet-control, rustynet-relay, rustynetd excluded: they pull in libsqlite3-sys
    # which compiles bundled SQLite C source; clang-cl cannot find windows.h through
    # the xwin /imsvc SDK paths for this bundled C build.  The Rust API surface
    # compiles fine; a future task can wire in a pre-built SQLite lib or fix the
    # xwin SDK path injection for cc-rs C builds.
    for CRATE in \
      rustynet-backend-api \
      rustynet-backend-stub \
      rustynet-backend-wireguard \
      rustynet-backend-userspace \
      rustynet-windows-native \
      rustynet-policy \
      rustynet-crypto \
      rustynet-dns-zone \
      rustynet-local-security \
      rustynet-sysinfo; do
      echo "  cargo xwin check -p $CRATE --target aarch64-pc-windows-msvc"
      CRATES_CHECKED=$((CRATES_CHECKED + 1))
      if ! cargo xwin check -p "$CRATE" --target aarch64-pc-windows-msvc 2>&1; then
        echo "FAIL: $CRATE failed aarch64-pc-windows-msvc xwin check"
        FAILED=1
      fi
    done
    echo "  SKIP rustynet-control rustynet-relay rustynetd aarch64-pc-windows-msvc (libsqlite3-sys C build requires pre-built SQLite lib)"
  fi
fi

# ---------------------------------------------------------------------------
# x86_64-pc-windows-msvc  (cargo-xwin, if available)
# ---------------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q 'x86_64-pc-windows-msvc'; then
  echo "--- x86_64-pc-windows-msvc ---"

  if ! cargo xwin --version >/dev/null 2>&1; then
    note_skip "x86_64-pc-windows-msvc: cargo-xwin not installed"
  else
    LEGS_RUN=$((LEGS_RUN + 1))
    # rustynet-cli excluded: Unix-only.
    # rustynet-control, rustynet-relay, rustynetd excluded: libsqlite3-sys C build limitation.
    for CRATE in \
      rustynet-backend-api \
      rustynet-backend-stub \
      rustynet-backend-wireguard \
      rustynet-backend-userspace \
      rustynet-windows-native \
      rustynet-policy \
      rustynet-crypto \
      rustynet-dns-zone \
      rustynet-local-security \
      rustynet-sysinfo; do
      echo "  cargo xwin check -p $CRATE --target x86_64-pc-windows-msvc"
      CRATES_CHECKED=$((CRATES_CHECKED + 1))
      if ! cargo xwin check -p "$CRATE" --target x86_64-pc-windows-msvc 2>&1; then
        echo "FAIL: $CRATE failed x86_64-pc-windows-msvc xwin check"
        FAILED=1
      fi
    done
    echo "  SKIP rustynet-control rustynet-relay rustynetd x86_64-pc-windows-msvc (libsqlite3-sys C build requires pre-built SQLite lib)"
  fi
fi

# Zero-leg guard: installed Windows targets whose linker / cargo-xwin
# prerequisite is missing are skipped above; if EVERY leg was skipped, nothing
# was compiled and this must not read as a pass.
if [[ "$CRATES_CHECKED" -eq 0 ]]; then
  nothing_checked "every leg was skipped (installed Windows targets had no usable linker or cargo-xwin):
${SKIPPED_LEGS}"
fi

if [[ "$FAILED" -ne 0 ]]; then
  echo "FAIL: Windows cross-compile gate failed"
  exit 1
fi

if [[ -n "$SKIPPED_LEGS" ]]; then
  echo "NOTE: legs skipped (not checked):"
  printf '%s' "$SKIPPED_LEGS"
fi
echo "PASS: Windows cross-compile gate passed ($CRATES_CHECKED crate check(s) across $LEGS_RUN leg(s))"
exit 0
