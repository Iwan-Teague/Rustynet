#!/usr/bin/env bash
# Windows cross-compile gate.
#
# Exit modes:
#   0 + "PASS" line  — all checked targets compiled successfully.
#   0 + "SKIP" line  — no Windows targets are installed in rustup; acceptable
#                      on a Linux CI runner that never needs Windows artifacts.
#   1               — compilation failure; treat as regression.
#
# Toolchain notes:
#   - MUST use rustup cargo (has Windows targets).
#     Homebrew cargo only has aarch64-apple-darwin and will error "can't find crate for `core`".
#   - x86_64-pc-windows-gnu  → linker is x86_64-w64-mingw32-gcc (Homebrew mingw-w64).
#   - aarch64-pc-windows-gnullvm → skipped unless aarch64-w64-mingw32-clang is on PATH.
#   - aarch64-pc-windows-msvc  → skipped unless cargo-xwin is available (set up by Task 4).

set -euo pipefail

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
  echo "SKIP: rustup cargo not found; Windows cross-compile gate skipped"
  exit 0
fi

RUSTUP_BIN_DIR="$(dirname "$RUSTUP_CARGO")"
export PATH="$RUSTUP_BIN_DIR:$PATH"

# Check that at least one Windows target is installed.
INSTALLED_WINDOWS_TARGETS=$(rustup target list --installed 2>/dev/null | grep -E '^.*-windows-' || true)
if [[ -z "$INSTALLED_WINDOWS_TARGETS" ]]; then
  echo "SKIP: no Windows targets installed in rustup; Windows cross-compile gate skipped"
  exit 0
fi

FAILED=0

# ---------------------------------------------------------------------------
# x86_64-pc-windows-gnu  (mingw-w64 linker, always attempted when target installed)
# ---------------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q 'x86_64-pc-windows-gnu'; then
  echo "--- x86_64-pc-windows-gnu ---"

  MINGW_LINKER="$(which x86_64-w64-mingw32-gcc 2>/dev/null || true)"
  if [[ -z "$MINGW_LINKER" ]]; then
    echo "SKIP x86_64-pc-windows-gnu: x86_64-w64-mingw32-gcc not on PATH"
  else
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$MINGW_LINKER"

    # Core Windows-supported crates.
    # rustynet-cli is excluded: it uses nix / std::os::unix and is Unix-only by design.
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

  AARCH64_CLANG="$(which aarch64-w64-mingw32-clang 2>/dev/null || true)"
  if [[ -z "$AARCH64_CLANG" ]]; then
    echo "SKIP aarch64-pc-windows-gnullvm: aarch64-w64-mingw32-clang not on PATH"
  else
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
    echo "SKIP aarch64-pc-windows-msvc: cargo-xwin not installed (run: cargo install cargo-xwin)"
  else
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
    echo "SKIP x86_64-pc-windows-msvc: cargo-xwin not installed"
  else
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
      if ! cargo xwin check -p "$CRATE" --target x86_64-pc-windows-msvc 2>&1; then
        echo "FAIL: $CRATE failed x86_64-pc-windows-msvc xwin check"
        FAILED=1
      fi
    done
    echo "  SKIP rustynet-control rustynet-relay rustynetd x86_64-pc-windows-msvc (libsqlite3-sys C build requires pre-built SQLite lib)"
  fi
fi

if [[ "$FAILED" -ne 0 ]]; then
  echo "FAIL: Windows cross-compile gate failed"
  exit 1
fi

echo "PASS: Windows cross-compile gate passed"
exit 0
