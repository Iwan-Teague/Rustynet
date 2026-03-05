#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

echo "[macos-smoke] validating hardened macOS startup contracts in start.sh"
if ! rg -n 'RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH' start.sh >/dev/null; then
  echo "[macos-smoke] missing explicit macOS passphrase source contract wiring in start.sh" >&2
  exit 1
fi
if ! rg -n 'RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT' start.sh >/dev/null; then
  echo "[macos-smoke] missing macOS keychain account passphrase contract wiring in start.sh" >&2
  exit 1
fi
if ! rg -n 'rustynetd key store-passphrase' start.sh >/dev/null; then
  echo "[macos-smoke] missing macOS keychain passphrase provisioning command in start.sh" >&2
  exit 1
fi
if rg -n 'install_macos_unprivileged_wireguard_tools' start.sh >/dev/null; then
  echo "[macos-smoke] insecure macOS unprivileged wireguard fallback is still present" >&2
  exit 1
fi
if ! rg -n 'launchctl bootstrap system "\$\{MACOS_LAUNCHD_HELPER_PLIST_PATH\}"' start.sh >/dev/null; then
  echo "[macos-smoke] launchd helper bootstrap wiring missing in start.sh" >&2
  exit 1
fi
if ! rg -n 'launchctl bootstrap "\$\{daemon_domain\}" "\$\{MACOS_LAUNCHD_DAEMON_PLIST_PATH\}"' start.sh >/dev/null; then
  echo "[macos-smoke] launchd daemon bootstrap wiring missing in start.sh" >&2
  exit 1
fi
if ! bash -n start.sh; then
  echo "[macos-smoke] start.sh syntax check failed" >&2
  exit 1
fi

echo "[macos-smoke] running targeted macOS dataplane security tests"
cargo test -p rustynetd --all-features phase10::tests::macos_render_pf_rules_enforces_dns_fail_closed_when_enabled -- --exact
cargo test -p rustynetd --all-features phase10::tests::macos_dns_rule_parser_accepts_port_alias_output -- --exact
cargo test -p rustynet-backend-wireguard --all-features tests::macos_backend_reports_ipv6_not_supported_until_parity_is_implemented -- --exact
