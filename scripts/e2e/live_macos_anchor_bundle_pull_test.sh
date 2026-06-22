#!/usr/bin/env bash
# Focused macOS anchor bundle-pull live validator (sub-test A1.2 parity).
#
# Drives the dedicated live_macos_anchor_test bin, which proves the
# com.rustynet.anchor loopback bundle-pull listener serves the signed
# membership snapshot byte-for-byte to a token-bearing peer and that
# every fail-closed control (token gate, LAN-bind refusal, secrets
# hygiene) holds live. Distinct from live_macos_anchor_test.sh, which
# drives the full shared anchor validator (membership / gossip /
# enrollment / downgrade) via live_linux_anchor_test --platform macos.
exec cargo run --quiet -p rustynet-cli --bin live_macos_anchor_test -- "$@"
