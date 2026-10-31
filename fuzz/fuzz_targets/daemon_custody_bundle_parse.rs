#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynetd::daemon::daemon_custody_fuzz;

// AQ-29: the daemon's private local-custody bundle loaders, reached through
// the `fuzzing`-feature-only module daemon_custody_fuzz (compiled from the
// real `load_trust_evidence`, `load_auto_tunnel_bundle`,
// `load_traversal_bundle_set` and `load_relay_fleet_bundle` in
// crates/rustynetd/src/daemon.rs — the same functions the daemon's boot and
// role-switch paths call on artifacts read from local disk).
//
// ATTACKER: anyone who can write or tamper with the daemon's on-disk custody
// files (a compromised co-tenant, a stolen/rotated artifact, a hostile
// backup-restore). The leading selector byte picks the loader; the remaining
// bytes are the raw artifact body staged to a per-execution temp file by the
// module. Results are ignored: we are hunting panics/hangs, and the bool
// return only records whether the real loader accepted the input.
fuzz_target!(|data: &[u8]| {
    let Some((selector, artifact)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => {
            let _ = daemon_custody_fuzz::fuzz_load_trust_evidence(artifact);
        }
        1 => {
            let _ = daemon_custody_fuzz::fuzz_load_auto_tunnel_bundle(artifact);
        }
        2 => {
            let _ = daemon_custody_fuzz::fuzz_load_traversal_bundle_set(artifact);
        }
        _ => {
            let _ = daemon_custody_fuzz::fuzz_load_relay_fleet_bundle(artifact);
        }
    }
});
