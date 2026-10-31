#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_relay::transport::parse_relay_hello;

// AQ-29: the relay hello is the most exposed attacker-reachable parser in
// rustynet — a pre-authentication UDP datagram parsed before any signature
// verification. Every byte of `data` is hostile input; the parser must
// always return `Ok` (bounded, well-formed) or `Err` (rejected), never
// panic. Length-bound regressions here are covered by the daemon-side
// RLY-05/AUDIT-031 tests; this target is the always-on PR gate.
fuzz_target!(|data: &[u8]| {
    let _ = parse_relay_hello(data);
});
