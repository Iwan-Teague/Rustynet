#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynetd::fetcher::SignedBundle;

// AQ-29: the daemon's signed-bundle pull/decode path
// (crates/rustynetd/src/fetcher.rs:268 SignedBundle::parse — the function
// `StateFetcher::process_response_bytes` calls on every fetched bundle body
// BEFORE signature verification at fetcher.rs:224).
//
// ATTACKER: the control-plane server on the other side of the mTLS control
// channel (or a channel injector). Its response bytes are the raw input to
// this parser; whatever survives parse then reaches verify_signature and the
// watermark store, so a parser panic here is pre-verification attacker
// reachability.
fuzz_target!(|data: &[u8]| {
    let _ = SignedBundle::parse(data);
});
