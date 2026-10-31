#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_dns_zone::{
    parse_dns_zone_verifying_key, parse_signed_dns_zone_bundle_wire, verify_signed_dns_zone_bundle,
};

// AQ-29: dns-zone signed bundle wire parser + verifier
// (crates/rustynet-dns-zone/src/lib.rs:291 parse, :274 verify).
//
// ATTACKER: the control-plane zone publisher (an authenticated but untrusted
// principal, or anyone who can inject into the zone-distribution channel).
// These bytes arrive as the fetched dns_zone bundle body and are decoded by
// `parse_signed_dns_zone_bundle_wire` BEFORE signature verification, then fed
// to `verify_signed_dns_zone_bundle`. The fixed key is the RFC 8032 test-1
// public key; verification with it still exercises the strict verifier on
// attacker-shaped bundles while never accepting them.
const FIXED_VERIFYING_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fuzz_target!(|data: &[u8]| {
    let wire = String::from_utf8_lossy(data);
    if let Ok(key) = parse_dns_zone_verifying_key(FIXED_VERIFYING_KEY_HEX) {
        if let Ok(bundle) = parse_signed_dns_zone_bundle_wire(wire.as_ref()) {
            let _ = verify_signed_dns_zone_bundle(&bundle, &key);
        }
    }
});
