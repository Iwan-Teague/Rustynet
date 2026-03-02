#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_control::membership::decode_membership_state;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = decode_membership_state(input.as_ref());
});
