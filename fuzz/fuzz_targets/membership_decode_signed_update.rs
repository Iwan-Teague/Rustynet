#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_control::membership::decode_signed_update;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = decode_signed_update(input.as_ref());
});
