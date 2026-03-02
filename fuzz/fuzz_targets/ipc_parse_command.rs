#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynetd::ipc::parse_command;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = parse_command(input.as_ref());
});
