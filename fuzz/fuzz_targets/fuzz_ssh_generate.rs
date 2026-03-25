#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: ([u8; 32], &str)| {
    let _ = passeport::keys::ssh::generate(&data.0, data.1);
});
