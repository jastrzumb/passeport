#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 64]| {
    let _ = passeport::derive::derive_keys(&data);
});
