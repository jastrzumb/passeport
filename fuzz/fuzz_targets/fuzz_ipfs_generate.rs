#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let _ = passeport::keys::ipfs::generate(&data);
});
