#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let _ = passeport::mnemonic::mnemonic_to_seed(data.0, data.1);
});
