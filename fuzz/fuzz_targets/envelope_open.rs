#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(env) = serde_json::from_slice::<remit_wire::Envelope>(data) {
        let _ = remit_wire::open_manifest(&env, remit_wire::public_key_from_did_key);
    }
});
