#![no_main]
// The manifest decoder must never panic, and accepted manifests must hash.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(m) = remit_wire::Manifest::from_slice(data) {
        let _ = m.remit_id();
        let _ = m.params_sha256();
        let _ = remit_analyze::parse_returns(&m.returns);
    }
});
