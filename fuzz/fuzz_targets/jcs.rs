#![no_main]
// Canonicalization is idempotent and parses back to the same value.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Ok(c) = remit_wire::jcs::canonicalize(&v) {
            let back: serde_json::Value = serde_json::from_str(&c).expect("canonical JSON parses");
            assert_eq!(remit_wire::jcs::canonicalize(&back).unwrap(), c);
        }
    }
});
