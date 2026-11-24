#![no_main]
// Malformed CBOR from guests must never crash the emit plane.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(v) = remit_emit::decode_kernel(data) {
        let rt = remit_types::Rt::from_json(&serde_json::json!({"list": {"max": 8, "of": {"struct": {"a": {"int": {"min": 0, "max": 9}}}}}})).unwrap();
        let _ = remit_emit::emit(&rt, &v, 1 << 16);
    }
});
