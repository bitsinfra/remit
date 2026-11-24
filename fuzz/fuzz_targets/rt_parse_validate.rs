#![no_main]
// Split input into (type JSON, value JSON). Soundness: anything the validator
// accepts re-validates to itself (idempotent normalization).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (a, b) = s.split_once('\u{0}').unwrap_or((s, "null"));
    let (Ok(t), Ok(v)) = (serde_json::from_str::<serde_json::Value>(a), serde_json::from_str::<serde_json::Value>(b)) else { return };
    if let Ok(rt) = remit_types::Rt::from_json(&t) {
        let c = rt.capacity_bits();
        assert!(c >= 0.0 && !c.is_nan());
        if let Ok(n) = rt.validate(&v) {
            assert_eq!(rt.validate(&n).as_ref(), Ok(&n));
        }
    }
});
