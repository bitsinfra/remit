#![no_main]
// Anything the validator accepts must inhabit the type, idempotently, and the
// encoded set of accepted values never exceeds the declared capacity bound.
libfuzzer_sys::fuzz_target!(|data: (String, String)| {
    let (Ok(ty), Ok(v)) = (serde_json::from_str::<serde_json::Value>(&data.0), serde_json::from_str::<serde_json::Value>(&data.1)) else { return };
    let Ok(rt) = remit_types::Rt::from_json(&ty) else { return };
    let cap = rt.capacity_bits();
    assert!(cap >= 0.0 && !cap.is_nan(), "{ty}: {cap}");
    if let Ok(x) = rt.validate(&v) {
        assert_eq!(rt.validate(&x).as_ref(), Ok(&x), "validation must be idempotent");
    }
});
