#![no_main]
// The local binder must agree with the profile checker and never panic.
libfuzzer_sys::fuzz_target!(|data: &str| {
    let cat = serde_json::json!({"resources": [{"name": "a.b", "columns": [{"name": "x", "type": "int"}, {"name": "y", "type": "string"}]}]});
    let p = remit_sql::Profile::default();
    let bound = remit_sql::bind::bind(data, &cat, &p);
    if remit_sql::check(data, &p).is_err() {
        assert!(bound.is_err(), "binder accepted what the profile refuses");
    }
    if let Ok(b) = bound {
        assert!(b.reads.keys().all(|t| t == "a.b"));
    }
});
