#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = remit_analyze::check_js(s, "main");
    }
});
