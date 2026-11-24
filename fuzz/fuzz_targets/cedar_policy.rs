#![no_main]
// Policy text is Holder-authored but still parsed, linted and diffed.
libfuzzer_sys::fuzz_target!(|data: &str| {
    if data.len() > 4096 { return; }
    let _ = remit_policy::PolicyEngine::new(data, &Default::default(), &[]);
    if let Ok(set) = remit_policy::parse_policies(data) {
        let _ = remit_policy::symbolic::Model::new(&set, &Default::default());
    }
});
